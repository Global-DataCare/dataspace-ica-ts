import { createHash, createHmac, randomUUID, timingSafeEqual } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import { loadIcaSecurityConfigFromEnv } from '../security-mode.ts';

type JsonObject = Record<string, unknown>;

type SessionClaims = {
  iss: string;
  sub: string;
  aud: string;
  iat: number;
  exp: number;
  jti: string;
  token_use: 'dataconv_access';
  organization: string;
  scope: string;
  scopes: string[];
  client_id?: string;
};

type ApiKeyPolicyRecord = {
  keyId: string;
  keyHash: string;
  tenantId: string;
  emailHash: string;
  scopes: string[];
  target: string;
  instrument: JsonObject;
  actionStatus: 'active' | 'disabled';
  disabled: boolean;
  createdAt: string;
  createdBy: string;
  expiresAt?: string;
};

type DcrBindingRecord = {
  tenantId: string;
  clientId: string;
  apiKeyHash: string;
  controllerPublicKeyJwk: JsonObject;
  metadata: JsonObject;
  bindingStatus: 'bound';
  boundAt: number;
  device: JsonObject;
};

type PkceCodeRecord = {
  tenantId: string;
  clientId: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
  expiresAtEpoch: number;
};

type IdTokenRecord = {
  tenantId: string;
  clientId: string;
  expiresAtEpoch: number;
};

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function toLower(value: string): string {
  return value.trim().toLowerCase();
}

function sha256Hex(value: string): string {
  return createHash('sha256').update(value, 'utf8').digest('hex').toLowerCase();
}

function sha3_256Multibase(email: string): string {
  const digest = createHash('sha3-256').update(email, 'utf8').digest();
  const multihash = Buffer.concat([Buffer.from([0x16, digest.length]), digest]);
  const alphabet = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
  let zeros = 0;
  for (const byte of multihash) {
    if (byte === 0) zeros += 1;
    else break;
  }
  let value = BigInt(`0x${multihash.toString('hex')}`);
  let out = '';
  while (value > 0n) {
    const rem = Number(value % 58n);
    out = alphabet[rem] + out;
    value = value / 58n;
  }
  if (!out) out = '1';
  if (zeros > 0) out = `${'1'.repeat(zeros)}${out}`;
  return `z${out}`;
}

function b64UrlEncode(raw: Buffer): string {
  return raw.toString('base64url');
}

function b64UrlDecode(text: string): Buffer {
  return Buffer.from(text, 'base64url');
}

function parseJwtUnverified(token: string): { header: JsonObject; payload: JsonObject; signedInput: string; signatureB64: string } {
  const parts = String(token || '').trim().split('.');
  if (parts.length !== 3) {
    throw new Error('JWT must have exactly 3 parts.');
  }
  const [headerB64, payloadB64, signatureB64] = parts;
  let header: JsonObject;
  let payload: JsonObject;
  try {
    header = JSON.parse(b64UrlDecode(headerB64).toString('utf8')) as JsonObject;
    payload = JSON.parse(b64UrlDecode(payloadB64).toString('utf8')) as JsonObject;
  } catch {
    throw new Error('Invalid JWT encoding.');
  }
  return {
    header,
    payload,
    signedInput: `${headerB64}.${payloadB64}`,
    signatureB64,
  };
}

function verifyHs256Signature(token: string, secret: string): boolean {
  const { signedInput, signatureB64 } = parseJwtUnverified(token);
  const expected = createHmac('sha256', secret).update(signedInput, 'utf8').digest();
  const actual = b64UrlDecode(signatureB64);
  if (expected.length !== actual.length) return false;
  return timingSafeEqual(expected, actual);
}

function toEpoch(value: unknown): number {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? Math.trunc(parsed) : 0;
}

function temporalClaimsValid(payload: JsonObject, nowEpoch: number, skewSeconds = 60): boolean {
  const exp = toEpoch(payload.exp);
  if (exp <= 0 || exp < (nowEpoch - skewSeconds)) return false;
  const nbf = toEpoch(payload.nbf);
  if (nbf && nbf > (nowEpoch + skewSeconds)) return false;
  const iat = toEpoch(payload.iat);
  if (iat && iat > (nowEpoch + skewSeconds)) return false;
  return true;
}

function normalizeEmail(email: string): string {
  return toLower(email);
}

function pkceS256Challenge(codeVerifier: string): string {
  const digest = createHash('sha256').update(codeVerifier, 'utf8').digest();
  return b64UrlEncode(digest);
}

function decodeBearerToken(req: IncomingMessage): string {
  const authHeader = req.headers.authorization;
  const raw = Array.isArray(authHeader) ? authHeader[0] : (authHeader || '');
  const value = String(raw || '').trim();
  if (!value.toLowerCase().startsWith('bearer ')) {
    throw new Error('Bearer token required.');
  }
  const token = value.slice(7).trim();
  if (!token) {
    throw new Error('Bearer token required.');
  }
  return token;
}

function buildSessionSecret(): string {
  return (
    process.env.ICA_EXCHANGE_SESSION_TOKEN_SECRET
    || process.env.EXCHANGE_SESSION_TOKEN_SECRET
    || process.env.ICA_AUTH_SESSION_TOKEN_SECRET
    || ''
  ).trim();
}

function buildJwt(payload: JsonObject, secret: string): string {
  const header = {
    alg: 'HS256',
    typ: 'JWT',
  };
  const encodedHeader = b64UrlEncode(Buffer.from(JSON.stringify(header), 'utf8'));
  const encodedPayload = b64UrlEncode(Buffer.from(JSON.stringify(payload), 'utf8'));
  const signedInput = `${encodedHeader}.${encodedPayload}`;
  const signature = createHmac('sha256', secret).update(signedInput, 'utf8').digest();
  return `${signedInput}.${b64UrlEncode(signature)}`;
}

function parseScopes(payload: JsonObject): string[] {
  const result = new Set<string>();
  const rawScope = asNonEmptyString(payload.scope);
  if (rawScope) {
    rawScope.split(' ').map((item) => item.trim()).filter(Boolean).forEach((item) => result.add(item));
  }
  const rawScopes = payload.scopes;
  if (Array.isArray(rawScopes)) {
    rawScopes
      .map((item) => asNonEmptyString(item))
      .filter(Boolean)
      .forEach((item) => result.add(item));
  }
  return Array.from(result.values());
}

export type ApiKeyAction = '_create' | '_disable' | '_remove' | '_search';

export class BackendAuthService {
  private readonly apiKeysByTenant = new Map<string, ApiKeyPolicyRecord[]>();
  private readonly bindingsByTenant = new Map<string, DcrBindingRecord[]>();
  private readonly pkceCodes = new Map<string, PkceCodeRecord>();
  private readonly idTokens = new Map<string, IdTokenRecord>();

  validateBearerAccess(req: IncomingMessage, expectedTenantId?: string): SessionClaims {
    const token = decodeBearerToken(req);
    const security = loadIcaSecurityConfigFromEnv();
    const secret = buildSessionSecret();
    const { header, payload } = parseJwtUnverified(token);
    const skipBearerSignatureValidation = security.securityMode === 'demo'
      && security.demoAllowInsecureBearer;

    if (!skipBearerSignatureValidation) {
      const alg = asNonEmptyString(header.alg).toUpperCase();
      if (alg !== 'HS256') {
        throw new Error('Unsupported session token algorithm.');
      }
      if (!secret || !verifyHs256Signature(token, secret)) {
        throw new Error('Invalid session token signature.');
      }
      const nowEpoch = Math.trunc(Date.now() / 1000);
      if (!temporalClaimsValid(payload, nowEpoch)) {
        throw new Error('Session token expired or invalid.');
      }
    }

    if (asNonEmptyString(payload.token_use) !== 'dataconv_access') {
      throw new Error('Invalid session token use.');
    }

    const organization = asNonEmptyString(payload.organization).toLowerCase();
    if (!organization) {
      throw new Error('Session token organization claim is required.');
    }
    if (expectedTenantId && organization !== toLower(expectedTenantId)) {
      throw new Error('Bearer token organization does not match tenantId path.');
    }

    return {
      iss: asNonEmptyString(payload.iss),
      sub: asNonEmptyString(payload.sub),
      aud: asNonEmptyString(payload.aud),
      iat: toEpoch(payload.iat),
      exp: toEpoch(payload.exp),
      jti: asNonEmptyString(payload.jti),
      token_use: 'dataconv_access',
      organization,
      scope: asNonEmptyString(payload.scope),
      scopes: parseScopes(payload),
      ...(asNonEmptyString(payload.client_id) ? { client_id: asNonEmptyString(payload.client_id) } : {}),
    };
  }

  issueAccessToken(params: {
    subject: string;
    organization: string;
    scopes: string[];
    clientId?: string;
  }): { accessToken: string; expiresIn: number; tokenType: 'Bearer'; claims: SessionClaims } {
    const secret = buildSessionSecret();
    if (!secret) {
      throw new Error('Session token secret is not configured.');
    }
    const issuer = (process.env.ICA_DIDCOMM_ISSUER_DID || 'did:web:localhost%3A3310').trim();
    const audience = (process.env.ICA_DIDCOMM_AUDIENCE_DID || 'did:web:localhost%3A3310').trim();
    const ttlSeconds = Number.parseInt(process.env.ICA_AUTH_ACCESS_TOKEN_TTL_SECONDS || '900', 10) || 900;
    const nowEpoch = Math.trunc(Date.now() / 1000);
    const claims: SessionClaims = {
      iss: issuer,
      sub: params.subject,
      aud: audience,
      iat: nowEpoch,
      exp: nowEpoch + ttlSeconds,
      jti: randomUUID(),
      token_use: 'dataconv_access',
      organization: toLower(params.organization),
      scope: params.scopes.join(' '),
      scopes: params.scopes,
      ...(params.clientId ? { client_id: params.clientId } : {}),
    };
    const accessToken = buildJwt(claims as unknown as JsonObject, secret);
    return {
      accessToken,
      expiresIn: ttlSeconds,
      tokenType: 'Bearer',
      claims,
    };
  }

  createApiKeys(params: {
    tenantId: string;
    actorSubject: string;
    actions: Array<{ email: string; scopes: string[]; target?: string; instrument?: JsonObject; expiresInSeconds?: number }>;
  }): Array<JsonObject> {
    const tenantKey = toLower(params.tenantId);
    const existing = this.apiKeysByTenant.get(tenantKey) || [];
    const now = new Date();
    const nowIso = now.toISOString();
    const created: JsonObject[] = [];

    for (const action of params.actions) {
      const email = normalizeEmail(action.email);
      if (!email) throw new Error('agent.email is required for each action.');
      if (!action.scopes.length) throw new Error('scope is required for each action.');

      const apiKey = `ica_k_${randomUUID().replace(/-/g, '')}`;
      const keyId = randomUUID();
      const keyHash = sha256Hex(apiKey);
      const expiresAt = action.expiresInSeconds && action.expiresInSeconds > 0
        ? new Date(now.getTime() + action.expiresInSeconds * 1000).toISOString()
        : undefined;

      const record: ApiKeyPolicyRecord = {
        keyId,
        keyHash,
        tenantId: tenantKey,
        emailHash: sha3_256Multibase(email),
        scopes: action.scopes,
        target: action.target || '',
        instrument: action.instrument || {},
        actionStatus: 'active',
        disabled: false,
        createdAt: nowIso,
        createdBy: params.actorSubject,
        ...(expiresAt ? { expiresAt } : {}),
      };
      existing.push(record);
      created.push({
        resource: {
          '@context': 'https://schema.org',
          '@type': 'Person',
          identifier: keyId,
          keyHash,
          actionStatus: 'active',
          bindingStatus: 'pending_dcr',
          agent: {
            sameAs: record.emailHash,
          },
          target: record.target,
          scope: record.scopes,
          instrument: record.instrument,
          tenantId: record.tenantId,
          ...(record.expiresAt ? { expiresAt: record.expiresAt } : {}),
          apiKey,
        },
      });
    }

    this.apiKeysByTenant.set(tenantKey, existing);
    return created;
  }

  mutateApiKeys(params: {
    tenantId: string;
    action: '_disable' | '_remove';
    selectors: Array<{ identifier?: string; emailHash?: string }>;
  }): Array<JsonObject> {
    const tenantKey = toLower(params.tenantId);
    const entries = this.apiKeysByTenant.get(tenantKey) || [];
    if (!params.selectors.length) {
      throw new Error('data must include at least one selector.');
    }

    const results: JsonObject[] = [];
    for (const selector of params.selectors) {
      const identifier = asNonEmptyString(selector.identifier);
      const emailHash = asNonEmptyString(selector.emailHash);
      const matched = entries.filter((item) =>
        (identifier && item.keyId === identifier)
        || (emailHash && item.emailHash === emailHash));

      if (!matched.length) {
        throw new Error('No API key matched selector.');
      }

      for (const item of matched) {
        if (params.action === '_disable') {
          item.disabled = true;
          item.actionStatus = 'disabled';
        }
      }

      if (params.action === '_remove') {
        for (const item of matched) {
          const idx = entries.findIndex((candidate) => candidate.keyId === item.keyId);
          if (idx >= 0) entries.splice(idx, 1);
        }
      }

      matched.forEach((item) => {
        results.push({
          resource: {
            '@context': 'https://schema.org',
            '@type': 'Person',
            identifier: item.keyId,
            keyHash: item.keyHash,
            actionStatus: params.action === '_disable' ? 'disabled' : 'removed',
            ...(params.action === '_remove' ? { removed: true } : {}),
            agent: { sameAs: item.emailHash },
            target: item.target,
            scope: item.scopes,
            instrument: item.instrument,
            tenantId: item.tenantId,
            ...(item.expiresAt ? { expiresAt: item.expiresAt } : {}),
          },
        });
      });
    }

    this.apiKeysByTenant.set(tenantKey, entries);
    return results;
  }

  listApiKeysWithBindings(tenantId: string): Array<JsonObject> {
    const tenantKey = toLower(tenantId);
    const keys = this.apiKeysByTenant.get(tenantKey) || [];
    const bindings = this.bindingsByTenant.get(tenantKey) || [];
    return keys.map((item) => {
      const relatedBindings = bindings
        .filter((binding) => binding.apiKeyHash === item.keyHash)
        .map((binding) => ({
          clientId: binding.clientId,
          bindingStatus: binding.bindingStatus,
          boundAt: binding.boundAt,
          controllerPublicKeyJwk: binding.controllerPublicKeyJwk,
          device: binding.device,
        }));
      return {
        resource: {
          '@context': 'https://schema.org',
          '@type': 'Person',
          identifier: item.keyId,
          keyHash: item.keyHash,
          actionStatus: item.actionStatus,
          bindingStatus: relatedBindings.length ? 'bound' : 'pending_dcr',
          agent: { sameAs: item.emailHash },
          target: item.target,
          scope: item.scopes,
          instrument: item.instrument,
          tenantId: item.tenantId,
          ...(item.expiresAt ? { expiresAt: item.expiresAt } : {}),
        },
        bindings: relatedBindings,
      };
    });
  }

  bindDcr(params: {
    tenantId: string;
    clientId: string;
    controllerPublicKeyJwk: JsonObject;
    metadata: JsonObject;
    device: JsonObject;
  }): { status: 'ok'; action: '_dcr'; bindingStatus: 'bound'; tenantId: string; clientId: string } {
    const tenantKey = toLower(params.tenantId);
    const clientId = asNonEmptyString(params.clientId);
    if (!clientId) throw new Error('client_id is required.');
    const keyHash = sha256Hex(clientId);

    const policies = this.apiKeysByTenant.get(tenantKey) || [];
    const policy = policies.find((item) => item.keyHash === keyHash);
    if (!policy) throw new Error('client_id does not match any provisioned API key.');
    if (policy.disabled || policy.actionStatus !== 'active') {
      throw new Error('API key is disabled or removed.');
    }

    const bindings = this.bindingsByTenant.get(tenantKey) || [];
    const nowEpoch = Math.trunc(Date.now() / 1000);
    const existingIndex = bindings.findIndex((item) => item.clientId === clientId);
    const binding: DcrBindingRecord = {
      tenantId: tenantKey,
      clientId,
      apiKeyHash: keyHash,
      controllerPublicKeyJwk: params.controllerPublicKeyJwk,
      metadata: params.metadata,
      bindingStatus: 'bound',
      boundAt: nowEpoch,
      device: params.device,
    };
    if (existingIndex >= 0) bindings[existingIndex] = binding;
    else bindings.push(binding);
    this.bindingsByTenant.set(tenantKey, bindings);

    return {
      status: 'ok',
      action: '_dcr',
      bindingStatus: 'bound',
      tenantId: tenantKey,
      clientId,
    };
  }

  issuePkceCode(params: {
    tenantId: string;
    clientId: string;
    codeChallenge: string;
    codeChallengeMethod: string;
  }): { status: 'ok'; action: '_code'; code: string; expires_in: number } {
    const tenantKey = toLower(params.tenantId);
    const clientId = asNonEmptyString(params.clientId);
    const codeChallenge = asNonEmptyString(params.codeChallenge);
    const method = asNonEmptyString(params.codeChallengeMethod || 'S256').toUpperCase();
    if (!clientId || !codeChallenge) {
      throw new Error('client_id and code_challenge are required.');
    }
    if (method !== 'S256') {
      throw new Error('code_challenge_method must be S256.');
    }
    this.assertBoundClient(tenantKey, clientId);

    const code = randomUUID();
    this.pkceCodes.set(code, {
      tenantId: tenantKey,
      clientId,
      codeChallenge,
      codeChallengeMethod: 'S256',
      expiresAtEpoch: Math.trunc(Date.now() / 1000) + 300,
    });

    return {
      status: 'ok',
      action: '_code',
      code,
      expires_in: 300,
    };
  }

  issuePkceIdToken(params: {
    tenantId: string;
    clientId: string;
    code: string;
    codeVerifier: string;
  }): { status: 'ok'; action: '_token'; id_token: string; token_type: string; expires_in: number } {
    const tenantKey = toLower(params.tenantId);
    const clientId = asNonEmptyString(params.clientId);
    const code = asNonEmptyString(params.code);
    const verifier = asNonEmptyString(params.codeVerifier);
    if (!clientId || !code || !verifier) {
      throw new Error('client_id, code and code_verifier are required.');
    }

    const codeRecord = this.pkceCodes.get(code);
    if (!codeRecord) throw new Error('invalid code.');
    if (codeRecord.expiresAtEpoch < Math.trunc(Date.now() / 1000)) {
      throw new Error('code expired.');
    }
    if (codeRecord.tenantId !== tenantKey) throw new Error('code tenant mismatch.');
    if (codeRecord.clientId !== clientId) throw new Error('code client mismatch.');
    const expectedChallenge = pkceS256Challenge(verifier);
    if (expectedChallenge !== codeRecord.codeChallenge) {
      throw new Error('invalid code_verifier.');
    }

    this.assertBoundClient(tenantKey, clientId);

    const nowEpoch = Math.trunc(Date.now() / 1000);
    const expiresIn = 300;
    const idPayload: JsonObject = {
      iss: 'https://identity.ica.local',
      sub: `client:${clientId}`,
      aud: 'ica',
      iat: nowEpoch,
      exp: nowEpoch + expiresIn,
      tenant: tenantKey,
      client_id: clientId,
      token_use: 'ica_pkce_id_token',
      jti: randomUUID(),
    };

    const secret = buildSessionSecret();
    if (!secret) {
      throw new Error('Session token secret is not configured.');
    }
    const idToken = buildJwt(idPayload, secret);
    this.idTokens.set(idToken, {
      tenantId: tenantKey,
      clientId,
      expiresAtEpoch: nowEpoch + expiresIn,
    });

    return {
      status: 'ok',
      action: '_token',
      id_token: idToken,
      token_type: 'urn:ietf:params:oauth:token-type:id_token',
      expires_in: expiresIn,
    };
  }

  exchangeIdentityToken(params: {
    tenantId: string;
    clientId: string;
    idToken: string;
  }): { status: 'ok'; action: '_exchange'; access_token: string; token_type: 'Bearer'; expires_in: number; scope: string } {
    const tenantKey = toLower(params.tenantId);
    const clientId = asNonEmptyString(params.clientId);
    const idToken = asNonEmptyString(params.idToken);
    if (!clientId || !idToken) {
      throw new Error('client_id and subject_token are required.');
    }

    const tokenRecord = this.idTokens.get(idToken);
    if (!tokenRecord) {
      throw new Error('subject_token is unknown or expired.');
    }
    if (tokenRecord.expiresAtEpoch < Math.trunc(Date.now() / 1000)) {
      throw new Error('subject_token expired.');
    }
    if (tokenRecord.tenantId !== tenantKey || tokenRecord.clientId !== clientId) {
      throw new Error('subject_token tenant/client mismatch.');
    }

    this.assertBoundClient(tenantKey, clientId);

    const issued = this.issueAccessToken({
      subject: `backend:${clientId}`,
      organization: tenantKey,
      scopes: ['ica.backend.read', 'ica.catalog.read'],
      clientId,
    });

    return {
      status: 'ok',
      action: '_exchange',
      access_token: issued.accessToken,
      token_type: issued.tokenType,
      expires_in: issued.expiresIn,
      scope: issued.claims.scope,
    };
  }

  exchangeControllerBootstrap(params: {
    tenantId: string;
    jurisdiction: string;
    sector: string;
    subject?: string;
  }): { status: 'ok'; action: '_exchange'; access_token: string; token_type: 'Bearer'; expires_in: number; organization: string; jurisdiction: string; sector: string } {
    const tenantKey = toLower(params.tenantId);
    const issued = this.issueAccessToken({
      subject: params.subject || `controller:${tenantKey}`,
      organization: tenantKey,
      scopes: ['dataconv.tenant.keys.manage', 'ica.backend.read', 'ica.catalog.read'],
    });

    return {
      status: 'ok',
      action: '_exchange',
      access_token: issued.accessToken,
      token_type: issued.tokenType,
      expires_in: issued.expiresIn,
      organization: tenantKey,
      jurisdiction: params.jurisdiction.toUpperCase(),
      sector: params.sector,
    };
  }

  private assertBoundClient(tenantId: string, clientId: string): void {
    const bindings = this.bindingsByTenant.get(tenantId) || [];
    const match = bindings.find((item) => item.clientId === clientId && item.bindingStatus === 'bound');
    if (!match) {
      throw new Error('client is not bound via _dcr (expected state: bound).');
    }
  }

  buildDeviceMetadata(req: IncomingMessage): JsonObject {
    const userAgent = req.headers['user-agent'];
    const xDeviceOs = req.headers['x-device-os'];
    const xDevicePlatform = req.headers['x-device-platform'];
    const xSdkVersion = req.headers['x-sdk-version'];
    return {
      userAgent: Array.isArray(userAgent) ? (userAgent[0] || '') : (userAgent || ''),
      os: Array.isArray(xDeviceOs) ? (xDeviceOs[0] || '') : (xDeviceOs || ''),
      platform: Array.isArray(xDevicePlatform) ? (xDevicePlatform[0] || '') : (xDevicePlatform || ''),
      sdkVersion: Array.isArray(xSdkVersion) ? (xSdkVersion[0] || '') : (xSdkVersion || ''),
    };
  }

  static extractDidcommControllerJwk(meta: unknown): JsonObject | undefined {
    const metaObj = asObject(meta);
    const jws = asObject(metaObj?.jws);
    const protectedHeader = asObject(jws?.protected);
    const jwk = asObject(protectedHeader?.jwk);
    if (!jwk) return undefined;
    return jwk;
  }
}

export function resolveDidcommBody(parsed: JsonObject): JsonObject {
  const body = asObject(parsed.body);
  return body || {};
}

export function resolveStringField(parsed: JsonObject, body: JsonObject, key: string): string {
  return asNonEmptyString(parsed[key]) || asNonEmptyString(body[key]);
}

export function resolveDidcommDataEntries(parsed: JsonObject, body: JsonObject): JsonObject[] {
  const bodyData = Array.isArray(body.data) ? body.data : [];
  const parsedData = Array.isArray(parsed.data) ? parsed.data : [];
  const selected = bodyData.length ? bodyData : parsedData;
  return selected
    .map((entry) => asObject(entry))
    .filter((entry): entry is JsonObject => Boolean(entry));
}

export function parseDidcommPlainPayload(req: IncomingMessage, rawBody: Buffer, actionLabel: string): JsonObject {
  const contentTypeHeader = Array.isArray(req.headers['content-type'])
    ? (req.headers['content-type'][0] || '')
    : (req.headers['content-type'] || '');
  const contentType = String(contentTypeHeader || '').split(';')[0].trim().toLowerCase();
  const contentEncodingHeader = Array.isArray(req.headers['content-encoding'])
    ? (req.headers['content-encoding'][0] || '')
    : (req.headers['content-encoding'] || '');
  const contentEncoding = String(contentEncodingHeader || '').trim().toLowerCase();

  if (contentEncoding && contentEncoding !== 'identity') {
    throw new Error(`Unsupported Content-Encoding for ${actionLabel}: ${contentEncoding} (expected identity)`);
  }
  if (contentType !== 'application/didcomm-plain+json') {
    throw new Error(`Unsupported Content-Type for ${actionLabel}: ${contentTypeHeader || '(missing)'} (expected application/didcomm-plain+json)`);
  }
  if (!rawBody.length) {
    throw new Error('Empty request payload.');
  }

  try {
    const parsed = JSON.parse(rawBody.toString('utf8')) as JsonObject;
    return asObject(parsed) || {};
  } catch (error: unknown) {
    throw new Error(`Invalid JSON body: ${(error as Error).message}`);
  }
}

export async function readIncomingBufferFromReq(req: IncomingMessage): Promise<Buffer<ArrayBufferLike>> {
  const chunks: Buffer<ArrayBufferLike>[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}
