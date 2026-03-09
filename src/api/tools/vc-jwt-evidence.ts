import {
  constants as cryptoConstants,
  createHash,
  createPublicKey,
  createVerify,
  randomUUID,
  verify as verifyDetachedRaw,
  X509Certificate,
} from 'node:crypto';
import type { AddEvidenceInput, SupportedSigningAlgorithm } from '../types.ts';

type JsonObject = Record<string, unknown>;

type ParsedCompactJwt = {
  header: JsonObject;
  payload: JsonObject;
  protectedEncoded: string;
  payloadEncoded: string;
  signature: Buffer;
  alg: SupportedSigningAlgorithm;
  kid?: string;
};

type ResolvedVcJwtAttachment = {
  attachmentId: string;
  jwt: string;
};

type TrustedVerificationKey = {
  kid?: string;
  jwk: JsonObject;
  x5c: string[];
  x5u?: string;
};

type TrustedIssuerProfile = {
  issuer: string;
  source: string;
  keys: TrustedVerificationKey[];
  allowedAlgs: Set<SupportedSigningAlgorithm>;
  trustAnchorPinsSha256: string[];
  allowedIssuerSubstrings: string[];
};

type TrustedIssuerEntry = {
  issuer?: string;
  did?: string;
  didUrl?: string;
  jwksUrl?: string;
  jwksKeys: JsonObject[];
  allowedAlgs?: Set<SupportedSigningAlgorithm>;
  trustAnchorPinsSha256: string[];
  allowedIssuerSubstrings: string[];
};

const ISSUER_CACHE = {
  expiresAt: 0,
  value: null as TrustedIssuerProfile[] | null,
  loading: null as Promise<TrustedIssuerProfile[]> | null,
};

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function asStringArray(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => asNonEmptyString(entry))
    .filter(Boolean);
}

function asCsv(value: string | undefined): string[] {
  return (value || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function parseSupportedSigningAlgorithm(raw: string): SupportedSigningAlgorithm | undefined {
  const normalized = raw.trim().toUpperCase();
  if (normalized === 'ES384') return 'ES384';
  if (normalized === 'ES256K') return 'ES256K';
  if (normalized === 'RS256') return 'RS256';
  if (normalized === 'PS256') return 'PS256';
  if (normalized === 'EDDSA') return 'EdDSA';
  return undefined;
}

function base64UrlDecodeToBuffer(input: string, segmentLabel: string): Buffer {
  const normalized = input.trim();
  if (!normalized) {
    throw new Error(`vc+jwt attachment has empty ${segmentLabel} segment.`);
  }
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  try {
    return Buffer.from(base64, 'base64');
  } catch (error: unknown) {
    throw new Error(`vc+jwt attachment has invalid ${segmentLabel} segment: ${(error as Error).message}`);
  }
}

function parseCompactJwt(jwt: string): ParsedCompactJwt {
  const parts = jwt.trim().split('.');
  if (parts.length !== 3) {
    throw new Error('vc+jwt attachment must be a compact JWS with 3 segments.');
  }
  const [protectedEncoded, payloadEncoded, signatureEncoded] = parts;
  const headerRaw = base64UrlDecodeToBuffer(protectedEncoded, 'protected');
  const payloadRaw = base64UrlDecodeToBuffer(payloadEncoded, 'payload');
  const signature = base64UrlDecodeToBuffer(signatureEncoded, 'signature');

  let header: JsonObject;
  let payload: JsonObject;
  try {
    header = JSON.parse(headerRaw.toString('utf8')) as JsonObject;
  } catch (error: unknown) {
    throw new Error(`vc+jwt attachment protected header is not valid JSON: ${(error as Error).message}`);
  }
  try {
    payload = JSON.parse(payloadRaw.toString('utf8')) as JsonObject;
  } catch (error: unknown) {
    throw new Error(`vc+jwt attachment payload is not valid JSON: ${(error as Error).message}`);
  }

  const alg = parseSupportedSigningAlgorithm(asNonEmptyString(header.alg));
  if (!alg) {
    throw new Error('vc+jwt attachment header.alg is required and must be supported.');
  }
  const kid = asNonEmptyString(header.kid) || undefined;
  return {
    header,
    payload,
    protectedEncoded,
    payloadEncoded,
    signature,
    alg,
    ...(kid ? { kid } : {}),
  };
}

function resolveDefaultAllowedAlgs(): Set<SupportedSigningAlgorithm> {
  const configured = asCsv(process.env.ICA_EVIDENCE_VC_ALLOWED_ALGS || process.env.ICA_PONTUSX_ALLOWED_ALGS);
  if (!configured.length) {
    return new Set<SupportedSigningAlgorithm>(['ES256K']);
  }
  const parsed = configured
    .map((value) => parseSupportedSigningAlgorithm(value))
    .filter(Boolean) as SupportedSigningAlgorithm[];
  return new Set(parsed);
}

function resolveGlobalTrustAnchorPinsSha256(): string[] {
  return asCsv(process.env.ICA_EVIDENCE_VC_ISSUERS_TRUST_ANCHOR_PINS_SHA256)
    .map((value) => normalizeHexLikeFingerprint(value))
    .filter(Boolean);
}

function resolveGlobalAllowedIssuerSubstrings(): string[] {
  return asCsv(process.env.ICA_EVIDENCE_VC_ISSUERS_ALLOWED_ISSUER_SUBSTRINGS)
    .map((value) => value.toLowerCase());
}

function isUrl(value: string): boolean {
  return /^https?:\/\//i.test(value.trim());
}

function parseTrustedIssuerEntriesFromRaw(raw: string): TrustedIssuerEntry[] {
  const trimmed = raw.trim();
  if (!trimmed) return [];

  const parseEntry = (entry: unknown): TrustedIssuerEntry | null => {
    if (typeof entry === 'string') {
      const value = entry.trim();
      if (!value) return null;
      if (value.startsWith('did:web:')) {
        return {
          did: value,
          jwksKeys: [],
          trustAnchorPinsSha256: [],
          allowedIssuerSubstrings: [],
        };
      }
      if (isUrl(value)) {
        return {
          didUrl: value,
          jwksKeys: [],
          trustAnchorPinsSha256: [],
          allowedIssuerSubstrings: [],
        };
      }
      return {
        issuer: value,
        jwksKeys: [],
        trustAnchorPinsSha256: [],
        allowedIssuerSubstrings: [],
      };
    }

    const objectEntry = asObject(entry);
    if (!objectEntry) return null;

    const did = asNonEmptyString(objectEntry.did || objectEntry.didWeb) || undefined;
    const didUrl = asNonEmptyString(objectEntry.didUrl || objectEntry.url) || undefined;
    const issuer = asNonEmptyString(objectEntry.issuer || objectEntry.iss || objectEntry.id) || undefined;
    const jwksUrl = asNonEmptyString(objectEntry.jwksUrl) || undefined;

    const jwksValue = objectEntry.jwks;
    const directKeys = Array.isArray(jwksValue)
      ? jwksValue.map((candidate) => asObject(candidate)).filter(Boolean) as JsonObject[]
      : Array.isArray(asObject(jwksValue)?.keys)
        ? ((asObject(jwksValue)?.keys as unknown[]).map((candidate) => asObject(candidate)).filter(Boolean) as JsonObject[])
        : [];

    const algValues = [
      ...asStringArray(objectEntry.allowedAlgs),
      ...asCsv(asNonEmptyString(objectEntry.allowedAlgsCsv) || undefined),
    ];
    const allowedAlgs = new Set(
      algValues
        .map((value) => parseSupportedSigningAlgorithm(value))
        .filter(Boolean) as SupportedSigningAlgorithm[],
    );

    const trustAnchorPinsSha256 = [
      ...asStringArray(objectEntry.trustAnchorPinsSha256),
      ...asCsv(asNonEmptyString(objectEntry.trustAnchorPinsSha256Csv) || undefined),
    ]
      .map((value) => normalizeHexLikeFingerprint(value))
      .filter(Boolean);

    const allowedIssuerSubstrings = [
      ...asStringArray(objectEntry.allowedIssuerSubstrings),
      ...asCsv(asNonEmptyString(objectEntry.allowedIssuerSubstringsCsv) || undefined),
    ]
      .map((value) => value.toLowerCase())
      .filter(Boolean);

    return {
      issuer,
      did,
      didUrl,
      jwksUrl,
      jwksKeys: directKeys,
      ...(allowedAlgs.size ? { allowedAlgs } : {}),
      trustAnchorPinsSha256,
      allowedIssuerSubstrings,
    };
  };

  try {
    const parsed = JSON.parse(trimmed) as unknown;
    if (Array.isArray(parsed)) {
      return parsed.map((entry) => parseEntry(entry)).filter(Boolean) as TrustedIssuerEntry[];
    }
    const parsedObject = asObject(parsed);
    if (Array.isArray(parsedObject?.issuers)) {
      return parsedObject.issuers
        .map((entry) => parseEntry(entry))
        .filter(Boolean) as TrustedIssuerEntry[];
    }
    const single = parseEntry(parsedObject);
    return single ? [single] : [];
  } catch {
    return asCsv(trimmed)
      .map((entry) => parseEntry(entry))
      .filter(Boolean) as TrustedIssuerEntry[];
  }
}

function parseLegacyTrustedJwksFromEnv(): JsonObject[] {
  const rawCollection = (process.env.ICA_PONTUSX_TRUSTED_JWKS_JSON || process.env.ICA_EVIDENCE_VCJWT_TRUSTED_JWKS_JSON || '').trim();
  const rawSingle = (process.env.ICA_PONTUSX_TRUSTED_JWK_JSON || process.env.ICA_EVIDENCE_VCJWT_TRUSTED_JWK_JSON || '').trim();

  const parsedKeys: JsonObject[] = [];
  if (rawCollection) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(rawCollection);
    } catch (error: unknown) {
      throw new Error(`Invalid trusted JWKS JSON in env: ${(error as Error).message}`);
    }
    if (Array.isArray(parsed)) {
      parsed.forEach((entry) => {
        const jwk = asObject(entry);
        if (jwk) parsedKeys.push(jwk);
      });
    } else {
      const jwks = asObject(parsed);
      const keys = Array.isArray(jwks?.keys) ? jwks.keys : [];
      keys.forEach((entry) => {
        const jwk = asObject(entry);
        if (jwk) parsedKeys.push(jwk);
      });
    }
  }

  if (rawSingle) {
    try {
      const parsed = JSON.parse(rawSingle);
      const jwk = asObject(parsed);
      if (jwk) parsedKeys.push(jwk);
    } catch (error: unknown) {
      throw new Error(`Invalid trusted JWK JSON in env: ${(error as Error).message}`);
    }
  }

  return parsedKeys;
}

function resolveTrustedIssuerEntriesFromEnv(): TrustedIssuerEntry[] {
  const raw = (
    process.env.ICA_EVIDENCE_VC_ISSUERS_LIST
    || process.env.ICA_VC_ISSUERS_LIST
    || process.env.ICA_VCISSUERSLIST
    || ''
  ).trim();
  const parsedEntries = parseTrustedIssuerEntriesFromRaw(raw);
  if (parsedEntries.length) return parsedEntries;

  const legacyKeys = parseLegacyTrustedJwksFromEnv();
  if (!legacyKeys.length) return [];

  const legacyIssuers = asCsv(process.env.ICA_PONTUSX_ALLOWED_ISSUERS || process.env.ICA_EVIDENCE_VCJWT_ALLOWED_ISSUERS);
  if (!legacyIssuers.length) {
    return [{
      issuer: '*',
      jwksKeys: legacyKeys,
      trustAnchorPinsSha256: [],
      allowedIssuerSubstrings: [],
    }];
  }
  return legacyIssuers.map((issuer) => ({
    issuer,
    jwksKeys: legacyKeys,
    trustAnchorPinsSha256: [],
    allowedIssuerSubstrings: [],
  }));
}

function decodeDidWebSegment(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

function didWebToDidJsonUrl(did: string): string {
  const normalized = did.trim();
  const suffix = normalized.slice('did:web:'.length);
  const segments = suffix.split(':').map((segment) => decodeDidWebSegment(segment)).filter(Boolean);
  if (!segments.length) {
    throw new Error(`Invalid did:web value "${did}".`);
  }
  const host = segments[0];
  const path = segments.slice(1).join('/');
  if (!path) {
    return `https://${host}/.well-known/did.json`;
  }
  return `https://${host}/${path}/did.json`;
}

async function fetchJsonObject(url: string, label: string): Promise<JsonObject> {
  let response: Response;
  try {
    response = await fetch(url);
  } catch (error: unknown) {
    throw new Error(`${label} fetch failed for ${url}: ${(error as Error).message}`);
  }
  if (!response.ok) {
    throw new Error(`${label} fetch failed for ${url}: HTTP ${response.status}.`);
  }
  let parsed: unknown;
  try {
    parsed = await response.json();
  } catch (error: unknown) {
    throw new Error(`${label} at ${url} is not valid JSON: ${(error as Error).message}`);
  }
  const object = asObject(parsed);
  if (!object) {
    throw new Error(`${label} at ${url} must be a JSON object.`);
  }
  return object;
}

async function fetchCertificateChainFromX5u(x5u: string): Promise<string[]> {
  const url = x5u.trim();
  if (!url) return [];
  let response: Response;
  try {
    response = await fetch(url);
  } catch (error: unknown) {
    throw new Error(`x5u fetch failed for ${url}: ${(error as Error).message}`);
  }
  if (!response.ok) {
    throw new Error(`x5u fetch failed for ${url}: HTTP ${response.status}.`);
  }
  const text = (await response.text()).trim();
  if (!text) return [];

  try {
    const parsed = JSON.parse(text) as unknown;
    const object = asObject(parsed);
    const x5c = asStringArray(object?.x5c);
    if (x5c.length) {
      return x5c.map((entry) => asPemFromX5c(entry));
    }
  } catch {
    // ignore non-json x5u payload
  }

  const pemChain = splitPemCertificates(text);
  if (pemChain.length) return pemChain;
  return [asPemFromX5c(text)];
}

function resolveDidAssertionMethodIds(didDocument: JsonObject): Set<string> {
  const assertionRaw = Array.isArray(didDocument.assertionMethod) ? didDocument.assertionMethod : [];
  const ids = new Set<string>();
  assertionRaw.forEach((entry) => {
    if (typeof entry === 'string') {
      const value = entry.trim();
      if (value) ids.add(value);
      return;
    }
    const objectEntry = asObject(entry);
    const value = asNonEmptyString(objectEntry?.id);
    if (value) ids.add(value);
  });
  return ids;
}

function extractTrustedKeysFromDidDocument(didDocument: JsonObject): TrustedVerificationKey[] {
  const methods = Array.isArray(didDocument.verificationMethod)
    ? didDocument.verificationMethod.map((entry) => asObject(entry)).filter(Boolean) as JsonObject[]
    : [];
  const assertionMethodIds = resolveDidAssertionMethodIds(didDocument);

  const keys: TrustedVerificationKey[] = [];
  methods.forEach((method) => {
    const methodId = asNonEmptyString(method.id) || undefined;
    if (assertionMethodIds.size && (!methodId || !assertionMethodIds.has(methodId))) {
      return;
    }
    const jwk = asObject(method.publicKeyJwk);
    if (!jwk) return;

    const x5c = [
      ...asStringArray(method.x5c),
      ...asStringArray(jwk.x5c),
    ];
    const x5u = asNonEmptyString(method.x5u || jwk.x5u) || undefined;

    const kid = methodId || asNonEmptyString(jwk.kid) || undefined;
    keys.push({
      jwk,
      ...(kid ? { kid } : {}),
      x5c,
      ...(x5u ? { x5u } : {}),
    });
  });

  return keys;
}

function extractKeysFromJwks(jwks: JsonObject): TrustedVerificationKey[] {
  const keys = Array.isArray(jwks.keys) ? jwks.keys : [];
  return keys
    .map((entry) => asObject(entry))
    .filter((entry): entry is JsonObject => Boolean(entry))
    .map((jwk) => ({
      jwk,
      ...(asNonEmptyString(jwk.kid) ? { kid: asNonEmptyString(jwk.kid) } : {}),
      x5c: asStringArray(jwk.x5c),
      ...(asNonEmptyString(jwk.x5u) ? { x5u: asNonEmptyString(jwk.x5u) } : {}),
    }));
}

async function resolveIssuerProfile(entry: TrustedIssuerEntry): Promise<TrustedIssuerProfile> {
  const source = entry.did || entry.didUrl || entry.issuer || 'vc-issuer';
  const keys: TrustedVerificationKey[] = entry.jwksKeys.map((jwk) => ({
    jwk,
    ...(asNonEmptyString(jwk.kid) ? { kid: asNonEmptyString(jwk.kid) } : {}),
    x5c: asStringArray(jwk.x5c),
    ...(asNonEmptyString(jwk.x5u) ? { x5u: asNonEmptyString(jwk.x5u) } : {}),
  }));

  let issuerFromDidOrConfig = entry.issuer || '';

  const resolvedDid = entry.did || (entry.didUrl && entry.didUrl.startsWith('did:web:') ? entry.didUrl : '');
  if (resolvedDid) {
    const didDocument = await fetchJsonObject(didWebToDidJsonUrl(resolvedDid), 'DID document');
    issuerFromDidOrConfig = issuerFromDidOrConfig || asNonEmptyString(didDocument.id) || resolvedDid;
    keys.push(...extractTrustedKeysFromDidDocument(didDocument));
  } else if (entry.didUrl) {
    const didLikeDocument = await fetchJsonObject(entry.didUrl, 'Issuer metadata');
    if (Array.isArray(didLikeDocument.verificationMethod)) {
      issuerFromDidOrConfig = issuerFromDidOrConfig || asNonEmptyString(didLikeDocument.id);
      keys.push(...extractTrustedKeysFromDidDocument(didLikeDocument));
    }
    if (Array.isArray(didLikeDocument.keys)) {
      keys.push(...extractKeysFromJwks(didLikeDocument));
    }
  }

  if (entry.jwksUrl) {
    const jwks = await fetchJsonObject(entry.jwksUrl, 'JWKS');
    keys.push(...extractKeysFromJwks(jwks));
  }

  const dedupKeyMap = new Map<string, TrustedVerificationKey>();
  keys.forEach((key, index) => {
    const marker = [key.kid || '', JSON.stringify(key.jwk), index].join('::');
    if (!dedupKeyMap.has(marker)) {
      dedupKeyMap.set(marker, key);
    }
  });
  const dedupKeys = Array.from(dedupKeyMap.values());

  if (!dedupKeys.length) {
    throw new Error(`Trusted issuer profile "${source}" resolved with no verification keys.`);
  }

  const issuer = issuerFromDidOrConfig || '';
  if (!issuer) {
    throw new Error(`Trusted issuer profile "${source}" must provide issuer or DID id.`);
  }

  return {
    issuer,
    source,
    keys: dedupKeys,
    allowedAlgs: entry.allowedAlgs && entry.allowedAlgs.size
      ? entry.allowedAlgs
      : resolveDefaultAllowedAlgs(),
    trustAnchorPinsSha256: [
      ...resolveGlobalTrustAnchorPinsSha256(),
      ...entry.trustAnchorPinsSha256,
    ],
    allowedIssuerSubstrings: [
      ...resolveGlobalAllowedIssuerSubstrings(),
      ...entry.allowedIssuerSubstrings,
    ],
  };
}

function resolveIssuerCacheTtlMs(): number {
  const raw = Number.parseInt(process.env.ICA_EVIDENCE_VC_ISSUERS_CACHE_TTL_SECONDS || '300', 10);
  if (!Number.isFinite(raw) || raw < 0) return 300_000;
  return raw * 1000;
}

async function resolveTrustedIssuerProfiles(): Promise<TrustedIssuerProfile[]> {
  const now = Date.now();
  if (ISSUER_CACHE.value && now < ISSUER_CACHE.expiresAt) {
    return ISSUER_CACHE.value;
  }
  if (ISSUER_CACHE.loading) {
    return ISSUER_CACHE.loading;
  }

  const loading = (async () => {
    const entries = resolveTrustedIssuerEntriesFromEnv();
    if (!entries.length) {
      throw new Error(
        'vc+jwt attachment verification requires ICA_EVIDENCE_VC_ISSUERS_LIST (JSON/CSV with did:web or URL entries).',
      );
    }
    const profiles = await Promise.all(entries.map((entry) => resolveIssuerProfile(entry)));
    ISSUER_CACHE.value = profiles;
    ISSUER_CACHE.expiresAt = Date.now() + resolveIssuerCacheTtlMs();
    ISSUER_CACHE.loading = null;
    return profiles;
  })();

  ISSUER_CACHE.loading = loading;
  try {
    return await loading;
  } catch (error) {
    ISSUER_CACHE.loading = null;
    throw error;
  }
}

function normalizeHexLikeFingerprint(raw: string): string {
  return raw.trim().toUpperCase().replace(/[^0-9A-F]/g, '');
}

function asPemFromX5c(base64Der: string): string {
  const normalized = base64Der.trim();
  if (!normalized) {
    throw new Error('x5c entry cannot be empty.');
  }
  const wrapped = normalized.match(/.{1,64}/g)?.join('\n') || normalized;
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----`;
}

function splitPemCertificates(pemText: string): string[] {
  const output: string[] = [];
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(pemText)) !== null) {
    const certificatePem = match[0].trim();
    if (certificatePem) output.push(certificatePem);
  }
  return output;
}

function checkKidMatch(expectedKid: string | undefined, providedKid: string | undefined): boolean {
  const expected = asNonEmptyString(expectedKid);
  const provided = asNonEmptyString(providedKid);
  if (!expected || !provided) return false;
  if (expected === provided) return true;

  const expectedFragment = expected.split('#').pop() || '';
  const providedFragment = provided.split('#').pop() || '';
  return Boolean(expectedFragment && providedFragment && expectedFragment === providedFragment);
}

function ensureAllowedAlg(parsed: ParsedCompactJwt, profile: TrustedIssuerProfile): void {
  if (!profile.allowedAlgs.has(parsed.alg)) {
    throw new Error(`vc+jwt attachment alg "${parsed.alg}" is not allowed for issuer "${profile.issuer}".`);
  }
}

function ensureTimeValidity(payload: JsonObject): void {
  const nowSeconds = Math.floor(Date.now() / 1000);
  const exp = typeof payload.exp === 'number' ? payload.exp : undefined;
  if (typeof exp === 'number' && nowSeconds > exp) {
    throw new Error('vc+jwt attachment is expired (payload.exp).');
  }
  const nbf = typeof payload.nbf === 'number' ? payload.nbf : undefined;
  if (typeof nbf === 'number' && nowSeconds < nbf) {
    throw new Error('vc+jwt attachment is not yet valid (payload.nbf).');
  }
}

function verifySignatureWithAlgorithm(parsed: ParsedCompactJwt, jwk: JsonObject): boolean {
  const publicKey = createPublicKey({
    key: jwk,
    format: 'jwk',
  });
  const signingInput = `${parsed.protectedEncoded}.${parsed.payloadEncoded}`;
  const data = Buffer.from(signingInput);

  if (parsed.alg === 'EdDSA') {
    return verifyDetachedRaw(null, data, publicKey, parsed.signature);
  }
  if (parsed.alg === 'ES384') {
    const verifier = createVerify('sha384');
    verifier.update(data);
    verifier.end();
    return verifier.verify({ key: publicKey, dsaEncoding: 'ieee-p1363' }, parsed.signature);
  }
  if (parsed.alg === 'ES256K') {
    const verifier = createVerify('sha256');
    verifier.update(data);
    verifier.end();
    return verifier.verify({ key: publicKey, dsaEncoding: 'ieee-p1363' }, parsed.signature);
  }
  if (parsed.alg === 'PS256') {
    const verifier = createVerify('sha256');
    verifier.update(data);
    verifier.end();
    return verifier.verify({
      key: publicKey,
      padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    }, parsed.signature);
  }
  const verifier = createVerify('RSA-SHA256');
  verifier.update(data);
  verifier.end();
  return verifier.verify(publicKey, parsed.signature);
}

function assertCertificateChainIntegrity(chain: X509Certificate[], indexLabel: string): void {
  for (let i = 0; i < chain.length - 1; i += 1) {
    const child = chain[i];
    const issuer = chain[i + 1];
    if (!child.checkIssued(issuer)) {
      throw new Error(`x509 chain at ${indexLabel} is not properly ordered at position ${i} -> ${i + 1}.`);
    }
    if (!child.verify(issuer.publicKey)) {
      throw new Error(`x509 chain signature invalid at ${indexLabel}, position ${i}.`);
    }
  }
}

function assertCertificatesValidNow(chain: X509Certificate[], indexLabel: string): void {
  const now = Date.now();
  chain.forEach((cert, index) => {
    const notBefore = Date.parse(cert.validFrom);
    const notAfter = Date.parse(cert.validTo);
    if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter)) {
      throw new Error(`Invalid certificate validity at ${indexLabel}[${index}].`);
    }
    if (now < notBefore) {
      throw new Error(`Certificate not valid yet at ${indexLabel}[${index}] (validFrom=${cert.validFrom}).`);
    }
    if (now > notAfter) {
      throw new Error(`Certificate expired at ${indexLabel}[${index}] (validTo=${cert.validTo}).`);
    }
  });
}

function assertTrustAnchors(chain: X509Certificate[], trustAnchorPinsSha256: string[], indexLabel: string): void {
  if (!trustAnchorPinsSha256.length) return;
  const certPins = new Set(
    chain
      .map((cert) => normalizeHexLikeFingerprint(cert.fingerprint256 || ''))
      .filter(Boolean),
  );
  const anyMatch = trustAnchorPinsSha256.some((pin) => certPins.has(pin));
  if (!anyMatch) {
    throw new Error(`x509 chain at ${indexLabel} does not include any configured trust anchor pin.`);
  }
}

function assertAllowedIssuerSubstrings(
  chain: X509Certificate[],
  allowedIssuerSubstrings: string[],
  indexLabel: string,
): void {
  if (!allowedIssuerSubstrings.length) return;
  const issuers = chain.map((cert) => (cert.issuer || '').toLowerCase());
  const matched = allowedIssuerSubstrings.some((needle) => issuers.some((issuer) => issuer.includes(needle)));
  if (!matched) {
    throw new Error(`x509 chain at ${indexLabel} does not match allowed issuer substrings.`);
  }
}

function assertLeafCertificateMatchesJwk(leaf: X509Certificate, jwk: JsonObject, indexLabel: string): void {
  const leafSpki = leaf.publicKey.export({ type: 'spki', format: 'pem' }).toString();
  const keySpki = createPublicKey({ key: jwk, format: 'jwk' }).export({ type: 'spki', format: 'pem' }).toString();
  if (leafSpki !== keySpki) {
    throw new Error(`x509 leaf at ${indexLabel} does not match JWK public key.`);
  }
}

function resolveRequireX509Chain(): boolean {
  return parseBoolean(process.env.ICA_EVIDENCE_VC_ISSUERS_REQUIRE_X509_CHAIN, false);
}

async function validateKeyTrustChain(key: TrustedVerificationKey, profile: TrustedIssuerProfile): Promise<void> {
  const chainFromX5c = key.x5c.map((entry) => asPemFromX5c(entry));
  const chainFromX5u = key.x5u ? await fetchCertificateChainFromX5u(key.x5u) : [];
  const chainPem = [...chainFromX5c, ...chainFromX5u].filter(Boolean);

  if (!chainPem.length) {
    if (resolveRequireX509Chain()) {
      throw new Error(`Trusted key ${key.kid || '<without-kid>'} requires x5c/x5u certificate chain.`);
    }
    return;
  }

  const certificates = chainPem.map((pem, index) => {
    try {
      return new X509Certificate(pem);
    } catch (error: unknown) {
      throw new Error(
        `Invalid x509 certificate at key ${key.kid || '<without-kid>'}, chain position ${index}: ${(error as Error).message}`,
      );
    }
  });

  assertLeafCertificateMatchesJwk(certificates[0], key.jwk, key.kid || '<without-kid>');
  assertCertificatesValidNow(certificates, key.kid || '<without-kid>');
  assertCertificateChainIntegrity(certificates, key.kid || '<without-kid>');
  assertTrustAnchors(certificates, profile.trustAnchorPinsSha256, key.kid || '<without-kid>');
  assertAllowedIssuerSubstrings(certificates, profile.allowedIssuerSubstrings, key.kid || '<without-kid>');
}

async function verifyJwtAgainstTrustedIssuer(parsed: ParsedCompactJwt, profile: TrustedIssuerProfile): Promise<void> {
  ensureAllowedAlg(parsed, profile);

  const candidates = parsed.kid
    ? profile.keys.filter((key) => checkKidMatch(key.kid, parsed.kid))
    : profile.keys;
  if (!candidates.length) {
    throw new Error(`vc+jwt attachment kid "${parsed.kid}" is not present in trusted issuer profile "${profile.issuer}".`);
  }

  const errors: string[] = [];
  for (const candidate of candidates) {
    try {
      if (!verifySignatureWithAlgorithm(parsed, candidate.jwk)) {
        errors.push(`signature mismatch for key ${candidate.kid || '<without-kid>'}`);
        continue;
      }
      await validateKeyTrustChain(candidate, profile);
      return;
    } catch (error: unknown) {
      errors.push((error as Error).message || String(error));
    }
  }

  throw new Error(`vc+jwt attachment verification failed for issuer "${profile.issuer}": ${errors.join('; ')}`);
}

function resolveIssuerFromPayload(payload: JsonObject): string {
  const issuer = asNonEmptyString(payload.iss);
  if (!issuer) {
    throw new Error('vc+jwt attachment payload.iss is required.');
  }
  return issuer;
}

async function resolveTrustedIssuerProfileByIss(iss: string): Promise<TrustedIssuerProfile> {
  const profiles = await resolveTrustedIssuerProfiles();
  const direct = profiles.find((profile) => profile.issuer.toLowerCase() === iss.toLowerCase());
  if (direct) return direct;

  const wildcard = profiles.find((profile) => profile.issuer === '*');
  if (wildcard) return wildcard;

  throw new Error(`vc+jwt attachment issuer "${iss}" is not present in ICA_EVIDENCE_VC_ISSUERS_LIST.`);
}

function decodeBase64ToUtf8(input: string): string {
  try {
    return Buffer.from(input, 'base64').toString('utf8').trim();
  } catch {
    return '';
  }
}

function resolveVcJwtFromAttachment(rawAttachment: unknown): ResolvedVcJwtAttachment | null {
  const attachment = asObject(rawAttachment);
  if (!attachment) return null;

  const mediaType = asNonEmptyString(attachment.media_type).toLowerCase();
  const format = asNonEmptyString(attachment.format).toLowerCase();
  if (mediaType !== 'application/vc+jwt' && format !== 'vc+jwt') {
    return null;
  }

  const data = asObject(attachment.data) || {};
  const dataJson = asObject(data.json) || {};
  const attachmentId = asNonEmptyString(attachment.id) || randomUUID();
  const jwtFromJson = asNonEmptyString(dataJson.jwt);
  if (jwtFromJson) {
    return { attachmentId, jwt: jwtFromJson };
  }

  const jwtFromData = asNonEmptyString(data.jwt);
  if (jwtFromData) {
    return { attachmentId, jwt: jwtFromData };
  }

  const jwtFromBase64 = decodeBase64ToUtf8(asNonEmptyString(data.base64));
  if (jwtFromBase64.includes('.')) {
    return { attachmentId, jwt: jwtFromBase64 };
  }

  throw new Error(`vc+jwt attachment ${attachmentId} must include data.json.jwt, data.jwt or base64 compact JWT.`);
}

function resolveEvidenceTimeIso(payload: JsonObject): string {
  const iat = typeof payload.iat === 'number' ? payload.iat : undefined;
  if (iat && Number.isFinite(iat) && iat > 0) {
    return new Date(iat * 1000).toISOString();
  }
  return new Date().toISOString();
}

function buildJwtDigest(jwt: string): string {
  return createHash('sha3-384').update(jwt, 'utf8').digest('base64');
}

function buildEvidenceObjectFromVerifiedJwt(
  parsed: ParsedCompactJwt,
  attachmentId: string,
  issuer: string,
): JsonObject {
  const subject = asNonEmptyString(parsed.payload.sub) || undefined;
  const credentialId =
    asNonEmptyString(parsed.payload.jti)
    || asNonEmptyString(asObject(parsed.payload.vc)?.id)
    || undefined;
  const evidenceTime = resolveEvidenceTimeIso(parsed.payload);
  const verifiedAt = new Date().toISOString();
  const digest = buildJwtDigest(`${parsed.protectedEncoded}.${parsed.payloadEncoded}.${parsed.signature.toString('base64url')}`);

  const record: JsonObject = {
    type: 'vc+jwt',
    format: 'vc+jwt',
    issuer,
    alg: parsed.alg,
    jwt: `${parsed.protectedEncoded}.${parsed.payloadEncoded}.${parsed.signature.toString('base64url')}`,
    claims: parsed.payload,
    header: parsed.header,
  };
  if (subject) record.subject = subject;
  if (credentialId) record.credentialId = credentialId;
  if (parsed.kid) record.kid = parsed.kid;

  return {
    type: 'electronic_record',
    time: evidenceTime,
    verifier: { organization: issuer },
    record,
    check_details: [
      {
        check_method: 'jws-signature',
        organization: issuer,
        time: verifiedAt,
      },
    ],
    attachments: [
      {
        digest: {
          alg: 'sha3-384',
          value: digest,
        },
        url: `urn:uuid:${attachmentId}`,
      },
    ],
  };
}

export async function extractVerifiedVcJwtAttachmentEvidence(
  attachments: unknown[],
  options?: {
    issuedCredentialRecordId?: string;
    operatorDid?: string;
  },
): Promise<AddEvidenceInput[]> {
  if (!Array.isArray(attachments) || !attachments.length) return [];
  const resolvedAttachments = attachments
    .map((entry) => resolveVcJwtFromAttachment(entry))
    .filter(Boolean) as ResolvedVcJwtAttachment[];
  if (!resolvedAttachments.length) return [];

  const output: AddEvidenceInput[] = [];
  for (const entry of resolvedAttachments) {
    const parsed = parseCompactJwt(entry.jwt);
    ensureTimeValidity(parsed.payload);
    const issuer = resolveIssuerFromPayload(parsed.payload);
    const profile = await resolveTrustedIssuerProfileByIss(issuer);
    await verifyJwtAgainstTrustedIssuer(parsed, profile);

    const evidence = buildEvidenceObjectFromVerifiedJwt(parsed, entry.attachmentId, issuer);
    const credentialId =
      asNonEmptyString(parsed.payload.jti)
      || asNonEmptyString(asObject(parsed.payload.vc)?.id)
      || undefined;
    output.push({
      evidence,
      ...(options?.issuedCredentialRecordId ? { issuedCredentialRecordId: options.issuedCredentialRecordId } : {}),
      ...(options?.operatorDid ? { operatorDid: options.operatorDid } : {}),
      source: 'didcomm-vc+jwt',
      attachmentId: entry.attachmentId,
      vcJwtIssuer: issuer,
      ...(parsed.kid ? { vcJwtKid: parsed.kid } : {}),
      vcJwtAlg: parsed.alg,
      ...(credentialId ? { vcJwtCredentialId: credentialId } : {}),
    });
  }

  return output;
}
