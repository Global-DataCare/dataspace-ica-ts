// Construye el DID principal de la ICA como did:web:<domain>:<tenant>
export function buildIcaDid(req?: IncomingMessage): string {
  const domain = (process.env.DID_WEB_DOMAIN || '').replace(/^did:web:/, '').trim();
  const tenant = (process.env.ICA_LOCAL_TENANT_ID || 'ica').trim();
  if (domain) {
    return `did:web:${domain.replace(/:/g, '%3A')}:${tenant}`;
  }
  // fallback autodetect
  const host = req && req.headers && req.headers.host ? req.headers.host : 'localhost';
  return `did:web:${host.replace(/:/g, '%3A')}:${tenant}`;
}

// Añade alsoKnownAs al did document si MASK_LOCAL_ICA no es true
export function addAlsoKnownAsToDidDocument(didDocument: any, req?: IncomingMessage): void {
  const mask = String(process.env.MASK_LOCAL_ICA || '').toLowerCase() === 'true';
  if (mask) return;
  const realHost = req && req.headers && req.headers.host ? req.headers.host : '';
  if (realHost) {
    didDocument.alsoKnownAs = [`https://${realHost}`];
  }
}
// Devuelve el DID audience para DIDComm, usando la misma lógica que resolveIcaIssuerDid
export function resolveIcaAudienceDid(req?: IncomingMessage): string {
  const configuredAudienceDid = (process.env.ICA_DIDCOMM_AUDIENCE_DID || '').trim();
  if (configuredAudienceDid) return configuredAudienceDid;

  // Reutiliza la lógica de issuer para coherencia
  return resolveIcaIssuerDid(req);
}
import {
  constants as cryptoConstants,
  createHash,
  createPrivateKey,
  createPublicKey,
  createSign,
  randomUUID,
  sign as signDetachedRaw,
} from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { VerifiableCredentialV2 } from 'gdc-common-utils-ts/models/verifiable-credential';
import type { SupportedSigningAlgorithm, VerifyRouteContext } from '../types.ts';
import { getPreferredSigningKey, listActiveSigningKeys, upsertDidSigningMethods } from './active-signing-keys.ts';
import { resolveControllerMemberDescriptor } from './controller-identity.ts';
import { useInvalidProofForTestResourceVersion } from './self-signing.ts';

type JsonObject = Record<string, unknown>;

type SigningKeyMaterial = {
  privateKey: ReturnType<typeof createPrivateKey>;
  publicJwk: JsonObject;
  alg: SupportedSigningAlgorithm;
  keyId: string;
};

type ControllerVerificationMethod = {
  methodId: string;
  method: JsonObject;
};

function firstHeaderValue(header: string | string[] | undefined): string {
  if (Array.isArray(header)) {
    return (header.find((value) => value && value.trim()) || '').trim();
  }
  return (header || '').trim();
}

function firstForwardedHost(req: IncomingMessage | undefined): string {
  if (!req) return '';
  const raw = firstHeaderValue(req.headers['x-forwarded-host']);
  if (!raw) return '';
  return raw.split(',')[0]?.trim() || '';
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function decodeMultilineEnv(value: string): string {
  return value.includes('\\n') ? value.replace(/\\n/g, '\n') : value;
}

function tryParseJson(value: string | undefined): JsonObject | null {
  if (!value || !value.trim()) return null;
  try {
    const parsed = JSON.parse(value) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    return parsed as JsonObject;
  } catch {
    return null;
  }
}

function parseOptionalJsonObject(value: string | undefined): JsonObject | undefined {
  const parsed = tryParseJson(value);
  return parsed || undefined;
}

function normalizeAuthority(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      return new URL(trimmed).host.toLowerCase();
    } catch {
      return '';
    }
  }
  return trimmed.split('/')[0].trim().toLowerCase();
}

function buildDidWebFromAuthority(raw: string): string {
  const authority = normalizeAuthority(raw);
  if (!authority) return '';
  if (authority.startsWith('did:')) return authority;
  return `did:web:${authority.replace(/:/g, '%3A')}`;
}

function resolveDidFromConfiguredDocument(): string | null {
  const configuredDocument = tryParseJson(process.env.ICA_DID_DOCUMENT_JSON);
  const id = typeof configuredDocument?.id === 'string' ? configuredDocument.id.trim() : '';
  return id || null;
}

function resolveTenantIdForApiPaths(): string {
  return (process.env.ICA_LOCAL_TENANT_ID || 'ica').trim() || 'ica';
}

function resolveApiBasePathTemplate(): string {
  return `/${resolveTenantIdForApiPaths()}/cds-{jurisdiction}/v1/{sector}`;
}

function resolveVerifyServiceEndpoint(): string {
  const explicit = (process.env.ICA_DID_SERVICE_ENDPOINT || '').trim();
  if (explicit) return explicit;
  return `${resolveApiBasePathTemplate()}/terms/pdf/{resourceType}/_verify`;
}

function resolveDcatCatalogServiceEndpoint(): string {
  const explicit = (process.env.ICA_DCAT_SERVICE_ENDPOINT || process.env.ICA_DCAT_CATALOG_SERVICE_ENDPOINT || '').trim();
  if (explicit) return explicit;
  return '/.well-known/dcat3/catalog';
}

function resolveDidWebAuthority(did: string): string {
  const normalized = did.trim();
  if (!normalized.startsWith('did:web:')) return '';
  const suffix = normalized.slice('did:web:'.length);
  const [rawAuthority] = suffix.split(':');
  if (!rawAuthority) return '';
  try {
    return decodeURIComponent(rawAuthority).trim();
  } catch {
    return rawAuthority.trim();
  }
}

function resolveDataServiceEndpoint(issuerDid: string): string {
  const explicit = (process.env.ICA_DSP_DATA_SERVICE_ENDPOINT || process.env.ICA_DID_PROTOCOL_SERVICE_ENDPOINT || '').trim();
  if (explicit) return explicit;
  const authority = resolveDidWebAuthority(issuerDid);
  if (!authority) return '/.well-known/dspace-version';
  return `https://${authority}/.well-known/dspace-version`;
}

function resolveIssuerServiceEndpoint(issuerDid: string): string {
  const explicit = (process.env.ICA_DCP_ISSUER_SERVICE_ENDPOINT || '').trim();
  if (!explicit) return '';
  return explicit;
}

function appendDidService(document: JsonObject, service: JsonObject): void {
  const services = Array.isArray(document.service)
    ? [...(document.service as JsonObject[])]
    : [];
  const serviceId = String(service.id || '').trim();
  if (!serviceId) return;
  if (!services.some((entry) => String(entry.id || '').trim() === serviceId)) {
    services.push(service);
  }
  document.service = services;
}

function parseSupportedSigningAlgorithm(raw: string | undefined): SupportedSigningAlgorithm | undefined {
  const normalized = (raw || '').trim().toUpperCase();
  if (normalized === 'ES384') return 'ES384';
  if (normalized === 'ES256K') return 'ES256K';
  if (normalized === 'RS256') return 'RS256';
  if (normalized === 'PS256') return 'PS256';
  if (normalized === 'EDDSA') return 'EdDSA';
  return undefined;
}

function resolveSigningAlgorithm(
  configuredAlg: string | undefined,
  publicJwk: JsonObject,
): SigningKeyMaterial['alg'] {
  const configured = parseSupportedSigningAlgorithm(configuredAlg);
  if (configured) return configured;

  const kty = String(publicJwk.kty || '');
  const crv = String(publicJwk.crv || '');
  if (kty === 'RSA') return 'RS256';
  if (kty === 'EC' && crv === 'P-384') return 'ES384';
  if (kty === 'EC' && crv === 'secp256k1') return 'ES256K';
  if (kty === 'OKP' && (crv === 'Ed25519' || crv === 'Ed448')) return 'EdDSA';
  throw new Error('Unsupported VC signing key type. Supported: RSA, EC P-384, EC secp256k1, Ed25519.');
}

function resolveEnvSigningKeyMaterial(): SigningKeyMaterial | null {
  const pemRaw = (process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM || '').trim();
  if (!pemRaw) return null;
  const privateKey = createPrivateKey(decodeMultilineEnv(pemRaw));
  const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' }) as JsonObject;
  const keyId = (process.env.ICA_VC_SIGNING_KEY_ID || 'key-1').trim();
  const alg = resolveSigningAlgorithm(process.env.ICA_VC_SIGNING_ALG, publicJwk);
  return { privateKey, publicJwk, alg, keyId };
}

function resolvePreferredSigningAlgorithmFromEnv(): SupportedSigningAlgorithm | undefined {
  return parseSupportedSigningAlgorithm(process.env.ICA_VC_SIGNING_PREFERRED_ALG);
}

function resolveSigningKeyMaterial(): SigningKeyMaterial | null {
  const preferredAlg = resolvePreferredSigningAlgorithmFromEnv();
  const activated = getPreferredSigningKey(preferredAlg);
  if (activated) {
    return {
      privateKey: createPrivateKey(activated.privateKeyPem),
      publicJwk: activated.publicJwk,
      alg: activated.alg,
      keyId: activated.kid,
    };
  }
  return resolveEnvSigningKeyMaterial();
}

function normalizeKid(raw: string | undefined): string {
  const trimmed = (raw || '').trim();
  if (!trimmed) return '';
  const fragmentIndex = trimmed.lastIndexOf('#');
  if (fragmentIndex < 0 || fragmentIndex >= trimmed.length - 1) return trimmed;
  return trimmed.slice(fragmentIndex + 1);
}

function parseControllerX5cFromEnv(): string[] | undefined {
  const csv = (process.env.ICA_SELF_CONTROLLER_X5C || '').trim();
  if (!csv) return undefined;
  const values = csv
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
  return values.length ? values : undefined;
}

function resolveControllerVerificationMethod(controllerDid: string): ControllerVerificationMethod | null {
  const configuredKid = normalizeKid(process.env.ICA_SELF_CONTROLLER_KID);
  const configuredAlg = parseSupportedSigningAlgorithm(process.env.ICA_SELF_CONTROLLER_ALG);
  const configuredJwk = parseOptionalJsonObject(process.env.ICA_SELF_CONTROLLER_PUBLIC_KEY_JWK);
  const configuredX5c = parseControllerX5cFromEnv();

  if (configuredJwk) {
    const kid = normalizeKid(String(configuredJwk.kid || configuredKid || 'controller-key'));
    const methodId = `${controllerDid}#${kid}`;
    return {
      methodId,
      method: {
        id: methodId,
        type: 'JsonWebKey2020',
        controller: controllerDid,
        publicKeyJwk: {
          ...configuredJwk,
          kid,
          ...(configuredAlg ? { alg: configuredAlg } : {}),
          ...(configuredX5c?.length ? { x5c: configuredX5c } : {}),
        },
      },
    };
  }

  if (configuredKid) {
    const active = listActiveSigningKeys().find((entry) => normalizeKid(entry.kid) === configuredKid);
    if (active) {
      const methodId = `${controllerDid}#${active.kid}`;
      return {
        methodId,
        method: {
          id: methodId,
          type: 'JsonWebKey2020',
          controller: controllerDid,
          publicKeyJwk: {
            ...active.publicJwk,
            kid: active.kid,
            alg: active.alg,
            use: 'sig',
            ...(active.x5c?.length ? { x5c: active.x5c } : {}),
          },
        },
      };
    }
  }

  const envSigning = resolveEnvSigningKeyMaterial();
  if (envSigning && configuredKid && normalizeKid(envSigning.keyId) === configuredKid) {
    const methodId = `${controllerDid}#${envSigning.keyId}`;
    return {
      methodId,
      method: {
        id: methodId,
        type: 'JsonWebKey2020',
        controller: controllerDid,
        publicKeyJwk: {
          ...envSigning.publicJwk,
          kid: envSigning.keyId,
          alg: envSigning.alg,
          use: 'sig',
        },
      },
    };
  }

  return null;
}

function appendVerificationMethod(document: JsonObject, method: JsonObject): void {
  const methods = Array.isArray(document.verificationMethod)
    ? [...(document.verificationMethod as JsonObject[])]
    : [];
  const methodId = String(method.id || '').trim();
  if (!methodId) return;
  const exists = methods.some((entry) => String(entry.id || '').trim() === methodId);
  if (!exists) {
    methods.push(method);
    document.verificationMethod = methods;
  }
}

function mergeControllerDidReference(document: JsonObject, controllerDid: string): void {
  const existing = document.controller;
  if (typeof existing === 'string' && existing.trim()) {
    if (existing.trim() === controllerDid) return;
    document.controller = [existing.trim(), controllerDid];
    return;
  }
  if (Array.isArray(existing)) {
    const values = existing
      .map((entry) => String(entry || '').trim())
      .filter(Boolean);
    if (!values.includes(controllerDid)) {
      values.push(controllerDid);
    }
    document.controller = values;
    return;
  }
  document.controller = controllerDid;
}

function base64UrlEncode(input: Buffer | string): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
}

function selectPublicJwkForDidJwk(publicJwk: JsonObject): JsonObject | null {
  const kty = String(publicJwk.kty || '');
  if (kty === 'EC') {
    const crv = String(publicJwk.crv || '');
    const x = String(publicJwk.x || '');
    const y = String(publicJwk.y || '');
    if (!crv || !x || !y) return null;
    return { kty: 'EC', crv, x, y };
  }
  if (kty === 'OKP') {
    const crv = String(publicJwk.crv || '');
    const x = String(publicJwk.x || '');
    if (!crv || !x) return null;
    return { kty: 'OKP', crv, x };
  }
  if (kty === 'RSA') {
    const n = String(publicJwk.n || '');
    const e = String(publicJwk.e || '');
    if (!n || !e) return null;
    return { kty: 'RSA', n, e };
  }
  return null;
}

function stableJsonStringify(value: unknown): string {
  if (value === null || typeof value !== 'object') {
    return JSON.stringify(value);
  }
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJsonStringify(entry)).join(',')}]`;
  }
  const record = value as Record<string, unknown>;
  const keys = Object.keys(record).sort();
  return `{${keys.map((key) => `${JSON.stringify(key)}:${stableJsonStringify(record[key])}`).join(',')}}`;
}

function canonicalizeJsonValue<T>(value: T): T {
  if (value === null || typeof value !== 'object') return value;
  if (Array.isArray(value)) {
    return value.map((entry) => canonicalizeJsonValue(entry)) as T;
  }
  const record = value as Record<string, unknown>;
  const output: Record<string, unknown> = {};
  for (const key of Object.keys(record).sort()) {
    output[key] = canonicalizeJsonValue(record[key]);
  }
  return output as T;
}

function buildDidJwkFromPublicJwk(publicJwk: JsonObject): string | null {
  const didJwkPublic = selectPublicJwkForDidJwk(publicJwk);
  if (!didJwkPublic) return null;
  const canonical = stableJsonStringify(didJwkPublic);
  return `did:jwk:${base64UrlEncode(canonical)}`;
}

function buildDidJwtFromPublicJwk(publicJwk: JsonObject): string | null {
  const didJwkPublic = selectPublicJwkForDidJwk(publicJwk);
  if (!didJwkPublic) return null;
  const canonical = stableJsonStringify(didJwkPublic);
  const thumbprint = createHash('sha256').update(canonical).digest('base64url');
  return `did:jwt:${thumbprint}`;
}

function buildDetachedJws(
  payloadBytes: Buffer,
  signing: SigningKeyMaterial,
  verificationMethod: string,
): string {
  const protectedHeader = {
    alg: signing.alg,
    kid: verificationMethod,
  };
  const headerEncoded = base64UrlEncode(JSON.stringify(protectedHeader));
  const payloadEncoded = base64UrlEncode(payloadBytes);
  const signingInput = `${headerEncoded}.${payloadEncoded}`;

  const signatureEncoded = base64UrlEncode(signJwsInput(signingInput, signing));
  return `${headerEncoded}..${signatureEncoded}`;
}

function signJwsInput(signingInput: string, signing: SigningKeyMaterial): Buffer {
  let signatureBytes: Buffer;
  if (signing.alg === 'EdDSA') {
    signatureBytes = signDetachedRaw(null, Buffer.from(signingInput), signing.privateKey);
  } else if (signing.alg === 'ES384') {
    const signer = createSign('sha384');
    signer.update(signingInput);
    signer.end();
    signatureBytes = signer.sign({ key: signing.privateKey, dsaEncoding: 'ieee-p1363' });
  } else if (signing.alg === 'ES256K') {
    const signer = createSign('sha256');
    signer.update(signingInput);
    signer.end();
    signatureBytes = signer.sign({ key: signing.privateKey, dsaEncoding: 'ieee-p1363' });
  } else if (signing.alg === 'PS256') {
    const signer = createSign('sha256');
    signer.update(signingInput);
    signer.end();
    signatureBytes = signer.sign({
      key: signing.privateKey,
      padding: cryptoConstants.RSA_PKCS1_PSS_PADDING,
      saltLength: 32,
    });
  } else {
    const signer = createSign('RSA-SHA256');
    signer.update(signingInput);
    signer.end();
    signatureBytes = signer.sign(signing.privateKey);
  }
  return signatureBytes;
}

function buildCompactJws(
  payload: Record<string, unknown>,
  signing: SigningKeyMaterial,
  verificationMethod: string,
): string {
  const protectedHeader = {
    alg: signing.alg,
    kid: verificationMethod,
    typ: 'vc+jwt',
  };
  const headerEncoded = base64UrlEncode(JSON.stringify(protectedHeader));
  const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
  const signingInput = `${headerEncoded}.${payloadEncoded}`;
  const signatureEncoded = base64UrlEncode(signJwsInput(signingInput, signing));
  return `${headerEncoded}.${payloadEncoded}.${signatureEncoded}`;
}

function buildUnsecuredCompactJwt(
  payload: Record<string, unknown>,
  verificationMethod: string,
): string {
  const protectedHeader = {
    alg: 'none',
    kid: verificationMethod,
    typ: 'vc+jwt',
  };
  const headerEncoded = base64UrlEncode(JSON.stringify(protectedHeader));
  const payloadEncoded = base64UrlEncode(JSON.stringify(payload));
  return `${headerEncoded}.${payloadEncoded}.`;
}

function unixTimeFromIsoDate(value: unknown): number | undefined {
  if (typeof value !== 'string' || !value.trim()) return undefined;
  const epochMs = Date.parse(value);
  if (!Number.isFinite(epochMs)) return undefined;
  return Math.floor(epochMs / 1000);
}

function extractCredentialSubjectId(vc: VerifiableCredentialV2): string | undefined {
  const subject = vc.credentialSubject as unknown;
  if (Array.isArray(subject)) {
    for (const entry of subject) {
      if (!entry || typeof entry !== 'object') continue;
      const id = String((entry as Record<string, unknown>).id || '').trim();
      if (id) return id;
    }
    return undefined;
  }
  if (!subject || typeof subject !== 'object') return undefined;
  const id = String((subject as Record<string, unknown>).id || '').trim();
  return id || undefined;
}

function buildInvalidDetachedJws(verificationMethod: string): string {
  const headerEncoded = base64UrlEncode(JSON.stringify({ alg: 'none', kid: verificationMethod }));
  const fakeSignature = base64UrlEncode('invalid-test-signature');
  return `${headerEncoded}..${fakeSignature}`;
}

export function resolveIcaIssuerDid(req?: IncomingMessage): string {
  const configuredIssuerDid = (process.env.ICA_DIDCOMM_ISSUER_DID || '').trim();
  if (configuredIssuerDid) return configuredIssuerDid;

  const issuerDidFromDocument = resolveDidFromConfiguredDocument();
  if (issuerDidFromDocument) return issuerDidFromDocument;

  const externalDomain = (process.env.ICA_EXTERNAL_DOMAIN || '').trim();
  if (externalDomain) {
    const didFromExternalDomain = buildDidWebFromAuthority(externalDomain);
    if (didFromExternalDomain) return didFromExternalDomain;
  }

  const requestHost = firstForwardedHost(req) || (req ? firstHeaderValue(req.headers.host) : '');
  if (requestHost) {
    const didFromHostHeader = buildDidWebFromAuthority(requestHost);
    if (didFromHostHeader) return didFromHostHeader;
  }

  const port = process.env.ICA_API_PORT || process.env.PORT || '3310';
  return buildDidWebFromAuthority(`localhost:${port}`) || 'did:web:localhost%3A3310';
}

export function resolveVcIssuerDid(req?: IncomingMessage): string {
  const forcedIssuer = (process.env.ICA_VC_ISSUER_DID || '').trim();
  if (forcedIssuer) return forcedIssuer;

  const deterministicByContract = parseBoolean(process.env.DETERMINISTIC_VC_BY_CONTRACT, false);
  if (deterministicByContract) {
    const signing = resolveSigningKeyMaterial();
    if (signing) {
      const didJwt = buildDidJwtFromPublicJwk(signing.publicJwk);
      if (didJwt) return didJwt;
    }
    throw new Error('Deterministic VC issuer requires active signing key (bootstrap key)');
  }

  const signing = resolveSigningKeyMaterial();
  if (signing) {
    const didJwk = buildDidJwkFromPublicJwk(signing.publicJwk);
    if (didJwk) return didJwk;
  }
  return resolveIcaIssuerDid(req);
}

function mergeSigningMethods(document: JsonObject, issuerDid: string): void {
  const existingVerification = Array.isArray(document.verificationMethod)
    ? (document.verificationMethod as JsonObject[])
    : [];
  const existingAssertion = Array.isArray(document.assertionMethod)
    ? (document.assertionMethod as string[])
    : [];
  const activatedMethods = upsertDidSigningMethods(issuerDid);

  let mergedVerification = [...existingVerification];
  let mergedAssertion = [...existingAssertion];

  if (activatedMethods.verificationMethod.length) {
    const seenIds = new Set(
      existingVerification
        .map((entry) => String(entry.id || '').trim())
        .filter(Boolean),
    );
    for (const method of activatedMethods.verificationMethod) {
      const id = String(method.id || '').trim();
      if (!id || seenIds.has(id)) continue;
      mergedVerification.push(method);
      seenIds.add(id);
    }

    const assertionSet = new Set(existingAssertion);
    for (const id of activatedMethods.assertionMethod) {
      assertionSet.add(id);
    }
    mergedAssertion = Array.from(assertionSet);
  } else {
    const envSigning = resolveEnvSigningKeyMaterial();
    if (envSigning) {
      const verificationMethodId = `${issuerDid}#${envSigning.keyId}`;
      const envMethod = {
        id: verificationMethodId,
        type: 'JsonWebKey2020',
        controller: issuerDid,
        publicKeyJwk: {
          ...envSigning.publicJwk,
          kid: envSigning.keyId,
          alg: envSigning.alg,
          use: 'sig',
        },
      };
      const seenIds = new Set(
        existingVerification
          .map((entry) => String(entry.id || '').trim())
          .filter(Boolean),
      );
      if (!seenIds.has(verificationMethodId)) {
        mergedVerification = [...existingVerification, envMethod];
      }
      const assertionSet = new Set(existingAssertion);
      assertionSet.add(verificationMethodId);
      mergedAssertion = Array.from(assertionSet);
    }
  }

  if (mergedVerification.length) {
    document.verificationMethod = mergedVerification;
  }
  if (mergedAssertion.length) {
    document.assertionMethod = mergedAssertion;
    if (!Array.isArray(document.authentication) || !document.authentication.length) {
      document.authentication = mergedAssertion;
    }
  }
}

export function buildIcaDidDocument(req?: IncomingMessage): JsonObject {
  const configuredDocument = tryParseJson(process.env.ICA_DID_DOCUMENT_JSON);
  const issuerDid = resolveIcaIssuerDid(req);
  const serviceEndpoint = resolveVerifyServiceEndpoint();
  const dcatCatalogServiceEndpoint = resolveDcatCatalogServiceEndpoint();

  const document: JsonObject = configuredDocument || {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: issuerDid,
  };
  // Añadir alsoKnownAs con did:jwt derivado de la clave bootstrap si existe
  const signing = resolveSigningKeyMaterial();
  if (signing) {
    const didJwt = buildDidJwtFromPublicJwk(signing.publicJwk);
    if (didJwt) {
      document.alsoKnownAs = [didJwt];
    }
  }
  mergeSigningMethods(document, issuerDid);

  const controllerDescriptor = resolveControllerMemberDescriptor(issuerDid);
  if (controllerDescriptor?.did) {
    mergeControllerDidReference(document, controllerDescriptor.did);
    const controllerVerificationMethod = resolveControllerVerificationMethod(controllerDescriptor.did);
    if (controllerVerificationMethod) {
      appendVerificationMethod(document, controllerVerificationMethod.method);
    }
  }

  appendDidService(document, {
    id: `${issuerDid}#verify-terms`,
    type: 'DataSpaceIcaVerifyService',
    serviceEndpoint,
  });

  if (dcatCatalogServiceEndpoint) {
    appendDidService(document, {
      id: `${issuerDid}#dsp-catalog-service`,
      type: 'CatalogService',
      serviceEndpoint: dcatCatalogServiceEndpoint,
    });
  }

  appendDidService(document, {
    id: `${issuerDid}#dsp-data-service`,
    type: 'DataService',
    serviceEndpoint: resolveDataServiceEndpoint(issuerDid),
  });

  const issuerServiceEndpoint = resolveIssuerServiceEndpoint(issuerDid);
  if (issuerServiceEndpoint) {
    appendDidService(document, {
      id: `${issuerDid}#dcp-issuer-service`,
      type: 'IssuerService',
      serviceEndpoint: issuerServiceEndpoint,
    });
  }

  return document;
}

export function resolveControllerDidDocumentPath(req?: IncomingMessage): string | null {
  const issuerDid = resolveIcaIssuerDid(req);
  const descriptor = resolveControllerMemberDescriptor(issuerDid);
  return descriptor?.didJsonPath || null;
}

export function buildControllerDidDocument(req?: IncomingMessage): JsonObject | null {
  const issuerDid = resolveIcaIssuerDid(req);
  const descriptor = resolveControllerMemberDescriptor(issuerDid);
  if (!descriptor?.did) return null;

  const document: JsonObject = {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: descriptor.did,
  };
  const controllerVerificationMethod = resolveControllerVerificationMethod(descriptor.did);
  if (controllerVerificationMethod) {
    document.verificationMethod = [controllerVerificationMethod.method];
    document.assertionMethod = [controllerVerificationMethod.methodId];
    document.authentication = [controllerVerificationMethod.methodId];
  }
  return document;
}

export function attachProofToCredential(
  vc: VerifiableCredentialV2,
  route: VerifyRouteContext,
  issuerDidInput?: string,
  proofCreatedAtOverride?: string,
): VerifiableCredentialV2 {
  const issuerDid = (issuerDidInput || '').trim() || resolveIcaIssuerDid();
  const deterministicByContract = parseBoolean(process.env.DETERMINISTIC_VC_BY_CONTRACT, false);
  const vcRecord = vc as unknown as Record<string, unknown>;
  const deterministicCreatedAt = typeof vcRecord.validFrom === 'string' ? vcRecord.validFrom : '';
  const createdAt = deterministicByContract
    ? (proofCreatedAtOverride || deterministicCreatedAt || new Date().toISOString())
    : new Date().toISOString();
  const vcWithoutProof = { ...vc };
  delete vcWithoutProof.proof;
  const canonicalVcWithoutProof = canonicalizeJsonValue(vcWithoutProof);

  const signing = resolveSigningKeyMaterial();
  const verificationMethod = `${issuerDid}#${signing?.keyId || (process.env.ICA_VC_SIGNING_KEY_ID || 'key-1').trim()}`;

  const isTestVersion = route.resourceType.toLowerCase().startsWith('test-');
  if (isTestVersion && useInvalidProofForTestResourceVersion()) {
    return {
      ...canonicalVcWithoutProof,
      proof: {
        type: 'JsonWebSignature2020',
        created: createdAt,
        proofPurpose: 'assertionMethod',
        verificationMethod,
        jws: buildInvalidDetachedJws(verificationMethod),
      },
    };
  }

  if (!signing) {
    if (parseBoolean(process.env.ICA_VC_SIGNING_REQUIRED_FOR_PROD, false)) {
      throw new Error(
        'Missing active signing key for production VC signing (activate key or configure ICA_VC_SIGNING_PRIVATE_KEY_PEM).',
      );
    }
    return canonicalVcWithoutProof;
  }

  const payloadBytes = Buffer.from(stableJsonStringify(canonicalVcWithoutProof));
  const detachedJws = buildDetachedJws(payloadBytes, signing, verificationMethod);
  return {
    ...canonicalVcWithoutProof,
    proof: {
      type: 'JsonWebSignature2020',
      created: createdAt,
      proofPurpose: 'assertionMethod',
      verificationMethod,
      jws: detachedJws,
    },
  };
}

export function convertCredentialToVcJwt(
  vc: VerifiableCredentialV2,
  route: VerifyRouteContext,
  issuerDidInput?: string,
): string {
  const issuerDid = (issuerDidInput || '').trim() || resolveIcaIssuerDid();
  const signing = resolveSigningKeyMaterial();
  const isTestVersion = route.resourceType.toLowerCase().startsWith('test-');

  if (!signing) {
    if (!isTestVersion
      && parseBoolean(process.env.ICA_VC_SIGNING_REQUIRED_FOR_PROD, false)) {
      throw new Error(
        'Missing active signing key for production VC-JWT signing (activate key or configure ICA_VC_SIGNING_PRIVATE_KEY_PEM).',
      );
    }
  }

  const verificationMethod = `${issuerDid}#${signing?.keyId || (process.env.ICA_VC_SIGNING_KEY_ID || 'key-1').trim()}`;
  const vcWithoutProof = { ...vc };
  delete vcWithoutProof.proof;
  const vcRecord = vc as unknown as Record<string, unknown>;

  const jwtPayload: Record<string, unknown> = {
    iss: typeof vc.issuer === 'string' ? vc.issuer : issuerDid,
    iat: Math.floor(Date.now() / 1000),
    vc: vcWithoutProof,
  };

  const subjectId = extractCredentialSubjectId(vc);
  if (subjectId) jwtPayload.sub = subjectId;

  const jwtId = String(vc.id || '').trim();
  if (jwtId) jwtPayload.jti = jwtId;

  const notBefore = unixTimeFromIsoDate(vcRecord.validFrom);
  if (notBefore !== undefined) jwtPayload.nbf = notBefore;

  const expiresAt =
    unixTimeFromIsoDate(vcRecord.validUntil)
    ?? unixTimeFromIsoDate(vcRecord.expirationDate);
  if (expiresAt !== undefined) jwtPayload.exp = expiresAt;

  if (!signing) {
    return buildUnsecuredCompactJwt(jwtPayload, verificationMethod);
  }

  return buildCompactJws(jwtPayload, signing, verificationMethod);
}

export function buildDidDocumentMessage(req?: IncomingMessage): {
  jti: string;
  issuerDid: string;
  didDocument: JsonObject;
} {
  const issuerDid = resolveIcaIssuerDid(req);
  return {
    jti: `urn:uuid:${randomUUID()}`,
    issuerDid,
    didDocument: buildIcaDidDocument(req),
  };
}
