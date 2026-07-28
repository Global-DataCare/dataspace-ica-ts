import {
  createHash,
  createPrivateKey,
  createPublicKey,
  X509Certificate,
} from 'node:crypto';

type JsonObject = Record<string, unknown>;
type Environment = Record<string, string | undefined>;

export type IcaSigningTrustResult = {
  required: boolean;
  validated: boolean;
  rootDid?: string;
  rootDidDocumentUrl?: string;
  rootCertificateSha256?: string;
  leafCertificateSha256?: string;
  chainLength: number;
};

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined || value.trim() === '') return fallback;
  return ['true', '1', 'yes'].includes(value.trim().toLowerCase());
}

function decodeMultiline(value: string): string {
  return value.includes('\\n') ? value.replace(/\\n/g, '\n') : value;
}

function normalizeFingerprint(value: string | undefined): string {
  return String(value || '').trim().toUpperCase().replace(/[^0-9A-F]/g, '');
}

function splitPemCertificates(value: string): string[] {
  const output: string[] = [];
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(decodeMultiline(value))) !== null) {
    output.push(match[0].trim());
  }
  return output;
}

function x5cToPem(value: string): string {
  const body = value.trim();
  if (!body) throw new Error('ICA VC signing x5c entry cannot be empty.');
  const wrapped = body.match(/.{1,64}/g)?.join('\n') || body;
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----`;
}

/**
 * Loads the exact ICA leaf-to-Root chain supplied by the offline activation
 * flow. The private key and chain remain Kubernetes Secret values; only the
 * Root DID, public pin and x5u belong in the ConfigMap.
 */
export function loadIcaSigningCertificateChainFromEnv(env: Environment = process.env): string[] {
  const x5cJson = String(env.ICA_VC_SIGNING_X5C_JSON || '').trim();
  if (x5cJson) {
    let parsed: unknown;
    try {
      parsed = JSON.parse(x5cJson);
    } catch (error: unknown) {
      throw new Error(`ICA_VC_SIGNING_X5C_JSON must be a JSON string array: ${(error as Error).message}`);
    }
    if (!Array.isArray(parsed) || parsed.some((entry) => typeof entry !== 'string' || !entry.trim())) {
      throw new Error('ICA_VC_SIGNING_X5C_JSON must be a non-empty JSON string array.');
    }
    return parsed.map((entry) => x5cToPem(String(entry)));
  }
  return splitPemCertificates(String(env.ICA_VC_SIGNING_CERTIFICATE_CHAIN_PEM || ''));
}

export function certificatePemToX5c(pem: string): string {
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
  if (!body) throw new Error('Invalid X.509 certificate PEM.');
  return body;
}

function comparableJwk(jwk: JsonObject): JsonObject {
  const kty = String(jwk.kty || '');
  if (kty === 'EC') return { crv: jwk.crv, kty, x: jwk.x, y: jwk.y };
  if (kty === 'RSA') return { e: jwk.e, kty, n: jwk.n };
  if (kty === 'OKP') return { crv: jwk.crv, kty, x: jwk.x };
  return jwk;
}

function jwkThumbprint(jwk: JsonObject): string {
  return createHash('sha256')
    .update(JSON.stringify(comparableJwk(jwk)))
    .digest('base64url');
}

function assertSamePublicKey(left: JsonObject, right: JsonObject, message: string): void {
  if (JSON.stringify(comparableJwk(left)) !== JSON.stringify(comparableJwk(right))) {
    throw new Error(message);
  }
}

function resolveDidWebDocumentUrl(did: string): string {
  if (!did.startsWith('did:web:')) throw new Error('ICA_ROOT_CA_DID must use did:web.');
  const segments = did.slice('did:web:'.length).split(':').map((entry) => decodeURIComponent(entry));
  const authority = segments.shift() || '';
  if (!authority || authority.includes('/') || authority.includes('@')) {
    throw new Error('ICA_ROOT_CA_DID contains an invalid web authority.');
  }
  const path = segments.length ? `/${segments.map(encodeURIComponent).join('/')}/did.json` : '/.well-known/did.json';
  return `https://${authority}${path}`;
}

function parseDidDocumentJson(value: string): JsonObject {
  const parsed = JSON.parse(value) as unknown;
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('Root CA DID document must be a JSON object.');
  }
  return parsed as JsonObject;
}

async function loadRootDidDocument(
  env: Environment,
  expectedDid: string,
  fetchImpl: typeof fetch,
): Promise<{ document: JsonObject; url: string }> {
  const derivedUrl = resolveDidWebDocumentUrl(expectedDid);
  const configuredUrl = String(env.ICA_ROOT_CA_DID_DOCUMENT_URL || '').trim();
  const url = configuredUrl || derivedUrl;
  if (!url.startsWith('https://')) throw new Error('Root CA DID document URL must use HTTPS.');
  const inline = String(env.ICA_ROOT_CA_DID_DOCUMENT_JSON || '').trim();
  if (inline) return { document: parseDidDocumentJson(inline), url };

  const response = await fetchImpl(url, {
    headers: { accept: 'application/did+ld+json, application/json' },
    signal: AbortSignal.timeout(8_000),
  });
  if (!response.ok) throw new Error(`Unable to resolve Root CA DID document (${response.status} ${response.statusText}).`);
  return { document: parseDidDocumentJson(await response.text()), url };
}

function validateRootDidDocument(document: JsonObject, expectedDid: string, root: X509Certificate): void {
  if (String(document.id || '').trim() !== expectedDid) {
    throw new Error(`Root CA DID document id must equal ICA_ROOT_CA_DID (${expectedDid}).`);
  }
  const methods = Array.isArray(document.verificationMethod)
    ? document.verificationMethod.filter((entry): entry is JsonObject => Boolean(entry && typeof entry === 'object'))
    : [];
  const rootJwk = root.publicKey.export({ format: 'jwk' }) as JsonObject;
  const matchingMethod = methods.find((method) => {
    const publicJwk = method.publicKeyJwk;
    if (!publicJwk || typeof publicJwk !== 'object' || Array.isArray(publicJwk)) return false;
    try {
      assertSamePublicKey(publicJwk as JsonObject, rootJwk, 'mismatch');
      return true;
    } catch {
      return false;
    }
  });
  if (!matchingMethod) throw new Error('Root CA DID document has no verification method matching the pinned Root certificate.');

  const methodJwk = matchingMethod.publicKeyJwk as JsonObject;
  const expectedKid = jwkThumbprint(methodJwk);
  if (String(methodJwk.kid || '') !== expectedKid || !String(matchingMethod.id || '').endsWith(`#${expectedKid}`)) {
    throw new Error('Root CA DID verification method kid must be the RFC 7638 JWK thumbprint.');
  }
  const x5c = Array.isArray(methodJwk.x5c) ? methodJwk.x5c.map(String) : [];
  if (!x5c.includes(root.raw.toString('base64'))) {
    throw new Error('Root CA DID verification method x5c must contain the pinned Root certificate.');
  }
}

/**
 * Validates the ICA signing key and certificate chain against the configured
 * static Root CA DID. X.509 proves the cryptographic chain; ICA_ROOT_CA_DID
 * additionally binds that root key to the governed public authority and its
 * resolvable metadata. Neither value substitutes for the other.
 */
export async function validateIcaSigningTrustFromEnv(
  env: Environment = process.env,
  fetchImpl: typeof fetch = fetch,
): Promise<IcaSigningTrustResult> {
  const required = parseBoolean(env.ICA_VC_SIGNING_TRUST_REQUIRED, false);
  const chainPem = loadIcaSigningCertificateChainFromEnv(env);
  if (!chainPem.length) {
    if (required) throw new Error('ICA signing trust requires ICA_VC_SIGNING_CERTIFICATE_CHAIN_PEM or ICA_VC_SIGNING_X5C_JSON.');
    return { required, validated: false, chainLength: 0 };
  }

  const privateKeyPem = decodeMultiline(String(env.ICA_VC_SIGNING_PRIVATE_KEY_PEM || '')).trim();
  if (!privateKeyPem) throw new Error('ICA signing certificate chain requires ICA_VC_SIGNING_PRIVATE_KEY_PEM.');
  const certificates = chainPem.map((pem, index) => {
    try {
      return new X509Certificate(pem);
    } catch (error: unknown) {
      throw new Error(`Invalid ICA signing certificate at chain position ${index}: ${(error as Error).message}`);
    }
  });
  if (required && certificates.length < 2) {
    throw new Error('Required ICA signing trust needs a leaf certificate plus at least one CA certificate.');
  }
  const now = Date.now();
  certificates.forEach((certificate, index) => {
    const notBefore = Date.parse(certificate.validFrom);
    const notAfter = Date.parse(certificate.validTo);
    if (!Number.isFinite(notBefore) || !Number.isFinite(notAfter) || now < notBefore || now > notAfter) {
      throw new Error(`ICA signing certificate at chain position ${index} is outside its validity window.`);
    }
  });
  const leaf = certificates[0];
  const root = certificates[certificates.length - 1];
  if (leaf.ca) throw new Error('ICA signing leaf certificate must not be a CA certificate.');
  if (!root.ca) throw new Error('ICA signing chain terminal certificate must be a Root CA certificate.');
  if (!leaf.checkPrivateKey(createPrivateKey(privateKeyPem))) {
    throw new Error('ICA signing private key does not match the leaf X.509 certificate.');
  }
  for (let index = 0; index < certificates.length - 1; index += 1) {
    const child = certificates[index];
    const issuer = certificates[index + 1];
    if (!child.checkIssued(issuer) || !child.verify(issuer.publicKey)) {
      throw new Error(`ICA signing X.509 chain is invalid at position ${index} -> ${index + 1}.`);
    }
  }
  if (!root.checkIssued(root) || !root.verify(root.publicKey)) {
    throw new Error('ICA signing X.509 chain must terminate in a self-signed Root CA certificate.');
  }

  const expectedPin = normalizeFingerprint(env.ICA_ROOT_CA_CERT_SHA256);
  const actualPin = normalizeFingerprint(root.fingerprint256);
  if (required && !expectedPin) throw new Error('ICA_VC_SIGNING_TRUST_REQUIRED requires ICA_ROOT_CA_CERT_SHA256.');
  if (expectedPin && expectedPin !== actualPin) {
    throw new Error('ICA signing X.509 chain does not terminate in ICA_ROOT_CA_CERT_SHA256.');
  }

  const rootDid = String(env.ICA_ROOT_CA_DID || '').trim();
  if (required && !rootDid) throw new Error('ICA_VC_SIGNING_TRUST_REQUIRED requires ICA_ROOT_CA_DID.');
  let rootDidDocumentUrl: string | undefined;
  if (rootDid) {
    const resolved = await loadRootDidDocument(env, rootDid, fetchImpl);
    validateRootDidDocument(resolved.document, rootDid, root);
    rootDidDocumentUrl = resolved.url;
  }

  const leafJwk = leaf.publicKey.export({ format: 'jwk' }) as JsonObject;
  const privatePublicJwk = createPublicKey(createPrivateKey(privateKeyPem)).export({ format: 'jwk' }) as JsonObject;
  assertSamePublicKey(leafJwk, privatePublicJwk, 'ICA signing private key public JWK does not match the leaf certificate.');
  const configuredKid = String(env.ICA_VC_SIGNING_KEY_ID || '').trim();
  const leafKid = jwkThumbprint(leafJwk);
  if (configuredKid && configuredKid !== leafKid) {
    throw new Error('ICA_VC_SIGNING_KEY_ID must be the RFC 7638 thumbprint of the ICA leaf public JWK.');
  }
  const x5u = String(env.ICA_VC_SIGNING_X5U || '').trim();
  if (required && !x5u) throw new Error('ICA_VC_SIGNING_TRUST_REQUIRED requires ICA_VC_SIGNING_X5U.');
  if (x5u && !x5u.startsWith('https://')) throw new Error('ICA_VC_SIGNING_X5U must use HTTPS.');

  return {
    required,
    validated: Boolean(rootDid && expectedPin),
    rootDid: rootDid || undefined,
    rootDidDocumentUrl,
    rootCertificateSha256: actualPin,
    leafCertificateSha256: normalizeFingerprint(leaf.fingerprint256),
    chainLength: certificates.length,
  };
}
