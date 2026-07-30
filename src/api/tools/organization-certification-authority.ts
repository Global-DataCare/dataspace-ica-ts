import {
  createHash,
  createPrivateKey,
  createPublicKey,
  X509Certificate,
} from 'node:crypto';

type JsonObject = Record<string, unknown>;
type Environment = Record<string, string | undefined>;

export type OrganizationCertificationAuthority = {
  kid: string;
  privateKeyPem: string;
  publicJwk: JsonObject;
  x5c: string[];
  x5u?: string;
};

function decodeMultiline(value: string): string {
  return value.includes('\\n') ? value.replace(/\\n/g, '\n') : value;
}

function splitPemCertificates(value: string): string[] {
  return decodeMultiline(value).match(
    /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g,
  )?.map((entry) => entry.trim()) || [];
}

function x5cToPem(value: string): string {
  const body = value.trim();
  if (!body) throw new Error('Organization certification x5c entry cannot be empty.');
  return `-----BEGIN CERTIFICATE-----\n${body.match(/.{1,64}/g)?.join('\n') || body}\n-----END CERTIFICATE-----`;
}

function certificatePemToX5c(pem: string): string {
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '');
  if (!body) throw new Error('Invalid organization certification certificate PEM.');
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

function loadChain(env: Environment): string[] {
  const x5cJson = String(env.ICA_ORGANIZATION_CA_X5C_JSON || '').trim();
  if (x5cJson) {
    const parsed = JSON.parse(x5cJson) as unknown;
    if (!Array.isArray(parsed) || !parsed.length
      || parsed.some((entry) => typeof entry !== 'string' || !entry.trim())) {
      throw new Error('ICA_ORGANIZATION_CA_X5C_JSON must be a non-empty JSON string array.');
    }
    return parsed.map((entry) => x5cToPem(String(entry)));
  }
  return splitPemCertificates(String(env.ICA_ORGANIZATION_CA_CERTIFICATE_CHAIN_PEM || ''));
}

/**
 * Loads the dedicated subordinate CA used only to issue organization/tenant
 * public X.509 leaves. It must not be the `CA:FALSE` VC-signing certificate.
 */
export function loadOrganizationCertificationAuthority(
  env: Environment = process.env,
): OrganizationCertificationAuthority | undefined {
  const privateKeyPem = decodeMultiline(
    String(env.ICA_ORGANIZATION_CA_PRIVATE_KEY_PEM || ''),
  ).trim();
  const chainPem = loadChain(env);
  if (!privateKeyPem && !chainPem.length) return undefined;
  if (!privateKeyPem || !chainPem.length) {
    throw new Error(
      'Organization certification requires both ICA_ORGANIZATION_CA_PRIVATE_KEY_PEM and a certificate chain.',
    );
  }

  const certificates = chainPem.map((pem, index) => {
    try {
      return new X509Certificate(pem);
    } catch (error: unknown) {
      throw new Error(
        `Invalid organization certification certificate at position ${index}: ${(error as Error).message}`,
      );
    }
  });
  const issuer = certificates[0];
  const root = certificates[certificates.length - 1];
  if (!issuer.ca) {
    throw new Error('ICA organization certification leaf must be a CA certificate (CA:TRUE).');
  }
  if (!root.ca) {
    throw new Error('ICA organization certification chain must terminate in a CA certificate.');
  }
  const privateKey = createPrivateKey(privateKeyPem);
  if (!issuer.checkPrivateKey(privateKey)) {
    throw new Error('ICA organization certification private key does not match its CA certificate.');
  }
  for (let index = 0; index < certificates.length - 1; index += 1) {
    const child = certificates[index];
    const parent = certificates[index + 1];
    if (!child.checkIssued(parent) || !child.verify(parent.publicKey)) {
      throw new Error(
        `ICA organization certification chain is invalid at position ${index} -> ${index + 1}.`,
      );
    }
  }

  const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' }) as JsonObject;
  if (publicJwk.kty !== 'EC' || publicJwk.crv !== 'P-384') {
    throw new Error('ICA organization certification key must be EC P-384.');
  }
  const kid = jwkThumbprint(publicJwk);
  const configuredKid = String(env.ICA_ORGANIZATION_CA_KEY_ID || '').trim();
  if (configuredKid && configuredKid !== kid) {
    throw new Error('ICA_ORGANIZATION_CA_KEY_ID must be the RFC 7638 JWK thumbprint.');
  }
  const x5u = String(env.ICA_ORGANIZATION_CA_X5U || '').trim();
  if (x5u && !x5u.startsWith('https://')) {
    throw new Error('ICA_ORGANIZATION_CA_X5U must use HTTPS.');
  }
  return {
    kid,
    privateKeyPem,
    publicJwk,
    x5c: chainPem.map(certificatePemToX5c),
    ...(x5u ? { x5u } : {}),
  };
}

export function buildOrganizationCertificationVerificationMethod(
  issuerDid: string,
  env: Environment = process.env,
): JsonObject | undefined {
  const authority = loadOrganizationCertificationAuthority(env);
  if (!authority) return undefined;
  return {
    id: `${issuerDid}#${authority.kid}`,
    type: 'JsonWebKey2020',
    controller: issuerDid,
    publicKeyJwk: {
      ...authority.publicJwk,
      kid: authority.kid,
      alg: 'ES384',
      use: 'sig',
      key_ops: ['verify'],
      x5c: authority.x5c,
      ...(authority.x5u ? { x5u: authority.x5u } : {}),
      purposes: ['organization-certificate-issuance'],
    },
  };
}

