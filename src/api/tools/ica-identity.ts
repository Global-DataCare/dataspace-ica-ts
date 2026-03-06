import {
  constants as cryptoConstants,
  createPrivateKey,
  createPublicKey,
  createSign,
  randomUUID,
  sign as signDetachedRaw,
} from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { VerifiableCredentialV2 } from 'gdc-common-utils-ts/models/verifiable-credential';
import type { SupportedSigningAlgorithm, VerifyRouteContext } from '../types.ts';
import { getPreferredSigningKey, upsertDidSigningMethods } from './active-signing-keys.ts';

type JsonObject = Record<string, unknown>;

type SigningKeyMaterial = {
  privateKey: ReturnType<typeof createPrivateKey>;
  publicJwk: JsonObject;
  alg: SupportedSigningAlgorithm;
  keyId: string;
};

function firstHeaderValue(header: string | string[] | undefined): string {
  if (Array.isArray(header)) {
    return (header.find((value) => value && value.trim()) || '').trim();
  }
  return (header || '').trim();
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

function base64UrlEncode(input: Buffer | string): string {
  return Buffer.from(input)
    .toString('base64')
    .replace(/=/g, '')
    .replace(/\+/g, '-')
    .replace(/\//g, '_');
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

  const signatureEncoded = base64UrlEncode(signatureBytes);
  return `${headerEncoded}..${signatureEncoded}`;
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

  const requestHost = req ? firstHeaderValue(req.headers.host) : '';
  if (requestHost) {
    const didFromHostHeader = buildDidWebFromAuthority(requestHost);
    if (didFromHostHeader) return didFromHostHeader;
  }

  const port = process.env.ICA_API_PORT || process.env.PORT || '3310';
  return buildDidWebFromAuthority(`localhost:${port}`) || 'did:web:localhost%3A3310';
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
  const serviceEndpoint = (process.env.ICA_DID_SERVICE_ENDPOINT || '').trim();

  const document: JsonObject = configuredDocument || {
    '@context': ['https://www.w3.org/ns/did/v1', 'https://w3id.org/security/suites/jws-2020/v1'],
    id: issuerDid,
  };
  mergeSigningMethods(document, issuerDid);

  if (serviceEndpoint) {
    const services = Array.isArray(document.service)
      ? [...(document.service as JsonObject[])]
      : [];
    if (!services.some((entry) => String(entry.id || '') === `${issuerDid}#verify`)) {
      services.push({
        id: `${issuerDid}#verify`,
        type: 'DataSpaceIcaVerifyService',
        serviceEndpoint,
      });
    }
    document.service = services;
  }

  return document;
}

export function attachProofToCredential(
  vc: VerifiableCredentialV2,
  route: VerifyRouteContext,
): VerifiableCredentialV2 {
  const issuerDid = resolveIcaIssuerDid();
  const createdAt = new Date().toISOString();
  const vcWithoutProof = { ...vc };
  delete vcWithoutProof.proof;

  const signing = resolveSigningKeyMaterial();
  const verificationMethod = `${issuerDid}#${signing?.keyId || (process.env.ICA_VC_SIGNING_KEY_ID || 'key-1').trim()}`;

  const isTestVersion = route.resourceType.toLowerCase().startsWith('test-');
  if (isTestVersion) {
    return {
      ...vcWithoutProof,
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
    return vcWithoutProof;
  }

  const payloadBytes = Buffer.from(JSON.stringify(vcWithoutProof));
  const detachedJws = buildDetachedJws(payloadBytes, signing, verificationMethod);
  return {
    ...vcWithoutProof,
    proof: {
      type: 'JsonWebSignature2020',
      created: createdAt,
      proofPurpose: 'assertionMethod',
      verificationMethod,
      jws: detachedJws,
    },
  };
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
