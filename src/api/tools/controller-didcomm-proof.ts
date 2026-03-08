import {
  constants as cryptoConstants,
  createHash,
  createPrivateKey,
  createPublicKey,
  createVerify,
  verify as verifyDetachedRaw,
} from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type {
  ActivateSigningKeySubmission,
  RotateRouteContext,
  RotateSubmission,
  SupportedSigningAlgorithm,
} from '../types.ts';
import { buildControllerDidDocument, buildIcaDidDocument } from './ica-identity.ts';
import { computeActivateDataPayloadBase64Url } from './activate-payload-digest.ts';

type JsonObject = Record<string, unknown>;

type ParsedCompactJws = {
  header: JsonObject;
  payload?: JsonObject;
  protectedEncoded: string;
  payloadEncoded: string;
  signature: Buffer;
  alg: SupportedSigningAlgorithm;
};

type PublicKeyCandidate = {
  publicKey: ReturnType<typeof createPublicKey>;
  alg?: SupportedSigningAlgorithm;
};

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function normalizeKid(raw: string): string {
  const trimmed = raw.trim();
  if (!trimmed) return '';
  const fragmentIndex = trimmed.lastIndexOf('#');
  if (fragmentIndex < 0 || fragmentIndex >= trimmed.length - 1) return trimmed;
  return trimmed.slice(fragmentIndex + 1);
}

function normalizeSupportedSigningAlgorithm(raw: string): SupportedSigningAlgorithm | undefined {
  const normalized = raw.trim().toUpperCase();
  if (!normalized) return undefined;
  if (normalized === 'ES384') return 'ES384';
  if (normalized === 'ES256K') return 'ES256K';
  if (normalized === 'RS256') return 'RS256';
  if (normalized === 'PS256') return 'PS256';
  if (normalized === 'EDDSA') return 'EdDSA';
  return undefined;
}

function buildJwkThumbprintSource(publicJwk: JsonObject): JsonObject {
  const kty = String(publicJwk.kty || '');
  if (kty === 'EC') {
    return {
      crv: publicJwk.crv,
      kty: publicJwk.kty,
      x: publicJwk.x,
      y: publicJwk.y,
    };
  }
  if (kty === 'RSA') {
    return {
      e: publicJwk.e,
      kty: publicJwk.kty,
      n: publicJwk.n,
    };
  }
  if (kty === 'OKP') {
    return {
      crv: publicJwk.crv,
      kty: publicJwk.kty,
      x: publicJwk.x,
    };
  }
  return publicJwk;
}

function computeKidFromPublicJwk(publicJwk: JsonObject): string {
  const source = buildJwkThumbprintSource(publicJwk);
  return createHash('sha256')
    .update(JSON.stringify(source))
    .digest('base64url');
}

function base64UrlDecodeToBuffer(input: string, segmentLabel: string): Buffer {
  const normalized = input.trim();
  if (!normalized) {
    throw new Error(`Controller DIDComm signature has empty ${segmentLabel} segment.`);
  }
  const padded = normalized + '='.repeat((4 - (normalized.length % 4)) % 4);
  const base64 = padded.replace(/-/g, '+').replace(/_/g, '/');
  try {
    return Buffer.from(base64, 'base64');
  } catch (error: unknown) {
    throw new Error(
      `Controller DIDComm signature has invalid ${segmentLabel} segment: ${(error as Error).message}`,
    );
  }
}

function parseCompactJws(jws: string, options?: { allowDetachedPayload?: boolean }): ParsedCompactJws {
  const parts = jws.trim().split('.');
  if (parts.length !== 3) {
    throw new Error('Controller DIDComm signature must be a compact JWS with 3 segments.');
  }
  const [protectedEncoded, payloadEncoded, signatureEncoded] = parts;
  const headerRaw = base64UrlDecodeToBuffer(protectedEncoded, 'protected');
  const signature = base64UrlDecodeToBuffer(signatureEncoded, 'signature');

  let header: JsonObject;
  let payload: JsonObject | undefined;
  try {
    header = JSON.parse(headerRaw.toString('utf8')) as JsonObject;
  } catch (error: unknown) {
    throw new Error(`Controller DIDComm signature protected header is not valid JSON: ${(error as Error).message}`);
  }

  if (payloadEncoded) {
    const payloadRaw = base64UrlDecodeToBuffer(payloadEncoded, 'payload');
    try {
      payload = JSON.parse(payloadRaw.toString('utf8')) as JsonObject;
    } catch (error: unknown) {
      throw new Error(`Controller DIDComm signature payload is not valid JSON: ${(error as Error).message}`);
    }
  } else if (!options?.allowDetachedPayload) {
    throw new Error('Controller DIDComm signature payload must not be empty.');
  }

  const alg = normalizeSupportedSigningAlgorithm(asNonEmptyString(header.alg));
  if (!alg) {
    throw new Error('Controller DIDComm signature header.alg is required and must be supported.');
  }

  return {
    header,
    payload,
    protectedEncoded,
    payloadEncoded,
    signature,
    alg,
  };
}

function verifySignatureWithAlgorithm(
  parsed: ParsedCompactJws,
  publicKey: ReturnType<typeof createPublicKey>,
  signingInputOverride?: string,
): boolean {
  const signingInput = signingInputOverride || `${parsed.protectedEncoded}.${parsed.payloadEncoded}`;
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

function configuredSelfControllerKid(): string {
  return normalizeKid(process.env.ICA_SELF_CONTROLLER_KID || '');
}

function isControllerProofRequired(): boolean {
  const disable = process.env.DISABLE_CONTROLLER_DIDCOMM_PROOF;
  return !parseBoolean(disable, false);
}

function resolveProofKid(parsed: ParsedCompactJws, proofKidHint?: string): string {
  const fromHeader = normalizeKid(asNonEmptyString(parsed.header.kid));
  const fromHint = normalizeKid(proofKidHint || '');
  if (fromHint && fromHeader && fromHint !== fromHeader) {
    throw new Error('body.signature.kid does not match JWS header.kid.');
  }
  const resolved = fromHint || fromHeader;
  if (!resolved) {
    throw new Error('Controller DIDComm signature must provide kid in header.kid (or body.signature.kid).');
  }
  return resolved;
}

function ensureSelfControllerKidMatch(signerKid: string): void {
  const configuredKid = configuredSelfControllerKid();
  if (!configuredKid) return;
  if (signerKid !== configuredKid) {
    throw new Error(
      `Controller DIDComm signature kid "${signerKid}" does not match ICA_SELF_CONTROLLER_KID="${configuredKid}".`,
    );
  }
}

function publicKeyCandidatesFromDidDocumentObject(
  didDocument: JsonObject,
  signerKid: string,
): PublicKeyCandidate[] {
  const verificationMethods = Array.isArray(didDocument.verificationMethod)
    ? (didDocument.verificationMethod as unknown[])
    : [];
  const candidates: PublicKeyCandidate[] = [];

  for (const entry of verificationMethods) {
    const method = asObject(entry);
    if (!method) continue;
    const publicKeyJwk = asObject(method.publicKeyJwk);
    if (!publicKeyJwk) continue;

    const methodId = asNonEmptyString(method.id);
    const methodKid = normalizeKid(
      asNonEmptyString(publicKeyJwk.kid) || methodId,
    );
    if (!methodKid || methodKid !== signerKid) continue;

    try {
      const keyObject = createPublicKey({ key: publicKeyJwk as any, format: 'jwk' });
      const methodAlg = normalizeSupportedSigningAlgorithm(asNonEmptyString(publicKeyJwk.alg));
      candidates.push({
        publicKey: keyObject,
        ...(methodAlg ? { alg: methodAlg } : {}),
      });
    } catch {
      // Ignore malformed entries from externally supplied DID docs.
    }
  }

  return candidates;
}

function publicKeyCandidatesFromDidDocuments(
  req: IncomingMessage,
  signerKid: string,
): PublicKeyCandidate[] {
  const candidates = [
    ...publicKeyCandidatesFromDidDocumentObject(buildIcaDidDocument(req), signerKid),
  ];
  const controllerDidDocument = buildControllerDidDocument(req);
  if (controllerDidDocument) {
    candidates.push(...publicKeyCandidatesFromDidDocumentObject(controllerDidDocument, signerKid));
  }
  return candidates;
}

function assertProofClaims(
  parsed: ParsedCompactJws,
  expected: {
    action: '_activate' | '_rotate';
    thid: string;
    jti?: string;
    signerKid: string;
    resourceType?: string;
  },
): void {
  const payload = parsed.payload;
  if (!payload) {
    throw new Error('Controller DIDComm signature payload is required.');
  }
  const payloadThid = asNonEmptyString(payload.thid);
  if (!payloadThid) {
    throw new Error('Controller DIDComm signature payload.thid is required.');
  }
  if (payloadThid !== expected.thid) {
    throw new Error('Controller DIDComm signature payload.thid does not match request thid.');
  }

  const payloadAction = asNonEmptyString(payload.action);
  if (!payloadAction) {
    throw new Error('Controller DIDComm signature payload.action is required.');
  }
  if (payloadAction !== expected.action) {
    throw new Error(`Controller DIDComm signature payload.action must be "${expected.action}".`);
  }

  const payloadKid = normalizeKid(asNonEmptyString(payload.kid));
  if (payloadKid && payloadKid !== expected.signerKid) {
    throw new Error('Controller DIDComm signature payload.kid does not match signer kid.');
  }

  const payloadJti = asNonEmptyString(payload.jti);
  if (expected.jti && payloadJti && payloadJti !== expected.jti) {
    throw new Error('Controller DIDComm signature payload.jti does not match request jti.');
  }

  if (expected.resourceType) {
    const payloadResourceType = asNonEmptyString(payload.resourceType);
    if (payloadResourceType && payloadResourceType !== expected.resourceType) {
      throw new Error('Controller DIDComm signature payload.resourceType does not match route resourceType.');
    }
  }
}

function assertAlgorithmConstraints(
  parsed: ParsedCompactJws,
  proofAlgHint: string | undefined,
  candidateAlgorithms: SupportedSigningAlgorithm[],
): void {
  const proofAlg = normalizeSupportedSigningAlgorithm(proofAlgHint || '');
  if (proofAlg && proofAlg !== parsed.alg) {
    throw new Error('body.signature.alg does not match JWS header.alg.');
  }
  if (candidateAlgorithms.length && !candidateAlgorithms.includes(parsed.alg)) {
    throw new Error('Controller DIDComm signature alg does not match the controller key algorithm.');
  }
}

function verifyAgainstCandidates(
  parsed: ParsedCompactJws,
  candidates: PublicKeyCandidate[],
  signingInputOverride?: string,
): void {
  for (const candidate of candidates) {
    if (verifySignatureWithAlgorithm(parsed, candidate.publicKey, signingInputOverride)) return;
  }
  throw new Error('Invalid controller DIDComm signature.');
}

export function validateActivateControllerDidcommProof(
  submission: ActivateSigningKeySubmission,
  req: IncomingMessage,
): void {
  const proof = submission.controllerProof;
  if (!proof?.jws) {
    if (isControllerProofRequired()) {
      throw new Error('Activation request requires body.signature.data.');
    }
    return;
  }

  const parsedProof = parseCompactJws(proof.jws, { allowDetachedPayload: true });
  const signerKid = resolveProofKid(parsedProof, proof.kid);
  ensureSelfControllerKidMatch(signerKid);

  const activateCandidates: PublicKeyCandidate[] = [];
  const keyKids: string[] = [];
  for (const entry of submission.keys) {
    try {
      const privateKey = createPrivateKey(entry.privateKeyPem);
      const publicKey = createPublicKey(privateKey);
      const publicJwk = publicKey.export({ format: 'jwk' }) as JsonObject;
      const computedKid = computeKidFromPublicJwk(publicJwk);
      const entryKid = normalizeKid(entry.kid || computedKid);
      if (entryKid) {
        keyKids.push(entryKid);
      }
      if (entryKid !== signerKid) continue;
      activateCandidates.push({
        publicKey,
        alg: entry.alg,
      });
    } catch {
      // Activate flow will fail later with a clearer key parsing message.
    }
  }
  if (keyKids.length && !keyKids.includes(signerKid)) {
    throw new Error(
      'Activation DIDComm signature kid must match one of body.data[].key.kid/body.data[].kid values (or their derived RFC7638 kid).',
    );
  }

  const didCandidates = publicKeyCandidatesFromDidDocuments(req, signerKid);
  const allCandidates = [...activateCandidates, ...didCandidates];
  if (!allCandidates.length) {
    throw new Error(
      `No controller public key found for kid="${signerKid}" in activation payload or DID document.`,
    );
  }

  assertAlgorithmConstraints(
    parsedProof,
    proof.alg,
    allCandidates.map((entry) => entry.alg).filter(Boolean) as SupportedSigningAlgorithm[],
  );
  if (parsedProof.payloadEncoded) {
    throw new Error(
      'Activation controller signature must use detached compact JWS (empty payload segment) over canonical request body.',
    );
  }
  const detachedPayloadEncoded =
    submission.controllerAuthorizationPayloadBase64Url
    || computeActivateDataPayloadBase64Url(submission.keys);
  verifyAgainstCandidates(
    parsedProof,
    allCandidates,
    `${parsedProof.protectedEncoded}.${detachedPayloadEncoded}`,
  );
}

export function validateRotateControllerDidcommProof(
  submission: RotateSubmission,
  route: RotateRouteContext,
  req: IncomingMessage,
): void {
  const proof = submission.controllerProof;
  if (!proof?.jws) {
    if (isControllerProofRequired()) {
      throw new Error('Rotate request requires body.signature.data.');
    }
    return;
  }

  const parsedProof = parseCompactJws(proof.jws, { allowDetachedPayload: true });
  const signerKid = resolveProofKid(parsedProof, proof.kid);
  ensureSelfControllerKidMatch(signerKid);

  const didCandidates = publicKeyCandidatesFromDidDocuments(req, signerKid);
  if (!didCandidates.length) {
    throw new Error(
      `No controller verification method found in DID document for kid="${signerKid}".`,
    );
  }

  assertAlgorithmConstraints(
    parsedProof,
    proof.alg,
    didCandidates.map((entry) => entry.alg).filter(Boolean) as SupportedSigningAlgorithm[],
  );
  if (!parsedProof.payloadEncoded) {
    const detachedPayloadEncoded = submission.controllerAuthorizationPayloadBase64Url;
    if (!detachedPayloadEncoded) {
      throw new Error('Rotate detached signature missing canonical body payload.');
    }
    verifyAgainstCandidates(
      parsedProof,
      didCandidates,
      `${parsedProof.protectedEncoded}.${detachedPayloadEncoded}`,
    );
    return;
  }

  verifyAgainstCandidates(parsedProof, didCandidates);
  assertProofClaims(parsedProof, {
    action: '_rotate',
    thid: submission.thid,
    jti: submission.jti,
    signerKid,
    resourceType: route.resourceType,
  });
}
