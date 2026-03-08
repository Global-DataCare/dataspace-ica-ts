import { randomUUID } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import { Readable } from 'node:stream';
import type { IncomingMessage } from 'node:http';
import type {
  ActivateSigningKeyInput,
  ActivateSigningKeySubmission,
  AddEvidenceInput,
  AddEvidenceSubmission,
  ControllerDidcommProof,
  CredentialRevokeSubmission,
  DelegationPolicyInput,
  DelegationPolicySubmission,
  CredentialLookupInput,
  CredentialRevokeInput,
  CredentialStatusSubmission,
  IssueCredentialInput,
  IssueCredentialSubmission,
  RotateSubmission,
  SupportedSigningAlgorithm,
  VerifySubmission,
} from './types.ts';
import {
  assertValidOidc4idaEvidenceObject,
  assertValidOidc4idaVerifiedClaimsResource,
} from './tools/oidc4ida-evidence-validation.ts';
import { assertValidDelegationPolicyResource } from './tools/odrl-delegation-policy-validation.ts';
import { assertSchemaOrgCredential } from './tools/schemaorg-credential-validation.ts';
import { computeControllerAuthorizationPayloadBase64Url } from './tools/controller-authorization-payload.ts';

type ParsedThreadPayload = {
  thid?: string;
  jti?: string;
};

type ParsedObject = Record<string, unknown>;

type DidcommAttachmentData = {
  base64?: string;
  links?: string[];
};

type DidcommAttachment = {
  media_type?: string;
  data?: DidcommAttachmentData;
};

function normalizeHeader(value: string | string[] | undefined): string {
  if (Array.isArray(value)) return value[0] || '';
  return value || '';
}

function asObject(value: unknown): ParsedObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as ParsedObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function asNonEmptyStringList(value: unknown): string[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => asNonEmptyString(entry))
    .filter(Boolean);
}

function normalizeContentType(headerValue: string): string {
  return headerValue.split(';')[0].trim().toLowerCase();
}

function pad2(value: number): string {
  return String(value).padStart(2, '0');
}

function buildThreadTimestamp(date: Date = new Date()): string {
  return [
    date.getFullYear(),
    pad2(date.getMonth() + 1),
    pad2(date.getDate()),
    pad2(date.getHours()),
    pad2(date.getMinutes()),
    pad2(date.getSeconds()),
  ].join('');
}

function isAutoToken(value: string, prefix: 'thid' | 'req'): boolean {
  const normalized = value.trim().toLowerCase();
  if (!normalized) return false;
  return normalized === `${prefix}-auto`
    || normalized === `${prefix}-yyyymmddhhss`
    || normalized === `${prefix}-yyyymmddhhmmss`;
}

async function readIncomingBuffer(req: IncomingMessage): Promise<Buffer<ArrayBufferLike>> {
  const chunks: Buffer<ArrayBufferLike>[] = [];
  for await (const chunk of req) {
    chunks.push(Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk));
  }
  return Buffer.concat(chunks);
}

function extractThid(payload: ParsedThreadPayload): string {
  const fromThid = String(payload.thid || '').trim();
  const fromJti = String(payload.jti || '').trim();
  if (fromThid) {
    return isAutoToken(fromThid, 'thid')
      ? `thid-${buildThreadTimestamp()}`
      : fromThid;
  }
  if (fromJti) {
    return isAutoToken(fromJti, 'req')
      ? `thid-${buildThreadTimestamp()}`
      : fromJti;
  }
  return randomUUID();
}

function buildWebRequest(req: IncomingMessage): Request {
  const host = normalizeHeader(req.headers.host) || 'localhost';
  const url = `http://${host}${req.url || '/'}`;
  const headers = new Headers();
  for (const [name, raw] of Object.entries(req.headers)) {
    if (raw === undefined) continue;
    if (Array.isArray(raw)) {
      for (const value of raw) {
        headers.append(name, value);
      }
      continue;
    }
    headers.set(name, raw);
  }
  const init: RequestInit & { duplex?: 'half' } = {
    method: req.method,
    headers,
    body: Readable.toWeb(req) as ReadableStream<Uint8Array>,
    duplex: 'half',
  };
  return new Request(url, init);
}

async function resolveInputRef(inputRef: string): Promise<Buffer<ArrayBufferLike>> {
  const trimmed = inputRef.trim();
  if (!trimmed) throw new Error('inputRef is empty.');
  if (trimmed.startsWith('http://') || trimmed.startsWith('https://')) {
    const response = await fetch(trimmed);
    if (!response.ok) {
      throw new Error(`inputRef download failed (${response.status}).`);
    }
    return Buffer.from(await response.arrayBuffer());
  }
  if (trimmed.startsWith('file://')) {
    return readFile(fileURLToPath(trimmed));
  }
  return readFile(trimmed);
}

function looksLikePdf(bytes: Buffer<ArrayBufferLike>): boolean {
  if (!bytes.length) return false;
  const head = bytes.subarray(0, Math.min(bytes.length, 1024)).toString('latin1');
  return head.includes('%PDF-');
}

function invalidPdfAttachmentError(): Error {
  return new Error(
    'Attachment does not contain a valid PDF. For Google Drive use a direct download URL (not /file/d/... viewer URL) or send attachments[].data.base64.',
  );
}

function decodeBase64Payload(base64Payload: string): Buffer<ArrayBufferLike> {
  try {
    return Buffer.from(base64Payload, 'base64');
  } catch (error: unknown) {
    throw new Error(`Invalid base64 payload: ${(error as Error).message}`);
  }
}

async function resolvePdfFromDidcommAttachments(
  attachments: DidcommAttachment[],
): Promise<Buffer<ArrayBufferLike>> {
  for (const attachment of attachments) {
    const mediaType = asNonEmptyString(attachment.media_type).toLowerCase();
    if (mediaType && mediaType !== 'application/pdf' && mediaType !== 'application/octet-stream') {
      continue;
    }
    const data = asObject(attachment?.data);
    if (!data) continue;

    const base64Payload = asNonEmptyString(data.base64);
    if (base64Payload) {
      const pdfBytes = decodeBase64Payload(base64Payload);
      if (pdfBytes.length) return pdfBytes;
      continue;
    }

    const links = Array.isArray(data.links)
      ? data.links.map((link) => asNonEmptyString(link)).filter(Boolean)
      : [];
    if (!links.length) continue;
    const remoteBytes = await resolveInputRef(links[0]);
    if (remoteBytes.length) {
      if (!looksLikePdf(remoteBytes)) {
        throw invalidPdfAttachmentError();
      }
      return remoteBytes;
    }
  }
  return Buffer.alloc(0);
}

export async function parseVerifySubmission(req: IncomingMessage): Promise<VerifySubmission> {
  const contentTypeHeader = normalizeHeader(req.headers['content-type']);
  const contentType = normalizeContentType(contentTypeHeader);
  const contentEncodingHeader = normalizeHeader(req.headers['content-encoding']).trim().toLowerCase();

  if (contentEncodingHeader && contentEncodingHeader !== 'identity') {
    throw new Error(
      `Unsupported Content-Encoding for _verify: ${contentEncodingHeader} (expected identity)`,
    );
  }

  const rawBody = await readIncomingBuffer(req);

  if (!rawBody.length) {
    throw new Error('Empty request payload.');
  }

  if (contentType !== 'application/didcomm-plain+json') {
    if (contentType === 'application/didcomm-encrypted+json') {
      throw new Error(
        'Unsupported Content-Type for _verify: application/didcomm-encrypted+json (decrypt before calling this endpoint).',
      );
    }
    throw new Error(
      `Unsupported Content-Type for _verify: ${contentTypeHeader || '(missing)'} (expected application/didcomm-plain+json)`,
    );
  }

  let parsed: ParsedObject;
  try {
    parsed = JSON.parse(rawBody.toString('utf8')) as ParsedObject;
  } catch (error: unknown) {
    throw new Error(`Invalid JSON body: ${(error as Error).message}`);
  }

  const parsedBody = asObject(parsed.body) || {};
  const attachments = Array.isArray(parsed.attachments)
    ? (parsed.attachments
        .map((attachment) => asObject(attachment))
        .filter(Boolean) as DidcommAttachment[])
    : [];

  const pdfBytes = await resolvePdfFromDidcommAttachments(attachments);

  if (!pdfBytes.length) {
    throw new Error('DIDComm payload must include attachments[].data.base64 or attachments[].data.links.');
  }

  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });
  return { thid, pdfBytes, contentType };
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

function parseActivateSigningKeyInput(
  rawEntry: unknown,
  fallback: ParsedObject,
  indexLabel: string,
): ActivateSigningKeyInput {
  const entry = asObject(rawEntry) || {};
  const keyPayload = asObject(entry.key) || entry;
  const alg = parseSupportedSigningAlgorithm(
    asNonEmptyString(keyPayload.alg || entry.alg || fallback.alg),
  );
  if (!alg) {
    throw new Error(
      `Activation payload requires key algorithm (alg) at ${indexLabel}: ES384 | ES256K | RS256 | PS256 | EdDSA.`,
    );
  }

  const privateKeyPem = asNonEmptyString(
    keyPayload.privateKeyPem
      || keyPayload.private_key_pem
      || keyPayload.privateKey
      || entry.privateKeyPem
      || entry.private_key_pem
      || entry.privateKey
      || fallback.privateKeyPem
      || fallback.private_key_pem
      || fallback.privateKey,
  );
  if (!privateKeyPem) {
    throw new Error(`Activation payload requires key.privateKeyPem at ${indexLabel}.`);
  }

  const x5c = asNonEmptyStringList(
    keyPayload.x5c || entry.x5c || fallback.x5c,
  );
  const certificateChainPem = asNonEmptyStringList(
    keyPayload.certificateChainPem
      || keyPayload.chainPem
      || keyPayload.chain
      || entry.certificateChainPem
      || entry.chainPem
      || entry.chain
      || fallback.certificateChainPem
      || fallback.chainPem
      || fallback.chain,
  );

  const kid = asNonEmptyString(keyPayload.kid || entry.kid || fallback.kid) || undefined;
  return {
    kid,
    alg,
    privateKeyPem,
    ...(x5c.length ? { x5c } : {}),
    ...(certificateChainPem.length ? { certificateChainPem } : {}),
  };
}

function parseControllerDidcommProof(
  parsedBody: ParsedObject,
): ControllerDidcommProof | undefined {
  const signatureContainer =
    asObject(parsedBody.signature);
  if (signatureContainer) {
    const jwsFromSignature = resolveJwsFromSignatureContainer(signatureContainer);
    if (jwsFromSignature) {
      const kidFromWho = resolveSignatureWhoKid(signatureContainer);
      const kid = asNonEmptyString(kidFromWho || signatureContainer.kid) || undefined;
      const alg = asNonEmptyString(signatureContainer.alg) || undefined;
      return {
        jws: jwsFromSignature,
        ...(kid ? { kid } : {}),
        ...(alg ? { alg } : {}),
      };
    }
  }
  return undefined;
}

function resolveSignatureWhoKid(signatureContainer: ParsedObject): string {
  const who = asObject(signatureContainer.who);
  if (!who) return '';
  return asNonEmptyString(who.reference);
}

function tryDecodeBase64ToUtf8(value: string): string {
  try {
    return Buffer.from(value, 'base64').toString('utf8').trim();
  } catch {
    try {
      return Buffer.from(value, 'base64url').toString('utf8').trim();
    } catch {
      return '';
    }
  }
}

function resolveJwsFromSignatureContainer(signatureContainer: ParsedObject): string {
  const rawData = asNonEmptyString(
    signatureContainer.data
    || signatureContainer.jws
    || signatureContainer.signature
    || signatureContainer.jwt,
  );
  if (!rawData) return '';
  if (rawData.includes('.')) return rawData;
  const decoded = tryDecodeBase64ToUtf8(rawData);
  if (decoded.includes('.')) return decoded;
  return '';
}

export async function parseActivateSigningKeySubmission(
  req: IncomingMessage,
): Promise<ActivateSigningKeySubmission> {
  const contentTypeHeader = normalizeHeader(req.headers['content-type']);
  const contentType = normalizeContentType(contentTypeHeader);
  const contentEncodingHeader = normalizeHeader(req.headers['content-encoding']).trim().toLowerCase();

  if (contentEncodingHeader && contentEncodingHeader !== 'identity') {
    throw new Error(
      `Unsupported Content-Encoding for _activate: ${contentEncodingHeader} (expected identity)`,
    );
  }

  const rawBody = await readIncomingBuffer(req);
  if (!rawBody.length) {
    throw new Error('Empty request payload.');
  }

  if (contentType !== 'application/didcomm-plain+json') {
    if (contentType === 'application/didcomm-encrypted+json') {
      throw new Error(
        'Unsupported Content-Type for _activate: application/didcomm-encrypted+json (decrypt before calling this endpoint).',
      );
    }
    throw new Error(
      `Unsupported Content-Type for _activate: ${contentTypeHeader || '(missing)'} (expected application/didcomm-plain+json)`,
    );
  }

  let parsed: ParsedObject;
  try {
    parsed = JSON.parse(rawBody.toString('utf8')) as ParsedObject;
  } catch (error: unknown) {
    throw new Error(`Invalid JSON body: ${(error as Error).message}`);
  }

  const parsedBody = asObject(parsed.body) || {};
  const keyFallback: ParsedObject = { ...parsed, ...parsedBody };
  const rawDataEntries = Array.isArray(parsedBody.data) ? parsedBody.data : [];
  if (!rawDataEntries.length) {
    throw new Error('Activation payload requires body.data[] with at least one key item.');
  }
  const keys = rawDataEntries
    .map((entry, index) => parseActivateSigningKeyInput(entry, keyFallback, `body.data[${index}]`));

  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });
  const jti = asNonEmptyString(parsed.jti || parsedBody.jti) || undefined;
  const controllerProof = parseControllerDidcommProof(parsedBody);
  const controllerAuthorizationPayloadBase64Url = computeControllerAuthorizationPayloadBase64Url(parsedBody);
  return {
    thid,
    ...(jti ? { jti } : {}),
    keys,
    ...(controllerProof ? { controllerProof } : {}),
    controllerAuthorizationPayloadBase64Url,
  };
}

async function parseDidcommPlainObject(
  req: IncomingMessage,
  action: '_add' | '_issue' | '_status' | '_revoke' | '_rotate' | '_upsert',
): Promise<{ parsed: ParsedObject; parsedBody: ParsedObject }> {
  const contentTypeHeader = normalizeHeader(req.headers['content-type']);
  const contentType = normalizeContentType(contentTypeHeader);
  const contentEncodingHeader = normalizeHeader(req.headers['content-encoding']).trim().toLowerCase();

  if (contentEncodingHeader && contentEncodingHeader !== 'identity') {
    throw new Error(
      `Unsupported Content-Encoding for ${action}: ${contentEncodingHeader} (expected identity)`,
    );
  }

  const rawBody = await readIncomingBuffer(req);
  if (!rawBody.length) {
    throw new Error('Empty request payload.');
  }

  if (contentType !== 'application/didcomm-plain+json') {
    if (contentType === 'application/didcomm-encrypted+json') {
      throw new Error(
        `Unsupported Content-Type for ${action}: application/didcomm-encrypted+json (decrypt before calling this endpoint).`,
      );
    }
    throw new Error(
      `Unsupported Content-Type for ${action}: ${contentTypeHeader || '(missing)'} (expected application/didcomm-plain+json)`,
    );
  }

  let parsed: ParsedObject;
  try {
    parsed = JSON.parse(rawBody.toString('utf8')) as ParsedObject;
  } catch (error: unknown) {
    throw new Error(`Invalid JSON body: ${(error as Error).message}`);
  }

  return {
    parsed,
    parsedBody: asObject(parsed.body) || {},
  };
}

export async function parseRotateSubmission(req: IncomingMessage): Promise<RotateSubmission> {
  const { parsed, parsedBody } = await parseDidcommPlainObject(req, '_rotate');
  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });
  const jti = asNonEmptyString(parsed.jti || parsedBody.jti) || undefined;
  const controllerProof = parseControllerDidcommProof(parsedBody);
  const controllerAuthorizationPayloadBase64Url = computeControllerAuthorizationPayloadBase64Url(parsedBody);
  return {
    thid,
    ...(jti ? { jti } : {}),
    ...(controllerProof ? { controllerProof } : {}),
    controllerAuthorizationPayloadBase64Url,
  };
}

function parseEvidenceEntries(value: unknown): Record<string, unknown>[] {
  if (!Array.isArray(value)) return [];
  return value
    .map((entry) => asObject(entry))
    .filter(Boolean) as Record<string, unknown>[];
}

function parseAddEvidenceInput(
  rawEntry: unknown,
  fallback: ParsedObject,
  indexLabel: string,
): AddEvidenceInput {
  const entry = asObject(rawEntry) || {};
  const resource = asObject(entry.resource);
  const directEvidence =
    asObject(entry.evidence)
    || asObject(resource?.evidence);
  const wrappedVerifiedClaimsResource = resource && asObject(resource.verified_claims)
    ? resource
    : undefined;
  const rawEvidence = directEvidence || wrappedVerifiedClaimsResource || resource;
  if (!rawEvidence) {
    throw new Error(`Evidence payload requires ${indexLabel}.evidence object.`);
  }
  if (wrappedVerifiedClaimsResource) {
    assertValidOidc4idaVerifiedClaimsResource(wrappedVerifiedClaimsResource, `${indexLabel}.resource`);
  } else if (resource && !directEvidence) {
    assertValidOidc4idaEvidenceObject(resource, `${indexLabel}.resource`);
  } else {
    assertValidOidc4idaEvidenceObject(rawEvidence, `${indexLabel}.evidence`);
  }

  const issuedCredentialRecordId =
    asNonEmptyString(
      entry.issuedCredentialRecordId
      || resource?.issuedCredentialRecordId
      || fallback.issuedCredentialRecordId,
    ) || undefined;
  const operatorDid =
    asNonEmptyString(
      entry.operatorDid
      || entry.performedBy
      || resource?.operatorDid
      || resource?.performedBy
      || fallback.operatorDid
      || fallback.performedBy,
    )
    || undefined;

  return {
    evidence: { ...rawEvidence },
    ...(issuedCredentialRecordId ? { issuedCredentialRecordId } : {}),
    ...(operatorDid ? { operatorDid } : {}),
  };
}

export async function parseAddEvidenceSubmission(req: IncomingMessage): Promise<AddEvidenceSubmission> {
  const { parsed, parsedBody } = await parseDidcommPlainObject(req, '_add');

  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });

  const fallback: ParsedObject = { ...parsed, ...parsedBody };
  const rawBatchEntries = Array.isArray(parsedBody.data)
    ? parsedBody.data
    : Array.isArray(parsed.data)
      ? parsed.data
      : [];

  const evidences = rawBatchEntries.length
    ? rawBatchEntries.map((entry, index) => parseAddEvidenceInput(entry, fallback, `body.data[${index}]`))
    : (() => {
      const rawEvidence = asObject(parsedBody.evidence) || asObject(parsed.evidence);
      if (!rawEvidence) {
        throw new Error('Evidence payload requires body.evidence object or body.data[].resource/body.data[].evidence entries.');
      }
      if (asObject(rawEvidence.verified_claims)) {
        assertValidOidc4idaVerifiedClaimsResource(rawEvidence, 'body.evidence');
      } else {
        assertValidOidc4idaEvidenceObject(rawEvidence, 'body.evidence');
      }
      const issuedCredentialRecordId =
        asNonEmptyString(parsedBody.issuedCredentialRecordId || parsed.issuedCredentialRecordId) || undefined;
      const operatorDid =
        asNonEmptyString(
          parsedBody.operatorDid || parsed.operatorDid || parsedBody.performedBy || parsed.performedBy,
        )
        || undefined;
      return [{
        evidence: { ...rawEvidence },
        ...(issuedCredentialRecordId ? { issuedCredentialRecordId } : {}),
        ...(operatorDid ? { operatorDid } : {}),
      }];
    })();

  return {
    thid,
    evidences,
  };
}

function parseDelegationPolicyInput(rawEntry: unknown, indexLabel: string): DelegationPolicyInput {
  const entry = asObject(rawEntry) || {};
  const resource = asObject(entry.resource);
  if (!resource) {
    throw new Error(`Delegation policy payload requires ${indexLabel}.resource object.`);
  }
  assertValidDelegationPolicyResource(resource, `${indexLabel}.resource`);
  return {
    resource: { ...resource },
  };
}

export async function parseDelegationPolicySubmission(req: IncomingMessage): Promise<DelegationPolicySubmission> {
  const { parsed, parsedBody } = await parseDidcommPlainObject(req, '_upsert');

  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });

  const rawBatchEntries = Array.isArray(parsedBody.data)
    ? parsedBody.data
    : Array.isArray(parsed.data)
      ? parsed.data
      : [];
  if (!rawBatchEntries.length) {
    throw new Error('Delegation policy payload requires body.data[] with at least one resource item.');
  }

  const policies = rawBatchEntries
    .map((entry, index) => parseDelegationPolicyInput(entry, `body.data[${index}]`));

  return {
    thid,
    policies,
  };
}

export async function parseIssueCredentialSubmission(req: IncomingMessage): Promise<IssueCredentialSubmission> {
  const { parsed, parsedBody } = await parseDidcommPlainObject(req, '_issue');

  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });

  const fallback: ParsedObject = { ...parsed, ...parsedBody };
  const rawBatchEntries = Array.isArray(parsedBody.data)
    ? parsedBody.data
    : Array.isArray(parsed.data)
      ? parsed.data
      : [];
  const items: IssueCredentialInput[] = rawBatchEntries.length
    ? rawBatchEntries.map((entry, index) => parseIssueCredentialInput(entry, fallback, `body.data[${index}]`))
    : [parseIssueCredentialInput(parsedBody, fallback, 'body')];

  return {
    thid,
    items,
  };
}

function asCredentialLikeResource(value: unknown): ParsedObject | undefined {
  const resource = asObject(value);
  if (!resource) return undefined;
  if (asObject(resource.credentialSubject) || asNonEmptyString(resource.issuer) || resource.type) {
    return resource;
  }
  return undefined;
}

function parseIssueCredentialInput(
  rawEntry: unknown,
  fallback: ParsedObject,
  indexLabel: string,
): IssueCredentialInput {
  const entry = asObject(rawEntry) || {};
  const resource = asObject(entry.resource);
  const rawCredential =
    asCredentialLikeResource(entry.credential)
    || asCredentialLikeResource(resource)
    || asCredentialLikeResource(fallback.credential)
    || asCredentialLikeResource(asObject(fallback.resource));
  if (!rawCredential) {
    throw new Error(`Credential payload requires ${indexLabel}.resource (or ${indexLabel}.credential) object.`);
  }
  assertSchemaOrgCredential(rawCredential, `${indexLabel}.resource`);

  const evidence = [
    ...parseEvidenceEntries(entry.evidence),
  ];

  return {
    credential: { ...rawCredential },
    evidence,
  };
}

function resolveCredentialSubjectIdFromResource(resource: ParsedObject): string {
  const directSubjectId = asNonEmptyString(resource.subjectId);
  if (directSubjectId) return directSubjectId;
  const credentialSubject = resource.credentialSubject;
  if (Array.isArray(credentialSubject)) {
    for (const candidate of credentialSubject) {
      const subject = asObject(candidate);
      const subjectId = asNonEmptyString(subject?.id);
      if (subjectId) return subjectId;
    }
    return '';
  }
  const subject = asObject(credentialSubject);
  return asNonEmptyString(subject?.id);
}

function parseCredentialLookupFromObject(
  rawSource: ParsedObject,
  indexLabel: string,
): CredentialLookupInput {
  const source = rawSource || {};
  const resource = asObject(source.resource) || {};
  const credentialStatus = asObject(resource.credentialStatus) || {};

  const issuedCredentialRecordId = asNonEmptyString(
    source.issuedCredentialRecordId || resource.issuedCredentialRecordId,
  ) || undefined;
  const credentialId = asNonEmptyString(
    source.credentialId || resource.credentialId || resource.id,
  ) || undefined;
  const subjectId = asNonEmptyString(
    source.subjectId || resource.subjectId || resolveCredentialSubjectIdFromResource(resource),
  ) || undefined;
  const credentialStatusId = asNonEmptyString(
    source.credentialStatusId || resource.credentialStatusId || credentialStatus.id,
  ) || undefined;

  if (!issuedCredentialRecordId && !credentialId && !subjectId && !credentialStatusId) {
    throw new Error(
      `Credential lookup requires at least one identifier at ${indexLabel}: issuedCredentialRecordId, credentialId, subjectId, or credentialStatusId.`,
    );
  }

  return {
    issuedCredentialRecordId,
    credentialId,
    subjectId,
    credentialStatusId,
  };
}

function parseCredentialRevokeInput(
  rawEntry: unknown,
  fallback: ParsedObject,
  indexLabel: string,
): CredentialRevokeInput {
  const entry = asObject(rawEntry) || {};
  const resource = asObject(entry.resource) || {};
  const lookup = parseCredentialLookupFromObject({ ...fallback, ...entry }, indexLabel);
  const reason = asNonEmptyString(entry.reason || resource.reason || fallback.reason) || undefined;
  const revokedBy = asNonEmptyString(
    entry.revokedBy
    || resource.revokedBy
    || entry.operatorDid
    || entry.performedBy
    || fallback.revokedBy
    || fallback.operatorDid
    || fallback.performedBy,
  ) || undefined;

  return {
    ...lookup,
    reason,
    revokedBy,
  };
}

function parseCredentialLookupBatch(
  parsed: ParsedObject,
  parsedBody: ParsedObject,
): CredentialLookupInput[] {
  const fallback: ParsedObject = { ...parsed, ...parsedBody };
  const rawBatchEntries = Array.isArray(parsedBody.data)
    ? parsedBody.data
    : Array.isArray(parsed.data)
      ? parsed.data
      : [];
  if (rawBatchEntries.length) {
    return rawBatchEntries.map((entry, index) =>
      parseCredentialLookupFromObject({ ...fallback, ...(asObject(entry) || {}) }, `body.data[${index}]`));
  }
  return [parseCredentialLookupFromObject(fallback, 'body')];
}

export async function parseCredentialStatusSubmission(req: IncomingMessage): Promise<CredentialStatusSubmission> {
  const { parsed, parsedBody } = await parseDidcommPlainObject(req, '_status');
  const lookups = parseCredentialLookupBatch(parsed, parsedBody);
  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });
  return {
    thid,
    lookups,
  };
}

export async function parseCredentialRevokeSubmission(req: IncomingMessage): Promise<CredentialRevokeSubmission> {
  const { parsed, parsedBody } = await parseDidcommPlainObject(req, '_revoke');
  const fallback: ParsedObject = { ...parsed, ...parsedBody };
  const rawBatchEntries = Array.isArray(parsedBody.data)
    ? parsedBody.data
    : Array.isArray(parsed.data)
      ? parsed.data
      : [];
  const items = rawBatchEntries.length
    ? rawBatchEntries.map((entry, index) => parseCredentialRevokeInput(entry, fallback, `body.data[${index}]`))
    : [parseCredentialRevokeInput(parsedBody, fallback, 'body')];
  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });
  return {
    thid,
    items,
  };
}

export async function parsePollingThreadId(
  req: IncomingMessage,
  requestUrl: URL,
): Promise<string | undefined> {
  const queryValue = requestUrl.searchParams.get('thid') || requestUrl.searchParams.get('jti');
  if (queryValue?.trim()) return queryValue.trim();

  if (req.method?.toUpperCase() !== 'POST') {
    return undefined;
  }

  const contentTypeHeader = normalizeHeader(req.headers['content-type']);
  const contentType = normalizeContentType(contentTypeHeader);

  if (contentType === 'multipart/form-data') {
    const webReq = buildWebRequest(req);
    const formData = await webReq.formData();
    const thid = String(formData.get('thid') || '').trim();
    const jti = String(formData.get('jti') || '').trim();
    return thid || jti || undefined;
  }

  const raw = await readIncomingBuffer(req);
  if (!raw.length) return undefined;

  if (contentType === 'application/x-www-form-urlencoded') {
    const params = new URLSearchParams(raw.toString('utf8'));
    const thid = params.get('thid') || params.get('jti');
    return thid?.trim() || undefined;
  }

  if (contentType === 'application/json' || !contentType) {
    try {
      const body = JSON.parse(raw.toString('utf8')) as ParsedThreadPayload;
      const thid = String(body.thid || '').trim();
      const jti = String(body.jti || '').trim();
      return thid || jti || undefined;
    } catch {
      return undefined;
    }
  }

  return undefined;
}
