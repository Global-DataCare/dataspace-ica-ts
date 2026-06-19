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
  CreateDidDocumentInput,
  CreateDidDocumentJwkSet,
  CreateDidDocumentSubmission,
  TermsRemoveInput,
  TermsRemoveSubmission,
  ControllerDidcommProof,
  CredentialRevokeSubmission,
  DelegationPolicyInput,
  DelegationPolicySubmission,
  CredentialLookupInput,
  CredentialSearchInput,
  CredentialSearchSubmission,
  SpacesListSubmission,
  SpacesReplaceSubmission,
  SpacesTargetInput,
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
import { extractVerifiedVcJwtAttachmentEvidence } from './tools/vc-jwt-evidence.ts';
import {
  extractTermsAnnexFormFieldsFromPdf,
  extractVisibleOrganizationIdentityFromPdfText,
} from './tools/terms-annex-form.ts';
import { normalizeSameAsHash } from './tools/multihash.ts';
import {
  normalizeControllerPublicKeyJwk,
  normalizeOrganizationPublicKeyJwk,
} from './tools/bootstrap-organization-key.ts';
import { loadIcaSecurityConfigFromEnv } from './security-mode.ts';

type ParsedThreadPayload = {
  thid?: string;
  id?: string;
  jti?: string;
};

type ParsedObject = Record<string, unknown>;

type DidcommAttachmentData = {
  base64?: string;
  json?: unknown;
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

function normalizeVerifierVatToken(value: string): string {
  const upper = String(value || '').trim().toUpperCase().replace(/[\s-]+/g, '');
  if (!upper) return '';
  const withoutVates = upper.startsWith('VATES') ? upper.slice(5) : upper;
  const withoutVat = withoutVates.startsWith('VAT') ? withoutVates.slice(3) : withoutVates;
  return withoutVat.startsWith('ES') ? withoutVat.slice(2) : withoutVat;
}

function normalizeTaxToken(raw: string, jurisdiction: string): string {
  const upper = String(raw || '').trim().toUpperCase().replace(/[\s-]+/g, '');
  if (!upper) return '';
  const withoutVates = upper.startsWith('VATES') ? upper.slice(5) : upper;
  const withoutVat = /^VAT[A-Z]{2}/.test(withoutVates) ? withoutVates.slice(5) : (withoutVates.startsWith('VAT') ? withoutVates.slice(3) : withoutVates);
  const country = jurisdiction.toUpperCase();
  if (withoutVat.startsWith(country)) return withoutVat.slice(country.length);
  if (withoutVat.startsWith('ES')) return withoutVat.slice(2);
  if (withoutVat.startsWith('PT')) return withoutVat.slice(2);
  return withoutVat;
}

function extractTaxTokenFromValue(value: string): string | undefined {
  const normalized = String(value || '').trim().toUpperCase();
  if (!normalized) return undefined;
  const tokenMatch = normalized.match(/\b([A-Z]\d{8}|\d{8}[A-Z])\b/);
  return tokenMatch?.[1];
}

function looksLikeOrganizationName(value: string): boolean {
  const normalized = String(value || '').trim();
  if (normalized.length < 4) return false;
  if (/@/.test(normalized)) return false;
  if (/^\d+$/.test(normalized)) return false;
  if (!/[A-Za-zÁÉÍÓÚÜÑáéíóúüñ]/.test(normalized)) return false;
  if (/^(CEO|CTO|CFO|COO|MADRID|BARCELONA|SEVILLA|VALENCIA)$/i.test(normalized)) return false;
  return true;
}

function normalizeForMatching(value: string): string {
  return String(value || '')
    .normalize('NFD')
    .replace(/[\u0300-\u036f]/g, '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

function resolveOrganizationTaxCountryFromAnnexFields(
  annexFields: Record<string, string>,
  defaultJurisdiction: string,
): string {
  for (const [key, value] of Object.entries(annexFields)) {
    const normalizedKey = normalizeForMatching(key);
    if (!normalizedKey.includes('domicilio fiscal') && !normalizedKey.includes('fiscal address')) continue;
    const normalizedValue = normalizeForMatching(value);
    if (/\bportugal\b/.test(normalizedValue) || /\bportuguesa\b/.test(normalizedValue)) return 'PT';
  }
  return defaultJurisdiction.toUpperCase();
}

function inferOrganizationIdentityFromGenericAnnexFields(
  annexFields: Record<string, string>,
  verifierVatList: string[],
  jurisdiction: string,
): { taxID?: string; legalName?: string } {
  const entries = Object.entries(annexFields);
  if (!entries.length) return {};
  const verifierSet = new Set(
    verifierVatList
      .map((value) => normalizeVerifierVatToken(value))
      .filter(Boolean),
  );
  const effectiveCountry = resolveOrganizationTaxCountryFromAnnexFields(annexFields, jurisdiction);

  for (let index = 0; index < entries.length; index += 1) {
    const [, value] = entries[index];
    const token = extractTaxTokenFromValue(value);
    if (!token) continue;
    const normalizedToken = normalizeTaxToken(token, effectiveCountry);
    if (!normalizedToken || verifierSet.has(normalizedToken)) continue;
    const taxID = `VAT${effectiveCountry}-${normalizedToken}`;
    const previousValue = index > 0 ? entries[index - 1][1] : '';
    const legalName = looksLikeOrganizationName(previousValue)
      ? previousValue.trim()
      : entries.map((entry) => entry[1]).find((candidate) => looksLikeOrganizationName(candidate));
    return {
      taxID,
      ...(legalName ? { legalName } : {}),
    };
  }

  return {};
}

function normalizeContentType(headerValue: string): string {
  return headerValue.split(';')[0].trim().toLowerCase();
}

const DIDCOMM_PLAIN_JSON_MEDIA_TYPE = 'application/didcomm-plain+json';
const DIDCOMM_PLAINTEXT_JSON_LEGACY_MEDIA_TYPE = 'application/didcomm-plaintext+json';

function acceptsLegacyDidcommPlaintextMediaType(): boolean {
  return loadIcaSecurityConfigFromEnv().allowLegacyDidcommPlaintextMediaType;
}

function isAcceptedDidcommPlainContentType(contentType: string): boolean {
  return contentType === DIDCOMM_PLAIN_JSON_MEDIA_TYPE
    || (acceptsLegacyDidcommPlaintextMediaType() && contentType === DIDCOMM_PLAINTEXT_JSON_LEGACY_MEDIA_TYPE);
}

function buildExpectedDidcommPlainContentTypeLabel(): string {
  return acceptsLegacyDidcommPlaintextMediaType()
    ? `${DIDCOMM_PLAIN_JSON_MEDIA_TYPE} (canonical) or ${DIDCOMM_PLAINTEXT_JSON_LEGACY_MEDIA_TYPE} (temporary compatibility mode)`
    : DIDCOMM_PLAIN_JSON_MEDIA_TYPE;
}

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === '1' || normalized === 'true' || normalized === 'yes') return true;
  if (normalized === '0' || normalized === 'false' || normalized === 'no') return false;
  return fallback;
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
  const fromId = String(payload.id || '').trim();
  const fromJti = String(payload.jti || '').trim();
  if (fromThid) {
    return isAutoToken(fromThid, 'thid')
      ? `thid-${buildThreadTimestamp()}`
      : fromThid;
  }
  if (fromId) {
    return fromId;
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
    'Attachment does not contain a valid PDF. Use a direct PDF URL, a tested Dropbox direct-download link (`dl=1`), or send attachments[].data.base64.',
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

function resolveControllerPublicKeyFromMeta(parsed: ParsedObject): Record<string, unknown> | undefined {
  const meta = asObject(parsed.meta);
  const jws = asObject(meta?.jws);
  const protectedHeader = asObject(jws?.protected);
  return normalizeControllerPublicKeyJwk(
    protectedHeader?.jwk,
    asNonEmptyString(protectedHeader?.alg) || undefined,
    asNonEmptyString(protectedHeader?.kid) || undefined,
  );
}

function resolveControllerPublicKeyFromVerifyBody(parsedBody: ParsedObject): Record<string, unknown> | undefined {
  const dataArray = Array.isArray(parsedBody.data) ? parsedBody.data : [];
  const firstResource = dataArray.length > 0
    ? asObject((dataArray[0] as Record<string, unknown>)?.resource)
    : undefined;
  const controller = firstResource ? asObject(firstResource.controller) : undefined;
  return normalizeControllerPublicKeyJwk(
    controller?.publicKeyJwk,
    asNonEmptyString(controller?.alg) || undefined,
  );
}

function resolveOrganizationPublicKeyFromDidcommAttachments(
  attachments: DidcommAttachment[],
): Record<string, unknown> | undefined {
  for (const attachment of attachments) {
    const mediaType = asNonEmptyString(attachment.media_type).toLowerCase();
    const format = asNonEmptyString((attachment as ParsedObject).format).toLowerCase();
    const filename = asNonEmptyString((attachment as ParsedObject).filename).toLowerCase();
    const data = asObject(attachment?.data);
    if (!data) continue;
    const couldBeJwk =
      mediaType === 'application/jwk+json'
      || mediaType === 'application/json'
      || format === 'jwk'
      || filename.endsWith('.jwk.json')
      || filename.endsWith('.jwk')
      || filename.includes('organization-key');
    if (!couldBeJwk) continue;
    const jsonPayload = normalizeOrganizationPublicKeyJwk(data.json);
    if (jsonPayload) return jsonPayload;
    const base64Payload = asNonEmptyString(data.base64);
    if (!base64Payload) continue;
    const raw = decodeBase64Payload(base64Payload).toString('utf8');
    try {
      return normalizeOrganizationPublicKeyJwk(JSON.parse(raw));
    } catch (error: unknown) {
      throw new Error(`Invalid organization JWK attachment JSON: ${(error as Error).message}`);
    }
  }
  return undefined;
}

export async function parseVerifySubmission(
  req: IncomingMessage,
  options?: { jurisdiction?: string },
): Promise<VerifySubmission> {
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

  if (!isAcceptedDidcommPlainContentType(contentType)) {
    if (contentType === 'application/didcomm-encrypted+json') {
      throw new Error(
        'Unsupported Content-Type for _verify: application/didcomm-encrypted+json (decrypt before calling this endpoint).',
      );
    }
    throw new Error(
      `Unsupported Content-Type for _verify: ${contentTypeHeader || '(missing)'} (expected ${buildExpectedDidcommPlainContentTypeLabel()})`,
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
    id: asNonEmptyString(parsed.id || parsedBody.id),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });
  const annex = await extractTermsAnnexFormFieldsFromPdf(pdfBytes);
  const effectiveJurisdiction = asNonEmptyString(options?.jurisdiction).toUpperCase()
    || process.env.ICA_SUPPORTED_JURISDICTIONS?.split(',')[0]?.trim()
    || 'ES';
  const verifierVatList = String(process.env.VERIFIERS_VAT_LIST || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const inferredFromGenericFields = inferOrganizationIdentityFromGenericAnnexFields(
    annex.fields,
    verifierVatList,
    effectiveJurisdiction,
  );
  if (inferredFromGenericFields.taxID && !annex.fields['organization.taxID']) {
    annex.fields['organization.taxID'] = inferredFromGenericFields.taxID;
  }
  if (inferredFromGenericFields.legalName && !annex.fields['organization.legalName']) {
    annex.fields['organization.legalName'] = inferredFromGenericFields.legalName;
    if (!annex.fields['organization.name']) {
      annex.fields['organization.name'] = inferredFromGenericFields.legalName;
    }
  }
  const runInlineVisibleExtraction = parseBooleanEnv(process.env.ICA_VERIFY_INLINE_VISIBLE_EXTRACTION, false);
  if (runInlineVisibleExtraction) {
    const visibleIdentity = await extractVisibleOrganizationIdentityFromPdfText(
      pdfBytes,
      verifierVatList,
      effectiveJurisdiction,
    );
    if (visibleIdentity.taxID && !annex.fields['organization.taxID']) {
      annex.fields['organization.taxID'] = visibleIdentity.taxID;
    }
    if (visibleIdentity.legalName && !annex.fields['organization.legalName']) {
      annex.fields['organization.legalName'] = visibleIdentity.legalName;
      if (!annex.fields['organization.name']) {
        annex.fields['organization.name'] = visibleIdentity.legalName;
      }
    }
    if (visibleIdentity.legalRepresentativeName) {
      if (!annex.fields['Representante legal']) {
        annex.fields['Representante legal'] = visibleIdentity.legalRepresentativeName;
      }
      if (!annex.fields['person.name']) {
        annex.fields['person.name'] = visibleIdentity.legalRepresentativeName;
      }
    }
    if (visibleIdentity.warnings.length) {
      annex.warnings.push(...visibleIdentity.warnings);
    }
  }
  const controllerPublicKeyJwk = resolveControllerPublicKeyFromVerifyBody(parsedBody)
    || resolveControllerPublicKeyFromMeta(parsed);
  const organizationPublicKeyJwk = resolveOrganizationPublicKeyFromDidcommAttachments(attachments);
  
  const dataArray = Array.isArray(parsedBody.data) ? parsedBody.data : [];
  const firstResource = dataArray.length > 0 ? asObject((dataArray[0] as Record<string, unknown>)?.resource) : undefined;
  const organizationPayload = firstResource ? asObject(firstResource.organization) : undefined;
  const legalRepresentativePayload = firstResource ? asObject(firstResource.legalRepresentative) : undefined;

  return {
    thid,
    pdfBytes,
    contentType,
    ...(controllerPublicKeyJwk ? { controllerPublicKeyJwk } : {}),
    ...(organizationPublicKeyJwk ? { organizationPublicKeyJwk } : {}),
    ...(organizationPayload ? { organizationPayload } : {}),
    ...(legalRepresentativePayload ? { legalRepresentativePayload } : {}),
    ...(Object.keys(annex.fields).length ? { annexFormFields: annex.fields } : {}),
    ...(annex.warnings.length ? { annexExtractionWarnings: annex.warnings } : {}),
  };
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

  if (!isAcceptedDidcommPlainContentType(contentType)) {
    if (contentType === 'application/didcomm-encrypted+json') {
      throw new Error(
        'Unsupported Content-Type for _activate: application/didcomm-encrypted+json (decrypt before calling this endpoint).',
      );
    }
    throw new Error(
      `Unsupported Content-Type for _activate: ${contentTypeHeader || '(missing)'} (expected ${buildExpectedDidcommPlainContentTypeLabel()})`,
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
    id: asNonEmptyString(parsed.id || parsedBody.id),
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
  action: '_add' | '_issue' | '_status' | '_revoke' | '_rotate' | '_upsert' | '_search' | '_list' | '_replace' | '_create' | '_remove',
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

  if (!isAcceptedDidcommPlainContentType(contentType)) {
    if (contentType === 'application/didcomm-encrypted+json') {
      throw new Error(
        `Unsupported Content-Type for ${action}: application/didcomm-encrypted+json (decrypt before calling this endpoint).`,
      );
    }
    throw new Error(
      `Unsupported Content-Type for ${action}: ${contentTypeHeader || '(missing)'} (expected ${buildExpectedDidcommPlainContentTypeLabel()})`,
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
    id: asNonEmptyString(parsed.id || parsedBody.id),
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


function parseOptionalDidDocumentJwks(rawValue: unknown, label: string): CreateDidDocumentJwkSet | undefined {
  const jwks = asObject(rawValue);
  if (!jwks) return undefined;
  const keys = Array.isArray(jwks.keys)
    ? jwks.keys
      .map((entry, index) => {
        const key = asObject(entry);
        if (!key) {
          throw new Error(`${label}.keys[${index}] must be an object.`);
        }
        const purposes = Array.isArray(key.purposes)
          ? key.purposes.filter((value): value is string => typeof value === 'string' && value.trim().length > 0)
          : undefined;
        return {
          ...key,
          ...(purposes?.length ? { purposes } : {}),
        };
      })
    : undefined;
  if (!keys || !keys.length) {
    throw new Error(`${label}.keys[] must contain at least one key when jwks is provided.`);
  }
  return { keys };
}

function parseCreateDidDocumentController(
  rawValue: unknown,
  indexLabel: string,
): CreateDidDocumentInput['controller'] {
  const controller = asObject(rawValue) || {};
  const publicKeyJwk = asObject(controller.publicKeyJwk);
  const alg = asNonEmptyString(controller.alg) || asNonEmptyString(publicKeyJwk?.alg) || undefined;
  const sameAs = normalizeSameAsHash(asNonEmptyString(controller.sameAs)) || undefined;
  const jwks = parseOptionalDidDocumentJwks(controller.jwks, `${indexLabel}.controller.jwks`);
  return {
    ...(sameAs ? { sameAs } : {}),
    ...(alg ? { alg: alg as SupportedSigningAlgorithm } : {}),
    ...(publicKeyJwk ? { publicKeyJwk: { ...publicKeyJwk } } : {}),
    ...(jwks ? { jwks } : {}),
  };
}

function parseCreateDidDocumentOrganization(
  rawValue: unknown,
  indexLabel: string,
): CreateDidDocumentInput['organization'] {
  const organization = asObject(rawValue) || {};
  const publicKeyJwk = asObject(organization.publicKeyJwk);
  const identifier =
    asNonEmptyString(organization.identifier)
    || asNonEmptyString(organization.id)
    || undefined;
  const taxID =
    asNonEmptyString(organization.taxID)
    || asNonEmptyString(organization.taxId)
    || undefined;
  const legalName = asNonEmptyString(organization.legalName) || undefined;
  const sameAs = asNonEmptyString(organization.sameAs) || undefined;
  const url = asNonEmptyString(organization.url) || undefined;
  const alternateName = asNonEmptyString(organization.alternateName) || undefined;
  const additionalType = asNonEmptyString(organization.additionalType) || undefined;
  const alg = asNonEmptyString(organization.alg) || asNonEmptyString(publicKeyJwk?.alg) || undefined;
  const jwks = parseOptionalDidDocumentJwks(organization.jwks, `${indexLabel}.organization.jwks`);
  if (!identifier && !url) {
    throw new Error(
      `${indexLabel}.organization.identifier is required unless ${indexLabel}.organization.url is provided.`,
    );
  }
  if (!identifier && !taxID) {
    throw new Error(
      `${indexLabel}.organization.taxID is required when ${indexLabel}.organization.identifier is omitted.`,
    );
  }
  return {
    ...(identifier ? { identifier } : {}),
    ...(taxID ? { taxID } : {}),
    ...(legalName ? { legalName } : {}),
    ...(sameAs ? { sameAs } : {}),
    ...(url ? { url } : {}),
    ...(alternateName ? { alternateName } : {}),
    ...(additionalType ? { additionalType } : {}),
    ...(alg ? { alg: alg as SupportedSigningAlgorithm } : {}),
    ...(publicKeyJwk ? { publicKeyJwk: { ...publicKeyJwk } } : {}),
    ...(jwks ? { jwks } : {}),
  };
}

function parseCreateDidDocumentInput(
  rawEntry: unknown,
  fallback: ParsedObject,
  indexLabel: string,
): CreateDidDocumentInput {
  const entry = asObject(rawEntry) || {};
  const resource = asObject(entry.resource) || entry;
  const controller = parseCreateDidDocumentController(
    resource.controller || fallback.controller,
    indexLabel,
  );
  const organization = parseCreateDidDocumentOrganization(
    resource.organization || fallback.organization,
    indexLabel,
  );
  const id =
    asNonEmptyString(resource.id || entry.id || fallback.id || organization.identifier)
    || undefined;

  return {
    ...(id ? { id } : {}),
    controller,
    organization,
  };
}

export async function parseCreateDidDocumentSubmission(req: IncomingMessage): Promise<CreateDidDocumentSubmission> {
  const { parsed, parsedBody } = await parseDidcommPlainObject(req, '_create');
  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    id: asNonEmptyString(parsed.id || parsedBody.id),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });
  const jti = asNonEmptyString(parsed.jti || parsedBody.jti) || undefined;
  const fallback: ParsedObject = { ...parsed, ...parsedBody };
  const rawBatchEntries = Array.isArray(parsedBody.data)
    ? parsedBody.data
    : Array.isArray(parsed.data)
      ? parsed.data
      : [];
  if (!rawBatchEntries.length) {
    throw new Error('DID document create payload requires body.data[] with at least one item.');
  }
  const items = rawBatchEntries.map((entry, index) =>
    parseCreateDidDocumentInput(entry, fallback, `body.data[${index}]`));

  return {
    thid,
    ...(jti ? { jti } : {}),
    items,
  };
}

function parseTermsRemoveInput(
  rawEntry: unknown,
  fallback: ParsedObject,
  indexLabel: string,
): TermsRemoveInput {
  const entry = asObject(rawEntry) || {};
  const resource = asObject(entry.resource) || {};
  const rawOrganization = asObject(resource.organization) || asObject(entry.organization) || {};
  const rawController = asObject(resource.controller) || asObject(entry.controller) || {};

  const taxID = asNonEmptyString(
    rawOrganization.taxID || rawOrganization.taxId || entry.taxID || entry.taxId || fallback.taxID || fallback.taxId,
  ) || undefined;

  const identifier = asNonEmptyString(
    rawOrganization.identifier || rawOrganization.id || entry.identifier || entry.id || fallback.identifier || fallback.id,
  ) || undefined;
  if (!identifier && !taxID) {
    throw new Error(`${indexLabel}.organization.identifier (did) or ${indexLabel}.organization.taxID is required.`);
  }
  const sameAs = normalizeSameAsHash(asNonEmptyString(
    rawController.sameAs || entry.sameAs || fallback.sameAs,
  )) || undefined;
  const publicKeyJwk = normalizeControllerPublicKeyJwk(
    rawController.publicKeyJwk || entry.publicKeyJwk,
    asNonEmptyString(rawController.alg || entry.alg) || undefined,
  );
  const reason = asNonEmptyString(
    resource.reason || entry.reason || fallback.reason,
  ) || undefined;

  return {
    organization: {
      ...(taxID ? { taxID } : {}),
      ...(identifier ? { identifier } : {}),
    },
    controller: {
      ...(sameAs ? { sameAs } : {}),
      ...(publicKeyJwk ? { publicKeyJwk } : {}),
    },
    ...(reason ? { reason } : {}),
  };
}

export async function parseTermsRemoveSubmission(req: IncomingMessage): Promise<TermsRemoveSubmission> {
  const { parsed, parsedBody } = await parseDidcommPlainObject(req, '_remove');
  const fallback: ParsedObject = { ...parsed, ...parsedBody };
  const rawBatchEntries = Array.isArray(parsedBody.data)
    ? parsedBody.data
    : Array.isArray(parsed.data)
      ? parsed.data
      : [];
  const items = rawBatchEntries.length
    ? rawBatchEntries.map((entry, index) => parseTermsRemoveInput(entry, fallback, `body.data[${index}]`))
    : [parseTermsRemoveInput(parsedBody, fallback, 'body')];
  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    id: asNonEmptyString(parsed.id || parsedBody.id),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });
  const controllerPublicKeyJwk = resolveControllerPublicKeyFromMeta(parsed);
  return {
    thid,
    items: items.map((item) => ({
      ...item,
      controller: {
        ...item.controller,
        ...(item.controller.publicKeyJwk ? {} : controllerPublicKeyJwk ? { publicKeyJwk: controllerPublicKeyJwk } : {}),
      },
    })),
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
    source: 'body',
  };
}

export async function parseAddEvidenceSubmission(req: IncomingMessage): Promise<AddEvidenceSubmission> {
  const { parsed, parsedBody } = await parseDidcommPlainObject(req, '_add');

  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    id: asNonEmptyString(parsed.id || parsedBody.id),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });

  const fallback: ParsedObject = { ...parsed, ...parsedBody };
  const rawBatchEntries = Array.isArray(parsedBody.data)
    ? parsedBody.data
    : Array.isArray(parsed.data)
      ? parsed.data
      : [];
  const rawEvidence = asObject(parsedBody.evidence) || asObject(parsed.evidence);
  const evidencesFromBody = rawBatchEntries.length
    ? rawBatchEntries.map((entry, index) => parseAddEvidenceInput(entry, fallback, `body.data[${index}]`))
    : rawEvidence
      ? (() => {
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
          source: 'body' as const,
        }];
      })()
      : [];

  const fallbackIssuedCredentialRecordId =
    asNonEmptyString(parsedBody.issuedCredentialRecordId || parsed.issuedCredentialRecordId) || undefined;
  const fallbackOperatorDid =
    asNonEmptyString(
      parsedBody.operatorDid || parsed.operatorDid || parsedBody.performedBy || parsed.performedBy,
    )
    || undefined;
  const rawAttachments = Array.isArray(parsed.attachments) ? parsed.attachments : [];
  const evidencesFromAttachments = await extractVerifiedVcJwtAttachmentEvidence(rawAttachments, {
    issuedCredentialRecordId: fallbackIssuedCredentialRecordId,
    operatorDid: fallbackOperatorDid,
  });

  const evidences = [...evidencesFromBody, ...evidencesFromAttachments];
  if (!evidences.length) {
    throw new Error(
      'Evidence payload requires body.evidence, body.data[].resource/body.data[].evidence, or DIDComm attachments with application/vc+jwt.',
    );
  }

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
    id: asNonEmptyString(parsed.id || parsedBody.id),
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
    id: asNonEmptyString(parsed.id || parsedBody.id),
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
    id: asNonEmptyString(parsed.id || parsedBody.id),
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
    id: asNonEmptyString(parsed.id || parsedBody.id),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });
  return {
    thid,
    items,
  };
}

function parseCredentialSearchInput(
  rawEntry: unknown,
  fallback: ParsedObject,
  indexLabel: string,
): CredentialSearchInput {
  const entry = asObject(rawEntry) || {};
  const resource = asObject(entry.resource) || {};
  const id = asNonEmptyString(entry.id || resource.id || fallback.id) || undefined;
  const text = asNonEmptyString(entry.text || resource.text || fallback.text) || undefined;
  const email = asNonEmptyString(entry.email || resource.email || fallback.email) || undefined;
  const taxId = asNonEmptyString(entry.taxId || entry.taxID || resource.taxId || resource.taxID || fallback.taxId) || undefined;
  const identifierAsTaxId = asNonEmptyString(entry.identifier || resource.identifier || fallback.identifier) || undefined;
  const taxIdHash = asNonEmptyString(entry.taxIdHash || resource.taxIdHash || fallback.taxIdHash) || undefined;
  const legalName = asNonEmptyString(entry.legalName || resource.legalName || fallback.legalName) || undefined;
  const subjectId = asNonEmptyString(entry.subjectId || resource.subjectId || fallback.subjectId) || undefined;
  const issuerId = asNonEmptyString(entry.issuerId || resource.issuerId || fallback.issuerId) || undefined;
  const credentialId = asNonEmptyString(entry.credentialId || resource.credentialId || fallback.credentialId) || undefined;

  const resolvedTaxId = taxId || identifierAsTaxId;
  if (!id && !text && !email && !resolvedTaxId && !taxIdHash && !legalName && !subjectId && !issuerId && !credentialId) {
    throw new Error(
      `Credential search requires at least one filter at ${indexLabel}: id, text, email, taxId, taxIdHash, legalName, subjectId, issuerId, or credentialId.`,
    );
  }

  return {
    id,
    text,
    email,
    taxId: resolvedTaxId,
    taxIdHash,
    legalName,
    subjectId,
    issuerId,
    credentialId,
  };
}

function resolveSearchIdMappingHint(credentialType: string): 'taxId' | 'credentialId' | 'subjectId' | 'generic' {
  const normalized = credentialType.trim().toLowerCase();
  if (normalized.includes('taxid')) return 'taxId';
  if (normalized.includes('license')) return 'credentialId';
  if (normalized.includes('representative') || normalized.includes('delegation')) return 'subjectId';
  return 'generic';
}

function parseSearchInputFromParams(
  params: URLSearchParams,
  credentialType: string,
): CredentialSearchInput {
  const hint = resolveSearchIdMappingHint(credentialType);
  const id = (params.get('id') || '').trim();
  const text = (params.get('text') || '').trim();
  const email = (params.get('email') || '').trim();
  const taxId = (params.get('taxId') || params.get('taxID') || '').trim();
  const identifier = (params.get('identifier') || '').trim();
  const taxIdHash = (params.get('taxIdHash') || '').trim();
  const legalName = (params.get('legalName') || params.get('name') || '').trim();
  const subjectId = (params.get('subjectId') || '').trim();
  const issuerId = (params.get('issuerId') || '').trim();
  const credentialId = (params.get('credentialId') || '').trim();

  const mappedTaxId = taxId || identifier || (hint === 'taxId' ? id : '');
  const mappedCredentialId = credentialId || (hint === 'credentialId' ? id : '');
  const mappedSubjectId = subjectId || (hint === 'subjectId' ? id : '');
  const mappedId = hint === 'generic' ? id : '';

  if (!mappedId && !text && !email && !mappedTaxId && !taxIdHash && !legalName && !mappedSubjectId && !issuerId && !mappedCredentialId) {
    throw new Error(
      'Credential search requires at least one filter: id, text, email, taxId, taxIdHash, legalName, subjectId, issuerId, or credentialId.',
    );
  }

  return {
    ...(mappedId ? { id: mappedId } : {}),
    ...(text ? { text } : {}),
    ...(email ? { email } : {}),
    ...(mappedTaxId ? { taxId: mappedTaxId } : {}),
    ...(taxIdHash ? { taxIdHash } : {}),
    ...(legalName ? { legalName } : {}),
    ...(mappedSubjectId ? { subjectId: mappedSubjectId } : {}),
    ...(issuerId ? { issuerId } : {}),
    ...(mappedCredentialId ? { credentialId: mappedCredentialId } : {}),
  };
}

function parseRequestUrlSearchParams(req: IncomingMessage): URLSearchParams {
  const host = normalizeHeader(req.headers.host) || 'localhost';
  const requestUrl = new URL(req.url || '/', `http://${host}`);
  return requestUrl.searchParams;
}

export async function parseCredentialSearchSubmission(
  req: IncomingMessage,
  credentialType: string,
): Promise<CredentialSearchSubmission> {
  const security = loadIcaSecurityConfigFromEnv();
  const allowLegacySearchTransports = security.securityMode !== 'strict' && security.jsonLegacy;
  const expectedTransport = allowLegacySearchTransports
    ? `application/x-www-form-urlencoded, application/json or ${buildExpectedDidcommPlainContentTypeLabel()}`
    : buildExpectedDidcommPlainContentTypeLabel();
  const contentTypeHeader = normalizeHeader(req.headers['content-type']);
  const contentType = normalizeContentType(contentTypeHeader);
  const contentEncodingHeader = normalizeHeader(req.headers['content-encoding']).trim().toLowerCase();
  if (contentEncodingHeader && contentEncodingHeader !== 'identity') {
    throw new Error(
      `Unsupported Content-Encoding for _search: ${contentEncodingHeader} (expected identity)`,
    );
  }

  if (isAcceptedDidcommPlainContentType(contentType)) {
    const { parsed, parsedBody } = await parseDidcommPlainObject(req, '_search');
    const fallback: ParsedObject = { ...parsed, ...parsedBody };
    const rawBatchEntries = Array.isArray(parsedBody.data)
      ? parsedBody.data
      : Array.isArray(parsed.data)
        ? parsed.data
        : [];
    const queries = rawBatchEntries.length
      ? rawBatchEntries.map((entry, index) => parseCredentialSearchInput(entry, fallback, `body.data[${index}]`))
      : [parseCredentialSearchInput(parsedBody, fallback, 'body')];
    const thid = extractThid({
      thid: asNonEmptyString(parsed.thid || parsedBody.thid),
      id: asNonEmptyString(parsed.id || parsedBody.id),
      jti: asNonEmptyString(parsed.jti || parsedBody.jti),
    });
    return {
      thid,
      queries,
    };
  }

  if (!allowLegacySearchTransports) {
    throw new Error(
      `Unsupported Content-Type for _search: ${contentTypeHeader || '(missing)'} (expected ${expectedTransport})`,
    );
  }

  if (contentType && contentType !== 'application/x-www-form-urlencoded' && contentType !== 'application/json') {
    throw new Error(
      `Unsupported Content-Type for _search: ${contentTypeHeader || '(missing)'} (expected ${expectedTransport})`,
    );
  }

  const urlParams = parseRequestUrlSearchParams(req);
  const bodyBuffer = await readIncomingBuffer(req);
  if (contentType === 'application/x-www-form-urlencoded') {
    const bodyParams = new URLSearchParams(bodyBuffer.toString('utf8'));
    const merged = new URLSearchParams(urlParams);
    bodyParams.forEach((value, key) => merged.set(key, value));
    const query = parseSearchInputFromParams(merged, credentialType);
    const thid = extractThid({
      thid: merged.get('thid') || undefined,
      id: merged.get('id') || undefined,
      jti: merged.get('jti') || undefined,
    });
    return {
      thid,
      queries: [query],
    };
  }

  if (contentType === 'application/json') {
    let bodyJson: ParsedObject = {};
    if (bodyBuffer.length) {
      try {
        const parsed = JSON.parse(bodyBuffer.toString('utf8')) as unknown;
        bodyJson = asObject(parsed) || {};
      } catch (error: unknown) {
        throw new Error(`Invalid JSON body: ${(error as Error).message}`);
      }
    }
    const merged = new URLSearchParams(urlParams);
    Object.entries(bodyJson).forEach(([key, value]) => {
      if (typeof value === 'string') merged.set(key, value);
    });
    const query = parseSearchInputFromParams(merged, credentialType);
    const thid = extractThid({
      thid: asNonEmptyString(bodyJson.thid || merged.get('thid') || ''),
      id: asNonEmptyString(bodyJson.id || merged.get('id') || ''),
      jti: asNonEmptyString(bodyJson.jti || merged.get('jti') || ''),
    });
    return {
      thid,
      queries: [query],
    };
  }

  const query = parseSearchInputFromParams(urlParams, credentialType);
  const thid = extractThid({
    thid: urlParams.get('thid') || undefined,
    id: urlParams.get('id') || undefined,
    jti: urlParams.get('jti') || undefined,
  });
  return {
    thid,
    queries: [query],
  };
}

export async function parseSpacesListSubmission(
  req: IncomingMessage,
): Promise<SpacesListSubmission> {
  const { parsed, parsedBody } = await parseDidcommPlainObject(req, '_list');
  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    id: asNonEmptyString(parsed.id || parsedBody.id),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });
  return { thid };
}

const SPACES_TARGET_ALLOWED_TYPES = new Set(['runtimeplatform', 'softwareapplication']);

function normalizeTypeToken(raw: string): string {
  const value = raw.trim().toLowerCase();
  if (!value) return '';
  if (!value.includes(':')) return value;
  const parts = value.split(':').filter(Boolean);
  return parts.length ? parts[parts.length - 1]! : value;
}

function validateSpacesTargetType(resource: ParsedObject, indexLabel: string): void {
  const jsonLdType = asNonEmptyString(resource['@type']);
  const resourceType = asNonEmptyString(resource.resourceType);
  const legacyType = asNonEmptyString(resource.type);

  if (legacyType && !jsonLdType && !resourceType) {
    throw new Error(
      `Spaces target ${indexLabel} uses unsupported field "type"; use "@type" or "resourceType". `
      + `This rule applies only to spaces target entries (body.data[]), not to body.type in DIDComm/FHIR Bundle envelopes.`,
    );
  }

  if (jsonLdType && resourceType) {
    const left = normalizeTypeToken(jsonLdType);
    const right = normalizeTypeToken(resourceType);
    if (left && right && left !== right) {
      throw new Error(`Spaces target ${indexLabel} has mismatched "@type" and "resourceType".`);
    }
  }

  const declaredType = jsonLdType || resourceType;
  if (!declaredType) return;

  if (!SPACES_TARGET_ALLOWED_TYPES.has(normalizeTypeToken(declaredType))) {
    throw new Error(`Spaces target ${indexLabel} must use RuntimePlatform or SoftwareApplication in "@type"/"resourceType".`);
  }
}

function parseSpacesTarget(
  rawEntry: unknown,
  indexLabel: string,
): SpacesTargetInput {
  const entry = asObject(rawEntry) || {};
  const resource = asObject(entry.resource) || entry;
  validateSpacesTargetType(resource, indexLabel);
  const did = asNonEmptyString(resource.did || resource.id || resource.identifier);
  if (!did) {
    throw new Error(`Spaces target requires ${indexLabel}.did.`);
  }
  const name = asNonEmptyString(resource.name) || undefined;
  const endpointUrl = asNonEmptyString(resource.endpointUrl || resource.endpoint || resource.url) || undefined;
  const apiKey = asNonEmptyString(resource.apiKey || resource.license) || undefined;
  return {
    ...(name ? { name } : {}),
    did,
    ...(endpointUrl ? { endpointUrl } : {}),
    ...(apiKey ? { apiKey } : {}),
  };
}

export async function parseSpacesReplaceSubmission(
  req: IncomingMessage,
): Promise<SpacesReplaceSubmission> {
  const { parsed, parsedBody } = await parseDidcommPlainObject(req, '_replace');
  const rawBatchEntries = Array.isArray(parsedBody.data)
    ? parsedBody.data
    : Array.isArray(parsed.data)
      ? parsed.data
      : [];
  if (!rawBatchEntries.length) {
    throw new Error('Spaces replace payload requires body.data[] with at least one target.');
  }
  const targets = rawBatchEntries.map((entry, index) =>
    parseSpacesTarget(entry, `body.data[${index}]`));
  const thid = extractThid({
    thid: asNonEmptyString(parsed.thid || parsedBody.thid),
    id: asNonEmptyString(parsed.id || parsedBody.id),
    jti: asNonEmptyString(parsed.jti || parsedBody.jti),
  });
  return {
    thid,
    targets,
  };
}

export async function parsePollingThreadId(
  req: IncomingMessage,
  requestUrl: URL,
): Promise<string | undefined> {
  const queryValue = extractPollingThreadId({
    thid: requestUrl.searchParams.get('thid') || undefined,
    id: requestUrl.searchParams.get('id') || undefined,
    jti: requestUrl.searchParams.get('jti') || undefined,
  });
  if (queryValue) return queryValue;

  if (req.method?.toUpperCase() !== 'POST') {
    return undefined;
  }

  const contentTypeHeader = normalizeHeader(req.headers['content-type']);
  const contentType = normalizeContentType(contentTypeHeader);

  if (contentType === 'multipart/form-data') {
    const webReq = buildWebRequest(req);
    const formData = await webReq.formData();
    return extractPollingThreadId({
      thid: String(formData.get('thid') || '').trim() || undefined,
      id: String(formData.get('id') || '').trim() || undefined,
      jti: String(formData.get('jti') || '').trim() || undefined,
    });
  }

  const raw = await readIncomingBuffer(req);
  if (!raw.length) return undefined;

  if (contentType === 'application/x-www-form-urlencoded') {
    const params = new URLSearchParams(raw.toString('utf8'));
    return extractPollingThreadId({
      thid: params.get('thid') || undefined,
      id: params.get('id') || undefined,
      jti: params.get('jti') || undefined,
    });
  }

  if (contentType === 'application/json' || isAcceptedDidcommPlainContentType(contentType) || !contentType) {
    try {
      const body = JSON.parse(raw.toString('utf8')) as ParsedThreadPayload;
      return extractPollingThreadId(body);
    } catch {
      return undefined;
    }
  }

  return undefined;
}

function extractPollingThreadId(payload: ParsedThreadPayload): string | undefined {
  const fromThid = String(payload.thid || '').trim();
  if (fromThid) return fromThid;

  const fromId = String(payload.id || '').trim();
  if (fromId) return fromId;

  const fromJti = String(payload.jti || '').trim();
  if (fromJti) return fromJti;

  return undefined;
}
