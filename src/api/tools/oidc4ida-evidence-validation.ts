import type { EvidenceObjectDLT } from 'gdc-common-utils-ts/models/oidc4ida.evidence.model';

type JsonObject = Record<string, unknown>;

export const SUPPORTED_OIDC4IDA_EVIDENCE_TYPES = [
  'document',
  'electronic_record',
  'electronic_signature',
] as const;

type SupportedOidc4idaEvidenceType = (typeof SUPPORTED_OIDC4IDA_EVIDENCE_TYPES)[number];

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function isIsoDateTime(value: string): boolean {
  if (!value) return false;
  return Number.isFinite(Date.parse(value));
}

function pushError(errors: string[], message: string): void {
  errors.push(message);
}

function validateIsoDateField(value: unknown, fieldPath: string, errors: string[]): void {
  const raw = asNonEmptyString(value);
  if (!raw) return;
  if (!isIsoDateTime(raw)) {
    pushError(errors, `${fieldPath} must be an ISO-8601 date/time string.`);
  }
}

function validateCheckDetails(value: unknown, fieldPath: string, errors: string[]): void {
  if (value === undefined) return;
  if (!Array.isArray(value)) {
    pushError(errors, `${fieldPath} must be an array.`);
    return;
  }
  value.forEach((entry, index) => {
    const itemPath = `${fieldPath}[${index}]`;
    const item = asObject(entry);
    if (!item) {
      pushError(errors, `${itemPath} must be an object.`);
      return;
    }
    if (!asNonEmptyString(item.check_method)) {
      pushError(errors, `${itemPath}.check_method is required.`);
    }
    validateIsoDateField(item.time, `${itemPath}.time`, errors);
  });
}

function validateAttachmentDigestObject(
  attachment: JsonObject,
  fieldPath: string,
  errors: string[],
): void {
  const digest = asObject(attachment.digest);
  if (!digest) {
    pushError(errors, `${fieldPath}.digest is required.`);
    return;
  }
  if (!asNonEmptyString(digest.alg)) {
    pushError(errors, `${fieldPath}.digest.alg is required.`);
  }
  if (!asNonEmptyString(digest.value)) {
    pushError(errors, `${fieldPath}.digest.value is required.`);
  }
}

function validateDocumentEvidence(evidence: JsonObject, path: string, errors: string[]): void {
  if (!asNonEmptyString(evidence.method)) {
    pushError(errors, `${path}.method is required for type=document.`);
  }

  const verifier = asObject(evidence.verifier);
  if (!verifier || !asNonEmptyString(verifier.organization)) {
    pushError(errors, `${path}.verifier.organization is required for type=document.`);
  }

  validateIsoDateField(evidence.time, `${path}.time`, errors);
  validateCheckDetails(evidence.check_details, `${path}.check_details`, errors);

  if (evidence.attachments !== undefined) {
    const attachments = asObject(evidence.attachments);
    if (!attachments) {
      pushError(errors, `${path}.attachments must be an object for type=document.`);
    } else {
      validateAttachmentDigestObject(attachments, `${path}.attachments`, errors);
      const url = attachments.url;
      if (url !== undefined && !asNonEmptyString(url)) {
        pushError(errors, `${path}.attachments.url must be a non-empty string when provided.`);
      }
    }
  }
}

function validateElectronicRecordEvidence(evidence: JsonObject, path: string, errors: string[]): void {
  validateIsoDateField(evidence.time, `${path}.time`, errors);
  validateCheckDetails(evidence.check_details, `${path}.check_details`, errors);

  const verifier = asObject(evidence.verifier);
  if (verifier && !asNonEmptyString(verifier.organization)) {
    pushError(errors, `${path}.verifier.organization must be a non-empty string when verifier is provided.`);
  }

  const hasRecord = asObject(evidence.record) !== undefined;
  const attachmentsRaw = evidence.attachments;
  const hasAttachments = Array.isArray(attachmentsRaw) && attachmentsRaw.length > 0;
  if (!hasRecord && !hasAttachments) {
    pushError(errors, `${path} must include record or attachments for type=electronic_record.`);
  }

  if (attachmentsRaw !== undefined) {
    if (!Array.isArray(attachmentsRaw)) {
      pushError(errors, `${path}.attachments must be an array for type=electronic_record.`);
    } else {
      attachmentsRaw.forEach((attachment, index) => {
        const itemPath = `${path}.attachments[${index}]`;
        const item = asObject(attachment);
        if (!item) {
          pushError(errors, `${itemPath} must be an object.`);
          return;
        }
        validateAttachmentDigestObject(item, itemPath, errors);
      });
    }
  }
}

function validateElectronicSignatureEvidence(evidence: JsonObject, path: string, errors: string[]): void {
  if (!asNonEmptyString(evidence.signature_type)) {
    pushError(errors, `${path}.signature_type is required for type=electronic_signature.`);
  }
  if (!asNonEmptyString(evidence.issuer)) {
    pushError(errors, `${path}.issuer is required for type=electronic_signature.`);
  }
  if (!asNonEmptyString(evidence.serial_number)) {
    pushError(errors, `${path}.serial_number is required for type=electronic_signature.`);
  }
  const createdAt = asNonEmptyString(evidence.created_at);
  if (!createdAt) {
    pushError(errors, `${path}.created_at is required for type=electronic_signature.`);
  } else if (!isIsoDateTime(createdAt)) {
    pushError(errors, `${path}.created_at must be an ISO-8601 date/time string.`);
  }

  const attachmentsRaw = evidence.attachments;
  if (attachmentsRaw !== undefined) {
    if (!Array.isArray(attachmentsRaw)) {
      pushError(errors, `${path}.attachments must be an array for type=electronic_signature.`);
    } else {
      attachmentsRaw.forEach((attachment, index) => {
        const itemPath = `${path}.attachments[${index}]`;
        const item = asObject(attachment);
        if (!item) {
          pushError(errors, `${itemPath} must be an object.`);
          return;
        }
        if (!asNonEmptyString(item.content_type)) {
          pushError(errors, `${itemPath}.content_type is required.`);
        }
        if (!asNonEmptyString(item.content)) {
          pushError(errors, `${itemPath}.content is required.`);
        }
      });
    }
  }
}

function resolveEvidenceType(rawType: unknown): SupportedOidc4idaEvidenceType | undefined {
  const normalized = asNonEmptyString(rawType).toLowerCase();
  if (normalized === 'document') return 'document';
  if (normalized === 'electronic_record') return 'electronic_record';
  if (normalized === 'electronic_signature') return 'electronic_signature';
  return undefined;
}

export function validateOidc4idaEvidenceObject(evidence: JsonObject, path = 'body.evidence'): string[] {
  const errors: string[] = [];
  const typedEvidence = evidence as Partial<EvidenceObjectDLT> & JsonObject;
  const evidenceType = resolveEvidenceType(typedEvidence.type);
  if (!evidenceType) {
    pushError(
      errors,
      `${path}.type must be one of: ${SUPPORTED_OIDC4IDA_EVIDENCE_TYPES.join(', ')}.`,
    );
    return errors;
  }

  if (evidenceType === 'document') {
    validateDocumentEvidence(typedEvidence, path, errors);
    return errors;
  }
  if (evidenceType === 'electronic_record') {
    validateElectronicRecordEvidence(typedEvidence, path, errors);
    return errors;
  }
  validateElectronicSignatureEvidence(typedEvidence, path, errors);
  return errors;
}

export function assertValidOidc4idaEvidenceObject(evidence: JsonObject, path = 'body.evidence'): void {
  const errors = validateOidc4idaEvidenceObject(evidence, path);
  if (!errors.length) return;
  throw new Error(`Invalid OIDC4IDA evidence payload: ${errors.join(' ')}`);
}

export function validateOidc4idaVerifiedClaimsResource(
  resource: JsonObject,
  path = 'body.data[].resource',
): string[] {
  const errors: string[] = [];
  const verifiedClaims = asObject(resource.verified_claims);
  if (!verifiedClaims) {
    pushError(errors, `${path}.verified_claims is required.`);
    return errors;
  }

  const verification = asObject(verifiedClaims.verification);
  if (!verification) {
    pushError(errors, `${path}.verified_claims.verification is required.`);
    return errors;
  }

  const trustFramework = verification.trust_framework;
  if (
    trustFramework !== undefined
    && trustFramework !== null
    && !asNonEmptyString(trustFramework)
  ) {
    pushError(errors, `${path}.verified_claims.verification.trust_framework must be string|null.`);
  }
  validateIsoDateField(verification.time, `${path}.verified_claims.verification.time`, errors);

  const evidenceEntries = verification.evidence;
  if (!Array.isArray(evidenceEntries) || !evidenceEntries.length) {
    pushError(errors, `${path}.verified_claims.verification.evidence must be a non-empty array.`);
    return errors;
  }

  evidenceEntries.forEach((entry, index) => {
    const evidence = asObject(entry);
    const evidencePath = `${path}.verified_claims.verification.evidence[${index}]`;
    if (!evidence) {
      pushError(errors, `${evidencePath} must be an object.`);
      return;
    }
    errors.push(...validateOidc4idaEvidenceObject(evidence, evidencePath));
  });

  const claims = verifiedClaims.claims;
  if (claims !== undefined && !asObject(claims)) {
    pushError(errors, `${path}.verified_claims.claims must be an object when provided.`);
  }

  return errors;
}

export function assertValidOidc4idaVerifiedClaimsResource(
  resource: JsonObject,
  path = 'body.data[].resource',
): void {
  const errors = validateOidc4idaVerifiedClaimsResource(resource, path);
  if (!errors.length) return;
  throw new Error(`Invalid OIDC4IDA verified_claims payload: ${errors.join(' ')}`);
}
