import type { IncomingMessage } from 'node:http';
import { buildVerifyResponseLocation } from '../path.ts';
import { parseVerifySubmission } from '../request-parsing.ts';
import { InMemoryVerificationJobStore } from '../job-store.ts';
import { extractVisibleOrganizationIdentityFromPdfText } from '../tools/terms-annex-form.ts';
import type {
  PdfVerificationService,
  VerificationErrorDetails,
  VerifyRouteContext,
  VerifySubmission,
} from '../types.ts';
import { AuditDocumentStorageService } from '../tools/audit-document-storage.ts';
import { generateOrganizationCredentialKeyPair } from '../tools/bootstrap-organization-key.ts';

export type VerifySubmitOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'accepted'; location: string; retryAfter: number };

function toStatusCodeFromParseError(message: string): number {
  return message.startsWith('Unsupported Content-Type') || message.startsWith('Unsupported Content-Encoding')
    ? 415
    : 400;
}

function extractVerificationErrorDetails(error: unknown): VerificationErrorDetails | undefined {
  if (!error || typeof error !== 'object') return undefined;
  const details = (error as { errorDetails?: VerificationErrorDetails }).errorDetails;
  if (!details || typeof details !== 'object') return undefined;
  return details;
}

function sanitizeVerificationErrorMessage(message: string): string {
  const normalized = String(message || '').replace(/\s+/g, ' ').trim();
  if (!normalized) return 'Verification failed.';

  if (/unable to get local issuer certificate/i.test(normalized)) {
    const signaturePrefix = normalized.match(/^Signature\s+\d+\s+failed:/i)?.[0] || 'Signature verification failed:';
    return `${signaturePrefix} Certificate chain validation failed: unable to get local issuer certificate.`;
  }

  let sanitized = normalized;
  sanitized = sanitized.replace(/Command failed:\s*openssl\s+verify\s+[\s\S]*?(?=error\s+\d+\s+at\s+\d+\s+depth\s+lookup:|verification failed|$)/i, '');
  sanitized = sanitized.replace(/\/(?:private\/)?var\/folders\/[\w./-]+/g, '<temp-path>');
  sanitized = sanitized.replace(/\/tmp\/[\w./-]+/g, '<temp-path>');
  sanitized = sanitized.replace(/\s+/g, ' ').trim();

  return sanitized || 'Verification failed.';
}

function getAnnexFieldCaseInsensitive(
  annexFormFields: Record<string, string> | undefined,
  name: string,
): string | undefined {
  if (!annexFormFields) return undefined;
  const direct = annexFormFields[name];
  const raw = direct !== undefined
    ? direct
    : Object.entries(annexFormFields).find(([key]) => key.toLowerCase() === name.toLowerCase())?.[1];
  const normalized = typeof raw === 'string' ? raw.trim() : '';
  return normalized || undefined;
}

function buildAnnexDebugDetails(
  submission: VerifySubmission,
): VerificationErrorDetails['annex'] {
  const fieldKeys = Object.keys(submission.annexFormFields || {})
    .map((key) => key.trim())
    .filter(Boolean)
    .sort((a, b) => a.localeCompare(b, 'en'));
  const warnings = (submission.annexExtractionWarnings || [])
    .map((warning) => String(warning || '').trim())
    .filter(Boolean);

  const organizationTaxId = getAnnexFieldCaseInsensitive(submission.annexFormFields, 'organization.taxID')
    || getAnnexFieldCaseInsensitive(submission.annexFormFields, 'organization.taxId')
    || getAnnexFieldCaseInsensitive(submission.annexFormFields, 'organization.cif')
    || getAnnexFieldCaseInsensitive(submission.annexFormFields, 'organization.nif');
  const organizationLegalName = getAnnexFieldCaseInsensitive(submission.annexFormFields, 'organization.legalName')
    || getAnnexFieldCaseInsensitive(submission.annexFormFields, 'organization.name')
    || getAnnexFieldCaseInsensitive(submission.annexFormFields, 'Razon Social')
    || getAnnexFieldCaseInsensitive(submission.annexFormFields, 'Razón Social');
  const personName = getAnnexFieldCaseInsensitive(submission.annexFormFields, 'person.name')
    || getAnnexFieldCaseInsensitive(submission.annexFormFields, 'Representante legal');

  return {
    fieldCount: fieldKeys.length,
    fieldKeys,
    warningCount: warnings.length,
    warnings,
    hasOrganizationTaxId: Boolean(organizationTaxId),
    hasOrganizationLegalName: Boolean(organizationLegalName),
    ...(organizationTaxId ? { organizationTaxId } : {}),
    ...(organizationLegalName ? { organizationLegalName } : {}),
    ...(personName ? { personName } : {}),
  };
}

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === '1' || normalized === 'true' || normalized === 'yes') return true;
  if (normalized === '0' || normalized === 'false' || normalized === 'no') return false;
  return fallback;
}

function mergeVisibleIdentityIntoSubmission(
  submission: VerifySubmission,
  visibleIdentity: { taxID?: string; legalName?: string; legalRepresentativeName?: string; warnings: string[] },
): VerifySubmission {
  const annexFormFields = { ...(submission.annexFormFields || {}) };
  if (visibleIdentity.taxID && !annexFormFields['organization.taxID']) {
    annexFormFields['organization.taxID'] = visibleIdentity.taxID;
  }
  if (visibleIdentity.legalName && !annexFormFields['organization.legalName']) {
    annexFormFields['organization.legalName'] = visibleIdentity.legalName;
    if (!annexFormFields['organization.name']) {
      annexFormFields['organization.name'] = visibleIdentity.legalName;
    }
  }
  if (visibleIdentity.legalRepresentativeName) {
    if (!annexFormFields['Representante legal']) {
      annexFormFields['Representante legal'] = visibleIdentity.legalRepresentativeName;
    }
    if (!annexFormFields['person.name']) {
      annexFormFields['person.name'] = visibleIdentity.legalRepresentativeName;
    }
  }

  return {
    ...submission,
    ...(Object.keys(annexFormFields).length ? { annexFormFields } : {}),
    ...(visibleIdentity.warnings.length
      ? { annexExtractionWarnings: [...(submission.annexExtractionWarnings || []), ...visibleIdentity.warnings] }
      : {}),
  };
}

async function enrichSubmissionWithDeferredVisibleIdentity(
  submission: VerifySubmission,
  jurisdiction: string,
): Promise<VerifySubmission> {
  const existingTaxId = getAnnexFieldCaseInsensitive(submission.annexFormFields, 'organization.taxID')
    || getAnnexFieldCaseInsensitive(submission.annexFormFields, 'organization.taxId');
  const existingLegalName = getAnnexFieldCaseInsensitive(submission.annexFormFields, 'organization.legalName')
    || getAnnexFieldCaseInsensitive(submission.annexFormFields, 'organization.name')
    || getAnnexFieldCaseInsensitive(submission.annexFormFields, 'Razon Social')
    || getAnnexFieldCaseInsensitive(submission.annexFormFields, 'Razón Social');
  if (existingTaxId && existingLegalName) return submission;

  const verifierVatList = String(process.env.VERIFIERS_VAT_LIST || '')
    .split(',')
    .map((value) => value.trim())
    .filter(Boolean);
  const visibleIdentity = await extractVisibleOrganizationIdentityFromPdfText(
    submission.pdfBytes,
    verifierVatList,
    jurisdiction,
  );
  return mergeVisibleIdentityIntoSubmission(submission, visibleIdentity);
}

export class VerifyRequestManager {
  private readonly jobStore: InMemoryVerificationJobStore;
  private readonly verifier: PdfVerificationService;
  private readonly auditStorage: AuditDocumentStorageService;

  constructor(
    jobStore: InMemoryVerificationJobStore,
    verifier: PdfVerificationService,
    auditStorage: AuditDocumentStorageService = new AuditDocumentStorageService(),
  ) {
    this.jobStore = jobStore;
    this.verifier = verifier;
    this.auditStorage = auditStorage;
  }

  async submit(route: VerifyRouteContext, req: IncomingMessage): Promise<VerifySubmitOutcome> {
    try {
      const submission = await parseVerifySubmission(req, { jurisdiction: route.jurisdiction });
      this.jobStore.enqueue(submission.thid, route);

      setImmediate(async () => {
        this.jobStore.markRunning(submission.thid);
        try {
          const deferVisibleExtraction = parseBooleanEnv(process.env.ICA_VERIFY_DEFER_VISIBLE_EXTRACTION, false);
          const effectiveSubmission = deferVisibleExtraction
            ? await enrichSubmissionWithDeferredVisibleIdentity(submission, route.jurisdiction)
            : submission;
          const verificationResult = await this.verifier.verify(route, effectiveSubmission);
          const enrichedResult = await this.auditStorage.persistVerifiedPdf(route, effectiveSubmission, verificationResult);
          const generatedOrganizationKeyPair = submission.organizationPublicKeyJwk
            ? undefined
            : generateOrganizationCredentialKeyPair();
          const mergedNotes = [
            ...(Array.isArray(enrichedResult.notes) ? enrichedResult.notes : []),
            ...((effectiveSubmission.annexExtractionWarnings || []).filter(Boolean)),
          ];
          this.jobStore.markSucceeded(submission.thid, {
            ...enrichedResult,
            notes: mergedNotes,
            ...(submission.controllerPublicKeyJwk ? { controllerPublicKeyJwk: submission.controllerPublicKeyJwk } : {}),
            ...(submission.organizationPublicKeyJwk
              ? {
                  organizationPublicKeyJwk: submission.organizationPublicKeyJwk,
                  organizationKeySource: 'attachment' as const,
                }
              : generatedOrganizationKeyPair
                ? {
                    organizationPublicKeyJwk: generatedOrganizationKeyPair.publicKeyJwk,
                    organizationPrivateKeyJwk: generatedOrganizationKeyPair.privateKeyJwk,
                    organizationKeySource: 'generated' as const,
                  }
                : {}),
            ...(effectiveSubmission.annexFormFields && Object.keys(effectiveSubmission.annexFormFields).length
              ? { annexFormFields: effectiveSubmission.annexFormFields }
              : {}),
          });
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          const sanitizedMessage = sanitizeVerificationErrorMessage(message);
          const extractedErrorDetails = extractVerificationErrorDetails(error);
          const annexDebugDetails = buildAnnexDebugDetails(submission);
          const errorDetails = {
            ...(extractedErrorDetails || {}),
            annex: annexDebugDetails,
          };
          console.error(`Verification job failed (thid=${submission.thid}): ${message}`);
          this.jobStore.markFailed(submission.thid, sanitizedMessage, errorDetails);
        }
      });

      return {
        type: 'accepted',
        location: buildVerifyResponseLocation(route, { thid: submission.thid }),
        retryAfter: 5,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid upload payload.';
      return {
        type: 'error',
        statusCode: toStatusCodeFromParseError(message),
        message,
      };
    }
  }
}
