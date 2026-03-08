import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parseIssueCredentialSubmission } from '../request-parsing.ts';
import { buildIssueCredentialResponseLocation } from '../path.ts';
import type { IssueCredentialResult, IssueCredentialRouteContext } from '../types.ts';
import type {
  EvidenceRecord,
  IssuedCredentialRecord,
  JsonObject,
} from '../tools/verification-collections-storage.ts';
import { VerificationCollectionsService } from '../tools/verification-collections-storage.ts';

export type IssueCredentialSubmitOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'accepted'; location: string; retryAfter: number };

function toStatusCodeFromParseError(message: string): number {
  return message.startsWith('Unsupported Content-Type') || message.startsWith('Unsupported Content-Encoding')
    ? 415
    : 400;
}

function asJsonObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function resolveCredentialSubjectId(credential: JsonObject): string {
  const subjectRaw = credential.credentialSubject;
  if (Array.isArray(subjectRaw)) {
    for (const candidate of subjectRaw) {
      const subject = asJsonObject(candidate);
      const subjectId = asNonEmptyString(subject?.id);
      if (subjectId) return subjectId;
    }
    return '';
  }
  const subject = asJsonObject(subjectRaw);
  return asNonEmptyString(subject?.id);
}

function resolveIssuerId(credential: JsonObject): string {
  const issuer = credential.issuer;
  if (typeof issuer === 'string') return issuer.trim();
  const issuerObject = asJsonObject(issuer);
  return asNonEmptyString(issuerObject?.id);
}

function collectEvidenceEntries(
  credential: JsonObject,
  requestEvidence: Record<string, unknown>[],
): JsonObject[] {
  const fromCredential = Array.isArray(credential.evidence)
    ? credential.evidence.map((entry) => asJsonObject(entry)).filter(Boolean) as JsonObject[]
    : [];
  const fromRequest = requestEvidence
    .map((entry) => asJsonObject(entry))
    .filter(Boolean) as JsonObject[];
  return [...fromCredential, ...fromRequest];
}

export class IssueCredentialRequestManager {
  private readonly jobStore: InMemoryEntityJobStore<IssueCredentialRouteContext, IssueCredentialResult>;
  private readonly collectionsService: VerificationCollectionsService;

  constructor(
    jobStore: InMemoryEntityJobStore<IssueCredentialRouteContext, IssueCredentialResult>,
    collectionsService: VerificationCollectionsService = new VerificationCollectionsService(),
  ) {
    this.jobStore = jobStore;
    this.collectionsService = collectionsService;
  }

  async submit(route: IssueCredentialRouteContext, req: IncomingMessage): Promise<IssueCredentialSubmitOutcome> {
    try {
      const submission = await parseIssueCredentialSubmission(req);
      this.jobStore.enqueue(submission.thid, route);

      setImmediate(async () => {
        this.jobStore.markRunning(submission.thid);
        try {
          const nowIso = new Date().toISOString();
          const issuedRecords: IssuedCredentialRecord[] = [];
          const evidenceRecords: EvidenceRecord[] = [];
          const resultItems = submission.items.map((item) => {
            const issuedCredentialRecordId = `urn:uuid:${randomUUID()}`;
            const credential = { ...item.credential } as JsonObject;
            const credentialId = asNonEmptyString(credential.id) || `urn:uuid:${randomUUID()}`;
            issuedRecords.push({
              id: issuedCredentialRecordId,
              tenantId: route.tenantId,
              jurisdiction: route.jurisdiction.toUpperCase(),
              sector: route.sector,
              resourceType: route.credentialType,
              thid: submission.thid,
              credentialType: route.credentialType,
              credentialId,
              subjectId: resolveCredentialSubjectId(credential),
              issuerId: resolveIssuerId(credential),
              credential,
              createdAt: nowIso,
              updatedAt: nowIso,
            });

            const evidenceEntryItems = collectEvidenceEntries(credential, item.evidence);
            const entryEvidenceRecords: EvidenceRecord[] = evidenceEntryItems.map((evidenceEntry) => ({
              id: `urn:uuid:${randomUUID()}`,
              issuedCredentialRecordId,
              tenantId: route.tenantId,
              jurisdiction: route.jurisdiction.toUpperCase(),
              sector: route.sector,
              resourceType: route.credentialType,
              thid: submission.thid,
              evidenceType: asNonEmptyString(evidenceEntry.type) || 'unknown',
              evidence: evidenceEntry,
              createdAt: nowIso,
              updatedAt: nowIso,
            }));
            evidenceRecords.push(...entryEvidenceRecords);

            return {
              issuedCredentialRecordId,
              credentialId,
              credentialType: route.credentialType,
              evidenceRecordIds: entryEvidenceRecords.map((record) => record.id),
              storedAt: nowIso,
            };
          });

          await this.collectionsService.storeIssuedCredentials(issuedRecords);
          await this.collectionsService.storeEvidenceRecords(evidenceRecords);
          this.jobStore.markSucceeded(submission.thid, {
            storedCount: resultItems.length,
            items: resultItems,
          });
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          console.error(`Credential _issue job failed (thid=${submission.thid}): ${message}`);
          this.jobStore.markFailed(submission.thid, message);
        }
      });

      return {
        type: 'accepted',
        location: buildIssueCredentialResponseLocation(route),
        retryAfter: 3,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid credential payload.';
      return {
        type: 'error',
        statusCode: toStatusCodeFromParseError(message),
        message,
      };
    }
  }
}
