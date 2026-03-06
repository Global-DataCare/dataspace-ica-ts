import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parseAddEvidenceSubmission } from '../request-parsing.ts';
import { buildAddEvidenceResponseLocation } from '../path.ts';
import type { AddEvidenceResult, AddEvidenceRouteContext } from '../types.ts';
import type { EvidenceRecord } from '../tools/verification-collections-storage.ts';
import { VerificationCollectionsService } from '../tools/verification-collections-storage.ts';

export type AddEvidenceSubmitOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'accepted'; location: string; retryAfter: number };

function toStatusCodeFromParseError(message: string): number {
  return message.startsWith('Unsupported Content-Type') || message.startsWith('Unsupported Content-Encoding')
    ? 415
    : 400;
}

export class AddEvidenceRequestManager {
  private readonly jobStore: InMemoryEntityJobStore<AddEvidenceRouteContext, AddEvidenceResult>;
  private readonly collectionsService: VerificationCollectionsService;

  constructor(
    jobStore: InMemoryEntityJobStore<AddEvidenceRouteContext, AddEvidenceResult>,
    collectionsService: VerificationCollectionsService = new VerificationCollectionsService(),
  ) {
    this.jobStore = jobStore;
    this.collectionsService = collectionsService;
  }

  async submit(route: AddEvidenceRouteContext, req: IncomingMessage): Promise<AddEvidenceSubmitOutcome> {
    try {
      const submission = await parseAddEvidenceSubmission(req);
      this.jobStore.enqueue(submission.thid, route);

      setImmediate(async () => {
        this.jobStore.markRunning(submission.thid);
        try {
          const nowIso = new Date().toISOString();
          const evidenceRecords: EvidenceRecord[] = [];
          const resultItems = submission.evidences.map((entry) => {
            const evidenceRecordId = `urn:uuid:${randomUUID()}`;
            const issuedCredentialRecordId = entry.issuedCredentialRecordId || `urn:uuid:${randomUUID()}`;
            evidenceRecords.push({
              id: evidenceRecordId,
              issuedCredentialRecordId,
              tenantId: route.tenantId,
              jurisdiction: route.jurisdiction.toUpperCase(),
              sector: route.sector,
              resourceType: route.evidenceType,
              thid: submission.thid,
              evidenceType: route.evidenceType,
              evidence: {
                ...entry.evidence,
                ...(entry.operatorDid ? { operatorDid: entry.operatorDid } : {}),
              },
              createdAt: nowIso,
              updatedAt: nowIso,
            });
            return {
              evidenceRecordId,
              evidenceType: route.evidenceType,
              issuedCredentialRecordId,
              linkedToCredential: Boolean(entry.issuedCredentialRecordId),
              storedAt: nowIso,
              ...(entry.operatorDid ? { operatorDid: entry.operatorDid } : {}),
            };
          });

          await this.collectionsService.storeEvidenceRecords(evidenceRecords);
          this.jobStore.markSucceeded(submission.thid, {
            evidenceType: route.evidenceType,
            storedCount: resultItems.length,
            items: resultItems,
          });
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          console.error(`Evidence _add job failed (thid=${submission.thid}): ${message}`);
          this.jobStore.markFailed(submission.thid, message);
        }
      });

      return {
        type: 'accepted',
        location: buildAddEvidenceResponseLocation(route),
        retryAfter: 3,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid evidence payload.';
      return {
        type: 'error',
        statusCode: toStatusCodeFromParseError(message),
        message,
      };
    }
  }
}
