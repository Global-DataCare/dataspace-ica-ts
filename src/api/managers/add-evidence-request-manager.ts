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
          const evidenceRecordId = `urn:uuid:${randomUUID()}`;
          const issuedCredentialRecordId = submission.issuedCredentialRecordId || `urn:uuid:${randomUUID()}`;
          const evidence: EvidenceRecord = {
            id: evidenceRecordId,
            issuedCredentialRecordId,
            tenantId: route.tenantId,
            jurisdiction: route.jurisdiction.toUpperCase(),
            sector: route.sector,
            resourceType: route.evidenceType,
            thid: submission.thid,
            evidenceType: route.evidenceType,
            evidence: {
              ...submission.evidence,
              ...(submission.operatorDid ? { operatorDid: submission.operatorDid } : {}),
            },
            createdAt: nowIso,
            updatedAt: nowIso,
          };
          await this.collectionsService.storeEvidenceRecords([evidence]);
          this.jobStore.markSucceeded(submission.thid, {
            evidenceRecordId,
            evidenceType: route.evidenceType,
            issuedCredentialRecordId,
            linkedToCredential: Boolean(submission.issuedCredentialRecordId),
            storedAt: nowIso,
            ...(submission.operatorDid ? { operatorDid: submission.operatorDid } : {}),
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
