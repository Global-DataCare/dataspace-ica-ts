import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parseCredentialRevokeSubmission } from '../request-parsing.ts';
import { buildCredentialRevokeResponseLocation } from '../path.ts';
import type { CredentialRevokeResult, CredentialRevokeRouteContext } from '../types.ts';
import type { JsonObject } from '../tools/verification-collections-storage.ts';
import { VerificationCollectionsService } from '../tools/verification-collections-storage.ts';

export type CredentialRevokeSubmitOutcome =
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

export class CredentialRevokeRequestManager {
  private readonly jobStore: InMemoryEntityJobStore<CredentialRevokeRouteContext, CredentialRevokeResult>;
  private readonly collectionsService: VerificationCollectionsService;

  constructor(
    jobStore: InMemoryEntityJobStore<CredentialRevokeRouteContext, CredentialRevokeResult>,
    collectionsService: VerificationCollectionsService = new VerificationCollectionsService(),
  ) {
    this.jobStore = jobStore;
    this.collectionsService = collectionsService;
  }

  async submit(route: CredentialRevokeRouteContext, req: IncomingMessage): Promise<CredentialRevokeSubmitOutcome> {
    try {
      const submission = await parseCredentialRevokeSubmission(req);
      this.jobStore.enqueue(submission.thid, route);

      setImmediate(async () => {
        this.jobStore.markRunning(submission.thid);
        try {
          const nowIso = new Date().toISOString();
          const record = await this.collectionsService.findIssuedCredential({
            tenantId: route.tenantId,
            jurisdiction: route.jurisdiction,
            sector: route.sector,
            credentialType: route.credentialType,
            issuedCredentialRecordId: submission.issuedCredentialRecordId,
            credentialId: submission.credentialId,
            subjectId: submission.subjectId,
          });
          if (!record) {
            throw new Error('Credential record not found for provided revoke lookup.');
          }

          const credential = { ...record.credential } as JsonObject;
          const previousStatus = asJsonObject(credential.credentialStatus) || {};
          const nextStatus: JsonObject = {
            ...previousStatus,
            id: asNonEmptyString(previousStatus.id) || `${record.id}#status`,
            type: asNonEmptyString(previousStatus.type) || 'SimpleCredentialStatus2026',
            status: 'revoked',
            revokedAt: nowIso,
            ...(submission.reason ? { reason: submission.reason } : {}),
            ...(submission.revokedBy ? { revokedBy: submission.revokedBy } : {}),
          };

          const updatedRecord = {
            ...record,
            credential: {
              ...credential,
              credentialStatus: nextStatus,
            },
            updatedAt: nowIso,
          };
          await this.collectionsService.upsertIssuedCredential(updatedRecord);

          this.jobStore.markSucceeded(submission.thid, {
            status: 'revoked',
            revokedAt: nowIso,
            issuedCredentialRecordId: record.id,
            credentialId: record.credentialId,
            subjectId: record.subjectId || undefined,
            reason: submission.reason,
            revokedBy: submission.revokedBy,
          });
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          console.error(`Credential _revoke job failed (thid=${submission.thid}): ${message}`);
          this.jobStore.markFailed(submission.thid, message);
        }
      });

      return {
        type: 'accepted',
        location: buildCredentialRevokeResponseLocation(route),
        retryAfter: 3,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid credential revoke payload.';
      return {
        type: 'error',
        statusCode: toStatusCodeFromParseError(message),
        message,
      };
    }
  }
}
