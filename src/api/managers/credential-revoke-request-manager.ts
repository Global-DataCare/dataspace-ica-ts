import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parseCredentialRevokeSubmission } from '../request-parsing.ts';
import { buildCredentialRevokeResponseLocation } from '../path.ts';
import type { CredentialRevokeResult, CredentialRevokeRouteContext } from '../types.ts';
import type { JsonObject } from '../tools/verification-collections-storage.ts';
import { VerificationCollectionsService } from '../tools/verification-collections-storage.ts';
import { DataspaceSyncService } from '../tools/dataspace-sync.ts';
import { CredentialLedgerService } from '../tools/credential-ledger.ts';

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
  private readonly dataspaceSyncService: DataspaceSyncService;
  private readonly credentialLedgerService: CredentialLedgerService;

  constructor(
    jobStore: InMemoryEntityJobStore<CredentialRevokeRouteContext, CredentialRevokeResult>,
    collectionsService: VerificationCollectionsService = new VerificationCollectionsService(),
    dataspaceSyncService: DataspaceSyncService = new DataspaceSyncService(),
    credentialLedgerService: CredentialLedgerService = new CredentialLedgerService(),
  ) {
    this.jobStore = jobStore;
    this.collectionsService = collectionsService;
    this.dataspaceSyncService = dataspaceSyncService;
    this.credentialLedgerService = credentialLedgerService;
  }

  async submit(route: CredentialRevokeRouteContext, req: IncomingMessage): Promise<CredentialRevokeSubmitOutcome> {
    try {
      const submission = await parseCredentialRevokeSubmission(req);
      this.jobStore.enqueue(submission.thid, route);

      setImmediate(async () => {
        this.jobStore.markRunning(submission.thid);
        try {
          const nowIso = new Date().toISOString();
          const resultItems = [];
          for (const entry of submission.items) {
            const record = await this.collectionsService.findIssuedCredential({
              tenantId: route.tenantId,
              jurisdiction: route.jurisdiction,
              sector: route.sector,
              credentialType: route.credentialType,
              issuedCredentialRecordId: entry.issuedCredentialRecordId,
              credentialId: entry.credentialId,
              subjectId: entry.subjectId,
              credentialStatusId: entry.credentialStatusId,
            });
            if (!record) {
              throw new Error('Credential record not found for provided revoke lookup.');
            }

            const credential = { ...record.credential } as JsonObject;
            await this.credentialLedgerService.revokeCredential(record.credentialId, {
              timestamp: nowIso,
              actor: entry.revokedBy,
              reason: entry.reason,
            });
            const previousStatus = asJsonObject(credential.credentialStatus) || {};
            const nextStatus: JsonObject = {
              ...previousStatus,
              id: asNonEmptyString(previousStatus.id) || `${record.id}#status`,
              type: asNonEmptyString(previousStatus.type) || 'SimpleCredentialStatus2026',
              status: 'revoked',
              revokedAt: nowIso,
              ...(entry.reason ? { reason: entry.reason } : {}),
              ...(entry.revokedBy ? { revokedBy: entry.revokedBy } : {}),
            };

            const updatedRecord = {
              ...record,
              credential: {
                ...credential,
                credentialStatus: nextStatus,
              },
              updatedAt: nowIso,
            };
            const syncedRecord = await this.dataspaceSyncService.syncIssuedCredentialRecord(updatedRecord, {
              event: 'revoked',
              status: 'revoked',
            });
            await this.collectionsService.upsertIssuedCredential(syncedRecord);
            resultItems.push({
              status: 'revoked' as const,
              revokedAt: nowIso,
              issuedCredentialRecordId: record.id,
              credentialId: record.credentialId,
              subjectId: record.subjectId || undefined,
              credentialStatusId: entry.credentialStatusId,
              reason: entry.reason,
              revokedBy: entry.revokedBy,
            });
          }

          this.jobStore.markSucceeded(submission.thid, {
            revokedCount: resultItems.length,
            items: resultItems,
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
