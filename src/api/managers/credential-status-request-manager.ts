import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parseCredentialStatusSubmission } from '../request-parsing.ts';
import { buildCredentialStatusResponseLocation } from '../path.ts';
import type { CredentialStatusResult, CredentialStatusRouteContext, RevocationStatus } from '../types.ts';
import type { IssuedCredentialRecord, JsonObject } from '../tools/verification-collections-storage.ts';
import { VerificationCollectionsService } from '../tools/verification-collections-storage.ts';
import { CredentialLedgerService } from '../tools/credential-ledger.ts';

export type CredentialStatusSubmitOutcome =
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

function resolveStatusFromRecord(record: IssuedCredentialRecord | undefined): {
  status: RevocationStatus;
  revokedAt?: string;
} {
  if (!record) return { status: 'unknown' };
  const credentialStatus = asJsonObject(record.credential.credentialStatus);
  const explicitStatus = asNonEmptyString(
    credentialStatus?.status || credentialStatus?.state || credentialStatus?.revocationStatus,
  ).toLowerCase();
  const revokedAt = asNonEmptyString(
    credentialStatus?.revokedAt || credentialStatus?.revocationDate || credentialStatus?.revocationTime,
  ) || undefined;
  const revokedFlag = credentialStatus?.revoked === true;
  if (explicitStatus === 'revoked' || revokedFlag) {
    return { status: 'revoked', revokedAt };
  }
  return { status: 'good', revokedAt };
}

export class CredentialStatusRequestManager {
  private readonly jobStore: InMemoryEntityJobStore<CredentialStatusRouteContext, CredentialStatusResult>;
  private readonly collectionsService: VerificationCollectionsService;
  private readonly credentialLedgerService: CredentialLedgerService;

  constructor(
    jobStore: InMemoryEntityJobStore<CredentialStatusRouteContext, CredentialStatusResult>,
    collectionsService: VerificationCollectionsService = new VerificationCollectionsService(),
    credentialLedgerService: CredentialLedgerService = new CredentialLedgerService(),
  ) {
    this.jobStore = jobStore;
    this.collectionsService = collectionsService;
    this.credentialLedgerService = credentialLedgerService;
  }

  async submit(route: CredentialStatusRouteContext, req: IncomingMessage): Promise<CredentialStatusSubmitOutcome> {
    try {
      const submission = await parseCredentialStatusSubmission(req);
      this.jobStore.enqueue(submission.thid, route);

      setImmediate(async () => {
        this.jobStore.markRunning(submission.thid);
        try {
          const nowIso = new Date().toISOString();
          const resultItems = [];
          for (const lookup of submission.lookups) {
            const record = await this.collectionsService.findIssuedCredential({
              tenantId: route.tenantId,
              jurisdiction: route.jurisdiction,
              sector: route.sector,
              credentialType: route.credentialType,
              issuedCredentialRecordId: lookup.issuedCredentialRecordId,
              credentialId: lookup.credentialId,
              subjectId: lookup.subjectId,
              credentialStatusId: lookup.credentialStatusId,
            });
            const ledgerAsset = record && this.credentialLedgerService.config.enabled
              ? await this.credentialLedgerService.getCredential(record.credentialId)
              : undefined;
            const resolved = ledgerAsset
              ? {
                status: ledgerAsset.status === 'active'
                  ? 'good' as const
                  : ledgerAsset.status === 'revoked'
                    ? 'revoked' as const
                    : 'unknown' as const,
                revokedAt: ledgerAsset.status === 'revoked' && ledgerAsset.updatedAt
                  ? new Date(
                    typeof ledgerAsset.updatedAt === 'number'
                      ? ledgerAsset.updatedAt * 1000
                      : ledgerAsset.updatedAt,
                  ).toISOString()
                  : undefined,
              }
              : resolveStatusFromRecord(record);
            resultItems.push({
              status: resolved.status,
              checkedAt: nowIso,
              issuedCredentialRecordId: record?.id || lookup.issuedCredentialRecordId,
              credentialId: record?.credentialId || lookup.credentialId,
              subjectId: record?.subjectId || lookup.subjectId,
              credentialStatusId: lookup.credentialStatusId,
              revokedAt: resolved.revokedAt,
            });
          }
          this.jobStore.markSucceeded(submission.thid, {
            resolvedCount: resultItems.length,
            items: resultItems,
          });
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          console.error(`Credential _status job failed (thid=${submission.thid}): ${message}`);
          this.jobStore.markFailed(submission.thid, message);
        }
      });

      return {
        type: 'accepted',
        location: buildCredentialStatusResponseLocation(route),
        retryAfter: 3,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid credential status payload.';
      return {
        type: 'error',
        statusCode: toStatusCodeFromParseError(message),
        message,
      };
    }
  }
}
