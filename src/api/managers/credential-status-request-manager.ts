import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parseCredentialStatusSubmission } from '../request-parsing.ts';
import { buildCredentialStatusResponseLocation } from '../path.ts';
import type { CredentialStatusResult, CredentialStatusRouteContext, RevocationStatus } from '../types.ts';
import type { IssuedCredentialRecord, JsonObject } from '../tools/verification-collections-storage.ts';
import { VerificationCollectionsService } from '../tools/verification-collections-storage.ts';

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

  constructor(
    jobStore: InMemoryEntityJobStore<CredentialStatusRouteContext, CredentialStatusResult>,
    collectionsService: VerificationCollectionsService = new VerificationCollectionsService(),
  ) {
    this.jobStore = jobStore;
    this.collectionsService = collectionsService;
  }

  async submit(route: CredentialStatusRouteContext, req: IncomingMessage): Promise<CredentialStatusSubmitOutcome> {
    try {
      const submission = await parseCredentialStatusSubmission(req);
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
          const resolved = resolveStatusFromRecord(record);
          this.jobStore.markSucceeded(submission.thid, {
            status: resolved.status,
            checkedAt: nowIso,
            issuedCredentialRecordId: record?.id || submission.issuedCredentialRecordId,
            credentialId: record?.credentialId || submission.credentialId,
            subjectId: record?.subjectId || submission.subjectId,
            revokedAt: resolved.revokedAt,
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
