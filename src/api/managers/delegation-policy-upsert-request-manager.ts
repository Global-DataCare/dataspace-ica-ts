import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parseDelegationPolicySubmission } from '../request-parsing.ts';
import { buildDelegationPolicyResponseLocation } from '../path.ts';
import type {
  DelegationPolicyRouteContext,
  DelegationPolicyUpsertResult,
} from '../types.ts';
import { summarizeDelegationPolicyResource } from '../tools/odrl-delegation-policy-validation.ts';

export type DelegationPolicyUpsertSubmitOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'accepted'; location: string; retryAfter: number };

function toStatusCodeFromParseError(message: string): number {
  return message.startsWith('Unsupported Content-Type') || message.startsWith('Unsupported Content-Encoding')
    ? 415
    : 400;
}

export class DelegationPolicyUpsertRequestManager {
  private readonly jobStore: InMemoryEntityJobStore<DelegationPolicyRouteContext, DelegationPolicyUpsertResult>;

  constructor(jobStore: InMemoryEntityJobStore<DelegationPolicyRouteContext, DelegationPolicyUpsertResult>) {
    this.jobStore = jobStore;
  }

  async submit(
    route: DelegationPolicyRouteContext,
    req: IncomingMessage,
  ): Promise<DelegationPolicyUpsertSubmitOutcome> {
    try {
      const submission = await parseDelegationPolicySubmission(req);
      this.jobStore.enqueue(submission.thid, route);

      setImmediate(() => {
        this.jobStore.markRunning(submission.thid);
        try {
          const nowIso = new Date().toISOString();
          const resultItems = submission.policies.map((entry) => {
            const summary = summarizeDelegationPolicyResource(entry.resource);
            return {
              policyId: summary.policyId || `urn:uuid:${randomUUID()}`,
              assigneeDid: summary.assigneeDid,
              roleIdentifier: summary.roleIdentifier,
              upsertedAt: nowIso,
            };
          });

          this.jobStore.markSucceeded(submission.thid, {
            upsertedCount: resultItems.length,
            items: resultItems,
          });
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          console.error(`Delegation policy _upsert job failed (thid=${submission.thid}): ${message}`);
          this.jobStore.markFailed(submission.thid, message);
        }
      });

      return {
        type: 'accepted',
        location: buildDelegationPolicyResponseLocation(route),
        retryAfter: 3,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid delegation policy payload.';
      return {
        type: 'error',
        statusCode: toStatusCodeFromParseError(message),
        message,
      };
    }
  }
}
