import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parsePollingThreadId } from '../request-parsing.ts';
import { buildTermsRemoveResponseLocation } from '../path.ts';
import { buildDidcommMessage, DIDCOMM_BUNDLE_TYPE } from '../tools/didcomm-message.ts';
import type {
  TermsRemoveResult,
  TermsRemoveRouteContext,
  DidcommPlaintextMessage,
  OperationOutcomeIssue,
  OperationOutcomeResource,
  VerifyBundleResponse,
} from '../types.ts';

export type TermsRemovePollOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'pending'; location: string; retryAfter: number }
  | { type: 'failed'; payload: unknown }
  | { type: 'succeeded'; payload: unknown };

function sameRoute(a: TermsRemoveRouteContext, b: TermsRemoveRouteContext): boolean {
  return (
    a.tenantId === b.tenantId &&
    a.jurisdiction.toLowerCase() === b.jurisdiction.toLowerCase() &&
    a.sector === b.sector &&
    a.resourceType.toLowerCase() === b.resourceType.toLowerCase()
  );
}

function buildDidcommTermsRemoveMessage(
  route: TermsRemoveRouteContext,
  thid: string,
  body: VerifyBundleResponse,
  req: IncomingMessage,
): DidcommPlaintextMessage<VerifyBundleResponse> {
  return buildDidcommMessage(req, body, {
    route,
    thid,
    type: DIDCOMM_BUNDLE_TYPE,
  });
}

function buildOperationOutcome(issue: OperationOutcomeIssue[]): OperationOutcomeResource {
  return {
    resourceType: 'OperationOutcome',
    issue,
  };
}

export class TermsRemoveResponseManager {
  private readonly jobStore: InMemoryEntityJobStore<TermsRemoveRouteContext, TermsRemoveResult>;

  constructor(jobStore: InMemoryEntityJobStore<TermsRemoveRouteContext, TermsRemoveResult>) {
    this.jobStore = jobStore;
  }

  async poll(
    route: TermsRemoveRouteContext,
    req: IncomingMessage,
    requestUrl: URL,
  ): Promise<TermsRemovePollOutcome> {
    const thid = await parsePollingThreadId(req, requestUrl);
    if (!thid) {
      return {
        type: 'error',
        statusCode: 400,
        message: 'Missing thid for _remove-response polling.',
      };
    }

    const job = this.jobStore.get(thid);
    if (!job) {
      return {
        type: 'error',
        statusCode: 404,
        message: `Terms _remove job not found for thid=${thid}.`,
      };
    }
    if (!sameRoute(job.route, route)) {
      return {
        type: 'error',
        statusCode: 404,
        message: 'Job exists but does not belong to this route.',
      };
    }

    if (job.status === 'queued' || job.status === 'running') {
      return {
        type: 'pending',
        location: buildTermsRemoveResponseLocation(route, { thid }),
        retryAfter: 3,
      };
    }

    if (job.status === 'failed') {
      const diagnostics = job.error || 'Unknown terms _remove failure.';
      const outcome = buildOperationOutcome([
        { severity: 'error', code: 'exception', diagnostics },
      ]);
      const failedBody: VerifyBundleResponse = {
        resourceType: 'Bundle',
        type: 'batch-response',
        issues: outcome,
        total: 1,
        data: [
          {
            type: 'TermsRemove-v1.0',
            resource: {
              error: {
                message: diagnostics,
              },
            },
            response: {
              status: '500',
              outcome,
            },
          },
        ],
      };
      return {
        type: 'failed',
        payload: buildDidcommTermsRemoveMessage(route, thid, failedBody, req),
      };
    }

    if (!job.result) {
      return {
        type: 'error',
        statusCode: 500,
        message: `Terms _remove job ${thid} finished without result payload.`,
      };
    }

    const outcome = buildOperationOutcome([
      {
        severity: 'information',
        code: 'informational',
        diagnostics: `Organization terms removed: ${job.result.removedCount}.`,
      },
    ]);
    const succeededBody: VerifyBundleResponse = {
      resourceType: 'Bundle',
      type: 'batch-response',
      issues: outcome,
      total: job.result.items.length,
      data: job.result.items.map((item) => ({
        type: 'TermsRemove-v1.0',
        resource: {
          id: `urn:uuid:${randomUUID()}`,
          status: 'removed',
          organizationTaxId: item.organizationTaxId,
          did: item.did,
          removedAt: item.removedAt,
          ...(item.reason ? { reason: item.reason } : {}),
          effects: item.effects,
        },
        response: {
          status: '200',
          outcome,
        },
      })),
    };
    return {
      type: 'succeeded',
      payload: buildDidcommTermsRemoveMessage(route, thid, succeededBody, req),
    };
  }
}
