import type { IncomingMessage } from 'node:http';
import { randomUUID } from 'node:crypto';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parsePollingThreadId } from '../request-parsing.ts';
import { buildDelegationPolicyResponseLocation } from '../path.ts';
import { buildDidcommMessage, DIDCOMM_BUNDLE_TYPE } from '../tools/didcomm-message.ts';
import type {
  DelegationPolicyRouteContext,
  DelegationPolicyUpsertResult,
  DidcommPlaintextMessage,
  OperationOutcomeIssue,
  OperationOutcomeResource,
  VerifyBundleResponse,
} from '../types.ts';

export type DelegationPolicyUpsertPollOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'pending'; location: string; retryAfter: number }
  | { type: 'failed'; payload: unknown }
  | { type: 'succeeded'; payload: unknown };

function sameRoute(a: DelegationPolicyRouteContext, b: DelegationPolicyRouteContext): boolean {
  return (
    a.tenantId === b.tenantId
    && a.jurisdiction.toLowerCase() === b.jurisdiction.toLowerCase()
    && a.sector === b.sector
    && a.policyType === b.policyType
  );
}

function buildDidcommPolicyMessage(
  route: DelegationPolicyRouteContext,
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

export class DelegationPolicyUpsertResponseManager {
  private readonly jobStore: InMemoryEntityJobStore<DelegationPolicyRouteContext, DelegationPolicyUpsertResult>;

  constructor(jobStore: InMemoryEntityJobStore<DelegationPolicyRouteContext, DelegationPolicyUpsertResult>) {
    this.jobStore = jobStore;
  }

  async poll(
    route: DelegationPolicyRouteContext,
    req: IncomingMessage,
    requestUrl: URL,
  ): Promise<DelegationPolicyUpsertPollOutcome> {
    const thid = await parsePollingThreadId(req, requestUrl);
    if (!thid) {
      return {
        type: 'error',
        statusCode: 400,
        message: 'Missing thid for _upsert-response polling.',
      };
    }

    const job = this.jobStore.get(thid);
    if (!job) {
      return {
        type: 'error',
        statusCode: 404,
        message: `Delegation policy _upsert job not found for thid=${thid}.`,
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
        location: buildDelegationPolicyResponseLocation(route),
        retryAfter: 3,
      };
    }

    if (job.status === 'failed') {
      const diagnostics = job.error || 'Unknown delegation policy _upsert failure.';
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
            type: 'DelegationPolicyUpsert-v1.0',
            resource: {
              id: `urn:uuid:${randomUUID()}`,
              type: 'delegation-policy-upsert-v1.0',
              thid,
              tenantId: route.tenantId,
              jurisdiction: route.jurisdiction.toUpperCase(),
              sector: route.sector,
              policyType: route.policyType,
              status: 'failed',
              createdAt: new Date(job.createdAt).toISOString(),
              updatedAt: new Date(job.updatedAt).toISOString(),
              content: [{ error: diagnostics }],
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
        payload: buildDidcommPolicyMessage(route, thid, failedBody, req),
      };
    }

    if (!job.result) {
      return {
        type: 'error',
        statusCode: 500,
        message: `Delegation policy _upsert job ${thid} finished without result payload.`,
      };
    }

    const outcome = buildOperationOutcome([
      {
        severity: 'information',
        code: 'informational',
        diagnostics: `Delegation policy record(s) upserted: ${job.result.upsertedCount}.`,
      },
    ]);
    const succeededBody: VerifyBundleResponse = {
      resourceType: 'Bundle',
      type: 'batch-response',
      issues: outcome,
      total: 1,
      data: [
        {
          type: 'DelegationPolicyUpsert-v1.0',
          resource: {
            id: `urn:uuid:${randomUUID()}`,
            type: 'delegation-policy-upsert-v1.0',
            thid,
            tenantId: route.tenantId,
            jurisdiction: route.jurisdiction.toUpperCase(),
            sector: route.sector,
            policyType: route.policyType,
            status: 'upserted',
            createdAt: new Date(job.createdAt).toISOString(),
            updatedAt: new Date(job.updatedAt).toISOString(),
            content: job.result.items,
          },
          response: {
            status: '200',
            outcome,
          },
        },
      ],
    };
    return {
      type: 'succeeded',
      payload: buildDidcommPolicyMessage(route, thid, succeededBody, req),
    };
  }
}
