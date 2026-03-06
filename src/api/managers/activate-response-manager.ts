import type { IncomingMessage } from 'node:http';
import { randomUUID } from 'node:crypto';
import { InMemoryActivationJobStore } from '../activation-job-store.ts';
import { parsePollingThreadId } from '../request-parsing.ts';
import { buildActivateResponseLocation } from '../path.ts';
import { buildDidcommMessage, DIDCOMM_BUNDLE_TYPE } from '../tools/didcomm-message.ts';
import type {
  ActivateRouteContext,
  DidcommPlaintextMessage,
  OperationOutcomeIssue,
  OperationOutcomeResource,
  VerifyBundleResponse,
} from '../types.ts';

export type ActivatePollOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'pending'; location: string; retryAfter: number }
  | { type: 'failed'; payload: unknown }
  | { type: 'succeeded'; payload: unknown };

function sameRoute(a: ActivateRouteContext, b: ActivateRouteContext): boolean {
  return (
    a.tenantId === b.tenantId &&
    a.jurisdiction.toLowerCase() === b.jurisdiction.toLowerCase() &&
    a.sector === b.sector &&
    a.resourceType === b.resourceType
  );
}

function buildDidcommActivateMessage(
  route: ActivateRouteContext,
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

export class ActivateResponseManager {
  private readonly jobStore: InMemoryActivationJobStore;

  constructor(jobStore: InMemoryActivationJobStore) {
    this.jobStore = jobStore;
  }

  async poll(route: ActivateRouteContext, req: IncomingMessage, requestUrl: URL): Promise<ActivatePollOutcome> {
    const thid = await parsePollingThreadId(req, requestUrl);
    if (!thid) {
      return {
        type: 'error',
        statusCode: 400,
        message: 'Missing thid or jti for _activate-response polling.',
      };
    }

    const job = this.jobStore.get(thid);
    if (!job) {
      return {
        type: 'error',
        statusCode: 404,
        message: `Activation job not found for thid=${thid}.`,
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
        location: buildActivateResponseLocation(route),
        retryAfter: 3,
      };
    }

    if (job.status === 'failed') {
      const diagnostics = job.error || 'Unknown activation failure.';
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
            type: 'SigningKeyActivation-v1.0',
            resource: {
              id: `urn:uuid:${randomUUID()}`,
              type: 'signing-key-activation-v1.0',
              thid,
              tenantId: route.tenantId,
              jurisdiction: route.jurisdiction.toUpperCase(),
              sector: route.sector,
              status: 'failed',
              createdAt: new Date(job.createdAt).toISOString(),
              updatedAt: new Date(job.updatedAt).toISOString(),
              content: {
                error: diagnostics,
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
        payload: buildDidcommActivateMessage(route, thid, failedBody, req),
      };
    }

    if (!job.result) {
      return {
        type: 'error',
        statusCode: 500,
        message: `Activation job ${thid} finished without result payload.`,
      };
    }

    const outcome = buildOperationOutcome([
      {
        severity: 'information',
        code: 'informational',
        diagnostics: 'Signing key activation completed.',
      },
    ]);
    const succeededBody: VerifyBundleResponse = {
      resourceType: 'Bundle',
      type: 'batch-response',
      issues: outcome,
      total: 1,
      data: [
        {
          type: 'SigningKeyActivation-v1.0',
          resource: {
            id: `urn:uuid:${randomUUID()}`,
            type: 'signing-key-activation-v1.0',
            thid,
            tenantId: route.tenantId,
            jurisdiction: route.jurisdiction.toUpperCase(),
            sector: route.sector,
            status: 'activated',
            createdAt: new Date(job.createdAt).toISOString(),
            updatedAt: new Date(job.updatedAt).toISOString(),
            content: job.result,
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
      payload: buildDidcommActivateMessage(route, thid, succeededBody, req),
    };
  }
}
