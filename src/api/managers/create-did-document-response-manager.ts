import { randomUUID } from 'node:crypto';
import type { IncomingMessage } from 'node:http';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parsePollingThreadId } from '../request-parsing.ts';
import { buildCreateDidDocumentResponseLocation } from '../path.ts';
import { buildDidcommMessage, DIDCOMM_BUNDLE_TYPE } from '../tools/didcomm-message.ts';
import type {
  CreateDidDocumentResult,
  CreateDidDocumentRouteContext,
  DidcommPlaintextMessage,
  OperationOutcomeIssue,
  OperationOutcomeResource,
  VerifyBundleResponse,
} from '../types.ts';

export type CreateDidDocumentPollOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'pending'; location: string; retryAfter: number }
  | { type: 'failed'; payload: unknown }
  | { type: 'succeeded'; payload: unknown };

function sameRoute(a: CreateDidDocumentRouteContext, b: CreateDidDocumentRouteContext): boolean {
  return (
    a.tenantId === b.tenantId &&
    a.jurisdiction.toLowerCase() === b.jurisdiction.toLowerCase() &&
    a.sector === b.sector
  );
}

function routeKey(route: CreateDidDocumentRouteContext): string {
  return `${route.tenantId}|${route.jurisdiction.toUpperCase()}|${route.sector}|${route.action}`;
}

function buildDidcommCreateDidDocumentMessage(
  route: CreateDidDocumentRouteContext,
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

export class CreateDidDocumentResponseManager {
  private readonly jobStore: InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>;

  constructor(jobStore: InMemoryEntityJobStore<CreateDidDocumentRouteContext, CreateDidDocumentResult>) {
    this.jobStore = jobStore;
  }

  async poll(
    route: CreateDidDocumentRouteContext,
    req: IncomingMessage,
    requestUrl: URL,
  ): Promise<CreateDidDocumentPollOutcome> {
    const thid = await parsePollingThreadId(req, requestUrl);
    if (!thid) {
      return {
        type: 'error',
        statusCode: 400,
        message: 'Missing thid for _create-response polling.',
      };
    }

    const job = this.jobStore.get(thid);
    if (!job) {
      return {
        type: 'error',
        statusCode: 404,
        message: `DID document _create job not found for thid=${thid}.`,
      };
    }
    if (!sameRoute(job.route, route)) {
      return {
        type: 'error',
        statusCode: 404,
        message: `Job exists but does not belong to this route (thid=${thid}, expected=${routeKey(job.route)}, got=${routeKey(route)}).`,
      };
    }

    if (job.status === 'queued' || job.status === 'running') {
      return {
        type: 'pending',
        location: buildCreateDidDocumentResponseLocation(route, { thid }),
        retryAfter: 3,
      };
    }

    if (job.status === 'failed') {
      const diagnostics = job.error || 'Unknown DID document _create failure.';
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
            type: 'EntityDidDocumentCreate-v1.0',
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
        payload: buildDidcommCreateDidDocumentMessage(route, thid, failedBody, req),
      };
    }

    if (!job.result) {
      return {
        type: 'error',
        statusCode: 500,
        message: `DID document _create job ${thid} finished without result payload.`,
      };
    }

    const outcome = buildOperationOutcome([
      {
        severity: 'information',
        code: 'informational',
        diagnostics: `DID document(s) created: ${job.result.createdCount}.`,
      },
    ]);
    const succeededBody: VerifyBundleResponse = {
      resourceType: 'Bundle',
      type: 'batch-response',
      issues: outcome,
      total: job.result.items.length,
      data: job.result.items.map((item) => ({
        type: 'EntityDidDocumentCreate-v1.0',
        resource: {
          didDocument: item.didDocument,
          meta: {
            createdAt: item.createdAt,
          },
        },
        response: {
          status: '200',
          outcome,
        },
      })),
    };
    return {
      type: 'succeeded',
      payload: buildDidcommCreateDidDocumentMessage(route, thid, succeededBody, req),
    };
  }
}
