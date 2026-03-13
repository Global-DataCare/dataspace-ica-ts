import type { IncomingMessage } from 'node:http';
import { randomUUID } from 'node:crypto';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parsePollingThreadId } from '../request-parsing.ts';
import { buildAddEvidenceResponseLocation } from '../path.ts';
import { buildDidcommMessage, DIDCOMM_BUNDLE_TYPE } from '../tools/didcomm-message.ts';
import type {
  AddEvidenceResult,
  AddEvidenceRouteContext,
  DidcommPlaintextMessage,
  OperationOutcomeIssue,
  OperationOutcomeResource,
  VerifyBundleResponse,
} from '../types.ts';

export type AddEvidencePollOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'pending'; location: string; retryAfter: number }
  | { type: 'failed'; payload: unknown }
  | { type: 'succeeded'; payload: unknown };

function sameRoute(a: AddEvidenceRouteContext, b: AddEvidenceRouteContext): boolean {
  return (
    a.tenantId === b.tenantId &&
    a.jurisdiction.toLowerCase() === b.jurisdiction.toLowerCase() &&
    a.sector === b.sector &&
    a.evidenceType.toLowerCase() === b.evidenceType.toLowerCase()
  );
}

function buildDidcommAddEvidenceMessage(
  route: AddEvidenceRouteContext,
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

export class AddEvidenceResponseManager {
  private readonly jobStore: InMemoryEntityJobStore<AddEvidenceRouteContext, AddEvidenceResult>;

  constructor(jobStore: InMemoryEntityJobStore<AddEvidenceRouteContext, AddEvidenceResult>) {
    this.jobStore = jobStore;
  }

  async poll(route: AddEvidenceRouteContext, req: IncomingMessage, requestUrl: URL): Promise<AddEvidencePollOutcome> {
    const thid = await parsePollingThreadId(req, requestUrl);
    if (!thid) {
      return {
        type: 'error',
        statusCode: 400,
        message: 'Missing thid for _add-response polling.',
      };
    }

    const job = this.jobStore.get(thid);
    if (!job) {
      return {
        type: 'error',
        statusCode: 404,
        message: `Evidence _add job not found for thid=${thid}.`,
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
        location: buildAddEvidenceResponseLocation(route),
        retryAfter: 3,
      };
    }

    if (job.status === 'failed') {
      const diagnostics = job.error || 'Unknown evidence _add failure.';
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
            type: 'NetworkEvidenceAdd-v1.0',
            resource: {
              id: `urn:uuid:${randomUUID()}`,
              type: 'network-evidence-add-v1.0',
              thid,
              tenantId: route.tenantId,
              jurisdiction: route.jurisdiction.toUpperCase(),
              sector: route.sector,
              evidenceType: route.evidenceType,
              status: 'failed',
              createdAt: new Date(job.createdAt).toISOString(),
              updatedAt: new Date(job.updatedAt).toISOString(),
              content: [
                {
                  error: diagnostics,
                },
              ],
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
        payload: buildDidcommAddEvidenceMessage(route, thid, failedBody, req),
      };
    }

    if (!job.result) {
      return {
        type: 'error',
        statusCode: 500,
        message: `Evidence _add job ${thid} finished without result payload.`,
      };
    }

    const outcome = buildOperationOutcome([
      {
        severity: 'information',
        code: 'informational',
        diagnostics: `Evidence record(s) stored: ${job.result.storedCount}.`,
      },
    ]);
    const succeededBody: VerifyBundleResponse = {
      resourceType: 'Bundle',
      type: 'batch-response',
      issues: outcome,
      total: 1,
      data: [
        {
          type: 'NetworkEvidenceAdd-v1.0',
          resource: {
            id: `urn:uuid:${randomUUID()}`,
            type: 'network-evidence-add-v1.0',
            thid,
            tenantId: route.tenantId,
            jurisdiction: route.jurisdiction.toUpperCase(),
            sector: route.sector,
            evidenceType: route.evidenceType,
            status: 'stored',
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
      payload: buildDidcommAddEvidenceMessage(route, thid, succeededBody, req),
    };
  }
}
