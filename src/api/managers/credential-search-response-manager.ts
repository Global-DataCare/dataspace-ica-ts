import type { IncomingMessage } from 'node:http';
import { randomUUID } from 'node:crypto';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parsePollingThreadId } from '../request-parsing.ts';
import { buildCredentialSearchResponseLocation } from '../path.ts';
import { buildDidcommMessage, DIDCOMM_BUNDLE_TYPE } from '../tools/didcomm-message.ts';
import type {
  CredentialSearchResult,
  CredentialSearchRouteContext,
  DidcommPlaintextMessage,
  OperationOutcomeIssue,
  OperationOutcomeResource,
  VerifyBundleResponse,
} from '../types.ts';

export type CredentialSearchPollOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'pending'; location: string; retryAfter: number }
  | { type: 'failed'; payload: unknown }
  | { type: 'succeeded'; payload: unknown };

function sameRoute(a: CredentialSearchRouteContext, b: CredentialSearchRouteContext): boolean {
  return (
    a.tenantId === b.tenantId &&
    a.jurisdiction.toLowerCase() === b.jurisdiction.toLowerCase() &&
    a.sector === b.sector &&
    a.credentialType.toLowerCase() === b.credentialType.toLowerCase()
  );
}

function buildDidcommCredentialSearchMessage(
  route: CredentialSearchRouteContext,
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

export class CredentialSearchResponseManager {
  private readonly jobStore: InMemoryEntityJobStore<CredentialSearchRouteContext, CredentialSearchResult>;

  constructor(jobStore: InMemoryEntityJobStore<CredentialSearchRouteContext, CredentialSearchResult>) {
    this.jobStore = jobStore;
  }

  async poll(
    route: CredentialSearchRouteContext,
    req: IncomingMessage,
    requestUrl: URL,
  ): Promise<CredentialSearchPollOutcome> {
    const thid = await parsePollingThreadId(req, requestUrl);
    if (!thid) {
      return {
        type: 'error',
        statusCode: 400,
        message: 'Missing thid for _search-response polling.',
      };
    }

    const job = this.jobStore.get(thid);
    if (!job) {
      return {
        type: 'error',
        statusCode: 404,
        message: `Credential _search job not found for thid=${thid}.`,
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
        location: buildCredentialSearchResponseLocation(route),
        retryAfter: 3,
      };
    }

    if (job.status === 'failed') {
      const diagnostics = job.error || 'Unknown credential _search failure.';
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
            type: 'NetworkCredentialSearch-v1.0',
            resource: {
              id: `urn:uuid:${randomUUID()}`,
              type: 'network-credential-search-v1.0',
              thid,
              tenantId: route.tenantId,
              jurisdiction: route.jurisdiction.toUpperCase(),
              sector: route.sector,
              credentialType: route.credentialType,
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
        payload: buildDidcommCredentialSearchMessage(route, thid, failedBody, req),
      };
    }

    if (!job.result) {
      return {
        type: 'error',
        statusCode: 500,
        message: `Credential _search job ${thid} finished without result payload.`,
      };
    }

    const outcome = buildOperationOutcome([
      {
        severity: 'information',
        code: 'informational',
        diagnostics: `Credential search matched ${job.result.matchedCount} organization credential(s).`,
      },
    ]);
    const succeededBody: VerifyBundleResponse = {
      resourceType: 'Bundle',
      type: 'batch-response',
      issues: outcome,
      total: 1,
      data: [
        {
          type: 'NetworkCredentialSearch-v1.0',
          resource: {
            id: `urn:uuid:${randomUUID()}`,
            type: 'network-credential-search-v1.0',
            thid,
            tenantId: route.tenantId,
            jurisdiction: route.jurisdiction.toUpperCase(),
            sector: route.sector,
            credentialType: route.credentialType,
            status: 'matched',
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
      payload: buildDidcommCredentialSearchMessage(route, thid, succeededBody, req),
    };
  }
}
