import type { IncomingMessage } from 'node:http';
import { randomUUID } from 'node:crypto';
import { buildVerifyResponseLocation } from '../path.ts';
import { parsePollingThreadId } from '../request-parsing.ts';
import { InMemoryVerificationJobStore } from '../job-store.ts';
import type {
  DidcommAttachment,
  DidcommPlaintextMessage,
  OperationOutcomeIssue,
  OperationOutcomeResource,
  VerificationErrorDetails,
  VerifyBundleResponse,
  VerifyRouteContext,
} from '../types.ts';
import { buildVerificationVcBundle } from '../tools/vc-bundle.ts';
import { buildVcJwtAttachments } from '../tools/vc-jwt.ts';
import { buildDidcommMessage, DIDCOMM_BUNDLE_TYPE } from '../tools/didcomm-message.ts';
import { VerificationCollectionsService } from '../tools/verification-collections-storage.ts';

export type VerifyPollOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'pending'; location: string; retryAfter: number }
  | { type: 'failed'; payload: unknown }
  | { type: 'succeeded'; payload: unknown };

function sameRoute(a: VerifyRouteContext, b: VerifyRouteContext): boolean {
  return (
    a.tenantId === b.tenantId &&
    a.jurisdiction.toLowerCase() === b.jurisdiction.toLowerCase() &&
    a.sector === b.sector &&
    a.resourceType === b.resourceType
  );
}

function buildDidcommVerifyMessage(
  route: VerifyRouteContext,
  thid: string,
  body: VerifyBundleResponse,
  req: IncomingMessage,
  attachments?: DidcommAttachment[],
): DidcommPlaintextMessage<VerifyBundleResponse> {
  return buildDidcommMessage(req, body, {
    route,
    thid,
    type: DIDCOMM_BUNDLE_TYPE,
    attachments,
  });
}

function buildOperationOutcome(issue: OperationOutcomeIssue[]): OperationOutcomeResource {
  return {
    resourceType: 'OperationOutcome',
    issue,
  };
}

function mapRevocationDebugIssue(
  status: string,
): Pick<OperationOutcomeIssue, 'severity' | 'code'> {
  switch (status) {
    case 'ok':
      return { severity: 'information', code: 'informational' };
    case 'no_urls':
      return { severity: 'warning', code: 'incomplete' };
    case 'http_error':
      return { severity: 'warning', code: 'transient' };
    case 'timeout':
      return { severity: 'warning', code: 'timeout' };
    case 'download_error':
      return { severity: 'warning', code: 'transient' };
    case 'parse_error':
      return { severity: 'warning', code: 'structure' };
    case 'revoked':
      return { severity: 'error', code: 'security' };
    case 'verify_error':
      return { severity: 'warning', code: 'processing' };
    default:
      return { severity: 'warning', code: 'processing' };
  }
}

function buildRevocationOutcomeIssues(errorDetails: VerificationErrorDetails | undefined): OperationOutcomeIssue[] {
  const checks = errorDetails?.revocation?.checks || [];
  if (!checks.length) return [];
  return checks.map((check, index) => {
    const mapped = mapRevocationDebugIssue(check.status);
    const parts = [`revocation[${index}]`, `phase=${check.phase}`, `status=${check.status}`];
    if (check.httpStatus !== undefined) parts.push(`httpStatus=${check.httpStatus}`);
    if (check.url) parts.push(`url=${check.url}`);
    if (check.message) parts.push(`message=${check.message}`);
    return {
      severity: mapped.severity,
      code: mapped.code,
      diagnostics: parts.join(' | '),
    };
  });
}

export class VerifyResponseManager {
  private readonly jobStore: InMemoryVerificationJobStore;
  private readonly collectionsService: VerificationCollectionsService;

  constructor(
    jobStore: InMemoryVerificationJobStore,
    collectionsService: VerificationCollectionsService = new VerificationCollectionsService(),
  ) {
    this.jobStore = jobStore;
    this.collectionsService = collectionsService;
  }

  async poll(route: VerifyRouteContext, req: IncomingMessage, requestUrl: URL): Promise<VerifyPollOutcome> {
    const thid = await parsePollingThreadId(req, requestUrl);
    if (!thid) {
      return {
        type: 'error',
        statusCode: 400,
        message: 'Missing thid or jti for _verify-response polling.',
      };
    }

    const job = this.jobStore.get(thid);
    if (!job) {
      return {
        type: 'error',
        statusCode: 404,
        message: `Verification job not found for thid=${thid}.`,
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
        location: buildVerifyResponseLocation(route, { thid }),
        retryAfter: 5,
      };
    }

    if (job.status === 'failed') {
      const diagnostics = job.error || 'Unknown verification failure.';
      const outcome = buildOperationOutcome([
        { severity: 'error', code: 'exception', diagnostics },
        ...buildRevocationOutcomeIssues(job.errorDetails),
      ]);
      const failedBody: VerifyBundleResponse = {
        resourceType: 'Bundle',
        type: 'batch-response',
        issues: outcome,
        total: 1,
        data: [
          {
            type: 'TermsVerification-v1.0',
            resource: {
              id: `urn:uuid:${randomUUID()}`,
              type: 'terms-verification-v1.0',
              thid,
              tenantId: route.tenantId,
              jurisdiction: route.jurisdiction.toUpperCase(),
              sector: route.sector,
              section: route.section,
              format: route.format,
              resourceType: route.resourceType,
              status: 'failed',
              createdAt: new Date(job.createdAt).toISOString(),
              updatedAt: new Date(job.updatedAt).toISOString(),
              audit: {
                txId: '',
                txTime: '',
              },
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
        payload: buildDidcommVerifyMessage(route, thid, failedBody, req),
      };
    }

    const verificationResult = job.result;
    if (!verificationResult) {
      return {
        type: 'error',
        statusCode: 500,
        message: `Verification job ${thid} finished without result payload.`,
      };
    }

    const body = buildVerificationVcBundle(route, verificationResult) as VerifyBundleResponse;

    try {
      await this.collectionsService.persistFromVerificationBundle(route, thid, body);
    } catch (error: unknown) {
      return {
        type: 'error',
        statusCode: 500,
        message: (error as Error)?.message || 'Verification collections persistence failed.',
      };
    }

    return {
      type: 'succeeded',
      payload: buildDidcommVerifyMessage(route, thid, body, req, buildVcJwtAttachments(route, body)),
    };
  }
}
