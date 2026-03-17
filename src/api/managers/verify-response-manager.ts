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
  VerifyResult,
  VerifyRouteContext,
} from '../types.ts';
import { buildVerificationVcBundle } from '../tools/vc-bundle.ts';
import { buildVcJwtAttachments } from '../tools/vc-jwt.ts';
import { buildDidcommMessage, DIDCOMM_BUNDLE_TYPE } from '../tools/didcomm-message.ts';
import { VerificationCollectionsService } from '../tools/verification-collections-storage.ts';
import { resolveIcaIssuerDid } from '../tools/ica-identity.ts';
import { multibase58MultihashSha3_384Hex, sameAsValuesEqual } from '../tools/multihash.ts';

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

function asObject(value: unknown): Record<string, unknown> | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : undefined;
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function appendOutcomeIssue(
  outcome: unknown,
  issue: OperationOutcomeIssue,
): OperationOutcomeResource {
  const existing = asObject(outcome);
  const issueList = Array.isArray(existing?.issue)
    ? existing.issue.filter((entry) => entry && typeof entry === 'object') as OperationOutcomeIssue[]
    : [];
  return {
    resourceType: 'OperationOutcome',
    issue: [...issueList, issue],
  };
}

function parseIsoTimestamp(value: string): number {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

function selectLatestRecord<T extends { updatedAt?: string; createdAt?: string }>(records: T[]): T | undefined {
  return [...records].sort((left, right) => {
    const leftTime = Math.max(parseIsoTimestamp(left.updatedAt || ''), parseIsoTimestamp(left.createdAt || ''));
    const rightTime = Math.max(parseIsoTimestamp(right.updatedAt || ''), parseIsoTimestamp(right.createdAt || ''));
    return rightTime - leftTime;
  })[0];
}

function buildControllerChangedIssue(): OperationOutcomeIssue {
  return {
    severity: 'warning',
    code: 'business-rule',
    diagnostics: 'controllerChanged=true: incoming controller.sameAs differs from the latest stored legal representative credential for this organization.',
  };
}

function attachBootstrapKeysToVerificationEntries(
  result: VerifyResult,
  bundle: VerifyBundleResponse,
): void {
  const data = Array.isArray(bundle.data) ? bundle.data : [];
  const organizationEntry = data.find((entry) => entry?.type === 'Organization-verification-v1.0');
  const personEntry = data.find((entry) => entry?.type === 'LegalRepresentative-verification-v1.0');

  if (organizationEntry && result.organizationPublicKeyJwk) {
    organizationEntry.publicKeyJwk = { ...result.organizationPublicKeyJwk };
    if (result.organizationPrivateKeyJwk) {
      organizationEntry.privateKeyJwk = { ...result.organizationPrivateKeyJwk };
    }
    if (result.organizationKeySource) {
      organizationEntry.keySource = result.organizationKeySource;
    }
  }

  if (personEntry && result.controllerPublicKeyJwk) {
    personEntry.publicKeyJwk = { ...result.controllerPublicKeyJwk };
  }
}

async function enrichVerificationBundleWithStoredVersionState(
  route: VerifyRouteContext,
  result: VerifyResult,
  bundle: VerifyBundleResponse,
  collectionsService: VerificationCollectionsService,
): Promise<void> {
  const versionId = multibase58MultihashSha3_384Hex(result.digest?.signedPdfHex || '');
  const data = Array.isArray(bundle.data) ? bundle.data : [];
  const organizationEntry = data.find((entry) => entry?.type === 'Organization-verification-v1.0');
  const personEntry = data.find((entry) => entry?.type === 'LegalRepresentative-verification-v1.0');
  const organizationResource = asObject(organizationEntry?.resource);
  const personResource = asObject(personEntry?.resource);
  const organizationSubject = asObject(organizationResource?.credentialSubject);
  const personSubject = asObject(personResource?.credentialSubject);
  const organizationTaxId = asString(organizationSubject?.taxID);
  const currentControllerSameAs = asString(personSubject?.sameAs);

  const records = (await collectionsService.listIssuedCredentials()).filter((record) =>
    record.tenantId === route.tenantId
    && record.jurisdiction.toLowerCase() === route.jurisdiction.toLowerCase()
    && record.sector === route.sector
  );

  const organizationRecords = records.filter((record) => {
    const subject = asObject(record.credential?.credentialSubject);
    return asString(subject?.['@type']) === 'Organization' && asString(subject?.taxID) === organizationTaxId;
  });
  const latestOrganizationRecord = selectLatestRecord(organizationRecords);
  const latestOrganizationMeta = asObject(asObject(latestOrganizationRecord?.credential)?.meta);
  const previousVersionId = asString(latestOrganizationMeta?.versionId);

  const personRecords = records.filter((record) => {
    const subject = asObject(record.credential?.credentialSubject);
    const memberOf = asObject(subject?.memberOf);
    return asString(subject?.['@type']) === 'Person' && asString(memberOf?.taxID) === organizationTaxId;
  });
  const latestPersonRecord = selectLatestRecord(personRecords);
  const latestPersonSubject = asObject(asObject(latestPersonRecord?.credential)?.credentialSubject);
  const latestControllerSameAs = asString(latestPersonSubject?.sameAs);
  const controllerChanged = !!currentControllerSameAs
    && !!latestControllerSameAs
    && !sameAsValuesEqual(currentControllerSameAs, latestControllerSameAs);

  const meta: Record<string, unknown> = {
    versionId,
  };
  if (previousVersionId && previousVersionId !== versionId) {
    meta.previousVersionId = previousVersionId;
  }
  if (controllerChanged) {
    meta.controllerChanged = true;
  }

  for (const entry of data) {
    const resource = asObject(entry?.resource);
    if (!resource) continue;
    resource.meta = { ...meta };
  }

  if (controllerChanged) {
    const warning = buildControllerChangedIssue();
    bundle.issues = appendOutcomeIssue(bundle.issues, warning);
    for (const entry of data) {
      if (!entry?.response) continue;
      entry.response.outcome = appendOutcomeIssue(entry.response.outcome, warning);
    }
  }
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
        message: 'Missing thid for _verify-response polling.',
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

    const issuerDid = resolveIcaIssuerDid(req);
    const body = buildVerificationVcBundle(route, verificationResult, issuerDid) as VerifyBundleResponse;
    attachBootstrapKeysToVerificationEntries(verificationResult, body);

    try {
      await enrichVerificationBundleWithStoredVersionState(route, verificationResult, body, this.collectionsService);
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
      payload: buildDidcommVerifyMessage(route, thid, body, req, buildVcJwtAttachments(route, body, issuerDid)),
    };
  }
}
