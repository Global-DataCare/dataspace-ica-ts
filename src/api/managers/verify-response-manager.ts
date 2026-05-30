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
import { resolveVcIssuerDid } from '../tools/ica-identity.ts';
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

function parseBooleanEnv(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (!normalized) return fallback;
  if (normalized === '1' || normalized === 'true' || normalized === 'yes') return true;
  if (normalized === '0' || normalized === 'false' || normalized === 'no') return false;
  return fallback;
}

function cloneBundle(bundle: VerifyBundleResponse): VerifyBundleResponse {
  return JSON.parse(JSON.stringify(bundle)) as VerifyBundleResponse;
}

function removeInternalVersionMetaFromResponse(bundle: VerifyBundleResponse): void {
  const includeVersionMeta = parseBooleanEnv(process.env.ICA_VERIFY_RESPONSE_INCLUDE_VERSION_META, false);
  if (includeVersionMeta) return;

  const data = Array.isArray(bundle.data) ? bundle.data : [];
  for (const entry of data) {
    const resource = asObject(entry?.resource);
    if (!resource) continue;
    const meta = asObject(resource.meta);
    if (!meta) continue;
    delete meta.versionId;
    delete meta.previousVersionId;
    if (!Object.keys(meta).length) {
      delete resource.meta;
    }
  }
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
    const exposePrivateJwk = parseBooleanEnv(process.env.ICA_VERIFY_RESPONSE_INCLUDE_PRIVATE_KEY_JWK, true);
    if (exposePrivateJwk && result.organizationPrivateKeyJwk) {
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

function buildAnnexOutcomeIssues(errorDetails: VerificationErrorDetails | undefined): OperationOutcomeIssue[] {
  const annex = errorDetails?.annex;
  if (!annex) return [];

  const summaryParts = [
    `annex.fieldCount=${annex.fieldCount}`,
    `annex.warningCount=${annex.warningCount}`,
    `annex.hasOrganizationTaxId=${annex.hasOrganizationTaxId}`,
    `annex.hasOrganizationLegalName=${annex.hasOrganizationLegalName}`,
  ];
  if (annex.organizationTaxId) summaryParts.push(`annex.organizationTaxId=${annex.organizationTaxId}`);
  if (annex.organizationLegalName) summaryParts.push(`annex.organizationLegalName=${annex.organizationLegalName}`);
  if (annex.personName) summaryParts.push(`annex.personName=${annex.personName}`);

  const issues: OperationOutcomeIssue[] = [
    {
      severity: 'information',
      code: 'informational',
      diagnostics: summaryParts.join(' | '),
    },
  ];

  const maxWarnings = 8;
  for (let index = 0; index < annex.warnings.length && index < maxWarnings; index += 1) {
    issues.push({
      severity: 'warning',
      code: 'incomplete',
      diagnostics: `annex.warning[${index}]=${annex.warnings[index]}`,
    });
  }
  if (annex.warnings.length > maxWarnings) {
    issues.push({
      severity: 'information',
      code: 'informational',
      diagnostics: `annex.warning[+]=${annex.warnings.length - maxWarnings} additional warning(s) omitted`,
    });
  }

  return issues;
}

function buildFailedVerifyPayload(
  route: VerifyRouteContext,
  req: IncomingMessage,
  thid: string,
  job: {
    createdAt: number;
    updatedAt: number;
    error?: string;
    errorDetails?: VerificationErrorDetails;
  },
): DidcommPlaintextMessage<VerifyBundleResponse> {
  const diagnostics = job.error || 'Unknown verification failure.';
  const outcome = buildOperationOutcome([
    { severity: 'error', code: 'exception', diagnostics },
    ...buildRevocationOutcomeIssues(job.errorDetails),
    ...buildAnnexOutcomeIssues(job.errorDetails),
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
              ...(job.errorDetails?.annex ? { annex: job.errorDetails.annex } : {}),
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
  return buildDidcommVerifyMessage(route, thid, failedBody, req);
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
      return {
        type: 'failed',
        payload: buildFailedVerifyPayload(route, req, thid, job),
      };
    }

    const verificationResult = job.result;
    if (!verificationResult) {
      const message = `Verification job ${thid} finished without result payload.`;
      this.jobStore.markFailed(thid, message);
      return {
        type: 'failed',
        payload: buildFailedVerifyPayload(route, req, thid, {
          ...job,
          error: message,
          updatedAt: Date.now(),
        }),
      };
    }

    const issuerDid = resolveVcIssuerDid(req);
    const body = buildVerificationVcBundle(route, verificationResult, issuerDid) as VerifyBundleResponse;
    attachBootstrapKeysToVerificationEntries(verificationResult, body);

    try {
      await enrichVerificationBundleWithStoredVersionState(route, verificationResult, body, this.collectionsService);
      await this.collectionsService.persistFromVerificationBundle(route, thid, body);
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Verification collections persistence failed.';
      this.jobStore.markFailed(thid, message);
      return {
        type: 'failed',
        payload: buildFailedVerifyPayload(route, req, thid, {
          ...job,
          error: message,
          updatedAt: Date.now(),
        }),
      };
    }

    const responseBody = cloneBundle(body);
    removeInternalVersionMetaFromResponse(responseBody);
    return {
      type: 'succeeded',
      payload: buildDidcommVerifyMessage(
        route,
        thid,
        responseBody,
        req,
        buildVcJwtAttachments(route, responseBody, issuerDid),
      ),
    };
  }
}
