import type { IncomingMessage } from 'node:http';
import type { VerifiableCredentialV2 } from 'gdc-common-utils-ts/models/verifiable-credential';
import { toJwkThumbprintSha256Urn } from 'gdc-common-utils-ts/utils/jwk-thumbprint';
import type { InMemoryEntityJobStore } from '../entity-job-store.ts';
import { parseCredentialSearchSubmission } from '../request-parsing.ts';
import { buildCredentialRetrieveResponseLocation } from '../path.ts';
import type {
  CredentialRetrieveResult,
  CredentialRetrieveResultItem,
  CredentialRetrieveRouteContext,
  CredentialSearchInput,
  VerifyRouteContext,
} from '../types.ts';
import type {
  DidBindingRecord,
  DidDocumentRecord,
  IssuedCredentialRecord,
} from '../tools/verification-collections-storage.ts';
import { VerificationCollectionsService } from '../tools/verification-collections-storage.ts';
import { attachProofToCredential, convertCredentialToVcJwt } from '../tools/ica-identity.ts';
import { multibase58MultihashSha3_256 } from '../tools/multihash.ts';

export type CredentialRetrieveSubmitOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'accepted'; location: string; retryAfter: number };

export type CredentialRetrieveDirectOutcome =
  | { type: 'error'; statusCode: number; message: string }
  | { type: 'succeeded'; format: 'vc+json' | 'vc+jwt'; credential: Record<string, unknown>; vcJwt?: string };

function toStatusCodeFromParseError(message: string): number {
  return message.startsWith('Unsupported Content-Type') || message.startsWith('Unsupported Content-Encoding')
    ? 415
    : 400;
}

type JsonObject = Record<string, unknown>;

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function equalsIgnoreCase(left: string, right: string): boolean {
  return left.trim().toLowerCase() === right.trim().toLowerCase();
}

function includesIgnoreCase(left: string, right: string): boolean {
  return left.trim().toLowerCase().includes(right.trim().toLowerCase());
}

function resolveCredentialSubject(credential: JsonObject): JsonObject | undefined {
  const credentialSubject = credential.credentialSubject;
  if (Array.isArray(credentialSubject)) {
    for (const candidate of credentialSubject) {
      const subject = asObject(candidate);
      if (subject) return subject;
    }
    return undefined;
  }
  return asObject(credentialSubject);
}

function hasCredentialMaterialPopulated(subject: JsonObject | undefined): boolean {
  const hasCredential = asObject(subject?.hasCredential);
  return !!asNonEmptyString(hasCredential?.material);
}

function resolveLatestDidBindingRecord(
  records: DidBindingRecord[],
  route: CredentialRetrieveRouteContext,
  lookup: { did?: string; taxId?: string },
): DidBindingRecord | undefined {
  return [...records]
    .filter((record) =>
      equalsIgnoreCase(record.tenantId, route.tenantId)
      && equalsIgnoreCase(record.jurisdiction, route.jurisdiction)
      && equalsIgnoreCase(record.sector, route.sector)
      && record.status !== 'removed'
      && (
        (lookup.did ? equalsIgnoreCase(asNonEmptyString(record.did), lookup.did) : false)
        || (lookup.taxId ? equalsIgnoreCase(record.taxId, lookup.taxId) : false)
      ))
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))[0];
}

function resolveLatestDidDocumentRecord(
  records: DidDocumentRecord[],
  route: CredentialRetrieveRouteContext,
  lookup: { did?: string; taxId?: string },
): DidDocumentRecord | undefined {
  return [...records]
    .filter((record) =>
      equalsIgnoreCase(record.tenantId, route.tenantId)
      && equalsIgnoreCase(record.jurisdiction, route.jurisdiction)
      && equalsIgnoreCase(record.sector, route.sector)
      && (
        (lookup.did ? equalsIgnoreCase(record.did, lookup.did) : false)
        || (lookup.taxId ? equalsIgnoreCase(asNonEmptyString(record.taxId), lookup.taxId) : false)
      ))
    .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))[0];
}

function resolveOrganizationNode(subject: JsonObject): JsonObject {
  const memberOf = asObject(subject.memberOf);
  if (memberOf) return memberOf;
  const organization = asObject(subject.organization);
  if (organization) return organization;
  return subject;
}

function resolveTaxId(entity: JsonObject): string {
  return (
    asNonEmptyString(entity.taxId)
    || asNonEmptyString(entity.taxID)
    || asNonEmptyString(entity.vatID)
    || asNonEmptyString(entity.vatId)
    || asNonEmptyString(entity.identifier)
  );
}

function resolveLegalName(entity: JsonObject): string {
  return (
    asNonEmptyString(entity.legalName)
    || asNonEmptyString(entity.name)
    || asNonEmptyString(entity.alternateName)
  );
}

function resolveOrganizationDid(subject: JsonObject, record: IssuedCredentialRecord): string {
  const organizationNode = resolveOrganizationNode(subject);
  return (
    asNonEmptyString(organizationNode.id)
    || asNonEmptyString(subject.id)
    || asNonEmptyString(record.subjectId)
  );
}

function resolveAddressText(entity: JsonObject): string {
  const address = asObject(entity.address);
  if (!address) return '';
  return [
    asNonEmptyString(address.streetAddress),
    asNonEmptyString(address.addressLocality),
    asNonEmptyString(address.addressRegion),
    asNonEmptyString(address.postalCode),
    asNonEmptyString(address.addressCountry),
  ].filter(Boolean).join(' ');
}

function resolveEmail(entity: JsonObject): string {
  return asNonEmptyString(entity.email);
}

function normalizeRecordType(value: string): string {
  return value.trim().toLowerCase();
}

function recordMatchesType(record: IssuedCredentialRecord, typeFilter: string): boolean {
  const requested = normalizeRecordType(typeFilter);
  if (!requested) return true;
  const recordTypes = record.credentialType
    .split(',')
    .map((entry) => normalizeRecordType(entry))
    .filter(Boolean);
  const credential = asObject(record.credential);
  const credentialTypeRaw = credential?.type;
  const vcTypes = Array.isArray(credentialTypeRaw)
    ? credentialTypeRaw.map((entry) => normalizeRecordType(asNonEmptyString(entry))).filter(Boolean)
    : [normalizeRecordType(asNonEmptyString(credentialTypeRaw))].filter(Boolean);
  return recordTypes.includes(requested) || vcTypes.includes(requested);
}

function isLegalRepresentativeCredential(record: IssuedCredentialRecord): boolean {
  return recordMatchesType(record, 'LegalRepresentativeCredential');
}

function toMillis(value: string): number {
  const parsed = Date.parse(value);
  return Number.isNaN(parsed) ? 0 : parsed;
}

type RequestedStoredVersion = 'v1' | 'v2';

function resolveRequestedStoredVersion(version: string): RequestedStoredVersion {
  if (!version) return 'v2';
  const normalized = version.trim().toLowerCase();
  if (normalized === 'v1' || normalized === '1') return 'v1';
  if (normalized === 'v2' || normalized === '2') return 'v2';
  throw new Error(`Unsupported version "${version}". Supported values are v1 or v2.`);
}

function resolveRequestedFormat(
  explicit: string,
  acceptHeader: string,
): 'vc+json' | 'vc+jwt' {
  const normalizedExplicit = explicit.trim().toLowerCase().replace(/\s+/g, '+');
  if (normalizedExplicit === 'vc+jwt' || normalizedExplicit === 'application/vc+jwt') return 'vc+jwt';
  if (normalizedExplicit === 'vc+json' || normalizedExplicit === 'application/vc+json') return 'vc+json';

  const normalizedAccept = acceptHeader.trim().toLowerCase();
  if (normalizedAccept.includes('application/vc+jwt')) return 'vc+jwt';
  return 'vc+json';
}

function parseRequestUrl(req: IncomingMessage): URL {
  const host = asNonEmptyString(req.headers.host) || 'localhost';
  return new URL(req.url || '/', `http://${host}`);
}

function resolveTypeFilterFromRoute(
  route: CredentialRetrieveRouteContext,
  explicitTypeFilter: string,
): string {
  if (explicitTypeFilter.trim()) return explicitTypeFilter.trim();
  // For compatibility, "/network/credentials/contract/_retrieve" does not force a credential type filter.
  if (equalsIgnoreCase(route.credentialType, 'contract')) return '';
  return route.credentialType;
}

function matchesQuery(record: IssuedCredentialRecord, query: CredentialSearchInput): {
  matched: boolean;
  taxId: string;
  legalName: string;
  organizationDid: string;
  taxIdHash?: string;
} {
  const credential = asObject(record.credential) || {};
  const subject = resolveCredentialSubject(credential) || {};
  const organizationNode = resolveOrganizationNode(subject);
  const taxId = resolveTaxId(organizationNode) || resolveTaxId(subject);
  const legalName = resolveLegalName(organizationNode) || resolveLegalName(subject);
  const organizationDid = resolveOrganizationDid(subject, record);
  const taxIdHash = taxId ? multibase58MultihashSha3_256(taxId) : undefined;
  const email = resolveEmail(organizationNode) || resolveEmail(subject);
  const addressText = resolveAddressText(organizationNode) || resolveAddressText(subject);

  if (query.id) {
    const idMatched =
      equalsIgnoreCase(query.id, record.credentialId)
      || equalsIgnoreCase(query.id, record.subjectId)
      || equalsIgnoreCase(query.id, taxId)
      || equalsIgnoreCase(query.id, taxIdHash || '');
    if (!idMatched) {
      return { matched: false, taxId, legalName, organizationDid, taxIdHash };
    }
  }

  if (query.email && !equalsIgnoreCase(query.email, email)) {
    return { matched: false, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.text && !includesIgnoreCase(`${legalName} ${addressText}`.trim(), query.text)) {
    return { matched: false, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.taxId && !equalsIgnoreCase(query.taxId, taxId)) {
    return { matched: false, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.taxIdHash && !equalsIgnoreCase(query.taxIdHash, taxIdHash || '')) {
    return { matched: false, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.legalName && !includesIgnoreCase(legalName, query.legalName)) {
    return { matched: false, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.subjectId && !equalsIgnoreCase(query.subjectId, record.subjectId)) {
    return { matched: false, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.issuerId && !equalsIgnoreCase(query.issuerId, record.issuerId)) {
    return { matched: false, taxId, legalName, organizationDid, taxIdHash };
  }
  if (query.credentialId && !equalsIgnoreCase(query.credentialId, record.credentialId)) {
    return { matched: false, taxId, legalName, organizationDid, taxIdHash };
  }

  return { matched: true, taxId, legalName, organizationDid, taxIdHash };
}

function buildSigningRoute(record: IssuedCredentialRecord): VerifyRouteContext {
  return {
    tenantId: record.tenantId,
    jurisdiction: record.jurisdiction,
    sector: record.sector,
    section: record.networkKind || 'test',
    format: 'pdf',
    resourceType: asNonEmptyString(record.resourceType) || 'contract',
    action: '_verify',
  };
}

function signCredentialRecord(
  record: IssuedCredentialRecord,
  format: 'vc+json' | 'vc+jwt',
): { signedCredential: Record<string, unknown>; vcJwt?: string } {
  const credential = asObject(record.credential);
  if (!credential) {
    throw new Error(`Issued credential ${record.id} has invalid credential payload.`);
  }
  const vc = credential as unknown as VerifiableCredentialV2;
  const signingRoute = buildSigningRoute(record);
  const issuerDid = typeof vc.issuer === 'string' ? vc.issuer.trim() : '';
  const signedCredential = attachProofToCredential(
    vc,
    signingRoute,
    issuerDid || undefined,
  ) as unknown as Record<string, unknown>;

  if (format === 'vc+jwt') {
    const vcJwt = record.representations?.vcJwt
      || convertCredentialToVcJwt(vc, signingRoute, issuerDid || undefined);
    return { signedCredential, vcJwt };
  }
  return { signedCredential };
}

function enrichRepresentativeCredentialMaterial(
  route: CredentialRetrieveRouteContext,
  record: IssuedCredentialRecord,
  didBindings: DidBindingRecord[],
  didDocuments: DidDocumentRecord[],
): IssuedCredentialRecord {
  if (!isLegalRepresentativeCredential(record)) return record;

  const credential = asObject(record.credential);
  if (!credential) return record;
  const subject = resolveCredentialSubject(credential);
  if (!subject || hasCredentialMaterialPopulated(subject)) return record;

  const organizationNode = resolveOrganizationNode(subject);
  const taxId = resolveTaxId(organizationNode) || resolveTaxId(subject);
  const organizationDid = resolveOrganizationDid(subject, record);
  const binding = resolveLatestDidBindingRecord(didBindings, route, {
    ...(organizationDid ? { did: organizationDid } : {}),
    ...(taxId ? { taxId } : {}),
  });
  const didDocument = binding ? undefined : resolveLatestDidDocumentRecord(didDocuments, route, {
    ...(organizationDid ? { did: organizationDid } : {}),
    ...(taxId ? { taxId } : {}),
  });
  const controllerPublicKeyJwk = asObject(binding?.controllerPublicKeyJwk)
    || asObject(didDocument?.controllerPublicKeyJwk);
  if (!controllerPublicKeyJwk) return record;

  const material = toJwkThumbprintSha256Urn(controllerPublicKeyJwk);
  if (!material) return record;

  return {
    ...record,
    credential: {
      ...credential,
      credentialSubject: {
        ...subject,
        hasCredential: {
          ...(asObject(subject.hasCredential) || {}),
          material,
        },
      },
    },
  };
}

function parseDirectQueries(requestUrl: URL): {
  primary: CredentialSearchInput;
  fallback?: CredentialSearchInput;
} {
  const params = requestUrl.searchParams;
  const identifier = asNonEmptyString(params.get('identifier'));
  const taxIdLegacy = asNonEmptyString(params.get('taxId') || params.get('taxID'));
  const taxId = identifier || taxIdLegacy;
  const queryId = asNonEmptyString(params.get('id'));
  const text = asNonEmptyString(params.get('text'));
  const email = asNonEmptyString(params.get('email'));
  const taxIdHash = asNonEmptyString(params.get('taxIdHash'));
  const legalName = asNonEmptyString(params.get('legalName') || params.get('name'));
  const subjectId = asNonEmptyString(params.get('subjectId'));
  const issuerId = asNonEmptyString(params.get('issuerId'));
  const credentialId = asNonEmptyString(params.get('credentialId'));

  if (!queryId && !text && !email && !taxId && !taxIdHash && !legalName && !subjectId && !issuerId && !credentialId) {
    throw new Error(
      'Credential retrieve requires at least one filter: id, identifier/taxId, taxIdHash, legalName, subjectId, issuerId, credentialId, text, or email.',
    );
  }

  const sharedQuery = {
    ...(queryId ? { id: queryId } : {}),
    ...(text ? { text } : {}),
    ...(email ? { email } : {}),
    ...(taxIdHash ? { taxIdHash } : {}),
    ...(legalName ? { legalName } : {}),
    ...(subjectId ? { subjectId } : {}),
    ...(issuerId ? { issuerId } : {}),
    ...(credentialId ? { credentialId } : {}),
  };

  const primary: CredentialSearchInput = {
    ...sharedQuery,
    ...(taxId ? { taxId } : {}),
  };
  const fallback: CredentialSearchInput | undefined = (
    identifier
    && taxIdLegacy
    && !equalsIgnoreCase(identifier, taxIdLegacy)
  )
    ? {
      ...sharedQuery,
      taxId: taxIdLegacy,
    }
    : undefined;

  return { primary, ...(fallback ? { fallback } : {}) };
}

type LatestResolved = {
  record: IssuedCredentialRecord;
  taxId: string;
  legalName: string;
  organizationDid: string;
  taxIdHash?: string;
};

type ResolvedStoredMatch = LatestResolved;

function collectMatchingStoredRecords(
  records: IssuedCredentialRecord[],
  query: CredentialSearchInput,
  typeFilter: string,
): ResolvedStoredMatch[] {
  const matches: LatestResolved[] = [];
  for (const record of records) {
    if (!recordMatchesType(record, typeFilter)) continue;
    const evaluated = matchesQuery(record, query);
    if (!evaluated.matched) continue;
    matches.push({
      record,
      taxId: evaluated.taxId,
      legalName: evaluated.legalName,
      organizationDid: evaluated.organizationDid,
      ...(evaluated.taxIdHash ? { taxIdHash: evaluated.taxIdHash } : {}),
    });
  }
  return matches;
}

function sortStoredMatchesByCreation(matches: ResolvedStoredMatch[]): ResolvedStoredMatch[] {
  return [...matches].sort((left, right) => {
    const leftCreatedMs = toMillis(left.record.createdAt);
    const rightCreatedMs = toMillis(right.record.createdAt);
    if (leftCreatedMs !== rightCreatedMs) return leftCreatedMs - rightCreatedMs;

    const leftUpdatedMs = toMillis(left.record.updatedAt);
    const rightUpdatedMs = toMillis(right.record.updatedAt);
    if (leftUpdatedMs !== rightUpdatedMs) return leftUpdatedMs - rightUpdatedMs;

    return left.record.id.localeCompare(right.record.id);
  });
}

function pickV1StoredSnapshot(matches: ResolvedStoredMatch[]): ResolvedStoredMatch | undefined {
  if (!matches.length) return undefined;
  return sortStoredMatchesByCreation(matches)[0];
}

function pickV2RegenerationBase(matches: ResolvedStoredMatch[]): ResolvedStoredMatch | undefined {
  if (!matches.length) return undefined;
  const sorted = sortStoredMatchesByCreation(matches);
  return sorted[sorted.length - 1];
}

function pickMatchByVersion(
  records: IssuedCredentialRecord[],
  query: CredentialSearchInput,
  typeFilter: string,
  requestedVersion: RequestedStoredVersion,
): ResolvedStoredMatch | undefined {
  const matches = collectMatchingStoredRecords(records, query, typeFilter);
  if (requestedVersion === 'v1') {
    // v1 contract: return the first stored snapshot exactly as historical baseline.
    return pickV1StoredSnapshot(matches);
  }
  // v2 contract: return the newest stored base record used to regenerate deterministic VC output.
  // NOTE: v2 logical source is the verified document flow (`urn:audit` legacy or `ipfs://` locator).
  // This endpoint currently re-signs the canonical stored credential derived from that flow.
  return pickV2RegenerationBase(matches);
}

export class CredentialRetrieveRequestManager {
  private readonly jobStore: InMemoryEntityJobStore<CredentialRetrieveRouteContext, CredentialRetrieveResult>;
  private readonly collectionsService: VerificationCollectionsService;

  constructor(
    jobStore: InMemoryEntityJobStore<CredentialRetrieveRouteContext, CredentialRetrieveResult>,
    collectionsService: VerificationCollectionsService = new VerificationCollectionsService(),
  ) {
    this.jobStore = jobStore;
    this.collectionsService = collectionsService;
  }

  async submit(route: CredentialRetrieveRouteContext, req: IncomingMessage): Promise<CredentialRetrieveSubmitOutcome> {
    try {
      const requestUrl = parseRequestUrl(req);
      const requestedVersion = resolveRequestedStoredVersion(
        asNonEmptyString(requestUrl.searchParams.get('version')),
      );
      const requestedFormat = resolveRequestedFormat(
        asNonEmptyString(requestUrl.searchParams.get('format')),
        '',
      );
      const requestedTypeFilter = resolveTypeFilterFromRoute(
        route,
        asNonEmptyString(requestUrl.searchParams.get('type') || requestUrl.searchParams.get('credentialType')),
      );
      const submission = await parseCredentialSearchSubmission(req, route.credentialType);
      const query = submission.queries[0];
      if (!query) {
        return {
          type: 'error',
          statusCode: 400,
          message: 'Credential retrieve requires one search query.',
        };
      }

      this.jobStore.enqueue(submission.thid, route);

      setImmediate(async () => {
        this.jobStore.markRunning(submission.thid);
        try {
          const records = await this.collectionsService.listIssuedCredentials();
          const didBindings = requestedVersion === 'v2'
            ? await this.collectionsService.listDidBindings()
            : [];
          const didDocuments = requestedVersion === 'v2'
            ? await this.collectionsService.listDidDocuments()
            : [];
          const scoped = records.filter((record) =>
            equalsIgnoreCase(record.tenantId, route.tenantId) &&
            equalsIgnoreCase(record.jurisdiction, route.jurisdiction) &&
            equalsIgnoreCase(record.sector, route.sector)
          );
          const selected = pickMatchByVersion(scoped, query, requestedTypeFilter, requestedVersion);
          if (!selected) {
            throw new Error('Credential not found for the provided retrieval filters.');
          }
          const materializedRecord = requestedVersion === 'v2'
            ? enrichRepresentativeCredentialMaterial(route, selected.record, didBindings, didDocuments)
            : selected.record;
          const signed = signCredentialRecord(materializedRecord, requestedFormat);
          const item: CredentialRetrieveResultItem = {
            issuedCredentialRecordId: materializedRecord.id,
            credentialId: materializedRecord.credentialId,
            credentialType: materializedRecord.credentialType,
            subjectId: materializedRecord.subjectId,
            issuerId: materializedRecord.issuerId,
            ...(selected.legalName ? { legalName: selected.legalName } : {}),
            ...(selected.taxId ? { taxId: selected.taxId } : {}),
            ...(selected.taxIdHash ? { taxIdHash: selected.taxIdHash } : {}),
            ...(selected.organizationDid ? { organizationDid: selected.organizationDid } : {}),
            credential: signed.signedCredential,
            ...(signed.vcJwt ? { vcJwt: signed.vcJwt } : {}),
          };
          this.jobStore.markSucceeded(submission.thid, {
            matchedCount: 1,
            format: requestedFormat,
            item,
          });
        } catch (error: unknown) {
          const message = (error as Error)?.message || String(error);
          console.error(`Credential _retrieve job failed (thid=${submission.thid}): ${message}`);
          this.jobStore.markFailed(submission.thid, message);
        }
      });

      return {
        type: 'accepted',
        location: buildCredentialRetrieveResponseLocation(route),
        retryAfter: 3,
      };
    } catch (error: unknown) {
      const message = (error as Error)?.message || 'Invalid credential retrieve payload.';
      return {
        type: 'error',
        statusCode: toStatusCodeFromParseError(message),
        message,
      };
    }
  }

  async retrieveDirect(
    route: CredentialRetrieveRouteContext,
    requestUrl: URL,
    acceptHeader: string,
  ): Promise<CredentialRetrieveDirectOutcome> {
    try {
      const requestedVersion = resolveRequestedStoredVersion(
        asNonEmptyString(requestUrl.searchParams.get('version')),
      );
      const directQueries = parseDirectQueries(requestUrl);
      const requestedFormat = resolveRequestedFormat(
        asNonEmptyString(requestUrl.searchParams.get('format')),
        acceptHeader,
      );
      const requestedTypeFilter = resolveTypeFilterFromRoute(
        route,
        asNonEmptyString(requestUrl.searchParams.get('type') || requestUrl.searchParams.get('credentialType')),
      );
      const records = await this.collectionsService.listIssuedCredentials();
      const didBindings = requestedVersion === 'v2'
        ? await this.collectionsService.listDidBindings()
        : [];
      const didDocuments = requestedVersion === 'v2'
        ? await this.collectionsService.listDidDocuments()
        : [];
      const scoped = records.filter((record) =>
        equalsIgnoreCase(record.tenantId, route.tenantId) &&
        equalsIgnoreCase(record.jurisdiction, route.jurisdiction) &&
        equalsIgnoreCase(record.sector, route.sector)
      );
      const selected = pickMatchByVersion(scoped, directQueries.primary, requestedTypeFilter, requestedVersion)
        || (directQueries.fallback
          ? pickMatchByVersion(scoped, directQueries.fallback, requestedTypeFilter, requestedVersion)
          : undefined);
      if (!selected) {
        return {
          type: 'error',
          statusCode: 404,
          message: 'Credential not found for the provided retrieval filters.',
        };
      }
      const materializedRecord = requestedVersion === 'v2'
        ? enrichRepresentativeCredentialMaterial(route, selected.record, didBindings, didDocuments)
        : selected.record;
      const signed = signCredentialRecord(materializedRecord, requestedFormat);
      return {
        type: 'succeeded',
        format: requestedFormat,
        credential: signed.signedCredential,
        ...(signed.vcJwt ? { vcJwt: signed.vcJwt } : {}),
      };
    } catch (error: unknown) {
      return {
        type: 'error',
        statusCode: 400,
        message: (error as Error)?.message || 'Invalid credential retrieve request.',
      };
    }
  }
}
