import type { DidService } from 'gdc-common-utils-ts/models/did';
import type { DidDocumentRecord, IssuedCredentialRecord } from './verification-collections/types.ts';
import { multibase58MultihashSha3_256 } from './multihash.ts';

type JsonObject = Record<string, unknown>;

export type DcatCatalogRouteScope = {
  tenantId: string;
  jurisdiction: string;
  sector: string;
};

export type DcatCatalogFilters = {
  sector?: string;
  jurisdiction?: string;
};

export type ProviderDataset = {
  datasetId: string;
  publisherDid: string;
  title: string;
  sector?: string;
  jurisdiction?: string;
  accessUrl: string;
};

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

function decodeDidWebSegment(raw: string): string {
  try {
    return decodeURIComponent(raw);
  } catch {
    return raw;
  }
}

function parseDidWebPathSegments(did: string): string[] | null {
  const normalized = did.trim();
  if (!normalized.startsWith('did:web:')) return null;
  const suffix = normalized.slice('did:web:'.length);
  if (!suffix) return null;
  const segments = suffix.split(':').map((segment) => decodeDidWebSegment(segment)).filter(Boolean);
  if (segments.length < 1) return null;
  return segments.slice(1);
}

function isDidWeb(did: string): boolean {
  return did.trim().toLowerCase().startsWith('did:web:');
}

function isIcaMembershipDid(did: string, scope: DcatCatalogRouteScope): boolean {
  const pathSegments = parseDidWebPathSegments(did);
  if (!pathSegments || pathSegments.length < 3) return false;
  const [tenantId, cdsToken, versionToken] = pathSegments;
  if (!tenantId || !cdsToken || !versionToken) return false;
  return tenantId.toLowerCase() === scope.tenantId.trim().toLowerCase()
    && cdsToken.toLowerCase() === `cds-${scope.jurisdiction.trim().toLowerCase()}`
    && versionToken.toLowerCase() === 'v1';
}

function didWebToDidJsonUrl(did: string): string {
  const normalized = did.trim();
  if (!normalized.startsWith('did:web:')) return normalized;
  const suffix = normalized.slice('did:web:'.length);
  if (!suffix) return normalized;
  const segments = suffix.split(':').map((segment) => decodeDidWebSegment(segment)).filter(Boolean);
  if (!segments.length) return normalized;
  const host = segments[0];
  const path = segments.slice(1).join('/');
  if (!path) {
    return `https://${host}/.well-known/did.json`;
  }
  return `https://${host}/${path}/did.json`;
}

function resolveRelativeUrl(baseUrl: string, value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return '';
  try {
    return new URL(trimmed, baseUrl).toString();
  } catch {
    return trimmed;
  }
}

function toDatasetId(publisherDid: string): string {
  return encodeURIComponent(publisherDid);
}

function parseCategory(value: unknown): string {
  const raw = asNonEmptyString(value);
  if (!raw) return '';
  return raw.split(',')[0]?.trim() || '';
}

function parseJurisdiction(value: unknown): string {
  const raw = asNonEmptyString(value);
  return raw ? raw.toUpperCase() : '';
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

function resolvePublisherDid(
  subject: JsonObject,
  record: IssuedCredentialRecord,
  scope: DcatCatalogRouteScope,
): string {
  const organizationNode = resolveOrganizationNode(subject);
  const candidates = [
    asNonEmptyString(organizationNode.id),
    asNonEmptyString(subject.id),
    asNonEmptyString(record.subjectId),
  ].filter(Boolean);

  for (const candidate of candidates) {
    if (!isDidWeb(candidate)) continue;
    if (isIcaMembershipDid(candidate, scope)) continue;
    return candidate;
  }
  return '';
}

function toProviderDataset(record: IssuedCredentialRecord, scope: DcatCatalogRouteScope): ProviderDataset | null {
  const credential = asObject(record.credential);
  if (!credential) return null;

  const subject = resolveCredentialSubject(credential) || {};
  const organizationNode = resolveOrganizationNode(subject);
  const publisherDid = resolvePublisherDid(subject, record, scope);
  if (!publisherDid) return null;
  const taxId = resolveTaxId(organizationNode) || resolveTaxId(subject);

  const title =
    asNonEmptyString(organizationNode.legalName)
    || asNonEmptyString(organizationNode.name)
    || asNonEmptyString(organizationNode.alternateName)
    || asNonEmptyString(subject.legalName)
    || asNonEmptyString(subject.name)
    || publisherDid;
  const sector = parseCategory(organizationNode.category) || parseCategory(subject.category) || record.sector;
  const jurisdiction = parseJurisdiction(organizationNode.addressCountry)
    || parseJurisdiction(subject.addressCountry)
    || record.jurisdiction.toUpperCase();
  const accessUrl = didWebToDidJsonUrl(publisherDid);

  return {
    datasetId: taxId ? toDatasetId(multibase58MultihashSha3_256(taxId)) : toDatasetId(publisherDid),
    publisherDid,
    title,
    sector,
    jurisdiction,
    accessUrl,
  };
}

export function buildProviderDatasetsFromIssuedCredentials(
  records: IssuedCredentialRecord[],
  scope: DcatCatalogRouteScope,
): ProviderDataset[] {
  const dedup = new Map<string, ProviderDataset>();

  records.forEach((record) => {
    if (!equalsIgnoreCase(record.tenantId, scope.tenantId)) return;
    if (!equalsIgnoreCase(record.jurisdiction, scope.jurisdiction)) return;
    if (!equalsIgnoreCase(record.sector, scope.sector)) return;
    const dataset = toProviderDataset(record, scope);
    if (!dataset) return;
    if (!dedup.has(dataset.datasetId)) {
      dedup.set(dataset.datasetId, dataset);
    }
  });

  return Array.from(dedup.values())
    .sort((left, right) => left.title.localeCompare(right.title));
}

export function filterProviderDatasets(
  datasets: ProviderDataset[],
  filters?: DcatCatalogFilters,
): ProviderDataset[] {
  if (!filters) return datasets;
  const sectorFilter = asNonEmptyString(filters.sector).toLowerCase();
  const jurisdictionFilter = asNonEmptyString(filters.jurisdiction).toUpperCase();
  return datasets.filter((dataset) => {
    if (sectorFilter && asNonEmptyString(dataset.sector).toLowerCase() !== sectorFilter) return false;
    if (jurisdictionFilter && asNonEmptyString(dataset.jurisdiction).toUpperCase() !== jurisdictionFilter) return false;
    return true;
  });
}

export function filterProviderDatasetsByActiveDidDocuments(
  datasets: ProviderDataset[],
  didDocuments: DidDocumentRecord[],
  scope: DcatCatalogRouteScope,
): ProviderDataset[] {
  const latestByDid = new Map<string, DidDocumentRecord>();

  didDocuments.forEach((record) => {
    if (!equalsIgnoreCase(record.tenantId, scope.tenantId)) return;
    if (!equalsIgnoreCase(record.jurisdiction, scope.jurisdiction)) return;
    if (!equalsIgnoreCase(record.sector, scope.sector)) return;
    if (!record.did) return;
    const existing = latestByDid.get(record.did);
    if (!existing || existing.updatedAt.localeCompare(record.updatedAt) < 0) {
      latestByDid.set(record.did, record);
    }
  });

  const activeDids = new Set(
    Array.from(latestByDid.values())
      .filter((record) => record.status === 'confirmed')
      .map((record) => record.did),
  );

  return datasets.filter((dataset) => activeDids.has(dataset.publisherDid));
}

export function buildDcatCatalog(catalogBaseUrl: string, datasets: ProviderDataset[]): JsonObject {
  return {
    '@context': {
      dcat: 'https://www.w3.org/ns/dcat#',
      dcterms: 'http://purl.org/dc/terms/',
      odrl: 'http://www.w3.org/ns/odrl/2/',
    },
    '@id': catalogBaseUrl,
    '@type': 'dcat:Catalog',
    'dcat:dataset': datasets.map((dataset) => ({
      '@id': `${catalogBaseUrl}/datasets/${dataset.datasetId}`,
      '@type': 'dcat:Dataset',
      'dcterms:title': dataset.title,
      'dcterms:identifier': dataset.datasetId,
      'dcterms:publisher': { '@id': dataset.publisherDid },
      'dcat:theme': dataset.sector || undefined,
      'dcterms:spatial': dataset.jurisdiction || undefined,
      'dcat:distribution': [
        {
          '@type': 'dcat:Distribution',
          'dcat:accessURL': dataset.accessUrl,
        },
      ],
      'odrl:hasPolicy': {
        '@type': 'odrl:Set',
      },
    })),
  };
}

function toDcatService(catalogBaseUrl: string, service: DidService): JsonObject | null {
  const serviceId = String(service.id || '').trim();
  const endpointUrl = resolveRelativeUrl(catalogBaseUrl, String(service.serviceEndpoint || ''));
  if (!serviceId || !endpointUrl) return null;

  return {
    '@id': serviceId,
    '@type': 'dcat:DataService',
    'dcterms:title': String(service.type || '').trim() || 'Service',
    'dcterms:identifier': serviceId,
    'dcat:endpointURL': endpointUrl,
  };
}

export function buildDcatDiscoveryCatalog(
  catalogBaseUrl: string,
  services: DidService[],
): JsonObject {
  return {
    '@context': {
      dcat: 'https://www.w3.org/ns/dcat#',
      dcterms: 'http://purl.org/dc/terms/',
      odrl: 'http://www.w3.org/ns/odrl/2/',
    },
    '@id': catalogBaseUrl,
    '@type': 'dcat:Catalog',
    'dcat:dataset': [],
    'dcat:service': services
      .map((service) => toDcatService(catalogBaseUrl, service))
      .filter((service): service is JsonObject => Boolean(service)),
  };
}

export function findProviderDatasetById(
  datasets: ProviderDataset[],
  datasetId: string,
): ProviderDataset | undefined {
  const direct = datasets.find((item) => item.datasetId === datasetId);
  if (direct) return direct;
  try {
    const decoded = decodeURIComponent(datasetId);
    return datasets.find((item) => item.publisherDid === decoded);
  } catch {
    return undefined;
  }
}
