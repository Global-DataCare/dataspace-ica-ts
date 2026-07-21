import { createHash } from 'node:crypto';
import {
  buildGaiaXParticipantAttachment,
  buildGaiaXVcJwtAttachment,
  buildIcaMemberDiscoveryData,
} from 'gdc-common-utils-ts/convert/schemaorg-to-gaia-x';
import { GaiaXCredentialAttachmentRole } from 'gdc-common-utils-ts/models/gaia-x';
import type {
  GaiaXCredentialAttachmentRoleValue,
  IcaMemberDiscoveryData,
} from 'gdc-common-utils-ts/models/gaia-x';
import type { DidDocumentRecord, IssuedCredentialRecord } from './verification-collections/types.ts';
import type { ProviderDataset } from './dcat-catalog.ts';

type JsonObject = Record<string, unknown>;

export type MemberDiscoveryScope = {
  tenantId: string;
  jurisdiction: string;
  sector: string;
};

export type DiscoveryFetchResult = {
  document: JsonObject;
  sourceUpdatedAt?: string;
  etag?: string;
};

export type DiscoveryJsonFetcher = (url: string) => Promise<DiscoveryFetchResult>;

/**
 * Parses the transitional ICA host allowlist.
 *
 * Entries may be bare IPv4/IPv6 addresses, DNS names, or HTTP(S) origins. The
 * comparison is deliberately hostname-only so an IP can move from HTTP to
 * HTTPS without granting access to another host. Paths, credentials, queries
 * and fragments are rejected to keep the SSRF boundary explicit.
 */
export function parseMemberDiscoveryAllowedHosts(csv: string | undefined): ReadonlySet<string> {
  const hosts = new Set<string>();
  for (const entry of String(csv || '').split(',').map((value) => value.trim()).filter(Boolean)) {
    const candidate = /^[a-z][a-z0-9+.-]*:\/\//i.test(entry) ? entry : `https://${entry}`;
    let parsed: URL;
    try {
      parsed = new URL(candidate);
    } catch {
      throw new Error(`Invalid ICA member discovery allowlist entry '${entry}'.`);
    }
    if (!['http:', 'https:'].includes(parsed.protocol)
      || parsed.username
      || parsed.password
      || (parsed.pathname && parsed.pathname !== '/')
      || parsed.search
      || parsed.hash
      || !parsed.hostname) {
      throw new Error(`Invalid ICA member discovery allowlist entry '${entry}'. Use an IP, DNS name, or HTTP(S) origin.`);
    }
    hosts.add(parsed.hostname.toLowerCase());
  }
  return hosts;
}

/** Returns true only when the dataset URL is HTTP(S) and its host is allowed. */
export function isMemberDiscoveryUrlAllowed(url: string, allowedHosts: ReadonlySet<string>): boolean {
  try {
    const parsed = new URL(url);
    return ['http:', 'https:'].includes(parsed.protocol) && allowedHosts.has(parsed.hostname.toLowerCase());
  } catch {
    return false;
  }
}

type CachedMember = {
  expiresAtMs: number;
  value: IcaMemberDiscoveryData;
};

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value) ? value as JsonObject : undefined;
}

function asString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function credentialSubjectMatchesDid(record: IssuedCredentialRecord, did: string): boolean {
  const subject = asObject(record.credential.credentialSubject);
  const memberOf = asObject(subject?.memberOf);
  return [record.subjectId, subject?.id, subject?.['@id'], memberOf?.id, memberOf?.['@id']]
    .some((value) => asString(value) === did);
}

function isOrganizationCredential(record: IssuedCredentialRecord): boolean {
  const types = Array.isArray(record.credential.type) ? record.credential.type : [record.credential.type];
  return types.some((value) => asString(value).toLowerCase() === 'organizationcredential')
    || record.credentialType.toLowerCase().includes('organizationcredential');
}

function selectMemberCredentials(records: IssuedCredentialRecord[], dataset: ProviderDataset): JsonObject[] {
  const latestById = new Map<string, IssuedCredentialRecord>();
  records.filter((record) => credentialSubjectMatchesDid(record, dataset.publisherDid)).forEach((record) => {
    const key = record.credentialId || record.id;
    const existing = latestById.get(key);
    if (!existing || existing.updatedAt.localeCompare(record.updatedAt) < 0) latestById.set(key, record);
  });
  return Array.from(latestById.values())
    .sort((left, right) => Number(isOrganizationCredential(right)) - Number(isOrganizationCredential(left)))
    .map((record) => record.credential);
}

function resolveUrl(baseUrl: string, value: unknown): string {
  const raw = asString(value);
  if (!raw) return '';
  try {
    return new URL(raw, baseUrl).toString();
  } catch {
    return '';
  }
}

function services(document: JsonObject): JsonObject[] {
  return Array.isArray(document.service)
    ? document.service.map(asObject).filter((value): value is JsonObject => Boolean(value))
    : [];
}

function findServiceUrl(document: JsonObject, didUrl: string, predicate: (text: string) => boolean): string {
  const service = services(document).find((entry) => predicate([
    asString(entry.id),
    asString(entry.type),
    asString(entry.serviceEndpoint),
  ].join(' ').toLowerCase()));
  return resolveUrl(didUrl, service?.serviceEndpoint);
}

function siblingWellKnownUrl(didUrl: string, fileName: string): string {
  const parsed = new URL(didUrl);
  parsed.pathname = parsed.pathname.replace(/(?:\.well-known\/)?did\.json$/i, `.well-known/${fileName}`);
  parsed.search = '';
  parsed.hash = '';
  return parsed.toString();
}

function extractEnvelopedJwt(document: JsonObject): string {
  const proof = asObject(document.proof);
  const id = asString(proof?.id);
  const prefix = 'data:application/vc+jwt,';
  if (!id.startsWith(prefix)) throw new Error('Artifact is not an EnvelopedVerifiableCredential carrying application/vc+jwt.');
  return decodeURIComponent(id.slice(prefix.length));
}

function sha256(document: JsonObject): string {
  return `sha256:${createHash('sha256').update(JSON.stringify(document)).digest('hex')}`;
}

/**
 * In-memory, bounded-age ICA autodiscovery cache.
 *
 * Only ICA-authorized members supplied by the caller are traversed. Each
 * refresh resolves the member DID document, the exact signed Gaia-X VC-JWT
 * artifacts advertised by that DID, and its DCAT catalog. Current schema.org
 * VCs remain the locally issued ICA records in `vc[]`; they are never converted
 * into, or substituted for, signed Gaia-X attachments.
 */
export class MemberDiscoveryCache {
  private readonly cache = new Map<string, CachedMember>();
  private readonly fetchJson: DiscoveryJsonFetcher;
  private readonly maxAgeSeconds: number;

  constructor(
    fetchJson: DiscoveryJsonFetcher = async (url) => {
      const response = await fetch(url, { headers: { accept: 'application/json, application/ld+json' } });
      if (!response.ok) throw new Error(`Discovery fetch ${url} failed with HTTP ${response.status}.`);
      const document = await response.json() as JsonObject;
      return {
        document,
        sourceUpdatedAt: response.headers.get('last-modified') || undefined,
        etag: response.headers.get('etag') || undefined,
      };
    },
    maxAgeSeconds = 300,
  ) {
    this.fetchJson = fetchJson;
    this.maxAgeSeconds = maxAgeSeconds;
  }

  async resolve(input: Readonly<{
    dataset: ProviderDataset;
    issuedCredentials: IssuedCredentialRecord[];
    didDocuments: DidDocumentRecord[];
    forceRefresh?: boolean;
    now?: Date;
  }>): Promise<IcaMemberDiscoveryData> {
    const now = input.now || new Date();
    const cached = this.cache.get(input.dataset.publisherDid);
    if (!input.forceRefresh && cached && cached.expiresAtMs > now.getTime()) return cached.value;

    const vc = selectMemberCredentials(input.issuedCredentials, input.dataset);
    if (!vc.length || !input.issuedCredentials.some((record) => isOrganizationCredential(record) && credentialSubjectMatchesDid(record, input.dataset.publisherDid))) {
      throw new Error(`Authorized member '${input.dataset.publisherDid}' has no OrganizationCredential.`);
    }

    let didResult: DiscoveryFetchResult;
    try {
      didResult = await this.fetchJson(input.dataset.accessUrl);
    } catch (error) {
      const local = input.didDocuments
        .filter((record) => record.did === input.dataset.publisherDid && record.status === 'confirmed')
        .sort((left, right) => right.updatedAt.localeCompare(left.updatedAt))[0];
      if (!local) throw error;
      didResult = { document: local.didDocument, sourceUpdatedAt: local.updatedAt };
    }

    const participantUrl = findServiceUrl(didResult.document, input.dataset.accessUrl, (text) =>
      text.includes('legal-participant') || text.includes('legalparticipant') || text.includes('legalperson'))
      || siblingWellKnownUrl(input.dataset.accessUrl, 'legal-participant.vc.json');
    const participant = await this.fetchJson(participantUrl);
    const attachments = [buildGaiaXParticipantAttachment({
      id: participantUrl,
      jwt: extractEnvelopedJwt(participant.document),
    })];

    const artifactCandidates: Array<{ file: string; role: GaiaXCredentialAttachmentRoleValue }> = [
      { file: 'service-offering-index.json', role: GaiaXCredentialAttachmentRole.ServiceOffering },
      { file: 'service-offering-research.json', role: GaiaXCredentialAttachmentRole.ServiceOffering },
    ];
    for (const candidate of artifactCandidates) {
      const advertised = findServiceUrl(didResult.document, input.dataset.accessUrl, (text) => text.includes(candidate.file));
      const url = advertised || siblingWellKnownUrl(input.dataset.accessUrl, candidate.file);
      try {
        const artifact = await this.fetchJson(url);
        attachments.push(buildGaiaXVcJwtAttachment({ id: url, jwt: extractEnvelopedJwt(artifact.document), role: candidate.role }));
      } catch {
        // Service offerings are optional per host capability; participant is not.
      }
    }

    const catalogUrl = findServiceUrl(didResult.document, input.dataset.accessUrl, (text) =>
      text.includes('catalogservice') || text.includes('dsp-catalog') || text.includes('dcat3/catalog'));
    let dcat: IcaMemberDiscoveryData['dcat'];
    if (catalogUrl) {
      try {
        const catalog = await this.fetchJson(catalogUrl);
        dcat = {
          document: catalog.document,
          meta: {
            sourceUrl: catalogUrl,
            fetchedAt: now.toISOString(),
            sourceUpdatedAt: catalog.sourceUpdatedAt,
            etag: catalog.etag,
            contentHash: sha256(catalog.document),
          },
        };
      } catch {
        // A member remains discoverable when its optional catalog is temporarily unavailable.
      }
    }

    const expiresAt = new Date(now.getTime() + this.maxAgeSeconds * 1000);
    const value = buildIcaMemberDiscoveryData({
      id: input.dataset.publisherDid,
      vc,
      did: {
        document: didResult.document as any,
        meta: {
          sourceUrl: input.dataset.accessUrl,
          fetchedAt: now.toISOString(),
          sourceUpdatedAt: didResult.sourceUpdatedAt,
          etag: didResult.etag,
          contentHash: sha256(didResult.document),
        },
      },
      attachments,
      dcat,
      meta: { assembledAt: now.toISOString(), refreshAfter: expiresAt.toISOString() },
    });
    this.cache.set(input.dataset.publisherDid, { expiresAtMs: expiresAt.getTime(), value });
    return value;
  }
}
