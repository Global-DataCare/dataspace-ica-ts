import { randomUUID } from 'node:crypto';
import type { DidcommAttachment, VerifyBundleResponse, VerifyRouteContext } from '../types.ts';
import {
  createVerificationCollectionsAdapter,
  resetVerificationCollectionsMemAdapterStateForTests,
} from './verification-collections/adapters.ts';
import { DataspaceSyncService } from './dataspace-sync.ts';
import type {
  DidBindingRecord,
  DidDocumentRecord,
  EvidenceRecord,
  IssuedCredentialRecord,
  JsonObject,
  VerificationCollectionsAdapter,
  VerificationCollectionsConfig,
  VerificationCollectionsProvider,
} from './verification-collections/types.ts';

export type {
  DidBindingRecord,
  DidDocumentRecord,
  EvidenceRecord,
  IssuedCredentialRecord,
  JsonObject,
  VerificationCollectionsConfig,
  VerificationCollectionsProvider,
} from './verification-collections/types.ts';

export type IssuedCredentialLookup = {
  tenantId: string;
  jurisdiction: string;
  sector: string;
  credentialType: string;
  issuedCredentialRecordId?: string;
  credentialId?: string;
  subjectId?: string;
  credentialStatusId?: string;
};

const ISSUED_CREDENTIALS_COLLECTION_LEAF = 'issued_credentials';
const EVIDENCE_COLLECTION_LEAF = 'evidence_records';
const DID_BINDINGS_COLLECTION_LEAF = 'did_bindings';
const DID_DOCUMENTS_COLLECTION_LEAF = 'did_documents';

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function asJsonObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function credentialStatusIdFromCredential(credential: JsonObject): string {
  const credentialStatus = asJsonObject(credential.credentialStatus);
  return asNonEmptyString(credentialStatus?.id);
}

function includesValue(left: string, right: string): boolean {
  return left.trim().toLowerCase() === right.trim().toLowerCase();
}

function parseProvider(raw: string | undefined, fallback: VerificationCollectionsProvider): VerificationCollectionsProvider {
  const normalized = (raw || '').trim().toLowerCase();
  if (!normalized) return fallback;
  if (normalized === 'mem' || normalized === 'firestore' || normalized === 'postgres') {
    return normalized as VerificationCollectionsProvider;
  }
  throw new Error(`Unsupported DB_PROVIDER="${normalized}". Use "mem", "firestore" or "postgres".`);
}

function buildCollectionName(prefix: string, leaf: string): string {
  const normalizedPrefix = prefix.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
  if (!normalizedPrefix) return leaf;
  return `${normalizedPrefix}_${leaf}`;
}

export function loadVerificationCollectionsConfigFromEnv(): VerificationCollectionsConfig {
  const provider = parseProvider(process.env.DB_PROVIDER, 'mem');
  const prefix = (process.env.ICA_COLLECTIONS_PREFIX || 'ica').trim();
  return {
    provider,
    required: parseBoolean(process.env.ICA_COLLECTIONS_REQUIRED, true),
    firestoreProjectId: (process.env.FIRESTORE_PROJECT_ID || '').trim() || undefined,
    firestoreCollectionPrefix: prefix,
    postgresUrl: (process.env.POSTGRES_URL || '').trim() || undefined,
  };
}

export function resolveIssuedCredentialsCollectionName(prefix: string): string {
  return buildCollectionName(prefix, ISSUED_CREDENTIALS_COLLECTION_LEAF);
}

export function resolveEvidenceCollectionName(prefix: string): string {
  return buildCollectionName(prefix, EVIDENCE_COLLECTION_LEAF);
}

export function resolveDidBindingsCollectionName(prefix: string): string {
  return buildCollectionName(prefix, DID_BINDINGS_COLLECTION_LEAF);
}

export function resolveDidDocumentsCollectionName(prefix: string): string {
  return buildCollectionName(prefix, DID_DOCUMENTS_COLLECTION_LEAF);
}

function bindingRecordId(route: VerifyRouteContext, taxId: string): string {
  return [
    route.tenantId.trim().toLowerCase(),
    route.jurisdiction.trim().toLowerCase(),
    route.sector.trim().toLowerCase(),
    taxId.trim().toUpperCase(),
  ].join('::');
}

function extractCredentialRecords(
  route: VerifyRouteContext,
  thid: string,
  bundle: VerifyBundleResponse,
  nowIso: string,
  attachments: DidcommAttachment[] = [],
): { issued: IssuedCredentialRecord[]; evidence: EvidenceRecord[] } {
  const issued: IssuedCredentialRecord[] = [];
  const evidence: EvidenceRecord[] = [];

  for (const entry of bundle.data || []) {
    const resource = asJsonObject(entry.resource);
    if (!resource) continue;

    const recordId = `urn:uuid:${randomUUID()}`;
    const credentialId = asNonEmptyString(resource.id) || recordId;
    const vcJwt = attachments
      .map((attachment) => asJsonObject(attachment.data?.json))
      .find((json) => asNonEmptyString(json?.credentialId) === credentialId);
    const subject = asJsonObject(resource.credentialSubject);
    const subjectId = asNonEmptyString(subject?.id) || '';
    const issuerId = asNonEmptyString(resource.issuer);
    const credentialTypeRaw = resource.type;
    const credentialType = Array.isArray(credentialTypeRaw)
      ? credentialTypeRaw.map((item) => asNonEmptyString(item)).filter(Boolean).join(',')
      : asNonEmptyString(credentialTypeRaw) || asNonEmptyString(entry.type);

    issued.push({
      id: recordId,
      tenantId: route.tenantId,
      jurisdiction: route.jurisdiction.toUpperCase(),
      sector: route.sector,
      resourceType: route.resourceType,
      thid,
      credentialType: credentialType || 'VerifiableCredential',
      credentialId,
      subjectId,
      issuerId,
      credential: resource,
      ...(asNonEmptyString(vcJwt?.jwt) ? { representations: { vcJwt: asNonEmptyString(vcJwt?.jwt) } } : {}),
      ...(asJsonObject(entry.publicKeyJwk) ? { publicKeyJwk: asJsonObject(entry.publicKeyJwk) } : {}),
      ...(asNonEmptyString(entry.keySource) ? { keySource: asNonEmptyString(entry.keySource) as 'attachment' | 'generated' } : {}),
      originDataspaceDid: issuerId || undefined,
      createdAt: nowIso,
      updatedAt: nowIso,
    });

    const evidenceEntries = Array.isArray(resource.evidence) ? resource.evidence : [];
    for (const evidenceEntry of evidenceEntries) {
      const evidenceObject = asJsonObject(evidenceEntry);
      if (!evidenceObject) continue;
      evidence.push({
        id: `urn:uuid:${randomUUID()}`,
        issuedCredentialRecordId: recordId,
        tenantId: route.tenantId,
        jurisdiction: route.jurisdiction.toUpperCase(),
        sector: route.sector,
        resourceType: route.resourceType,
        thid,
        evidenceType: asNonEmptyString(evidenceObject.type) || 'unknown',
        evidence: evidenceObject,
        originDataspaceDid: issuerId || undefined,
        createdAt: nowIso,
        updatedAt: nowIso,
      });
    }
  }

  return { issued, evidence };
}

function extractDidBindingRecords(
  route: VerifyRouteContext,
  thid: string,
  bundle: VerifyBundleResponse,
  nowIso: string,
): DidBindingRecord[] {
  const data = Array.isArray(bundle.data) ? bundle.data : [];
  const organizationEntry = data.find((entry) => entry?.type === 'Organization-verification-v1.0');
  const personEntry = data.find((entry) => entry?.type === 'LegalRepresentative-verification-v1.0');
  const organizationResource = asJsonObject(organizationEntry?.resource);
  const personResource = asJsonObject(personEntry?.resource);
  const organizationSubject = asJsonObject(organizationResource?.credentialSubject);
  const personSubject = asJsonObject(personResource?.credentialSubject);
  const memberOf = asJsonObject(personSubject?.memberOf);
  const organizationTaxId = asNonEmptyString(organizationSubject?.taxID || organizationSubject?.taxId || memberOf?.taxID || memberOf?.taxId);
  if (!organizationTaxId) return [];

  const organizationPublicKeyJwk = asJsonObject(organizationEntry?.publicKeyJwk);
  const controllerPublicKeyJwk = asJsonObject(personEntry?.publicKeyJwk);
  if (!organizationPublicKeyJwk && !controllerPublicKeyJwk) return [];

  return [
    {
      id: bindingRecordId(route, organizationTaxId),
      tenantId: route.tenantId,
      jurisdiction: route.jurisdiction.toUpperCase(),
      sector: route.sector,
      resourceType: route.resourceType,
      thid,
      taxId: organizationTaxId,
      did: asNonEmptyString(organizationSubject?.id) || undefined,
      controllerSameAs: asNonEmptyString(personSubject?.sameAs) || undefined,
      ...(controllerPublicKeyJwk ? { controllerPublicKeyJwk } : {}),
      ...(organizationPublicKeyJwk ? { organizationPublicKeyJwk } : {}),
      ...(asNonEmptyString(organizationEntry?.keySource) ? { organizationKeySource: asNonEmptyString(organizationEntry?.keySource) as 'attachment' | 'generated' } : {}),
      status: 'draft',
      createdAt: nowIso,
      updatedAt: nowIso,
    },
  ];
}

export class VerificationCollectionsService {
  private readonly config: VerificationCollectionsConfig;
  private readonly adapter: VerificationCollectionsAdapter;
  private readonly dataspaceSyncService: DataspaceSyncService;

  constructor(
    config: VerificationCollectionsConfig = loadVerificationCollectionsConfigFromEnv(),
    dataspaceSyncService: DataspaceSyncService = new DataspaceSyncService(),
  ) {
    this.config = config;
    this.adapter = createVerificationCollectionsAdapter(config);
    this.dataspaceSyncService = dataspaceSyncService;
  }

  async persistFromVerificationBundle(
    route: VerifyRouteContext,
    thid: string,
    bundle: VerifyBundleResponse,
    attachments: DidcommAttachment[] = [],
  ): Promise<void> {
    const nowIso = new Date().toISOString();
    const extracted = extractCredentialRecords(route, thid, bundle, nowIso, attachments);
    const didBindings = extractDidBindingRecords(route, thid, bundle, nowIso);
    if (!extracted.issued.length && !extracted.evidence.length && !didBindings.length) {
      return;
    }
    const scope = {
      tenantId: route.tenantId,
      jurisdiction: route.jurisdiction.toUpperCase(),
      sector: route.sector,
    };
    extracted.issued = extracted.issued.map((record) => ({
      ...record,
      dataspacePublications: this.dataspaceSyncService.buildInitialPublications(record.originDataspaceDid, scope),
    }));
    extracted.evidence = extracted.evidence.map((record) => ({
      ...record,
      dataspacePublications: this.dataspaceSyncService.buildInitialPublications(record.originDataspaceDid, scope),
    }));

    await this.persistRecords(
      extracted.issued,
      extracted.evidence,
      didBindings,
      [],
      'Verification collections persistence failed',
    );

    try {
      const syncedIssued = await Promise.all(
        extracted.issued.map((record) =>
          this.dataspaceSyncService.syncIssuedCredentialRecord(record, { event: 'issued', status: 'active' })),
      );
      const syncedEvidence = await Promise.all(
        extracted.evidence.map((record) =>
          this.dataspaceSyncService.syncEvidenceRecord(record, { event: 'added', status: 'active' })),
      );
      await this.persistRecords(syncedIssued, syncedEvidence, [], [], 'Dataspace sync persistence failed');
    } catch (error: unknown) {
      const message = `Dataspace sync failed after verification persistence: ${(error as Error)?.message || String(error)}`;
      if (this.config.required) {
        throw new Error(message);
      }
      console.error(message);
    }
  }

  async storeIssuedCredentials(records: IssuedCredentialRecord[]): Promise<void> {
    await this.persistRecords(records, [], [], [], 'Issued credentials persistence failed');
  }

  async upsertIssuedCredential(record: IssuedCredentialRecord): Promise<void> {
    await this.storeIssuedCredentials([record]);
  }

  async storeEvidenceRecords(records: EvidenceRecord[]): Promise<void> {
    await this.persistRecords([], records, [], [], 'Evidence records persistence failed');
  }

  async storeDidBindings(records: DidBindingRecord[]): Promise<void> {
    await this.persistRecords([], [], records, [], 'DID bindings persistence failed');
  }

  async storeDidDocuments(records: DidDocumentRecord[]): Promise<void> {
    await this.persistRecords([], [], [], records, 'DID documents persistence failed');
  }

  private async persistRecords(
    issuedRecords: IssuedCredentialRecord[],
    evidenceRecords: EvidenceRecord[],
    didBindingRecords: DidBindingRecord[],
    didDocumentRecords: DidDocumentRecord[],
    errorPrefix: string,
  ): Promise<void> {
    if (!issuedRecords.length && !evidenceRecords.length && !didBindingRecords.length && !didDocumentRecords.length) {
      return;
    }

    try {
      await this.adapter.storeIssuedCredentials(issuedRecords);
      await this.adapter.storeEvidenceRecords(evidenceRecords);
      await this.adapter.storeDidBindings(didBindingRecords);
      await this.adapter.storeDidDocuments(didDocumentRecords);
    } catch (error: unknown) {
      const message = `${errorPrefix}: ${(error as Error)?.message || String(error)}`;
      if (this.config.required) {
        throw new Error(message);
      }
      console.error(message);
    }
  }

  async listIssuedCredentials(): Promise<IssuedCredentialRecord[]> {
    return this.adapter.listIssuedCredentials();
  }

  async listEvidenceRecords(): Promise<EvidenceRecord[]> {
    return this.adapter.listEvidenceRecords();
  }

  async listDidBindings(): Promise<DidBindingRecord[]> {
    return this.adapter.listDidBindings();
  }

  async listDidDocuments(): Promise<DidDocumentRecord[]> {
    return this.adapter.listDidDocuments();
  }

  async findIssuedCredential(lookup: IssuedCredentialLookup): Promise<IssuedCredentialRecord | undefined> {
    const records = await this.adapter.listIssuedCredentials();
    const scoped = records.filter((record) =>
      includesValue(record.tenantId, lookup.tenantId) &&
      includesValue(record.jurisdiction, lookup.jurisdiction) &&
      includesValue(record.sector, lookup.sector) &&
      includesValue(record.credentialType, lookup.credentialType)
    );

    if (lookup.issuedCredentialRecordId) {
      return scoped.find((record) => includesValue(record.id, lookup.issuedCredentialRecordId || ''));
    }
    if (lookup.credentialId) {
      return scoped.find((record) => includesValue(record.credentialId, lookup.credentialId || ''));
    }
    if (lookup.subjectId) {
      return scoped.find((record) => includesValue(record.subjectId, lookup.subjectId || ''));
    }
    if (lookup.credentialStatusId) {
      return scoped.find((record) =>
        includesValue(credentialStatusIdFromCredential(record.credential), lookup.credentialStatusId || ''),
      );
    }
    return undefined;
  }
}

export function createVerificationCollectionsServiceFromEnv(): VerificationCollectionsService {
  return new VerificationCollectionsService(loadVerificationCollectionsConfigFromEnv());
}

export function createVerificationCollectionsServiceFromEnvWithSync(
  dataspaceSyncService: DataspaceSyncService,
): VerificationCollectionsService {
  return new VerificationCollectionsService(loadVerificationCollectionsConfigFromEnv(), dataspaceSyncService);
}

export function resetVerificationCollectionsMemStateForTests(): void {
  resetVerificationCollectionsMemAdapterStateForTests();
}
