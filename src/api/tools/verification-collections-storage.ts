import { randomUUID } from 'node:crypto';
import type { VerifyBundleResponse, VerifyRouteContext } from '../types.ts';
import {
  createVerificationCollectionsAdapter,
  resetVerificationCollectionsMemAdapterStateForTests,
} from './verification-collections/adapters.ts';
import type {
  EvidenceRecord,
  IssuedCredentialRecord,
  JsonObject,
  VerificationCollectionsAdapter,
  VerificationCollectionsConfig,
  VerificationCollectionsProvider,
} from './verification-collections/types.ts';

export type {
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
};

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

function includesValue(left: string, right: string): boolean {
  return left.trim().toLowerCase() === right.trim().toLowerCase();
}

function parseProvider(raw: string | undefined, fallback: VerificationCollectionsProvider): VerificationCollectionsProvider {
  const normalized = (raw || '').trim().toLowerCase();
  if (!normalized) return fallback;
  if (normalized === 'mem' || normalized === 'firestore') {
    return normalized;
  }
  throw new Error(`Unsupported ICA_COLLECTIONS_PROVIDER="${normalized}". Use "mem" or "firestore".`);
}

function buildCollectionName(prefix: string, leaf: string): string {
  const normalizedPrefix = prefix.trim().toLowerCase().replace(/[^a-z0-9_-]+/g, '-').replace(/^-+|-+$/g, '');
  if (!normalizedPrefix) return leaf;
  return `${normalizedPrefix}_${leaf}`;
}

export function loadVerificationCollectionsConfigFromEnv(): VerificationCollectionsConfig {
  const provider = parseProvider(process.env.ICA_COLLECTIONS_PROVIDER, 'mem');
  const prefix = (process.env.ICA_COLLECTIONS_FIRESTORE_COLLECTION_PREFIX || 'ica').trim();
  const issuedLeaf = (process.env.ICA_COLLECTIONS_ISSUED_COLLECTION || 'issued_credentials').trim();
  const evidenceLeaf = (process.env.ICA_COLLECTIONS_EVIDENCE_COLLECTION || 'evidence_records').trim();
  return {
    provider,
    required: parseBoolean(process.env.ICA_COLLECTIONS_REQUIRED, true),
    firestoreProjectId: (process.env.ICA_COLLECTIONS_FIRESTORE_PROJECT_ID || '').trim() || undefined,
    firestoreDatabaseId: (process.env.ICA_COLLECTIONS_FIRESTORE_DATABASE_ID || '').trim() || undefined,
    firestoreCollectionPrefix: prefix,
    issuedCredentialsCollection: buildCollectionName(prefix, issuedLeaf),
    evidenceCollection: buildCollectionName(prefix, evidenceLeaf),
  };
}

function extractCredentialRecords(
  route: VerifyRouteContext,
  thid: string,
  bundle: VerifyBundleResponse,
  nowIso: string,
): { issued: IssuedCredentialRecord[]; evidence: EvidenceRecord[] } {
  const issued: IssuedCredentialRecord[] = [];
  const evidence: EvidenceRecord[] = [];

  for (const entry of bundle.data || []) {
    const resource = asJsonObject(entry.resource);
    if (!resource) continue;

    const recordId = `urn:uuid:${randomUUID()}`;
    const credentialId = asNonEmptyString(resource.id) || recordId;
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
        createdAt: nowIso,
        updatedAt: nowIso,
      });
    }
  }

  return { issued, evidence };
}

export class VerificationCollectionsService {
  private readonly config: VerificationCollectionsConfig;
  private readonly adapter: VerificationCollectionsAdapter;

  constructor(config: VerificationCollectionsConfig = loadVerificationCollectionsConfigFromEnv()) {
    this.config = config;
    this.adapter = createVerificationCollectionsAdapter(config);
  }

  async persistFromVerificationBundle(
    route: VerifyRouteContext,
    thid: string,
    bundle: VerifyBundleResponse,
  ): Promise<void> {
    const nowIso = new Date().toISOString();
    const extracted = extractCredentialRecords(route, thid, bundle, nowIso);
    if (!extracted.issued.length && !extracted.evidence.length) {
      return;
    }

    await this.persistRecords(
      extracted.issued,
      extracted.evidence,
      'Verification collections persistence failed',
    );
  }

  async storeIssuedCredentials(records: IssuedCredentialRecord[]): Promise<void> {
    await this.persistRecords(records, [], 'Issued credentials persistence failed');
  }

  async upsertIssuedCredential(record: IssuedCredentialRecord): Promise<void> {
    await this.storeIssuedCredentials([record]);
  }

  async storeEvidenceRecords(records: EvidenceRecord[]): Promise<void> {
    await this.persistRecords([], records, 'Evidence records persistence failed');
  }

  private async persistRecords(
    issuedRecords: IssuedCredentialRecord[],
    evidenceRecords: EvidenceRecord[],
    errorPrefix: string,
  ): Promise<void> {
    if (!issuedRecords.length && !evidenceRecords.length) {
      return;
    }

    try {
      await this.adapter.storeIssuedCredentials(issuedRecords);
      await this.adapter.storeEvidenceRecords(evidenceRecords);
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
    return undefined;
  }
}

export function createVerificationCollectionsServiceFromEnv(): VerificationCollectionsService {
  return new VerificationCollectionsService(loadVerificationCollectionsConfigFromEnv());
}

export function resetVerificationCollectionsMemStateForTests(): void {
  resetVerificationCollectionsMemAdapterStateForTests();
}
