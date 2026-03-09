import { createHash } from 'node:crypto';
import type {
  DataspacePublication,
  EvidenceRecord,
  IssuedCredentialRecord,
} from './verification-collections/types.ts';

type JsonObject = Record<string, unknown>;

export type DataspaceScope = {
  tenantId: string;
  jurisdiction: string;
  sector: string;
};

export type DataspaceSyncTarget = {
  name?: string;
  did: string;
  endpointUrl?: string;
  apiKey?: string;
};

const DATASPACE_SYNC_API_KEY_HEADER = 'x-api-key';
const SPACES_TARGET_ALLOWED_TYPES = new Set(['runtimeplatform', 'softwareapplication']);
const SPACES_METADATA_JSONLD_TYPE = 'DataspacePublicationMetadata';

type DataspaceSyncResult = {
  status: 'synced' | 'failed';
  txId?: string;
  message?: string;
};

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? (value as JsonObject)
    : undefined;
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function parseCsv(value: string | undefined): string[] {
  return (value || '')
    .split(',')
    .map((entry) => entry.trim())
    .filter(Boolean);
}

function normalizeDid(value: string): string {
  return value.trim().toLowerCase();
}

function normalizeForCanonical(value: unknown): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => normalizeForCanonical(entry));
  }
  if (!value || typeof value !== 'object') {
    return value;
  }
  const objectValue = value as Record<string, unknown>;
  const output: Record<string, unknown> = {};
  const keys = Object.keys(objectValue).sort((left, right) => left.localeCompare(right));
  keys.forEach((key) => {
    output[key] = normalizeForCanonical(objectValue[key]);
  });
  return output;
}

function computeSha3_384Base64(value: unknown): string {
  const canonical = JSON.stringify(normalizeForCanonical(value));
  return createHash('sha3-384').update(canonical, 'utf8').digest('base64');
}

function resolveApiKey(input: JsonObject): string | undefined {
  return asNonEmptyString(input.apiKey || input.license) || undefined;
}

function normalizeTypeToken(raw: string): string {
  const value = raw.trim().toLowerCase();
  if (!value) return '';
  if (!value.includes(':')) return value;
  const [, ...rest] = value.split(':');
  return (rest.length ? rest[rest.length - 1] : value).trim();
}

function resolveTargetType(
  target: JsonObject,
  contextLabel: string,
): string | undefined {
  const jsonLdType = asNonEmptyString(target['@type']);
  const resourceType = asNonEmptyString(target.resourceType);
  const legacyType = asNonEmptyString(target.type);

  if (legacyType && !jsonLdType && !resourceType) {
    throw new Error(
      `${contextLabel} uses unsupported field "type"; use "@type" or "resourceType". `
      + 'This rule applies only to spaces target entries, not to body.type in DIDComm/FHIR Bundle envelopes.',
    );
  }

  if (jsonLdType && resourceType) {
    const left = normalizeTypeToken(jsonLdType);
    const right = normalizeTypeToken(resourceType);
    if (left && right && left !== right) {
      throw new Error(`${contextLabel} has mismatched "@type" and "resourceType".`);
    }
  }

  const declaredType = jsonLdType || resourceType;
  if (!declaredType) return undefined;

  if (!SPACES_TARGET_ALLOWED_TYPES.has(normalizeTypeToken(declaredType))) {
    throw new Error(`${contextLabel} must use RuntimePlatform or SoftwareApplication in "@type"/"resourceType".`);
  }

  return declaredType;
}

function parseTargetsFromJson(raw: string): DataspaceSyncTarget[] {
  const parsed = JSON.parse(raw) as unknown;
  const list = Array.isArray(parsed)
    ? parsed
    : Array.isArray(asObject(parsed)?.targets)
      ? (asObject(parsed)?.targets as unknown[])
      : [];
  const targets: DataspaceSyncTarget[] = [];
  list.forEach((entry, index) => {
    const objectEntry = asObject(entry);
    if (!objectEntry) return;
    resolveTargetType(objectEntry, `targets[${index}]`);
    const did = asNonEmptyString(objectEntry.did || objectEntry.id || objectEntry.identifier);
    if (!did) return;
    const name = asNonEmptyString(objectEntry.name) || undefined;
    const endpointUrl = asNonEmptyString(objectEntry.endpointUrl || objectEntry.endpoint || objectEntry.url) || undefined;
    const apiKey = resolveApiKey(objectEntry);
    targets.push({
      ...(name ? { name } : {}),
      did,
      ...(endpointUrl ? { endpointUrl } : {}),
      ...(apiKey ? { apiKey } : {}),
    });
  });
  return targets;
}

export function loadDataspaceSyncTargetsFromEnv(): DataspaceSyncTarget[] {
  const rawJson = (process.env.ICA_SPACES_TARGETS_JSON || '').trim();
  if (rawJson) {
    try {
      return parseTargetsFromJson(rawJson);
    } catch (error: unknown) {
      throw new Error(`Invalid ICA_SPACES_TARGETS_JSON: ${(error as Error).message}`);
    }
  }

  const dids = parseCsv(process.env.ICA_SPACES_TARGET_DIDS);
  if (!dids.length) return [];
  const defaultEndpoint = asNonEmptyString(process.env.ICA_SPACES_DEFAULT_ENDPOINT) || undefined;
  const apiKey = asNonEmptyString(process.env.ICA_SPACES_DEFAULT_API_KEY) || undefined;
  return dids.map((did) => ({
    did,
    ...(defaultEndpoint ? { endpointUrl: defaultEndpoint } : {}),
    ...(apiKey ? { apiKey } : {}),
  }));
}

export function dedupeTargets(targets: DataspaceSyncTarget[]): DataspaceSyncTarget[] {
  const byDid = new Map<string, DataspaceSyncTarget>();
  targets.forEach((target) => {
    const key = normalizeDid(target.did);
    if (!key) return;
    if (!byDid.has(key)) {
      byDid.set(key, target);
      return;
    }
    const previous = byDid.get(key)!;
    byDid.set(key, {
      name: target.name || previous.name,
      did: previous.did,
      endpointUrl: target.endpointUrl || previous.endpointUrl,
      apiKey: target.apiKey || previous.apiKey,
    });
  });
  return Array.from(byDid.values());
}

function nowIso(): string {
  return new Date().toISOString();
}

export class DataspaceSyncService {
  private readonly staticTargets: DataspaceSyncTarget[];
  private readonly targetResolver?: (scope: DataspaceScope) => DataspaceSyncTarget[];
  private readonly strict: boolean;
  private readonly timeoutMs: number;

  constructor(options?: {
    targets?: DataspaceSyncTarget[];
    targetResolver?: (scope: DataspaceScope) => DataspaceSyncTarget[];
    strict?: boolean;
    timeoutMs?: number;
  }) {
    this.staticTargets = dedupeTargets(options?.targets || loadDataspaceSyncTargetsFromEnv());
    this.targetResolver = options?.targetResolver;
    this.strict = options?.strict ?? parseBoolean(process.env.ICA_SPACES_STRICT, false);
    this.timeoutMs = options?.timeoutMs ?? Number.parseInt(process.env.ICA_SPACES_TIMEOUT_MS || '8000', 10);
  }

  private resolveScopeFromRecord(record: { tenantId: string; jurisdiction: string; sector: string }): DataspaceScope {
    return {
      tenantId: record.tenantId,
      jurisdiction: record.jurisdiction,
      sector: record.sector,
    };
  }

  private resolveTargetsForScope(scope?: DataspaceScope): DataspaceSyncTarget[] {
    const scoped = (scope && this.targetResolver)
      ? dedupeTargets(this.targetResolver(scope))
      : [];
    if (scoped.length) return scoped;
    return this.staticTargets;
  }

  buildInitialPublications(originDataspaceDid?: string, scope?: DataspaceScope): DataspacePublication[] {
    const targets = this.resolveTargetsForScope(scope);
    const origin = asNonEmptyString(originDataspaceDid);
    const output: DataspacePublication[] = [];
    const targetByDid = new Map(targets.map((target) => [normalizeDid(target.did), target]));

    targets.forEach((target) => {
      const isOrigin = origin && normalizeDid(origin) === normalizeDid(target.did);
      output.push({
        did: target.did,
        status: isOrigin ? 'origin' : 'pending',
        ...(target.endpointUrl ? { endpointUrl: target.endpointUrl } : {}),
        message: isOrigin ? 'Origin dataspace detected from imported credential/evidence.' : undefined,
      });
    });

    if (origin && !targetByDid.has(normalizeDid(origin))) {
      output.push({
        did: origin,
        status: 'origin',
        message: 'Origin dataspace detected from imported credential/evidence.',
      });
    }

    return output;
  }

  private resolveTargetByDid(did: string, scope: DataspaceScope): DataspaceSyncTarget | undefined {
    const targets = this.resolveTargetsForScope(scope);
    return targets.find((target) => normalizeDid(target.did) === normalizeDid(did));
  }

  private async syncToTarget(
    target: DataspaceSyncTarget,
    payload: JsonObject,
    kind: 'credential' | 'evidence' | 'catalog',
  ): Promise<DataspaceSyncResult> {
    if (!target.endpointUrl) {
      return {
        status: 'failed',
        message: `No endpoint configured for dataspace ${target.did}.`,
      };
    }
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), this.timeoutMs);
    try {
      const headers: Record<string, string> = {
        'content-type': 'application/json',
      };
      const resolvedApiKey = target.apiKey || undefined;
      if (resolvedApiKey) {
        headers[DATASPACE_SYNC_API_KEY_HEADER] = resolvedApiKey;
      }
      const response = await fetch(target.endpointUrl, {
        method: 'POST',
        headers,
        body: JSON.stringify(payload),
        signal: controller.signal,
      });
      if (!response.ok) {
        const bodyText = (await response.text()).slice(0, 500);
        return {
          status: 'failed',
          message: `HTTP ${response.status} ${response.statusText}${bodyText ? ` body=${bodyText}` : ''}`,
        };
      }
      let txId = '';
      try {
        const responseJson = await response.json() as JsonObject;
        txId = asNonEmptyString(responseJson.txId || responseJson.transactionId || responseJson.id);
      } catch {
        // accept non-json success responses
      }
      return {
        status: 'synced',
        ...(txId ? { txId } : {}),
        message: `${kind} metadata synced successfully.`,
      };
    } catch (error: unknown) {
      return {
        status: 'failed',
        message: (error as Error)?.message || String(error),
      };
    } finally {
      clearTimeout(timeout);
    }
  }

  private async syncPublications(
    scope: DataspaceScope,
    publications: DataspacePublication[] | undefined,
    payloadBuilder: (targetDid: string) => JsonObject,
    kind: 'credential' | 'evidence' | 'catalog',
  ): Promise<DataspacePublication[]> {
    const entries = Array.isArray(publications) ? publications : [];
    const updated: DataspacePublication[] = [];
    const failures: string[] = [];

    for (const entry of entries) {
      if (entry.status === 'origin') {
        updated.push(entry);
        continue;
      }
      const target = this.resolveTargetByDid(entry.did, scope);
      const result = target
        ? await this.syncToTarget(target, payloadBuilder(entry.did), kind)
        : { status: 'failed', message: `No dataspace target config found for ${entry.did}.` } as DataspaceSyncResult;

      const attemptAt = nowIso();
      const nextEntry: DataspacePublication = {
        ...entry,
        status: result.status,
        lastAttemptAt: attemptAt,
        ...(result.status === 'synced' ? { lastSuccessAt: attemptAt } : {}),
        ...(result.txId ? { txId: result.txId } : {}),
        ...(result.message ? { message: result.message } : {}),
      };
      updated.push(nextEntry);

      if (result.status === 'failed') {
        const msg = `dataspace=${entry.did} kind=${kind} error=${result.message || 'unknown'}`;
        failures.push(msg);
        console.warn(`[spaces-sync] ${msg}`);
      } else {
        console.info(`[spaces-sync] dataspace=${entry.did} kind=${kind} status=synced`);
      }
    }

    if (failures.length && this.strict) {
      throw new Error(`Dataspace sync failures: ${failures.join(' | ')}`);
    }

    return updated;
  }

  async syncIssuedCredentialRecord(
    record: IssuedCredentialRecord,
    options?: {
      event?: 'issued' | 'revoked' | 'updated';
      status?: string;
    },
  ): Promise<IssuedCredentialRecord> {
    const scope = this.resolveScopeFromRecord(record);
    const publications = record.dataspacePublications || this.buildInitialPublications(record.originDataspaceDid, scope);
    const hash = computeSha3_384Base64(record.credential);
    const updatedPublications = await this.syncPublications(
      scope,
      publications,
      (targetDid) => ({
        '@type': SPACES_METADATA_JSONLD_TYPE,
        kind: 'credential',
        event: options?.event || 'updated',
        status: options?.status || asNonEmptyString(asObject(record.credential.credentialStatus)?.status) || 'active',
        targetNetwork: targetDid,
        sourceNetwork: record.originDataspaceDid || undefined,
        tenantId: record.tenantId,
        jurisdiction: record.jurisdiction,
        sector: record.sector,
        credentialType: record.credentialType,
        credentialId: record.credentialId,
        subjectId: record.subjectId,
        issuerId: record.issuerId,
        hashAlg: 'sha3-384',
        hashValue: hash,
        updatedAt: nowIso(),
      }),
      'credential',
    );

    return {
      ...record,
      dataspacePublications: updatedPublications,
      contentHashSha3_384: hash,
      updatedAt: nowIso(),
    };
  }

  async syncEvidenceRecord(
    record: EvidenceRecord,
    options?: {
      event?: 'added' | 'updated';
      status?: string;
    },
  ): Promise<EvidenceRecord> {
    const scope = this.resolveScopeFromRecord(record);
    const publications = record.dataspacePublications || this.buildInitialPublications(record.originDataspaceDid, scope);
    const hash = computeSha3_384Base64(record.evidence);
    const updatedPublications = await this.syncPublications(
      scope,
      publications,
      (targetDid) => ({
        '@type': SPACES_METADATA_JSONLD_TYPE,
        kind: 'evidence',
        event: options?.event || 'updated',
        status: options?.status || 'active',
        targetNetwork: targetDid,
        sourceNetwork: record.originDataspaceDid || undefined,
        tenantId: record.tenantId,
        jurisdiction: record.jurisdiction,
        sector: record.sector,
        evidenceType: record.evidenceType,
        evidenceRecordId: record.id,
        issuedCredentialRecordId: record.issuedCredentialRecordId,
        hashAlg: 'sha3-384',
        hashValue: hash,
        updatedAt: nowIso(),
      }),
      'evidence',
    );

    return {
      ...record,
      dataspacePublications: updatedPublications,
      contentHashSha3_384: hash,
      updatedAt: nowIso(),
    };
  }

  async syncCatalogSnapshot(input: {
    tenantId: string;
    jurisdiction: string;
    sector: string;
    catalogUrl: string;
    datasetList: string[];
  }): Promise<void> {
    const scope = {
      tenantId: input.tenantId,
      jurisdiction: input.jurisdiction,
      sector: input.sector,
    } satisfies DataspaceScope;
    const publications = this.buildInitialPublications(undefined, scope);
    await this.syncPublications(
      scope,
      publications,
      (targetDid) => ({
        '@type': SPACES_METADATA_JSONLD_TYPE,
        kind: 'catalog',
        event: 'published',
        status: 'active',
        targetNetwork: targetDid,
        tenantId: input.tenantId,
        jurisdiction: input.jurisdiction,
        sector: input.sector,
        catalogUrl: input.catalogUrl,
        datasetCount: input.datasetList.length,
        datasetList: input.datasetList,
        updatedAt: nowIso(),
      }),
      'catalog',
    );
  }
}
