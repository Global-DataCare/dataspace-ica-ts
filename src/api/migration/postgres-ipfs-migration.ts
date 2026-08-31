import { createHash } from 'node:crypto';
import { readdir, readFile } from 'node:fs/promises';
import path from 'node:path';
import type {
  EvidenceRecord,
  IssuedCredentialRecord,
  JsonObject,
  VerificationCollectionsAdapter,
} from '../tools/verification-collections/types.ts';

export type AuditMigrationObject = {
  objectKey: string;
  bytes: Buffer;
  contentType: string;
};

export type AuditMigrationMapping = {
  sourceObjectKey: string;
  targetUri: string;
  cid: string;
  contentType: string;
  sizeBytes: number;
  sha256: string;
};

export type AuditIpfsWriter = {
  write(object: AuditMigrationObject): Promise<{ cid: string }>;
};

export type AuditIpfsMigrationManifest = {
  schemaVersion: 'gdc.dataspace-ica.audit-ipfs-migration/v1';
  migratedAt: string;
  objectCount: number;
  totalBytes: number;
  objects: AuditMigrationMapping[];
};

/** Prevents accidental publication of private signed audit documents. */
export function validateIpfsMigrationCustody(
  custodyMode: string | undefined,
  dataProtectionConfirmed: string | undefined,
): void {
  if ((custodyMode || '').trim() !== 'private-encrypted') {
    throw new Error('ICA_MIGRATION_IPFS_CUSTODY must be private-encrypted.');
  }
  if ((dataProtectionConfirmed || '').trim().toLowerCase() !== 'true') {
    throw new Error('ICA_MIGRATION_DATA_PROTECTION_CONFIRMED=true is required.');
  }
}

function contentTypeForPath(filePath: string): string {
  switch (path.extname(filePath).toLowerCase()) {
    case '.pdf': return 'application/pdf';
    case '.json': return 'application/json';
    default: return 'application/octet-stream';
  }
}

async function listFilesRecursively(root: string, current: string): Promise<string[]> {
  const entries = await readdir(current, { withFileTypes: true });
  const files: string[] = [];
  for (const entry of entries.sort((left, right) => left.name.localeCompare(right.name))) {
    const entryPath = path.join(current, entry.name);
    if (entry.isDirectory()) files.push(...await listFilesRecursively(root, entryPath));
    if (entry.isFile()) files.push(entryPath);
  }
  return files.sort((left, right) => left.localeCompare(right));
}

/** Reads a downloaded GCS prefix without treating local paths as object keys. */
export async function* listAuditObjectsFromDirectory(
  sourceRoot: string,
): AsyncGenerator<AuditMigrationObject> {
  const absoluteRoot = path.resolve(sourceRoot);
  for (const filePath of await listFilesRecursively(absoluteRoot, absoluteRoot)) {
    const relativePath = path.relative(absoluteRoot, filePath).split(path.sep).join('/');
    yield {
      objectKey: relativePath,
      bytes: await readFile(filePath),
      contentType: contentTypeForPath(filePath),
    };
  }
}

/** Writes one immutable object through Kubo's public HTTP RPC API. */
export class KuboAuditIpfsWriter implements AuditIpfsWriter {
  private readonly apiUrl: string;

  constructor(apiUrl: string) {
    this.apiUrl = apiUrl.replace(/\/$/, '');
  }

  async write(object: AuditMigrationObject): Promise<{ cid: string }> {
    const form = new FormData();
    form.append(
      'file',
      new Blob([new Uint8Array(object.bytes)], { type: object.contentType }),
      path.posix.basename(object.objectKey),
    );
    const response = await fetch(
      `${this.apiUrl}/api/v0/add?pin=true&cid-version=1&hash=sha2-256`,
      { method: 'POST', body: form },
    );
    if (!response.ok) {
      throw new Error(`IPFS add failed for "${object.objectKey}": HTTP ${response.status}.`);
    }
    const responseLine = (await response.text()).trim().split('\n').filter(Boolean).at(-1);
    const payload = responseLine ? JSON.parse(responseLine) as { Hash?: string } : {};
    const cid = (payload.Hash || '').trim();
    if (!cid) throw new Error(`IPFS add returned no CID for "${object.objectKey}".`);
    return { cid };
  }
}

export type VerificationCollectionsMigrationReport = {
  schemaVersion: 'gdc.dataspace-ica.postgres-ipfs-migration/v1';
  migratedAt: string;
  counts: {
    issuedCredentials: number;
    evidenceRecords: number;
    didBindings: number;
    didDocuments: number;
  };
  sourceDigestSha256: string;
  targetDigestSha256: string;
  unresolvedGcsReferences: string[];
};

function sha256(bytes: Buffer | string): string {
  return createHash('sha256').update(bytes).digest('hex');
}

function stableJson(value: unknown): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableJson(entry)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    return `{${Object.entries(value as Record<string, unknown>)
      .sort(([left], [right]) => left.localeCompare(right))
      .map(([key, entry]) => `${JSON.stringify(key)}:${stableJson(entry)}`)
      .join(',')}}`;
  }
  return JSON.stringify(value);
}

function sortedById<T extends { id: string }>(records: T[]): T[] {
  return [...records].sort((left, right) => left.id.localeCompare(right.id));
}

/**
 * Uploads audit objects without placing their bytes or personal metadata in
 * the resulting evidence manifest. The manifest is safe to attach to an
 * auditor report only after source object keys have been classified as safe.
 */
export async function migrateAuditObjectsToIpfs(input: {
  objects: Iterable<AuditMigrationObject> | AsyncIterable<AuditMigrationObject>;
  writer: AuditIpfsWriter;
  migratedAt?: string;
}): Promise<AuditIpfsMigrationManifest> {
  const objects: AuditMigrationMapping[] = [];
  let totalBytes = 0;

  for await (const object of input.objects) {
    const objectKey = object.objectKey.trim();
    if (!objectKey) throw new Error('Audit migration objectKey cannot be empty.');
    if (!object.bytes.length) throw new Error(`Audit migration object "${objectKey}" is empty.`);
    const { cid } = await input.writer.write(object);
    if (!cid.trim()) throw new Error(`IPFS returned an empty CID for "${objectKey}".`);
    totalBytes += object.bytes.length;
    objects.push({
      sourceObjectKey: objectKey,
      targetUri: `ipfs://${cid}`,
      cid,
      contentType: object.contentType,
      sizeBytes: object.bytes.length,
      sha256: sha256(object.bytes),
    });
  }

  objects.sort((left, right) => left.sourceObjectKey.localeCompare(right.sourceObjectKey));
  return {
    schemaVersion: 'gdc.dataspace-ica.audit-ipfs-migration/v1',
    migratedAt: input.migratedAt || new Date().toISOString(),
    objectCount: objects.length,
    totalBytes,
    objects,
  };
}

function rewriteAuditReferences(
  value: unknown,
  mappings: Map<string, AuditMigrationMapping>,
  unresolved: Set<string>,
): unknown {
  if (Array.isArray(value)) {
    return value.map((entry) => rewriteAuditReferences(entry, mappings, unresolved));
  }
  if (!value || typeof value !== 'object') return value;

  const input = value as Record<string, unknown>;
  const objectKey = typeof input.objectKey === 'string' ? input.objectKey : '';
  if (input.provider === 'gcs' && objectKey) {
    const mapping = mappings.get(objectKey);
    if (!mapping) {
      unresolved.add(objectKey);
    } else {
      const rewrittenEntries = Object.entries(input)
        .filter(([key]) => key !== 'bucket')
        .map(([key, entry]) => [key, rewriteAuditReferences(entry, mappings, unresolved)]);
      return {
        ...Object.fromEntries(rewrittenEntries),
        provider: 'ipfs',
        objectKey: mapping.targetUri,
        attachmentUrl: mapping.targetUri,
        cid: mapping.cid,
        contentHashSha256: mapping.sha256,
      };
    }
  }

  return Object.fromEntries(
    Object.entries(input).map(([key, entry]) => [
      key,
      rewriteAuditReferences(entry, mappings, unresolved),
    ]),
  );
}

async function readCollections(adapter: VerificationCollectionsAdapter) {
  const [issuedCredentials, evidenceRecords, didBindings, didDocuments] = await Promise.all([
    adapter.listIssuedCredentials(),
    adapter.listEvidenceRecords(),
    adapter.listDidBindings(),
    adapter.listDidDocuments(),
  ]);
  return {
    issuedCredentials: sortedById(issuedCredentials),
    evidenceRecords: sortedById(evidenceRecords),
    didBindings: sortedById(didBindings),
    didDocuments: sortedById(didDocuments),
  };
}

/**
 * Copies the complete ICA verification state into a target adapter and proves
 * equality after rewriting governed GCS audit references to immutable IPFS
 * CIDs. No credential payload is written to the report.
 */
export async function migrateVerificationCollections(input: {
  source: VerificationCollectionsAdapter;
  target: VerificationCollectionsAdapter;
  auditObjects: AuditMigrationMapping[];
  migratedAt?: string;
}): Promise<VerificationCollectionsMigrationReport> {
  const source = await readCollections(input.source);
  const mappings = new Map(input.auditObjects.map((entry) => [entry.sourceObjectKey, entry]));
  const unresolved = new Set<string>();
  const issuedCredentials = source.issuedCredentials.map((record): IssuedCredentialRecord => ({
    ...record,
    credential: rewriteAuditReferences(record.credential, mappings, unresolved) as JsonObject,
  }));
  const evidenceRecords = source.evidenceRecords.map((record): EvidenceRecord => ({
    ...record,
    evidence: rewriteAuditReferences(record.evidence, mappings, unresolved) as JsonObject,
  }));
  const transformed = {
    issuedCredentials,
    evidenceRecords,
    didBindings: source.didBindings,
    didDocuments: source.didDocuments,
  };

  if (unresolved.size) {
    return {
      schemaVersion: 'gdc.dataspace-ica.postgres-ipfs-migration/v1',
      migratedAt: input.migratedAt || new Date().toISOString(),
      counts: {
        issuedCredentials: issuedCredentials.length,
        evidenceRecords: evidenceRecords.length,
        didBindings: source.didBindings.length,
        didDocuments: source.didDocuments.length,
      },
      sourceDigestSha256: sha256(stableJson(transformed)),
      targetDigestSha256: '',
      unresolvedGcsReferences: [...unresolved].sort(),
    };
  }

  await input.target.storeIssuedCredentials(issuedCredentials);
  await input.target.storeEvidenceRecords(evidenceRecords);
  await input.target.storeDidBindings(source.didBindings);
  await input.target.storeDidDocuments(source.didDocuments);

  const target = await readCollections(input.target);
  return {
    schemaVersion: 'gdc.dataspace-ica.postgres-ipfs-migration/v1',
    migratedAt: input.migratedAt || new Date().toISOString(),
    counts: {
      issuedCredentials: issuedCredentials.length,
      evidenceRecords: evidenceRecords.length,
      didBindings: source.didBindings.length,
      didDocuments: source.didDocuments.length,
    },
    sourceDigestSha256: sha256(stableJson(transformed)),
    targetDigestSha256: sha256(stableJson(target)),
    unresolvedGcsReferences: [],
  };
}
