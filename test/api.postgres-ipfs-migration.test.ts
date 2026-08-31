// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { mkdtemp, mkdir, readFile, rm, writeFile } from 'node:fs/promises';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { test } from 'node:test';
import {
  KuboAuditIpfsWriter,
  listAuditObjectsFromDirectory,
  migrateAuditObjectsToIpfs,
  migrateVerificationCollections,
  validateIpfsMigrationCustody,
} from '../src/api/migration/postgres-ipfs-migration.ts';
import type {
  DidBindingRecord,
  DidDocumentRecord,
  EvidenceRecord,
  IssuedCredentialRecord,
  VerificationCollectionsAdapter,
} from '../src/api/tools/verification-collections/types.ts';

const CREATED_AT = '2030-01-02T03:04:05.000Z';
const SOURCE_OBJECT_KEY = 'ica-audit/health-care/test/contract/2030-01-02/synthetic.pdf';
const SYNTHETIC_PDF = Buffer.from('%PDF-1.7 synthetic open-source fixture');
const SYNTHETIC_CID = 'bafybeigdyrzt5sfp7udm7hu76uh7y26nf3rzzzl3v7g5x5x5x5x5x5x5x5';

class CollectionsAdapterMemory implements VerificationCollectionsAdapter {
  issued: IssuedCredentialRecord[] = [];
  evidence: EvidenceRecord[] = [];
  bindings: DidBindingRecord[] = [];
  documents: DidDocumentRecord[] = [];

  async storeIssuedCredentials(records: IssuedCredentialRecord[]): Promise<void> { this.issued = structuredClone(records); }
  async storeEvidenceRecords(records: EvidenceRecord[]): Promise<void> { this.evidence = structuredClone(records); }
  async storeDidBindings(records: DidBindingRecord[]): Promise<void> { this.bindings = structuredClone(records); }
  async storeDidDocuments(records: DidDocumentRecord[]): Promise<void> { this.documents = structuredClone(records); }
  async listIssuedCredentials(): Promise<IssuedCredentialRecord[]> { return structuredClone(this.issued); }
  async listEvidenceRecords(): Promise<EvidenceRecord[]> { return structuredClone(this.evidence); }
  async listDidBindings(): Promise<DidBindingRecord[]> { return structuredClone(this.bindings); }
  async listDidDocuments(): Promise<DidDocumentRecord[]> { return structuredClone(this.documents); }
}

function buildSourceCollections(): CollectionsAdapterMemory {
  const source = new CollectionsAdapterMemory();
  source.issued = [{
    id: 'urn:uuid:00000000-0000-4000-8000-000000000001',
    tenantId: 'urn:example:tenant:synthetic',
    jurisdiction: 'TEST',
    sector: 'health-care',
    resourceType: 'Service',
    thid: 'urn:uuid:00000000-0000-4000-8000-000000000002',
    credentialType: 'HostingServiceCredential',
    credentialId: 'urn:uuid:00000000-0000-4000-8000-000000000003',
    subjectId: 'did:example:synthetic-host',
    issuerId: 'did:example:synthetic-issuer',
    credential: {
      evidence: [{
        provider: 'gcs',
        objectKey: SOURCE_OBJECT_KEY,
        attachmentUrl: `gs://synthetic-bucket/${SOURCE_OBJECT_KEY}`,
      }],
    },
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  }];
  source.evidence = [{
    id: 'urn:uuid:00000000-0000-4000-8000-000000000004',
    issuedCredentialRecordId: source.issued[0].id,
    tenantId: source.issued[0].tenantId,
    jurisdiction: 'TEST',
    sector: 'health-care',
    resourceType: 'Service',
    thid: source.issued[0].thid,
    evidenceType: 'DocumentVerification',
    evidence: { provider: 'gcs', objectKey: SOURCE_OBJECT_KEY },
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  }];
  source.bindings = [{
    id: 'synthetic-binding',
    tenantId: source.issued[0].tenantId,
    jurisdiction: 'TEST',
    sector: 'health-care',
    resourceType: 'Organization',
    thid: source.issued[0].thid,
    taxId: 'TEST-ID',
    status: 'confirmed',
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  }];
  source.documents = [{
    id: 'synthetic-document',
    tenantId: source.issued[0].tenantId,
    jurisdiction: 'TEST',
    sector: 'health-care',
    resourceType: 'Organization',
    thid: source.issued[0].thid,
    did: 'did:example:synthetic-host',
    didDocument: { id: 'did:example:synthetic-host' },
    status: 'confirmed',
    createdAt: CREATED_AT,
    updatedAt: CREATED_AT,
  }];
  return source;
}

test('migrates audit bytes to IPFS and emits a content-only manifest', async () => {
  const manifest = await migrateAuditObjectsToIpfs({
    objects: [{
      objectKey: SOURCE_OBJECT_KEY,
      bytes: SYNTHETIC_PDF,
      contentType: 'application/pdf',
    }],
    writer: {
      async write(object) {
        assert.equal(object.objectKey, SOURCE_OBJECT_KEY);
        assert.deepEqual(object.bytes, SYNTHETIC_PDF);
        return { cid: SYNTHETIC_CID };
      },
    },
    migratedAt: CREATED_AT,
  });

  assert.deepEqual(manifest, {
    schemaVersion: 'gdc.dataspace-ica.audit-ipfs-migration/v1',
    migratedAt: CREATED_AT,
    objectCount: 1,
    totalBytes: SYNTHETIC_PDF.length,
    objects: [{
      sourceObjectKey: SOURCE_OBJECT_KEY,
      targetUri: `ipfs://${SYNTHETIC_CID}`,
      cid: SYNTHETIC_CID,
      contentType: 'application/pdf',
      sizeBytes: SYNTHETIC_PDF.length,
      sha256: createHash('sha256').update(SYNTHETIC_PDF).digest('hex'),
    }],
  });
  assert.equal(JSON.stringify(manifest).includes(SYNTHETIC_PDF.toString()), false);
});

test('copies all verification collections and rewrites governed GCS references to IPFS', async () => {
  const source = buildSourceCollections();
  const target = new CollectionsAdapterMemory();

  const report = await migrateVerificationCollections({
    source,
    target,
    auditObjects: [{
      sourceObjectKey: SOURCE_OBJECT_KEY,
      targetUri: `ipfs://${SYNTHETIC_CID}`,
      cid: SYNTHETIC_CID,
      contentType: 'application/pdf',
      sizeBytes: SYNTHETIC_PDF.length,
      sha256: createHash('sha256').update(SYNTHETIC_PDF).digest('hex'),
    }],
    migratedAt: CREATED_AT,
  });

  assert.deepEqual(report.counts, {
    issuedCredentials: 1,
    evidenceRecords: 1,
    didBindings: 1,
    didDocuments: 1,
  });
  assert.equal(report.unresolvedGcsReferences.length, 0);
  assert.deepEqual(target.issued[0].credential, {
    evidence: [{
      provider: 'ipfs',
      objectKey: `ipfs://${SYNTHETIC_CID}`,
      attachmentUrl: `ipfs://${SYNTHETIC_CID}`,
      cid: SYNTHETIC_CID,
      contentHashSha256: createHash('sha256').update(SYNTHETIC_PDF).digest('hex'),
    }],
  });
  assert.deepEqual(target.evidence[0].evidence, {
    provider: 'ipfs',
    objectKey: `ipfs://${SYNTHETIC_CID}`,
    attachmentUrl: `ipfs://${SYNTHETIC_CID}`,
    cid: SYNTHETIC_CID,
    contentHashSha256: createHash('sha256').update(SYNTHETIC_PDF).digest('hex'),
  });
  assert.match(report.sourceDigestSha256, /^[a-f0-9]{64}$/);
  assert.equal(report.sourceDigestSha256, report.targetDigestSha256);
});

test('reads a local audit export and writes it through the real Kubo HTTP boundary', async () => {
  const sourceRoot = await mkdtemp(path.join(tmpdir(), 'ica-audit-migration-'));
  const objectPath = path.join(sourceRoot, SOURCE_OBJECT_KEY);
  await mkdir(path.dirname(objectPath), { recursive: true });
  await writeFile(objectPath, SYNTHETIC_PDF);

  const requests: string[] = [];
  const server = createServer((request, response) => {
    requests.push(request.url || '');
    request.resume();
    request.on('end', () => {
      response.writeHead(200, { 'content-type': 'application/json' });
      response.end(`${JSON.stringify({ Name: 'synthetic.pdf', Hash: SYNTHETIC_CID, Size: String(SYNTHETIC_PDF.length) })}\n`);
    });
  });
  await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));

  try {
    const address = server.address();
    assert.ok(address && typeof address === 'object');
    const objects = listAuditObjectsFromDirectory(sourceRoot);
    const manifest = await migrateAuditObjectsToIpfs({
      objects,
      writer: new KuboAuditIpfsWriter(`http://127.0.0.1:${address.port}`),
      migratedAt: CREATED_AT,
    });

    assert.equal(manifest.objectCount, 1);
    assert.equal(manifest.objects[0].sourceObjectKey, SOURCE_OBJECT_KEY);
    assert.match(requests[0], /^\/api\/v0\/add\?/);
    assert.match(requests[0], /pin=true/);
    assert.match(requests[0], /cid-version=1/);
  } finally {
    await new Promise<void>((resolve, reject) => server.close((error) => error ? reject(error) : resolve()));
    await rm(sourceRoot, { recursive: true, force: true });
  }
});

test('refuses real audit migration unless private encrypted IPFS custody is explicit', () => {
  assert.throws(
    () => validateIpfsMigrationCustody('public', 'true'),
    /private-encrypted/,
  );
  assert.throws(
    () => validateIpfsMigrationCustody('private-encrypted', 'false'),
    /ICA_MIGRATION_DATA_PROTECTION_CONFIRMED=true/,
  );
  assert.doesNotThrow(
    () => validateIpfsMigrationCustody('private-encrypted', 'true'),
  );
});

test('public migration gates do not print workstation paths', async () => {
  const cliSource = await readFile(
    new URL('../src/api/scripts/migrate-firestore-gcs-to-postgres-ipfs.ts', import.meta.url),
    'utf8',
  );
  const runnerSource = await readFile(
    new URL('../scripts/run-postgres-ipfs-migration-local.sh', import.meta.url),
    'utf8',
  );
  assert.match(cliSource, /process\.stdout\.write\(`Migration PASS\\n`\)/);
  assert.match(runnerSource, /echo 'Local PostgreSQL\/IPFS migration evidence: PASS'/);
  assert.doesNotMatch(cliSource, /Migration PASS: \$\{outputDirectory\}/);
  assert.doesNotMatch(runnerSource, /Local PostgreSQL\/IPFS migration evidence: \$\{OUTPUT_DIR\}/);
});
