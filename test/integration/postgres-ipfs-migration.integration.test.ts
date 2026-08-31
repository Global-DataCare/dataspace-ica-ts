// Flow contract: reuse shared test fixtures and canonical types; do not introduce duplicated literals.
import assert from 'node:assert/strict';
import { test } from 'node:test';
import {
  KuboAuditIpfsWriter,
  migrateAuditObjectsToIpfs,
} from '../../src/api/migration/postgres-ipfs-migration.ts';
import { VerificationCollectionsPostgresAdapter } from '../../src/api/tools/verification-collections/adapters.ts';
import type { IssuedCredentialRecord } from '../../src/api/tools/verification-collections/types.ts';

const POSTGRES_URL = process.env.POSTGRES_MIGRATION_TEST_URL;
const IPFS_API_URL = process.env.IPFS_MIGRATION_TEST_API_URL;
if (!POSTGRES_URL || !IPFS_API_URL) {
  throw new Error('The integration orchestrator must provide PostgreSQL and IPFS endpoints.');
}

function buildCredential(index: number): IssuedCredentialRecord {
  const suffix = String(index).padStart(4, '0');
  return {
    id: `urn:example:migration:credential:${suffix}`,
    tenantId: 'urn:example:tenant:synthetic',
    jurisdiction: 'TEST',
    sector: 'health-care',
    resourceType: 'Service',
    thid: `urn:example:migration:thread:${suffix}`,
    credentialType: 'SyntheticCredential',
    credentialId: `urn:example:migration:vc:${suffix}`,
    subjectId: `did:example:subject:${suffix}`,
    issuerId: 'did:example:issuer',
    credential: { id: `urn:example:migration:vc:${suffix}` },
    createdAt: '2030-01-02T03:04:05.000Z',
    updatedAt: '2030-01-02T03:04:05.000Z',
  };
}

test('PostgreSQL persists and lists every migrated record beyond the former page limit', async () => {
  const adapter = new VerificationCollectionsPostgresAdapter({
    provider: 'postgres',
    required: true,
    firestoreCollectionPrefix: 'migration_contract',
    postgresUrl: POSTGRES_URL,
  });
  try {
    const records = Array.from({ length: 205 }, (_, index) => buildCredential(index));
    await adapter.storeIssuedCredentials(records);
    const persisted = await adapter.listIssuedCredentials();
    assert.equal(persisted.length, records.length);
    assert.deepEqual(persisted.map((record) => record.id), records.map((record) => record.id));
  } finally {
    await adapter.close();
  }
});

test('Kubo stores and retrieves the exact migrated audit bytes by CID', async () => {
  const bytes = Buffer.from('%PDF-1.7 synthetic boundary fixture');
  const manifest = await migrateAuditObjectsToIpfs({
    objects: [{ objectKey: 'ica-audit/test/synthetic.pdf', bytes, contentType: 'application/pdf' }],
    writer: new KuboAuditIpfsWriter(IPFS_API_URL),
    migratedAt: '2030-01-02T03:04:05.000Z',
  });
  const response = await fetch(`${IPFS_API_URL}/api/v0/cat?arg=${encodeURIComponent(manifest.objects[0].cid)}`, {
    method: 'POST',
  });
  assert.equal(response.ok, true);
  assert.deepEqual(Buffer.from(await response.arrayBuffer()), bytes);
});
