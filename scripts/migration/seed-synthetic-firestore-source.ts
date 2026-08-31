#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import { VerificationCollectionsFirestoreAdapter } from '../../src/api/tools/verification-collections/adapters.ts';

const projectId = (process.env.FIRESTORE_PROJECT_ID || '').trim();
const prefix = (process.env.ICA_MIGRATION_SOURCE_COLLECTIONS_PREFIX || '').trim();
const auditRoot = path.resolve(process.env.ICA_MIGRATION_AUDIT_SOURCE_DIR || '');
if (!projectId || !prefix || !process.env.FIRESTORE_EMULATOR_HOST || !auditRoot) {
  throw new Error('Synthetic seeding requires project, prefix, audit directory and FIRESTORE_EMULATOR_HOST.');
}

const objectKey = 'ica-audit/health-care/test/contract/2030-01-02/synthetic.pdf';
const now = '2030-01-02T03:04:05.000Z';
const source = new VerificationCollectionsFirestoreAdapter({
  provider: 'firestore',
  required: true,
  firestoreProjectId: projectId,
  firestoreCollectionPrefix: prefix,
});

await source.storeIssuedCredentials([{
  id: 'urn:example:migration:credential:0001',
  tenantId: 'urn:example:tenant:synthetic',
  jurisdiction: 'TEST',
  sector: 'health-care',
  resourceType: 'Service',
  thid: 'urn:example:migration:thread:0001',
  credentialType: 'SyntheticCredential',
  credentialId: 'urn:example:migration:vc:0001',
  subjectId: 'did:example:subject:0001',
  issuerId: 'did:example:issuer',
  credential: {
    id: 'urn:example:migration:vc:0001',
    evidence: [{ provider: 'gcs', objectKey, attachmentUrl: `gs://synthetic/${objectKey}` }],
  },
  createdAt: now,
  updatedAt: now,
}]);
await source.storeEvidenceRecords([{
  id: 'urn:example:migration:evidence:0001',
  issuedCredentialRecordId: 'urn:example:migration:credential:0001',
  tenantId: 'urn:example:tenant:synthetic',
  jurisdiction: 'TEST',
  sector: 'health-care',
  resourceType: 'Service',
  thid: 'urn:example:migration:thread:0001',
  evidenceType: 'DocumentVerification',
  evidence: { provider: 'gcs', objectKey },
  createdAt: now,
  updatedAt: now,
}]);
await source.storeDidBindings([{
  id: 'synthetic-binding',
  tenantId: 'urn:example:tenant:synthetic',
  jurisdiction: 'TEST',
  sector: 'health-care',
  resourceType: 'Organization',
  thid: 'urn:example:migration:thread:0001',
  taxId: 'TEST-ID',
  status: 'confirmed',
  createdAt: now,
  updatedAt: now,
}]);
await source.storeDidDocuments([{
  id: 'synthetic-document',
  tenantId: 'urn:example:tenant:synthetic',
  jurisdiction: 'TEST',
  sector: 'health-care',
  resourceType: 'Organization',
  thid: 'urn:example:migration:thread:0001',
  did: 'did:example:subject:0001',
  didDocument: { id: 'did:example:subject:0001' },
  status: 'confirmed',
  createdAt: now,
  updatedAt: now,
}]);

const filePath = path.join(auditRoot, objectKey);
await mkdir(path.dirname(filePath), { recursive: true });
await writeFile(filePath, '%PDF-1.7 synthetic open-source migration fixture');
process.stdout.write('Synthetic Firestore/GCS source seeded.\n');
