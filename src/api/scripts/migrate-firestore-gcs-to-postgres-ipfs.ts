#!/usr/bin/env node
import { mkdir, writeFile } from 'node:fs/promises';
import path from 'node:path';
import {
  KuboAuditIpfsWriter,
  listAuditObjectsFromDirectory,
  migrateAuditObjectsToIpfs,
  migrateVerificationCollections,
  validateIpfsMigrationCustody,
} from '../migration/postgres-ipfs-migration.ts';
import {
  VerificationCollectionsFirestoreAdapter,
  VerificationCollectionsPostgresAdapter,
} from '../tools/verification-collections/adapters.ts';

function requiredEnv(name: string): string {
  const value = (process.env[name] || '').trim();
  if (!value) throw new Error(`Missing required environment variable ${name}.`);
  return value;
}

function assertApplyConfirmation(): void {
  if (!process.argv.includes('--apply')) {
    throw new Error('Refusing to migrate without --apply. Run against synthetic/local data first.');
  }
  const sourceProject = requiredEnv('FIRESTORE_PROJECT_ID');
  const confirmation = requiredEnv('ICA_MIGRATION_CONFIRM_SOURCE_PROJECT');
  if (confirmation !== sourceProject) {
    throw new Error('ICA_MIGRATION_CONFIRM_SOURCE_PROJECT must exactly match FIRESTORE_PROJECT_ID.');
  }
}

async function main(): Promise<void> {
  assertApplyConfirmation();
  validateIpfsMigrationCustody(
    process.env.ICA_MIGRATION_IPFS_CUSTODY,
    process.env.ICA_MIGRATION_DATA_PROTECTION_CONFIRMED,
  );
  const sourceProject = requiredEnv('FIRESTORE_PROJECT_ID');
  const sourcePrefix = requiredEnv('ICA_MIGRATION_SOURCE_COLLECTIONS_PREFIX');
  const targetPrefix = requiredEnv('ICA_MIGRATION_TARGET_COLLECTIONS_PREFIX');
  const postgresUrl = requiredEnv('POSTGRES_URL');
  const ipfsApiUrl = requiredEnv('IPFS_API_URL');
  const auditSourceDirectory = path.resolve(requiredEnv('ICA_MIGRATION_AUDIT_SOURCE_DIR'));
  const outputDirectory = path.resolve(requiredEnv('ICA_MIGRATION_OUTPUT_DIR'));
  await mkdir(outputDirectory, { recursive: false, mode: 0o700 });

  const source = new VerificationCollectionsFirestoreAdapter({
    provider: 'firestore',
    required: true,
    firestoreProjectId: sourceProject,
    firestoreCollectionPrefix: sourcePrefix,
  });
  const target = new VerificationCollectionsPostgresAdapter({
    provider: 'postgres',
    required: true,
    firestoreCollectionPrefix: targetPrefix,
    postgresUrl,
  });

  try {
    const migratedAt = new Date().toISOString();
    const auditManifest = await migrateAuditObjectsToIpfs({
      objects: listAuditObjectsFromDirectory(auditSourceDirectory),
      writer: new KuboAuditIpfsWriter(ipfsApiUrl),
      migratedAt,
    });
    const report = await migrateVerificationCollections({
      source,
      target,
      auditObjects: auditManifest.objects,
      migratedAt,
    });
    if (report.unresolvedGcsReferences.length) {
      throw new Error(`Unresolved GCS references: ${report.unresolvedGcsReferences.join(', ')}`);
    }
    if (report.sourceDigestSha256 !== report.targetDigestSha256) {
      throw new Error('PostgreSQL reconciliation digest does not match the transformed Firestore source.');
    }

    await writeFile(
      path.join(outputDirectory, 'audit-ipfs-manifest.json'),
      `${JSON.stringify(auditManifest, null, 2)}\n`,
      { mode: 0o600 },
    );
    await writeFile(
      path.join(outputDirectory, 'postgres-migration-report.json'),
      `${JSON.stringify(report, null, 2)}\n`,
      { mode: 0o600 },
    );
    process.stdout.write(`Migration PASS\n`);
  } finally {
    await target.close();
  }
}

main().catch((error: unknown) => {
  process.stderr.write(`${(error as Error)?.message || String(error)}\n`);
  process.exitCode = 1;
});
