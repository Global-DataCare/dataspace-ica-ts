import assert from 'node:assert/strict';
import test from 'node:test';
import { loadAuditDocumentStorageConfigFromEnv } from '../src/api/tools/audit-document-storage.ts';
import {
  assertIcaSecurityStartupGuardrails,
  loadIcaSecurityConfigFromEnv,
} from '../src/api/security-mode.ts';
import {
  loadVerificationCollectionsConfigFromEnv,
  resolveEvidenceCollectionName,
  resolveIssuedCredentialsCollectionName,
} from '../src/api/tools/verification-collections-storage.ts';

const ENV_KEYS = [
  'STORAGE_PROVIDER',
  'GCS_BUCKET_NAME',
  'ICA_AUDIT_STORAGE_REQUIRED',
  'ICA_CONFIDENTIAL_STORAGE_ENABLED',
  'ICA_AUDIT_ATTACHMENT_URL_PATTERN',
  'ICA_AUDIT_STORAGE_FS_DIR',
  'ICA_AUDIT_STORAGE_GCS_PREFIX',
  'DB_PROVIDER',
  'FIRESTORE_PROJECT_ID',
  'ICA_COLLECTIONS_REQUIRED',
  'ICA_COLLECTIONS_PREFIX',
  'SECURITY_MODE',
  'JSON_LEGACY',
  'DEMO_MODE',
  'DEMO_ALLOW_INSECURE_BEARER',
  'NODE_ENV',
] as const;

function withEnv(values: Partial<Record<(typeof ENV_KEYS)[number], string | undefined>>, fn: () => void): void {
  const previous = new Map<string, string | undefined>();
  for (const key of ENV_KEYS) {
    previous.set(key, process.env[key]);
  }
  try {
    for (const key of ENV_KEYS) {
      const nextValue = values[key];
      if (nextValue === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = nextValue;
      }
    }
    fn();
  } finally {
    for (const key of ENV_KEYS) {
      const previousValue = previous.get(key);
      if (previousValue === undefined) {
        delete process.env[key];
      } else {
        process.env[key] = previousValue;
      }
    }
  }
}

test('loadAuditDocumentStorageConfigFromEnv uses STORAGE_PROVIDER and GCS_BUCKET_NAME', () => {
  withEnv(
    {
      STORAGE_PROVIDER: 'gcs',
      GCS_BUCKET_NAME: 'globaldatacare-ica-dev',
    },
    () => {
      const config = loadAuditDocumentStorageConfigFromEnv();
      assert.equal(config.mode, 'gcs');
      assert.equal(config.gcsBucketName, 'globaldatacare-ica-dev');
      assert.equal(config.confidentialStorageEnabled, false);
    },
  );
});

test('loadAuditDocumentStorageConfigFromEnv enables confidential storage flag', () => {
  withEnv(
    {
      ICA_CONFIDENTIAL_STORAGE_ENABLED: 'true',
    },
    () => {
      const config = loadAuditDocumentStorageConfigFromEnv();
      assert.equal(config.confidentialStorageEnabled, true);
    },
  );
});

test('loadAuditDocumentStorageConfigFromEnv maps STORAGE_PROVIDER=mem to mode none', () => {
  withEnv(
    {
      STORAGE_PROVIDER: 'mem',
    },
    () => {
      const config = loadAuditDocumentStorageConfigFromEnv();
      assert.equal(config.mode, 'none');
    },
  );
});

test('loadVerificationCollectionsConfigFromEnv uses DB_PROVIDER and FIRESTORE_PROJECT_ID', () => {
  withEnv(
    {
      DB_PROVIDER: 'firestore',
      FIRESTORE_PROJECT_ID: 'globaldatacare-ica-dev',
    },
    () => {
      const config = loadVerificationCollectionsConfigFromEnv();
      assert.equal(config.provider, 'firestore');
      assert.equal(config.firestoreProjectId, 'globaldatacare-ica-dev');
      assert.equal(resolveIssuedCredentialsCollectionName(config.firestoreCollectionPrefix), 'ica_issued_credentials');
      assert.equal(resolveEvidenceCollectionName(config.firestoreCollectionPrefix), 'ica_evidence_records');
    },
  );
});

test('loadIcaSecurityConfigFromEnv defaults to compat and enables search legacy transport', () => {
  withEnv(
    {
      SECURITY_MODE: undefined,
      DEMO_MODE: undefined,
      JSON_LEGACY: undefined,
      DEMO_ALLOW_INSECURE_BEARER: undefined,
    },
    () => {
      const config = loadIcaSecurityConfigFromEnv();
      assert.equal(config.securityMode, 'compat');
      assert.equal(config.jsonLegacy, true);
      assert.equal(config.demoAllowInsecureBearer, false);
    },
  );
});

test('loadIcaSecurityConfigFromEnv maps legacy DEMO_MODE to SECURITY_MODE=demo', () => {
  withEnv(
    {
      SECURITY_MODE: undefined,
      DEMO_MODE: 'true',
    },
    () => {
      const config = loadIcaSecurityConfigFromEnv();
      assert.equal(config.securityMode, 'demo');
    },
  );
});

test('assertIcaSecurityStartupGuardrails blocks demo mode in production', () => {
  withEnv(
    {
      SECURITY_MODE: 'demo',
      NODE_ENV: 'production',
    },
    () => {
      const config = loadIcaSecurityConfigFromEnv();
      assert.throws(() => assertIcaSecurityStartupGuardrails(config), /SECURITY_MODE=demo is not allowed/);
    },
  );
});
