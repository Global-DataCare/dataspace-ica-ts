import assert from 'node:assert/strict';
import test from 'node:test';
import {
  clearSeedPassphraseRuntimeCacheForTests,
  resolveSeedPassphrase,
} from '../src/api/tools/seed-passphrase-provider.ts';

function resetSeedProviderEnv(snapshot: Record<string, string | undefined>): void {
  for (const [key, value] of Object.entries(snapshot)) {
    if (value === undefined) delete process.env[key];
    else process.env[key] = value;
  }
}

test('resolveSeedPassphrase prefers direct env when configured', async () => {
  const snapshot = {
    ICA_HOST_SECRET_PROVIDER: process.env.ICA_HOST_SECRET_PROVIDER,
    ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE: process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE,
    ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET: process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET,
  };
  clearSeedPassphraseRuntimeCacheForTests();
  process.env.ICA_HOST_SECRET_PROVIDER = 'gcp-secret-manager';
  process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE = 'direct-seed-passphrase';
  process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET = 'unused-secret';
  try {
    const resolved = await resolveSeedPassphrase(async () => {
      throw new Error('fetcher should not be called when env is present');
    });
    assert.equal(resolved.value, 'direct-seed-passphrase');
    assert.equal(resolved.source, 'env');
  } finally {
    clearSeedPassphraseRuntimeCacheForTests();
    resetSeedProviderEnv(snapshot);
  }
});

test('resolveSeedPassphrase fetches from GCP provider and then serves fresh cache', async () => {
  const snapshot = {
    ICA_HOST_SECRET_PROVIDER: process.env.ICA_HOST_SECRET_PROVIDER,
    ICA_GCP_PROJECT_ID: process.env.ICA_GCP_PROJECT_ID,
    ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET: process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET,
    ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE: process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE,
    ICA_HOST_SECRET_CACHE_TTL_SECONDS: process.env.ICA_HOST_SECRET_CACHE_TTL_SECONDS,
    ICA_HOST_SECRET_STALE_IF_ERROR_SECONDS: process.env.ICA_HOST_SECRET_STALE_IF_ERROR_SECONDS,
  };
  clearSeedPassphraseRuntimeCacheForTests();
  process.env.ICA_HOST_SECRET_PROVIDER = 'gcp-secret-manager';
  process.env.ICA_GCP_PROJECT_ID = 'test-project';
  process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET = 'ica-seed-passphrase';
  process.env.ICA_HOST_SECRET_CACHE_TTL_SECONDS = '60';
  process.env.ICA_HOST_SECRET_STALE_IF_ERROR_SECONDS = '600';
  delete process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE;

  let fetchCount = 0;
  const fetcher = async () => {
    fetchCount += 1;
    return 'seed-from-gcp';
  };

  try {
    const first = await resolveSeedPassphrase(fetcher);
    const second = await resolveSeedPassphrase(fetcher);
    assert.equal(first.value, 'seed-from-gcp');
    assert.equal(first.source, 'gcp-secret-manager');
    assert.equal(second.value, 'seed-from-gcp');
    assert.equal(second.source, 'gcp-secret-manager-cache');
    assert.equal(fetchCount, 1);
  } finally {
    clearSeedPassphraseRuntimeCacheForTests();
    resetSeedProviderEnv(snapshot);
  }
});

test('resolveSeedPassphrase serves stale cache when GCP refresh fails', async () => {
  const snapshot = {
    ICA_HOST_SECRET_PROVIDER: process.env.ICA_HOST_SECRET_PROVIDER,
    ICA_GCP_PROJECT_ID: process.env.ICA_GCP_PROJECT_ID,
    ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET: process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET,
    ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE: process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE,
    ICA_HOST_SECRET_CACHE_TTL_SECONDS: process.env.ICA_HOST_SECRET_CACHE_TTL_SECONDS,
    ICA_HOST_SECRET_STALE_IF_ERROR_SECONDS: process.env.ICA_HOST_SECRET_STALE_IF_ERROR_SECONDS,
  };
  clearSeedPassphraseRuntimeCacheForTests();
  process.env.ICA_HOST_SECRET_PROVIDER = 'gcp-secret-manager';
  process.env.ICA_GCP_PROJECT_ID = 'test-project';
  process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET = 'ica-seed-passphrase';
  process.env.ICA_HOST_SECRET_CACHE_TTL_SECONDS = '1';
  process.env.ICA_HOST_SECRET_STALE_IF_ERROR_SECONDS = '60';
  delete process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE;

  try {
    const first = await resolveSeedPassphrase(async () => 'seed-from-gcp');
    assert.equal(first.source, 'gcp-secret-manager');
    await new Promise((resolve) => setTimeout(resolve, 1100));
    const second = await resolveSeedPassphrase(async () => {
      throw new Error('offline');
    });
    assert.equal(second.value, 'seed-from-gcp');
    assert.equal(second.source, 'gcp-secret-manager-stale-cache');
  } finally {
    clearSeedPassphraseRuntimeCacheForTests();
    resetSeedProviderEnv(snapshot);
  }
});

