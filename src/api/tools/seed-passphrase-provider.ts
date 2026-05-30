import { readFileSync } from 'node:fs';
import { EncryptedRuntimeCache } from './encrypted-runtime-cache.ts';

type SeedPassphraseSource =
  | 'file'
  | 'secret-env'
  | 'env'
  | 'gcp-secret-manager'
  | 'gcp-secret-manager-cache'
  | 'gcp-secret-manager-stale-cache'
  | 'none';

type ResolvedSeedPassphrase = {
  value: string;
  source: SeedPassphraseSource;
};

type GcpSecretFetcher = (secretVersionName: string) => Promise<string>;

const runtimeCache = new EncryptedRuntimeCache();
const DEFAULT_CACHE_KEY = 'ica.vc.private_key_seed_passphrase';

function parsePositiveInt(raw: string | undefined, fallback: number): number {
  const parsed = Number.parseInt((raw || '').trim(), 10);
  if (!Number.isFinite(parsed) || parsed <= 0) return fallback;
  return parsed;
}

function buildGcpSecretVersionName(): string | undefined {
  const fullVersionName = (process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET_VERSION || '').trim();
  if (fullVersionName) return fullVersionName;
  const secretName = (process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET || '').trim();
  if (!secretName) return undefined;
  if (secretName.startsWith('projects/')) {
    if (secretName.includes('/versions/')) return secretName;
    return `${secretName}/versions/latest`;
  }
  const projectId = (process.env.ICA_GCP_PROJECT_ID || process.env.GOOGLE_CLOUD_PROJECT || '').trim();
  if (!projectId) {
    throw new Error(
      'ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET is set but ICA_GCP_PROJECT_ID/GOOGLE_CLOUD_PROJECT is missing.',
    );
  }
  return `projects/${projectId}/secrets/${secretName}/versions/latest`;
}

async function fetchGcpSecretVersionDefault(secretVersionName: string): Promise<string> {
  let moduleValue: unknown;
  try {
    moduleValue = await import('@google-cloud/secret-manager');
  } catch (error: unknown) {
    throw new Error(
      `Missing @google-cloud/secret-manager dependency required for GCP secret provider: ${(error as Error).message}`,
    );
  }
  const moduleRecord = moduleValue as {
    SecretManagerServiceClient?: new () => {
      accessSecretVersion(input: { name: string }): Promise<Array<{ payload?: { data?: Uint8Array } }>>;
    };
  };
  const SecretManagerServiceClientCtor = moduleRecord.SecretManagerServiceClient;
  if (!SecretManagerServiceClientCtor) {
    throw new Error('Failed to load SecretManagerServiceClient from @google-cloud/secret-manager.');
  }
  const client = new SecretManagerServiceClientCtor();
  const [version] = await client.accessSecretVersion({ name: secretVersionName });
  const raw = version?.payload?.data;
  const value = raw ? Buffer.from(raw).toString('utf8').trim() : '';
  if (!value) throw new Error(`Secret ${secretVersionName} resolved to an empty value.`);
  return value;
}

function resolveFromFileOrEnv(): ResolvedSeedPassphrase | undefined {
  const filePath = (process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_FILE || '').trim();
  if (filePath) {
    let fileValue = '';
    try {
      fileValue = readFileSync(filePath, 'utf8');
    } catch (error: unknown) {
      throw new Error(
        `Failed to read ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_FILE at "${filePath}": ${(error as Error).message}`,
      );
    }
    const trimmed = fileValue.trim();
    if (!trimmed) {
      throw new Error(`ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_FILE at "${filePath}" is empty.`);
    }
    return { value: trimmed, source: 'file' };
  }

  const secretEnvName = (process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_SECRET_ENV || '').trim();
  if (secretEnvName) {
    const envValue = process.env[secretEnvName];
    if (envValue === undefined) {
      throw new Error(
        `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_SECRET_ENV points to "${secretEnvName}", but that env var is not set.`,
      );
    }
    const trimmed = envValue.trim();
    if (!trimmed) {
      throw new Error(
        `ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_SECRET_ENV points to "${secretEnvName}", but the value is empty.`,
      );
    }
    return { value: trimmed, source: 'secret-env' };
  }

  const direct = (process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE || '').trim();
  if (direct) {
    return { value: direct, source: 'env' };
  }
  return undefined;
}

export async function resolveSeedPassphrase(
  gcpFetcher: GcpSecretFetcher = fetchGcpSecretVersionDefault,
): Promise<ResolvedSeedPassphrase> {
  const direct = resolveFromFileOrEnv();
  if (direct) return direct;

  const provider = (process.env.ICA_HOST_SECRET_PROVIDER || '').trim().toLowerCase();
  const gcpSecretVersion = buildGcpSecretVersionName();
  if (provider !== 'gcp-secret-manager' && !gcpSecretVersion) {
    return { value: '', source: 'none' };
  }
  if (!gcpSecretVersion) {
    throw new Error(
      'ICA_HOST_SECRET_PROVIDER=gcp-secret-manager requires ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET or ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE_GCP_SECRET_VERSION.',
    );
  }

  const cacheKey = (process.env.ICA_HOST_SECRET_CACHE_KEY || '').trim() || DEFAULT_CACHE_KEY;
  const cacheTtlSeconds = parsePositiveInt(process.env.ICA_HOST_SECRET_CACHE_TTL_SECONDS, 300);
  const staleIfErrorSeconds = parsePositiveInt(process.env.ICA_HOST_SECRET_STALE_IF_ERROR_SECONDS, 21600);

  const fresh = runtimeCache.getFresh(cacheKey);
  if (fresh) return { value: fresh, source: 'gcp-secret-manager-cache' };

  try {
    const fetched = (await gcpFetcher(gcpSecretVersion)).trim();
    if (!fetched) {
      throw new Error(`Secret ${gcpSecretVersion} resolved to an empty value.`);
    }
    runtimeCache.set(cacheKey, fetched, cacheTtlSeconds, staleIfErrorSeconds);
    return { value: fetched, source: 'gcp-secret-manager' };
  } catch (error: unknown) {
    const stale = runtimeCache.getStaleIfAllowed(cacheKey);
    if (stale) {
      return { value: stale, source: 'gcp-secret-manager-stale-cache' };
    }
    throw new Error(
      `Failed to resolve seed passphrase from GCP Secret Manager (${gcpSecretVersion}): ${(error as Error).message}`,
    );
  }
}

export function clearSeedPassphraseRuntimeCacheForTests(): void {
  runtimeCache.clear();
}

