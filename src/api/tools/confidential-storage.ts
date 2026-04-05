import { createCipheriv, createHash, createHmac, randomBytes } from 'node:crypto';
import { resolveSeedPassphrase } from './seed-passphrase-provider.ts';

type ProtectedEnvelopeV1 = {
  v: 1;
  alg: 'A256GCM';
  kid: string;
  iv: string;
  ciphertext: string;
  tag: string;
  aad: string;
};

type ConfidentialStorageConfig = {
  enabled: boolean;
  keyVersion: string;
};

const DEFAULT_KEY_VERSION = 'v1';

let cachedMasterSeed: string | undefined;

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function loadConfigFromEnv(): ConfidentialStorageConfig {
  return {
    enabled: parseBoolean(process.env.ICA_CONFIDENTIAL_STORAGE_ENABLED, false),
    keyVersion: (process.env.ICA_CONFIDENTIAL_STORAGE_KEY_VERSION || DEFAULT_KEY_VERSION).trim() || DEFAULT_KEY_VERSION,
  };
}

async function resolveMasterSeed(): Promise<string> {
  const explicit = (process.env.ICA_CONFIDENTIAL_STORAGE_KEY_SEED || '').trim();
  if (explicit) return explicit;
  const fromSeedPassphrase = await resolveSeedPassphrase();
  if (!fromSeedPassphrase.value) {
    throw new Error(
      'ICA_CONFIDENTIAL_STORAGE_ENABLED=true requires ICA_CONFIDENTIAL_STORAGE_KEY_SEED or an ICA seed passphrase source.',
    );
  }
  return fromSeedPassphrase.value;
}

function deriveTenantPurposeKey(masterSeed: string, tenantId: string, purpose: string, keyVersion: string): Buffer<ArrayBuffer> {
  const normalizedTenant = tenantId.trim().toLowerCase();
  const normalizedPurpose = purpose.trim().toLowerCase();
  return createHmac('sha256', Buffer.from(masterSeed, 'utf8'))
    .update(`ica:confidential-storage:${keyVersion}`)
    .update('|')
    .update(`tenant:${normalizedTenant}`)
    .update('|')
    .update(`purpose:${normalizedPurpose}`)
    .digest();
}

export type ProtectBinaryResult = {
  ciphertext: Buffer<ArrayBufferLike>;
  contentType: string;
  keyId: string;
};

export class ConfidentialStorageService {
  private readonly config: ConfidentialStorageConfig;

  constructor(config: ConfidentialStorageConfig = loadConfigFromEnv()) {
    this.config = config;
  }

  isEnabled(): boolean {
    return this.config.enabled;
  }

  async protectBinary(tenantId: string, purpose: string, plaintext: Buffer<ArrayBufferLike>): Promise<ProtectBinaryResult> {
    if (!this.config.enabled) {
      return {
        ciphertext: plaintext,
        contentType: 'application/pdf',
        keyId: '',
      };
    }

    if (!cachedMasterSeed) {
      cachedMasterSeed = await resolveMasterSeed();
    }

    const key = deriveTenantPurposeKey(cachedMasterSeed, tenantId, purpose, this.config.keyVersion);
    const iv = randomBytes(12);
    const aadRaw = `tenant=${tenantId}|purpose=${purpose}|v=${this.config.keyVersion}`;
    const aad = Buffer.from(aadRaw, 'utf8');
    const cipher = createCipheriv('aes-256-gcm', key, iv);
    cipher.setAAD(aad);
    const ciphertext = Buffer.concat([cipher.update(plaintext), cipher.final()]);
    const tag = cipher.getAuthTag();
    const kid = createHash('sha256')
      .update(`ica:confidential-storage:${this.config.keyVersion}|${tenantId.toLowerCase()}|${purpose.toLowerCase()}`)
      .digest('hex')
      .slice(0, 24);
    const envelope: ProtectedEnvelopeV1 = {
      v: 1,
      alg: 'A256GCM',
      kid: `${this.config.keyVersion}:${kid}`,
      iv: iv.toString('base64'),
      ciphertext: ciphertext.toString('base64'),
      tag: tag.toString('base64'),
      aad: aad.toString('base64'),
    };
    return {
      ciphertext: Buffer.from(JSON.stringify(envelope), 'utf8'),
      contentType: 'application/vnd.globaldatacare.encrypted+json',
      keyId: envelope.kid,
    };
  }
}

export function clearConfidentialStorageSeedCacheForTests(): void {
  cachedMasterSeed = undefined;
}
