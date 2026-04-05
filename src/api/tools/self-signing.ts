import {
  createHash,
  createPrivateKey,
  createPublicKey,
  generateKeyPairSync,
  scryptSync,
} from 'node:crypto';
import { readFileSync } from 'node:fs';
import type { SupportedSigningAlgorithm } from '../types.ts';
import { getPreferredSigningKey } from './active-signing-keys.ts';
import { deriveDeterministicEcPrivateKeyPem } from './deterministic-key-material.ts';

type BootstrapResult = {
  enabled: boolean;
  activated: boolean;
  alg?: SupportedSigningAlgorithm;
  kid?: string;
  source?: 'generated-seed' | 'generated-random' | 'active-key' | 'env-signing-key';
  warning?: string;
};

type ScryptProfile = {
  profile: string;
  log2N: number;
  N: number;
  r: number;
  p: number;
  dkLen: number;
};

type SeedConfig = {
  scrypt: ScryptProfile;
  salt: Buffer<ArrayBufferLike>;
};

type PublicJwk = Record<string, unknown>;

function parseBoolean(value: string | undefined, fallback: boolean): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function parseSupportedSigningAlgorithm(raw: string | undefined): SupportedSigningAlgorithm | undefined {
  const normalized = (raw || '').trim().toUpperCase();
  if (normalized === 'ES384') return 'ES384';
  if (normalized === 'ES256K') return 'ES256K';
  if (normalized === 'RS256') return 'RS256';
  if (normalized === 'PS256') return 'PS256';
  if (normalized === 'EDDSA') return 'EdDSA';
  return undefined;
}

function parseScryptProfile(raw: string | undefined): ScryptProfile {
  const profile = (raw || '17:8:1:48').trim();
  const parts = profile.split(':').map((part) => Number.parseInt(part, 10));
  if (parts.length !== 4 || parts.some((value) => !Number.isFinite(value) || value <= 0)) {
    throw new Error('Invalid seed scrypt profile. Expected format <log2N>:<r>:<p>:<dkLen>, e.g. 17:8:1:48.');
  }
  const [log2N, r, p, dkLen] = parts;
  if (log2N < 10 || log2N > 24) {
    throw new Error('seed scrypt log2N must be between 10 and 24.');
  }
  return {
    profile,
    log2N,
    N: 2 ** log2N,
    r,
    p,
    dkLen,
  };
}

function parseSalt(raw: unknown): Buffer<ArrayBufferLike> {
  if (typeof raw !== 'string') return Buffer.from('gdc:ica:vc:seed:v1', 'utf8');
  const trimmed = raw.trim();
  if (!trimmed) return Buffer.from('gdc:ica:vc:seed:v1', 'utf8');
  if (/^[0-9a-fA-F]+$/.test(trimmed) && trimmed.length % 2 === 0) {
    return Buffer.from(trimmed, 'hex');
  }
  return Buffer.from(trimmed, 'utf8');
}

function parseSeedConfig(raw: string | undefined, rawSaltOverride?: string): SeedConfig {
  const value = (raw || '').trim();
  const saltOverride = parseSalt(rawSaltOverride);
  const hasSaltOverride = typeof rawSaltOverride === 'string' && rawSaltOverride.trim().length > 0;
  if (!value) {
    return {
      scrypt: parseScryptProfile(undefined),
      salt: hasSaltOverride ? saltOverride : Buffer.from('gdc:ica:vc:seed:v1', 'utf8'),
    };
  }
  if (value.startsWith('{')) {
    let parsed: Record<string, unknown>;
    try {
      parsed = JSON.parse(value) as Record<string, unknown>;
    } catch (error: unknown) {
      throw new Error(`Invalid ICA_VC_PRIVATE_KEY_SEED_CONFIG JSON: ${(error as Error).message}`);
    }
    const profile = parseScryptProfile(
      typeof parsed.profile === 'string'
        ? parsed.profile
        : [parsed.log2N, parsed.r, parsed.p, parsed.dkLen].every((item) => Number.isFinite(item as number))
          ? `${parsed.log2N}:${parsed.r}:${parsed.p}:${parsed.dkLen}`
          : undefined,
    );
    return {
      scrypt: profile,
      salt: hasSaltOverride ? saltOverride : parseSalt(parsed.salt),
    };
  }

  const parts = value.split(':');
  if (parts.length >= 4) {
    const profile = parts.slice(0, 4).join(':');
    const saltCandidate = parts.length > 4 ? parts.slice(4).join(':') : '';
    return {
      scrypt: parseScryptProfile(profile),
      salt: hasSaltOverride ? saltOverride : parseSalt(saltCandidate),
    };
  }
  return {
    scrypt: parseScryptProfile(value),
    salt: hasSaltOverride ? saltOverride : Buffer.from('gdc:ica:vc:seed:v1', 'utf8'),
  };
}

function buildJwkThumbprintSource(publicJwk: PublicJwk): PublicJwk {
  const kty = String(publicJwk.kty || '');
  if (kty === 'EC') {
    return {
      crv: publicJwk.crv,
      kty: publicJwk.kty,
      x: publicJwk.x,
      y: publicJwk.y,
    };
  }
  if (kty === 'RSA') {
    return {
      e: publicJwk.e,
      kty: publicJwk.kty,
      n: publicJwk.n,
    };
  }
  if (kty === 'OKP') {
    return {
      crv: publicJwk.crv,
      kty: publicJwk.kty,
      x: publicJwk.x,
    };
  }
  return publicJwk;
}

function buildKidFromPrivateKeyPem(privateKeyPem: string): string {
  const privateKey = createPrivateKey(privateKeyPem);
  const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' }) as PublicJwk;
  const thumbprintSource = buildJwkThumbprintSource(publicJwk);
  return createHash('sha256')
    .update(JSON.stringify(thumbprintSource))
    .digest('base64url');
}

function installRuntimeEnvSigningKey(privateKeyPem: string, alg: SupportedSigningAlgorithm, kid: string): void {
  process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM = privateKeyPem;
  process.env.ICA_VC_SIGNING_ALG = alg;
  process.env.ICA_VC_SIGNING_KEY_ID = kid;
}

function generatePrivateKeyPem(alg: SupportedSigningAlgorithm): string {
  if (alg === 'ES384') {
    return generateKeyPairSync('ec', { namedCurve: 'P-384' })
      .privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
  }
  if (alg === 'ES256K') {
    return generateKeyPairSync('ec', { namedCurve: 'secp256k1' })
      .privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
  }
  if (alg === 'EdDSA') {
    return generateKeyPairSync('ed25519')
      .privateKey
      .export({ type: 'pkcs8', format: 'pem' })
      .toString();
  }
  return generateKeyPairSync('rsa', { modulusLength: 3072 })
    .privateKey
    .export({ type: 'pkcs8', format: 'pem' })
    .toString();
}

function deriveDeterministicPrivateKeyPemFromPassphrase(
  passphrase: string,
  alg: SupportedSigningAlgorithm,
  config: SeedConfig,
): string {
  if (alg !== 'ES384' && alg !== 'ES256K') {
    throw new Error('ICA_VC_SEED_ALG must be ES384 or ES256K for deterministic seed derivation.');
  }
  const derivedSeed = scryptSync(passphrase, config.salt, config.scrypt.dkLen, {
    N: config.scrypt.N,
    r: config.scrypt.r,
    p: config.scrypt.p,
    maxmem: 128 * config.scrypt.N * config.scrypt.r * 2,
  });
  const separation = Buffer.from(`gdc:v1:ica:vc:${alg.toLowerCase()}`, 'utf8');
  const separatedSeedHex = createHash('sha256')
    .update(derivedSeed)
    .update(Buffer.from('|'))
    .update(separation)
    .digest('hex');
  const derived = deriveDeterministicEcPrivateKeyPem(
    `scrypt:${config.scrypt.profile}:${separatedSeedHex}`,
    alg === 'ES384' ? 'P-384' : 'secp256k1',
  );
  return derived.privateKeyPem;
}

function resolveSeedPassphrase(): string {
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
    return trimmed;
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
    return trimmed;
  }

  return (process.env.ICA_VC_PRIVATE_KEY_SEED_PASSPHRASE || '').trim();
}

export function useInvalidProofForTestResourceVersion(): boolean {
  const validProofFlag = process.env.ICA_SELF_SIGN_TEST_VALID_PROOF;
  if (validProofFlag === undefined) return true;
  return !parseBoolean(validProofFlag, false);
}

export function bootstrapSelfSigningKey(): BootstrapResult {
  const active = getPreferredSigningKey(undefined);
  if (active) {
    return {
      enabled: true,
      activated: false,
      alg: active.alg,
      kid: active.kid,
      source: 'active-key',
    };
  }

  const envPrivateKey = (process.env.ICA_VC_SIGNING_PRIVATE_KEY_PEM || '').trim();
  if (envPrivateKey) {
    const alg = parseSupportedSigningAlgorithm(process.env.ICA_VC_SIGNING_ALG);
    const kid = (process.env.ICA_VC_SIGNING_KEY_ID || '').trim() || buildKidFromPrivateKeyPem(envPrivateKey);
    if (!process.env.ICA_VC_SIGNING_KEY_ID) {
      process.env.ICA_VC_SIGNING_KEY_ID = kid;
    }
    return {
      enabled: true,
      activated: false,
      alg,
      kid,
      source: 'env-signing-key',
    };
  }

  const explicitSelfSign = parseBoolean(process.env.ICA_SELF_SIGN_TEST, false);
  const selfSignIfMissing = parseBoolean(process.env.ICA_SELF_SIGN_IF_MISSING, true);
  if (!explicitSelfSign && !selfSignIfMissing) {
    return { enabled: false, activated: false };
  }

  const alg = parseSupportedSigningAlgorithm(process.env.ICA_VC_SEED_ALG)
    || parseSupportedSigningAlgorithm(process.env.ICA_SELF_SIGN_TEST_ALG)
    || 'ES384';
  const configuredKid = (process.env.ICA_SELF_SIGN_TEST_KEY_ID || '').trim() || undefined;
  const seedPassphrase = resolveSeedPassphrase();
  const privateKeyPem = seedPassphrase
    ? deriveDeterministicPrivateKeyPemFromPassphrase(
      seedPassphrase,
      alg,
      parseSeedConfig(
        process.env.ICA_VC_PRIVATE_KEY_SEED_CONFIG,
        process.env.ICA_VC_PRIVATE_KEY_SEED_SALT,
      ),
    )
    : generatePrivateKeyPem(alg);
  const generatedKid = configuredKid || buildKidFromPrivateKeyPem(privateKeyPem);
  installRuntimeEnvSigningKey(privateKeyPem, alg, generatedKid);

  return {
    enabled: true,
    activated: true,
    alg,
    kid: generatedKid,
    source: seedPassphrase ? 'generated-seed' : 'generated-random',
    warning: explicitSelfSign
      ? 'Self-signing key is active; signatures are not chained to an external CA.'
      : 'No VC signing key configured; generated local self-signing key (not chained to external CA).',
  };
}
