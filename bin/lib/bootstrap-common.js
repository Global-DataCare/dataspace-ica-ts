import { computeRfc7638JwkThumbprint } from 'gdc-common-utils-ts/utils/jwk-thumbprint';
import {
  deriveDeterministicEcPemKeyPair,
  deriveScryptSeparatedEcPemKeyPair,
  parseDeterministicSeedSalt,
  parseScryptDerivationProfile,
} from 'gdc-common-utils-ts/utils/deterministic-seed-key';

export function parseScryptProfile(raw, fallbackProfile = '17:8:1:48') {
  return parseScryptDerivationProfile(raw, fallbackProfile);
}

export function parseSeedSalt(rawSalt, defaultSalt) {
  const fallback = defaultSalt || 'gdc:ica:seed:v1';
  const parsed = parseDeterministicSeedSalt(rawSalt, fallback);
  return {
    saltBuffer: Buffer.from(parsed.salt),
    saltRaw: parsed.raw,
    saltEncoding: parsed.encoding,
  };
}

export function parseSeedConfig(args, options = {}) {
  const rawConfig = typeof args['seed-config'] === 'string' ? args['seed-config'].trim() : '';
  const explicitProfile = typeof args.scrypt === 'string' ? args.scrypt.trim() : '';
  const explicitSalt = typeof args.salt === 'string' ? args.salt.trim() : '';
  const fallbackProfile = options.defaultScryptProfile || '17:8:1:48';
  const fallbackSalt = options.defaultSalt || 'gdc:ica:seed:v1';

  if (!rawConfig) {
    const scrypt = parseScryptProfile(explicitProfile || undefined, fallbackProfile);
    const salt = parseSeedSalt(explicitSalt || undefined, fallbackSalt);
    return {
      scrypt,
      ...salt,
      source: explicitSalt ? '--salt' : 'default',
    };
  }

  if (rawConfig.startsWith('{')) {
    let parsed;
    try {
      parsed = JSON.parse(rawConfig);
    } catch (error) {
      throw new Error(`Invalid --seed-config JSON: ${error.message}`);
    }
    const profileFromJson = typeof parsed.profile === 'string'
      ? parsed.profile
      : [parsed.log2N, parsed.r, parsed.p, parsed.dkLen].every((item) => Number.isFinite(item))
        ? `${parsed.log2N}:${parsed.r}:${parsed.p}:${parsed.dkLen}`
        : undefined;
    const scrypt = parseScryptProfile(profileFromJson || explicitProfile || undefined, fallbackProfile);
    const salt = parseSeedSalt(
      typeof parsed.salt === 'string' && parsed.salt.trim()
        ? parsed.salt
        : explicitSalt || undefined,
      fallbackSalt,
    );
    return {
      scrypt,
      ...salt,
      source: 'seed-config-json',
    };
  }

  const parts = rawConfig.split(':');
  if (parts.length >= 4) {
    const profile = parts.slice(0, 4).join(':');
    const trailingSalt = parts.length > 4 ? parts.slice(4).join(':') : '';
    const scrypt = parseScryptProfile(profile, fallbackProfile);
    const salt = parseSeedSalt(trailingSalt || explicitSalt || undefined, fallbackSalt);
    return {
      scrypt,
      ...salt,
      source: 'seed-config-colon',
    };
  }

  const scrypt = parseScryptProfile(rawConfig || explicitProfile || undefined, fallbackProfile);
  const salt = parseSeedSalt(explicitSalt || undefined, fallbackSalt);
  return {
    scrypt,
    ...salt,
    source: 'seed-config-profile',
  };
}

export function resolvePassphrase(args, requireArg, options = {}) {
  const passphraseArg = options.passphraseArg || 'passphrase';
  const passphraseEnvArg = options.passphraseEnvArg || 'passphrase-env';
  if (typeof args[passphraseEnvArg] === 'string' && args[passphraseEnvArg].trim()) {
    const envName = args[passphraseEnvArg].trim();
    const envValue = process.env[envName];
    if (!envValue || !envValue.trim()) {
      throw new Error(`Missing passphrase env var ${envName}.`);
    }
    return envValue.trim();
  }
  return requireArg(args, passphraseArg);
}

export function deriveDeterministicEcPrivateKeyPem(seed, curve) {
  return deriveDeterministicEcPemKeyPair(seed, curve);
}

export function deriveDeterministicEcKeyMaterial(passphrase, alg, seedConfig, separationTag) {
  return deriveScryptSeparatedEcPemKeyPair({
    passphrase,
    alg,
    profile: seedConfig.scrypt,
    salt: seedConfig.saltBuffer,
    separationTag,
  });
}

export function computeJwkKid(publicJwk) {
  return computeRfc7638JwkThumbprint(publicJwk);
}

export function buildDidWebFromDomain(domain, normalizeDomain) {
  const authority = normalizeDomain(domain);
  return `did:web:${authority.replace(/:/g, '%3A')}`;
}
