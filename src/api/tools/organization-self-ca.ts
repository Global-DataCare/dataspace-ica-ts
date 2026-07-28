import { execFileSync } from 'node:child_process';
import { createECDH, createHash, createPrivateKey, createPublicKey, scryptSync } from 'node:crypto';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import path from 'node:path';
import { computeRfc7638JwkThumbprint } from 'gdc-common-utils-ts/utils/jwk-thumbprint';
import type { SupportedSigningAlgorithm } from '../types.ts';
import { getActiveSigningKeyByAlg } from './active-signing-keys.ts';

type JsonObject = Record<string, unknown>;

type CachedCaArtifacts = {
  tempDir: string;
  rootKeyPath: string;
  rootCertPath: string;
  issuerKeyPath: string;
  issuerCertPath: string;
  rootX5c: string;
  issuerX5c: string;
};

type SeedConfig = {
  profile: string;
  log2N: number;
  N: number;
  r: number;
  p: number;
  dkLen: number;
  saltBuffer: Buffer;
};

type ParsedOrganizationDid = {
  authority: string;
  sector: string;
  taxId: string;
};

const DEFAULT_NOT_BEFORE_UTC = '20240101000000Z';
const DEFAULT_ROOT_DAYS = 3650;
const DEFAULT_ISSUER_DAYS = 1825;
const DEFAULT_LEAF_DAYS = 730;
const caCache = new Map<string, CachedCaArtifacts>();

let cleanupRegistered = false;

function registerCleanup(): void {
  if (cleanupRegistered) return;
  cleanupRegistered = true;
  process.once('exit', () => {
    for (const cached of caCache.values()) {
      rmSync(cached.tempDir, { recursive: true, force: true });
    }
    caCache.clear();
  });
}

function asNonEmptyString(value: unknown): string {
  return typeof value === 'string' ? value.trim() : '';
}

function asNonEmptyStringArray(value: unknown): string[] {
  return Array.isArray(value)
    ? value.map((entry) => asNonEmptyString(entry)).filter(Boolean)
    : [];
}

function parseBooleanEnv(value: string | undefined, fallback = false): boolean {
  if (value === undefined) return fallback;
  const normalized = value.trim().toLowerCase();
  if (normalized === 'true' || normalized === '1' || normalized === 'yes') return true;
  if (normalized === 'false' || normalized === '0' || normalized === 'no') return false;
  return fallback;
}

function normalizeDidWebAuthority(raw: string | undefined): string {
  const trimmed = (raw || '').trim();
  if (!trimmed) return '';
  if (/^[a-z][a-z0-9+.-]*:\/\//i.test(trimmed)) {
    try {
      return new URL(trimmed).host.toLowerCase();
    } catch {
      return '';
    }
  }
  return trimmed.split('/')[0].trim().toLowerCase();
}

function parseOrganizationDid(did: string): ParsedOrganizationDid | null {
  const normalized = did.trim();
  if (!normalized.startsWith('did:web:')) return null;
  const segments = normalized
    .slice('did:web:'.length)
    .split(':')
    .map((part) => decodeURIComponent(part.trim()))
    .filter(Boolean);
  if (segments.length < 5) return null;
  const [authority, sector, resourceType, idType, ...taxIdParts] = segments;
  if (!authority || !sector || resourceType !== 'organization' || idType !== 'taxid' || taxIdParts.length === 0) {
    return null;
  }
  return {
    authority: authority.toLowerCase(),
    sector: sector.toLowerCase(),
    taxId: taxIdParts.join(':').toUpperCase(),
  };
}

function inferJurisdictionFromTaxId(taxId: string): string | undefined {
  const normalized = taxId.trim().toUpperCase();
  if (!normalized) return undefined;
  if (normalized.startsWith('VATES')) return 'ES';
  const match = /^VAT([A-Z]{2})(?:[-:].*)?$/.exec(normalized);
  if (match?.[1]) return match[1];
  return undefined;
}

function resolveCountryCode(value: string | undefined, fallback = 'ES'): string {
  const normalized = (value || '').trim().toUpperCase();
  return /^[A-Z]{2}$/.test(normalized) ? normalized : fallback;
}

function normalizeJwkForThumbprint(publicKeyJwk: JsonObject): Record<string, string> {
  return Object.fromEntries(
    Object.entries(publicKeyJwk)
      .filter(([, value]) => typeof value === 'string')
      .map(([key, value]) => [key, String(value)]),
  );
}

function normalizeSubjectValue(value: string): string {
  const normalized = value.replace(/[\\/+=",;<>#]/g, ' ').replace(/\s+/g, ' ').trim();
  return normalized || 'unknown';
}

function parseScryptProfile(rawValue: string | undefined, fallbackProfile: string): SeedConfig {
  const profile = (rawValue || fallbackProfile).trim();
  const parts = profile.split(':').map((entry) => Number.parseInt(entry, 10));
  if (parts.length !== 4 || parts.some((value) => !Number.isFinite(value) || value <= 0)) {
    throw new Error('Invalid self-CA scrypt profile. Expected <log2N>:<r>:<p>:<dkLen>.');
  }
  const [log2N, r, p, dkLen] = parts;
  if (log2N < 10 || log2N > 24) {
    throw new Error('Self-CA scrypt log2N must be between 10 and 24.');
  }
  return {
    profile,
    log2N,
    N: 2 ** log2N,
    r,
    p,
    dkLen,
    saltBuffer: Buffer.alloc(0),
  };
}

function parseSeedConfig(rawProfile: string | undefined, rawSalt: string | undefined, fallbackSalt: string): SeedConfig {
  const scrypt = parseScryptProfile(rawProfile, '17:8:1:48');
  const trimmedSalt = (rawSalt || '').trim();
  const saltBuffer = trimmedSalt
    ? (/^[0-9a-fA-F]+$/.test(trimmedSalt) && trimmedSalt.length % 2 === 0
        ? Buffer.from(trimmedSalt, 'hex')
        : Buffer.from(trimmedSalt, 'utf8'))
    : Buffer.from(fallbackSalt, 'utf8');
  return {
    ...scrypt,
    saltBuffer,
  };
}

function deriveDeterministicEcKeyMaterial(passphrase: string, seedConfig: SeedConfig, separationTag: string) {
  const derivedSeed = scryptSync(passphrase, seedConfig.saltBuffer, seedConfig.dkLen, {
    N: seedConfig.N,
    r: seedConfig.r,
    p: seedConfig.p,
    maxmem: 128 * seedConfig.N * seedConfig.r * 2,
  });
  const separatedSeedHex = createHash('sha256')
    .update(derivedSeed)
    .update(Buffer.from('|'))
    .update(Buffer.from(separationTag, 'utf8'))
    .digest('hex');
  const deterministicSeed = `scrypt:${seedConfig.profile}:${separatedSeedHex}`;
  return deriveDeterministicEcPrivateKeyPem(deterministicSeed);
}

function deriveDeterministicEcPrivateKeyPem(seed: string) {
  for (let counter = 0; counter < 256; counter += 1) {
    const material = createHash('sha512').update(`${seed}:P-384:${counter}`).digest();
    const candidate = material.subarray(0, 48);
    try {
      const ecdh = createECDH('secp384r1');
      ecdh.setPrivateKey(candidate);
      const privateBytes = ecdh.getPrivateKey();
      const publicBytes = ecdh.getPublicKey(undefined, 'uncompressed');
      const x = publicBytes.subarray(1, 49).toString('base64url');
      const y = publicBytes.subarray(49, 97).toString('base64url');
      const d = privateBytes.toString('base64url');
      const privateKey = createPrivateKey({
        key: { kty: 'EC', crv: 'P-384', x, y, d },
        format: 'jwk',
      });
      return {
        privateKeyPem: privateKey.export({ type: 'pkcs8', format: 'pem' }).toString(),
        publicJwk: { kty: 'EC', crv: 'P-384', x, y },
      };
    } catch {
      // Try the next candidate until a valid scalar is produced.
    }
  }
  throw new Error('Unable to derive deterministic P-384 key for self-CA.');
}

function parseUtcTimestamp(rawValue: string, label: string): { value: string; date: Date } {
  const value = rawValue.trim();
  if (!/^\d{14}Z$/.test(value)) {
    throw new Error(`${label} must use YYYYMMDDHHMMSSZ format.`);
  }
  const year = Number.parseInt(value.slice(0, 4), 10);
  const month = Number.parseInt(value.slice(4, 6), 10);
  const day = Number.parseInt(value.slice(6, 8), 10);
  const hour = Number.parseInt(value.slice(8, 10), 10);
  const minute = Number.parseInt(value.slice(10, 12), 10);
  const second = Number.parseInt(value.slice(12, 14), 10);
  const date = new Date(Date.UTC(year, month - 1, day, hour, minute, second));
  if (
    date.getUTCFullYear() !== year
    || date.getUTCMonth() !== month - 1
    || date.getUTCDate() !== day
    || date.getUTCHours() !== hour
    || date.getUTCMinutes() !== minute
    || date.getUTCSeconds() !== second
  ) {
    throw new Error(`${label} is not a valid UTC timestamp.`);
  }
  return { value, date };
}

function formatUtcTimestamp(date: Date): string {
  const pad = (value: number) => value.toString().padStart(2, '0');
  return [
    date.getUTCFullYear().toString().padStart(4, '0'),
    pad(date.getUTCMonth() + 1),
    pad(date.getUTCDate()),
    pad(date.getUTCHours()),
    pad(date.getUTCMinutes()),
    pad(date.getUTCSeconds()),
  ].join('') + 'Z';
}

function addDaysUtc(date: Date, days: number): Date {
  return new Date(date.getTime() + (days * 24 * 60 * 60 * 1000));
}

function resolveValidityWindow(days: number): { notBefore: string; notAfter: string } {
  const notBefore = parseUtcTimestamp(
    process.env.ICA_CREATE_DID_SELF_CA_NOT_BEFORE || DEFAULT_NOT_BEFORE_UTC,
    'ICA_CREATE_DID_SELF_CA_NOT_BEFORE',
  );
  return {
    notBefore: notBefore.value,
    notAfter: formatUtcTimestamp(addDaysUtc(notBefore.date, days)),
  };
}

function readPemAsBase64Der(pemPath: string): string {
  return readFileSync(pemPath, 'utf8')
    .replace(/-----BEGIN [^-]+-----/g, '')
    .replace(/-----END [^-]+-----/g, '')
    .replace(/\s+/g, '');
}

function base64DerToPem(base64Der: string): string {
  const normalized = base64Der.trim().replace(/\s+/g, '');
  if (!normalized) {
    throw new Error('x5c entry is empty.');
  }
  const wrapped = normalized.match(/.{1,64}/g)?.join('\n') || normalized;
  return `-----BEGIN CERTIFICATE-----\n${wrapped}\n-----END CERTIFICATE-----\n`;
}

function buildDeterministicSerialHex(parts: string[]): string {
  const digest = createHash('sha256')
    .update(parts.filter(Boolean).join('|'))
    .digest('hex')
    .toUpperCase();
  return `01${digest.slice(0, 30)}`;
}

function runOpenSsl(args: string[]): void {
  try {
    execFileSync('openssl', args, { stdio: 'pipe' });
  } catch (error: unknown) {
    const message = error instanceof Error ? error.message : String(error);
    throw new Error(`OpenSSL self-CA command failed (${args[0] || 'openssl'}): ${message}`);
  }
}

function createCaExtensionsFile(baseDir: string, commonName: string, dnsName: string, isRoot: boolean): string {
  const extPath = path.join(baseDir, isRoot ? 'root-ext.cnf' : 'issuer-ext.cnf');
  const lines = [
    '[v3_ca]',
    `basicConstraints=critical,CA:true,pathlen:${isRoot ? 1 : 0}`,
    'keyUsage=critical,keyCertSign,cRLSign',
    'subjectKeyIdentifier=hash',
    'authorityKeyIdentifier=keyid:always,issuer',
    `subjectAltName=DNS:${dnsName}`,
    `issuerAltName=DNS:${dnsName}`,
    `nsComment=${commonName}`,
  ];
  writeFileSync(extPath, `${lines.join('\n')}\n`);
  return extPath;
}

function createLeafExtensionsFile(baseDir: string, did: string, authority: string): string {
  const extPath = path.join(baseDir, 'leaf-ext.cnf');
  const sanEntries = [`URI:${did}`];
  if (authority) sanEntries.push(`DNS:${authority}`);
  const lines = [
    '[v3_leaf]',
    'basicConstraints=critical,CA:false',
    'keyUsage=critical,digitalSignature',
    'extendedKeyUsage=clientAuth',
    'subjectKeyIdentifier=hash',
    'authorityKeyIdentifier=keyid,issuer',
    `subjectAltName=${sanEntries.join(',')}`,
  ];
  writeFileSync(extPath, `${lines.join('\n')}\n`);
  return extPath;
}

function resolvePassphrase(): string {
  const direct = asNonEmptyString(process.env.ICA_CREATE_DID_SELF_CA_PASSPHRASE);
  if (direct) return direct;
  const envName = asNonEmptyString(process.env.ICA_CREATE_DID_SELF_CA_PASSPHRASE_ENV);
  if (!envName) {
    throw new Error(
      'ICA_CREATE_DID_SELF_CA_STAGING=true requires ICA_CREATE_DID_SELF_CA_PASSPHRASE or ICA_CREATE_DID_SELF_CA_PASSPHRASE_ENV.',
    );
  }
  const envValue = asNonEmptyString(process.env[envName]);
  if (!envValue) {
    throw new Error(`ICA_CREATE_DID_SELF_CA_PASSPHRASE_ENV references missing env var ${envName}.`);
  }
  return envValue;
}

function resolveCaArtifacts(input: {
  did: string;
  organization: { taxID?: string; url?: string };
  alg?: SupportedSigningAlgorithm;
}): CachedCaArtifacts {
  registerCleanup();
  const parsedDid = parseOrganizationDid(input.did);
  const authority = parsedDid?.authority || normalizeDidWebAuthority(input.organization.url);
  const sector = parsedDid?.sector || 'all';
  const taxId = asNonEmptyString(input.organization.taxID) || parsedDid?.taxId || '';
  const jurisdiction = inferJurisdictionFromTaxId(taxId) || 'GLOBAL';
  const domain = normalizeDidWebAuthority(
    process.env.ICA_CREATE_DID_SELF_CA_DOMAIN || process.env.ORG_PUBLIC_DOMAIN_NODE_OPERATOR || authority,
  );
  if (!domain) {
    throw new Error('ICA_CREATE_DID_SELF_CA_DOMAIN or ORG_PUBLIC_DOMAIN_NODE_OPERATOR must resolve to a valid authority.');
  }

  const passphrase = resolvePassphrase();
  const rootSeedConfig = parseSeedConfig(
    process.env.ICA_CREATE_DID_SELF_CA_ROOT_SEED_CONFIG,
    process.env.ICA_CREATE_DID_SELF_CA_ROOT_SEED_SALT,
    'gdc:dataspace:ca:root:seed:v1',
  );
  const issuerSeedConfig = parseSeedConfig(
    process.env.ICA_CREATE_DID_SELF_CA_ISSUER_SEED_CONFIG,
    process.env.ICA_CREATE_DID_SELF_CA_ISSUER_SEED_SALT,
    'gdc:dataspace:ca:issuer:seed:v1',
  );
  const cacheKey = createHash('sha256').update(JSON.stringify({
    domain,
    jurisdiction,
    sector,
    passphrase,
    rootProfile: rootSeedConfig.profile,
    rootSalt: rootSeedConfig.saltBuffer.toString('hex'),
    issuerProfile: issuerSeedConfig.profile,
    issuerSalt: issuerSeedConfig.saltBuffer.toString('hex'),
  })).digest('hex');
  const cached = caCache.get(cacheKey);
  if (cached) return cached;

  const baseDir = mkdtempSync(path.join(tmpdir(), 'ica-org-self-ca-'));
  const country = resolveCountryCode(
    asNonEmptyString(process.env.ICA_CREATE_DID_SELF_CA_COUNTRY) || jurisdiction,
  );
  const rootValidity = resolveValidityWindow(DEFAULT_ROOT_DAYS);
  const issuerValidity = resolveValidityWindow(DEFAULT_ISSUER_DAYS);
  const rootCommonName = asNonEmptyString(process.env.ICA_CREATE_DID_SELF_CA_ROOT_COMMON_NAME) || `Dataspace Root CA ${domain}`;
  const issuerCommonName = asNonEmptyString(process.env.ICA_CREATE_DID_SELF_CA_ISSUER_COMMON_NAME) || `Dataspace Issuer CA ${domain}`;
  const rootKeyMaterial = deriveDeterministicEcKeyMaterial(
    passphrase,
    rootSeedConfig,
    'gdc:v1:dataspace:ca:root:es384',
  );
  const issuerKeyMaterial = deriveDeterministicEcKeyMaterial(
    passphrase,
    issuerSeedConfig,
    `gdc:v1:dataspace:ca:issuer:${jurisdiction.toLowerCase()}:${sector}:${(input.alg || 'ES384').toLowerCase()}`,
  );
  const rootKid = computeRfc7638JwkThumbprint(rootKeyMaterial.publicJwk);
  const issuerKid = computeRfc7638JwkThumbprint(issuerKeyMaterial.publicJwk);

  const rootKeyPath = path.join(baseDir, 'root-key.pem');
  const rootCertPath = path.join(baseDir, 'root-cert.pem');
  const issuerKeyPath = path.join(baseDir, 'issuer-key.pem');
  const issuerCsrPath = path.join(baseDir, 'issuer.csr.pem');
  const issuerCertPath = path.join(baseDir, 'issuer-cert.pem');
  writeFileSync(rootKeyPath, rootKeyMaterial.privateKeyPem);
  writeFileSync(issuerKeyPath, issuerKeyMaterial.privateKeyPem);

  const rootExtPath = createCaExtensionsFile(baseDir, rootCommonName, domain, true);
  runOpenSsl([
    'x509',
    '-new',
    '-sha384',
    '-key',
    rootKeyPath,
    '-out',
    rootCertPath,
    '-set_serial',
    `0x${buildDeterministicSerialHex([domain, 'root', rootKid, rootCommonName])}`,
    '-set_subject',
    `/CN=${normalizeSubjectValue(rootCommonName)}/C=${normalizeSubjectValue(country)}`,
    '-not_before',
    rootValidity.notBefore,
    '-not_after',
    rootValidity.notAfter,
    '-sigopt',
    'nonce-type:1',
    '-extfile',
    rootExtPath,
    '-extensions',
    'v3_ca',
  ]);

  runOpenSsl([
    'req',
    '-new',
    '-sha384',
    '-sigopt',
    'nonce-type:1',
    '-key',
    issuerKeyPath,
    '-out',
    issuerCsrPath,
    '-subj',
    `/CN=${normalizeSubjectValue(issuerCommonName)}/C=${normalizeSubjectValue(country)}`,
  ]);

  const issuerExtPath = createCaExtensionsFile(baseDir, issuerCommonName, domain, false);
  runOpenSsl([
    'x509',
    '-req',
    '-in',
    issuerCsrPath,
    '-CA',
    rootCertPath,
    '-CAkey',
    rootKeyPath,
    '-out',
    issuerCertPath,
    '-sha384',
    '-not_before',
    issuerValidity.notBefore,
    '-not_after',
    issuerValidity.notAfter,
    '-sigopt',
    'nonce-type:1',
    '-set_serial',
    `0x${buildDeterministicSerialHex([domain, 'issuer', jurisdiction, sector, issuerKid, issuerCommonName])}`,
    '-extfile',
    issuerExtPath,
    '-extensions',
    'v3_ca',
  ]);

  const artifacts: CachedCaArtifacts = {
    tempDir: baseDir,
    rootKeyPath,
    rootCertPath,
    issuerKeyPath,
    issuerCertPath,
    rootX5c: readPemAsBase64Der(rootCertPath),
    issuerX5c: readPemAsBase64Der(issuerCertPath),
  };
  caCache.set(cacheKey, artifacts);
  return artifacts;
}

function exportOrganizationPublicKeyPem(publicKeyJwk: JsonObject): string {
  const keyObject = createPublicKey({
    key: publicKeyJwk as JsonWebKey,
    format: 'jwk',
  });
  return keyObject.export({ type: 'spki', format: 'pem' }).toString();
}

export function maybeAttachOrganizationSelfCaX5c(input: {
  did: string;
  organization: {
    taxID?: string;
    legalName?: string;
    url?: string;
    alg?: SupportedSigningAlgorithm;
  };
  publicKeyJwk: JsonObject;
}): JsonObject {
  if (!parseBooleanEnv(process.env.ICA_CREATE_DID_SELF_CA_STAGING, false)) {
    return input.publicKeyJwk;
  }

  const existingX5c = asNonEmptyStringArray(input.publicKeyJwk.x5c);
  const existingX5u = asNonEmptyString(input.publicKeyJwk.x5u);
  if (existingX5c.length || existingX5u) {
    return input.publicKeyJwk;
  }

  const kty = asNonEmptyString(input.publicKeyJwk.kty);
  const crv = asNonEmptyString(input.publicKeyJwk.crv);
  if (kty !== 'EC' || crv !== 'P-384') {
    throw new Error('ICA_CREATE_DID_SELF_CA_STAGING currently supports only organization.publicKeyJwk EC P-384 keys.');
  }

  const parsedDid = parseOrganizationDid(input.did);
  const authority = parsedDid?.authority || normalizeDidWebAuthority(input.organization.url);
  const leafValidity = resolveValidityWindow(DEFAULT_LEAF_DAYS);
  const leafThumbprint = computeRfc7638JwkThumbprint(normalizeJwkForThumbprint(input.publicKeyJwk));
  const leafBaseDir = mkdtempSync(path.join(tmpdir(), 'ica-org-self-ca-leaf-'));
  const leafPublicKeyPath = path.join(leafBaseDir, 'leaf-public.pem');
  const leafCertPath = path.join(leafBaseDir, 'leaf-cert.pem');
  const leafExtPath = createLeafExtensionsFile(leafBaseDir, input.did, authority);
  const caArtifacts = resolveCaArtifacts(input);
  const commonName = input.organization.legalName || input.did;
  const country = resolveCountryCode(
    asNonEmptyString(process.env.ICA_CREATE_DID_SELF_CA_COUNTRY)
      || inferJurisdictionFromTaxId(asNonEmptyString(input.organization.taxID) || parsedDid?.taxId || ''),
  );

  try {
    writeFileSync(leafPublicKeyPath, exportOrganizationPublicKeyPem(input.publicKeyJwk));
    runOpenSsl([
      'x509',
      '-new',
      '-sha384',
      '-CA',
      caArtifacts.issuerCertPath,
      '-CAkey',
      caArtifacts.issuerKeyPath,
      '-force_pubkey',
      leafPublicKeyPath,
      '-out',
      leafCertPath,
      '-set_serial',
      `0x${buildDeterministicSerialHex([input.did, leafThumbprint, commonName])}`,
      '-set_subject',
      `/CN=${normalizeSubjectValue(commonName)}/C=${normalizeSubjectValue(country)}`,
      '-not_before',
      leafValidity.notBefore,
      '-not_after',
      leafValidity.notAfter,
      '-sigopt',
      'nonce-type:1',
      '-extfile',
      leafExtPath,
      '-extensions',
      'v3_leaf',
    ]);
    return {
      ...input.publicKeyJwk,
      x5c: [readPemAsBase64Der(leafCertPath), caArtifacts.issuerX5c, caArtifacts.rootX5c],
    };
  } finally {
    rmSync(leafBaseDir, { recursive: true, force: true });
  }
}

function maybeAttachOrganizationIcaIssuedX5c(input: {
  did: string;
  organization: {
    taxID?: string;
    legalName?: string;
    url?: string;
    alg?: SupportedSigningAlgorithm;
  };
  publicKeyJwk: JsonObject;
}): JsonObject {
  const existingX5c = asNonEmptyStringArray(input.publicKeyJwk.x5c);
  const existingX5u = asNonEmptyString(input.publicKeyJwk.x5u);
  if (existingX5c.length || existingX5u) {
    return input.publicKeyJwk;
  }

  const kty = asNonEmptyString(input.publicKeyJwk.kty);
  const crv = asNonEmptyString(input.publicKeyJwk.crv);
  if (kty !== 'EC' || crv !== 'P-384') {
    return input.publicKeyJwk;
  }

  const activeIssuer = getActiveSigningKeyByAlg('ES384');
  if (!activeIssuer?.x5c?.length) {
    return input.publicKeyJwk;
  }

  const parsedDid = parseOrganizationDid(input.did);
  const authority = parsedDid?.authority || normalizeDidWebAuthority(input.organization.url);
  const leafValidity = resolveValidityWindow(DEFAULT_LEAF_DAYS);
  const leafThumbprint = computeRfc7638JwkThumbprint(normalizeJwkForThumbprint(input.publicKeyJwk));
  const leafBaseDir = mkdtempSync(path.join(tmpdir(), 'ica-org-active-ca-leaf-'));
  const leafPublicKeyPath = path.join(leafBaseDir, 'leaf-public.pem');
  const leafCertPath = path.join(leafBaseDir, 'leaf-cert.pem');
  const issuerCertPath = path.join(leafBaseDir, 'issuer-cert.pem');
  const issuerKeyPath = path.join(leafBaseDir, 'issuer-key.pem');
  const leafExtPath = createLeafExtensionsFile(leafBaseDir, input.did, authority);
  const commonName = input.organization.legalName || input.did;
  const country = resolveCountryCode(
    inferJurisdictionFromTaxId(asNonEmptyString(input.organization.taxID) || parsedDid?.taxId || ''),
  );

  try {
    writeFileSync(leafPublicKeyPath, exportOrganizationPublicKeyPem(input.publicKeyJwk));
    writeFileSync(issuerCertPath, base64DerToPem(activeIssuer.x5c[0] || ''));
    writeFileSync(issuerKeyPath, activeIssuer.privateKeyPem);
    runOpenSsl([
      'x509',
      '-new',
      '-sha384',
      '-CA',
      issuerCertPath,
      '-CAkey',
      issuerKeyPath,
      '-force_pubkey',
      leafPublicKeyPath,
      '-out',
      leafCertPath,
      '-set_serial',
      `0x${buildDeterministicSerialHex([input.did, leafThumbprint, commonName, activeIssuer.kid])}`,
      '-set_subject',
      `/CN=${normalizeSubjectValue(commonName)}/C=${normalizeSubjectValue(country)}`,
      '-not_before',
      leafValidity.notBefore,
      '-not_after',
      leafValidity.notAfter,
      '-sigopt',
      'nonce-type:1',
      '-extfile',
      leafExtPath,
      '-extensions',
      'v3_leaf',
    ]);
    return {
      ...input.publicKeyJwk,
      x5c: [readPemAsBase64Der(leafCertPath), ...activeIssuer.x5c],
    };
  } finally {
    rmSync(leafBaseDir, { recursive: true, force: true });
  }
}

export function maybeAttachOrganizationX5c(input: {
  did: string;
  organization: {
    taxID?: string;
    legalName?: string;
    url?: string;
    alg?: SupportedSigningAlgorithm;
  };
  publicKeyJwk: JsonObject;
}): JsonObject {
  if (parseBooleanEnv(process.env.ICA_CREATE_DID_SELF_CA_STAGING, false)) {
    return maybeAttachOrganizationSelfCaX5c(input);
  }
  return maybeAttachOrganizationIcaIssuedX5c(input);
}

export function resetOrganizationSelfCaCacheForTests(): void {
  for (const cached of caCache.values()) {
    rmSync(cached.tempDir, { recursive: true, force: true });
  }
  caCache.clear();
}
