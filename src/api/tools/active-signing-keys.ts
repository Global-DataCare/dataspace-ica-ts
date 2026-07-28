import { createHash, createPrivateKey, createPublicKey } from 'node:crypto';
import type { SupportedSigningAlgorithm } from '../types.ts';

type JsonObject = Record<string, unknown>;

export type ActiveSigningKeyRecord = {
  kid: string;
  alg: SupportedSigningAlgorithm;
  privateKeyPem: string;
  publicJwk: JsonObject;
  x5c?: string[];
  x5u?: string;
  activatedAt: string;
};

const state = {
  loaded: false,
  keysByKid: new Map<string, ActiveSigningKeyRecord>(),
  activeByAlg: {} as Record<string, string>,
};

function decodeMultilineEnv(value: string): string {
  return value.includes('\\n') ? value.replace(/\\n/g, '\n') : value;
}

function supportedAlgorithms(): SupportedSigningAlgorithm[] {
  return ['ES384', 'ES256K', 'RS256', 'PS256', 'EdDSA'];
}

function isSupportedAlgorithm(value: string): value is SupportedSigningAlgorithm {
  return supportedAlgorithms().includes(value as SupportedSigningAlgorithm);
}

function normalizeAlgorithm(raw: string): SupportedSigningAlgorithm {
  const normalized = raw.trim().toUpperCase();
  if (normalized === 'EDDSA') return 'EdDSA';
  if (!isSupportedAlgorithm(normalized)) {
    throw new Error(`Unsupported signing algorithm: ${raw}`);
  }
  return normalized;
}

function normalizePrivateKeyPem(raw: string): string {
  const normalized = decodeMultilineEnv(raw).trim();
  if (!normalized) {
    throw new Error('privateKeyPem cannot be empty.');
  }
  return normalized;
}

function buildJwkThumbprintSource(publicJwk: JsonObject): JsonObject {
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

function buildKidFromPublicJwk(publicJwk: JsonObject): string {
  const thumbprintSource = buildJwkThumbprintSource(publicJwk);
  return createHash('sha256')
    .update(JSON.stringify(thumbprintSource))
    .digest('base64url');
}

function splitPemCertificates(pemText: string): string[] {
  const output: string[] = [];
  const regex = /-----BEGIN CERTIFICATE-----[\s\S]*?-----END CERTIFICATE-----/g;
  let match: RegExpExecArray | null;
  while ((match = regex.exec(pemText)) !== null) {
    const certificatePem = match[0].trim();
    if (certificatePem) output.push(certificatePem);
  }
  return output;
}

function pemCertificateToDerBase64(pem: string): string {
  const body = pem
    .replace(/-----BEGIN CERTIFICATE-----/g, '')
    .replace(/-----END CERTIFICATE-----/g, '')
    .replace(/\s+/g, '')
    .trim();
  if (!body) {
    throw new Error('Invalid certificate PEM entry in chain.');
  }
  return body;
}

function normalizeX5cInput(x5c: string[] | undefined, chainPem: string[] | undefined): string[] | undefined {
  const fromX5c = (x5c || []).map((entry) => entry.trim()).filter(Boolean);
  if (fromX5c.length) return fromX5c;

  const fromPem = (chainPem || [])
    .flatMap((entry) => splitPemCertificates(decodeMultilineEnv(entry)))
    .map((pem) => pemCertificateToDerBase64(pem))
    .filter(Boolean);
  return fromPem.length ? fromPem : undefined;
}

function assertAlgorithmMatchesKey(alg: SupportedSigningAlgorithm, publicJwk: JsonObject): void {
  const kty = String(publicJwk.kty || '');
  const crv = String(publicJwk.crv || '');
  if (alg === 'ES384') {
    if (kty !== 'EC' || crv !== 'P-384') {
      throw new Error(`alg=ES384 requires EC P-384 key (got kty=${kty}, crv=${crv || 'n/a'}).`);
    }
    return;
  }
  if (alg === 'ES256K') {
    if (kty !== 'EC' || crv !== 'secp256k1') {
      throw new Error(`alg=ES256K requires EC secp256k1 key (got kty=${kty}, crv=${crv || 'n/a'}).`);
    }
    return;
  }
  if (alg === 'RS256' || alg === 'PS256') {
    if (kty !== 'RSA') {
      throw new Error(`alg=${alg} requires RSA key (got kty=${kty}).`);
    }
    return;
  }
  if (alg === 'EdDSA') {
    if (kty !== 'OKP' || (crv !== 'Ed25519' && crv !== 'Ed448')) {
      throw new Error(`alg=EdDSA requires OKP Ed25519/Ed448 key (got kty=${kty}, crv=${crv || 'n/a'}).`);
    }
  }
}

function buildRecordFromInput(input: {
  kid?: string;
  alg: string;
  privateKeyPem: string;
  x5c?: string[];
  x5u?: string;
  certificateChainPem?: string[];
  activatedAt?: string;
}): ActiveSigningKeyRecord {
  const alg = normalizeAlgorithm(input.alg);
  const privateKeyPem = normalizePrivateKeyPem(input.privateKeyPem);
  const privateKey = createPrivateKey(privateKeyPem);
  const publicJwk = createPublicKey(privateKey).export({ format: 'jwk' }) as JsonObject;
  assertAlgorithmMatchesKey(alg, publicJwk);
  const kid = (input.kid || '').trim() || buildKidFromPublicJwk(publicJwk);
  const x5c = normalizeX5cInput(input.x5c, input.certificateChainPem);
  const x5u = String(input.x5u || '').trim();
  if (x5u && !x5u.startsWith('https://')) {
    throw new Error('x5u must use HTTPS.');
  }
  return {
    kid,
    alg,
    privateKeyPem,
    publicJwk,
    ...(x5c?.length ? { x5c } : {}),
    ...(x5u ? { x5u } : {}),
    activatedAt: input.activatedAt || new Date().toISOString(),
  };
}

function loadState(): void {
  if (state.loaded) return;
  state.loaded = true;
}

export function activateSigningKey(input: {
  kid?: string;
  alg: string;
  privateKeyPem: string;
  x5c?: string[];
  x5u?: string;
  certificateChainPem?: string[];
}): ActiveSigningKeyRecord {
  loadState();
  const record = buildRecordFromInput(input);
  state.keysByKid.set(record.kid, record);
  state.activeByAlg[record.alg] = record.kid;
  return record;
}

export function listActiveSigningKeys(): ActiveSigningKeyRecord[] {
  loadState();
  return Array.from(state.keysByKid.values()).sort((left, right) => left.kid.localeCompare(right.kid));
}

export function getActiveSigningKeyByAlg(
  alg: SupportedSigningAlgorithm,
): ActiveSigningKeyRecord | undefined {
  loadState();
  const kid = state.activeByAlg[alg];
  if (!kid) return undefined;
  return state.keysByKid.get(kid);
}

export function getPreferredSigningKey(
  preferredAlg: SupportedSigningAlgorithm | undefined,
): ActiveSigningKeyRecord | undefined {
  loadState();
  if (preferredAlg) {
    const preferred = getActiveSigningKeyByAlg(preferredAlg);
    if (preferred) return preferred;
  }
  const es384 = getActiveSigningKeyByAlg('ES384');
  if (es384) return es384;
  const firstKid = Object.values(state.activeByAlg)[0];
  if (firstKid) return state.keysByKid.get(firstKid);
  return Array.from(state.keysByKid.values())[0];
}

export function upsertDidSigningMethods(
  issuerDid: string,
): { verificationMethod: JsonObject[]; assertionMethod: string[] } {
  const keys = listActiveSigningKeys();
  const methods = keys.map((entry) => ({
    id: `${issuerDid}#${entry.kid}`,
    type: 'JsonWebKey2020',
    controller: issuerDid,
    publicKeyJwk: {
      ...entry.publicJwk,
      kid: entry.kid,
      alg: entry.alg,
      use: 'sig',
      ...(entry.x5c?.length ? { x5c: entry.x5c } : {}),
      ...(entry.x5u ? { x5u: entry.x5u } : {}),
    },
  }));
  return {
    verificationMethod: methods,
    assertionMethod: methods.map((entry) => String(entry.id)),
  };
}

export function resetActiveSigningKeysStateForTests(): void {
  state.loaded = false;
  state.keysByKid.clear();
  state.activeByAlg = {} as Record<string, string>;
}
