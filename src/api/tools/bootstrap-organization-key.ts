import { createPublicKey, generateKeyPairSync } from 'node:crypto';
import { computeRfc7638JwkThumbprint } from 'gdc-common-utils-ts/utils/jwk-thumbprint';

type JsonObject = Record<string, unknown>;

function asObject(value: unknown): JsonObject | undefined {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as JsonObject
    : undefined;
}

function normalizeKid(jwk: JsonObject): string {
  const existingKid = typeof jwk.kid === 'string' ? jwk.kid.trim() : '';
  if (existingKid) return existingKid;
  return computeRfc7638JwkThumbprint({
    kty: String(jwk.kty || ''),
    crv: String(jwk.crv || ''),
    x: String(jwk.x || ''),
    y: String(jwk.y || ''),
  });
}

function normalizeEs384PublicJwk(input: JsonObject): JsonObject {
  return {
    ...input,
    alg: 'ES384',
    use: typeof input.use === 'string' && input.use.trim() ? input.use : 'sig',
    kid: normalizeKid(input),
  };
}

function normalizeEs384PrivateJwk(input: JsonObject): JsonObject {
  return {
    ...input,
    ...normalizeEs384PublicJwk(input),
  };
}

export function normalizeOrganizationPublicKeyJwk(input: unknown): JsonObject | undefined {
  const jwk = asObject(input);
  if (!jwk) return undefined;
  if (String(jwk.kty || '') !== 'EC' || String(jwk.crv || '') !== 'P-384' || !String(jwk.x || '') || !String(jwk.y || '')) {
    throw new Error('Organization credential signing key must be an EC P-384 public JWK.');
  }
  return normalizeEs384PublicJwk(jwk);
}

export function normalizeControllerPublicKeyJwk(input: unknown, algInput?: string, kidInput?: string): JsonObject | undefined {
  const jwk = asObject(input);
  if (!jwk) return undefined;
  return {
    ...jwk,
    ...(algInput && !jwk.alg ? { alg: algInput } : {}),
    ...(kidInput && !jwk.kid ? { kid: kidInput } : {}),
  };
}

export function generateOrganizationCredentialKeyPair(): {
  publicKeyJwk: JsonObject;
  privateKeyJwk: JsonObject;
} {
  const { privateKey } = generateKeyPairSync('ec', { namedCurve: 'secp384r1' });
  const privateKeyJwk = privateKey.export({ format: 'jwk' }) as JsonObject;
  const publicKeyJwk = createPublicKey(privateKey).export({ format: 'jwk' }) as JsonObject;
  return {
    publicKeyJwk: normalizeEs384PublicJwk(publicKeyJwk),
    privateKeyJwk: normalizeEs384PrivateJwk(privateKeyJwk),
  };
}
