import type { ActivateSigningKeyInput } from '../types.ts';
import type { JsonLike } from './canonical-json.ts';
import { stableStringifyJson, toBase64UrlUtf8 } from './canonical-json.ts';

function normalizeStringList(input: string[] | undefined): string[] {
  if (!input?.length) return [];
  return input.map((value) => value.trim()).filter(Boolean);
}

function normalizeActivateKeys(keys: ActivateSigningKeyInput[]): JsonLike[] {
  return keys.map((key) => ({
    ...(key.kid?.trim() ? { kid: key.kid.trim() } : {}),
    alg: key.alg,
    privateKeyPem: key.privateKeyPem.trim(),
    ...(normalizeStringList(key.x5c).length
      ? { x5c: normalizeStringList(key.x5c) }
      : {}),
    ...(normalizeStringList(key.certificateChainPem).length
      ? { certificateChainPem: normalizeStringList(key.certificateChainPem) }
      : {}),
  }));
}

export function computeActivateDataCanonicalJson(keys: ActivateSigningKeyInput[]): string {
  const normalized = normalizeActivateKeys(keys);
  const canonical = stableStringifyJson(normalized);
  return canonical;
}

export function computeActivateDataPayloadBase64Url(keys: ActivateSigningKeyInput[]): string {
  const canonical = computeActivateDataCanonicalJson(keys);
  return toBase64UrlUtf8(canonical);
}
