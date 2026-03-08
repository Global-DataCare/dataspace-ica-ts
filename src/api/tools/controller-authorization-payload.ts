import type { JsonLike } from './canonical-json.ts';
import { stableStringifyJson, toBase64UrlUtf8 } from './canonical-json.ts';

type JsonObject = Record<string, unknown>;

function asJsonLike(value: unknown): JsonLike {
  if (value === null) return null;
  if (typeof value === 'string' || typeof value === 'number' || typeof value === 'boolean') {
    return value;
  }
  if (Array.isArray(value)) {
    return value.map((entry) => asJsonLike(entry));
  }
  if (value && typeof value === 'object') {
    const objectValue = value as JsonObject;
    const normalized: Record<string, JsonLike> = {};
    for (const [key, entry] of Object.entries(objectValue)) {
      if (entry === undefined) continue;
      normalized[key] = asJsonLike(entry);
    }
    return normalized;
  }
  return String(value);
}

export function computeControllerAuthorizationPayloadBase64Url(body: JsonObject): string {
  const unsignedBody: JsonObject = { ...body };
  delete unsignedBody.signature;
  const resourceType = typeof unsignedBody.resourceType === 'string'
    ? unsignedBody.resourceType.trim().toLowerCase()
    : '';
  if (resourceType === 'bundle') {
    delete unsignedBody.id;
    delete unsignedBody.meta;
  }
  const canonical = stableStringifyJson(asJsonLike(unsignedBody));
  return toBase64UrlUtf8(canonical);
}
