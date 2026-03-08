type JsonLike = null | boolean | number | string | JsonLike[] | { [key: string]: JsonLike };

export function stableStringifyJson(value: JsonLike): string {
  if (Array.isArray(value)) {
    return `[${value.map((entry) => stableStringifyJson(entry)).join(',')}]`;
  }
  if (value && typeof value === 'object') {
    const entries = Object.entries(value)
      .filter(([, entryValue]) => entryValue !== undefined)
      .sort(([leftKey], [rightKey]) => leftKey.localeCompare(rightKey));
    return `{${entries.map(([key, entryValue]) => `${JSON.stringify(key)}:${stableStringifyJson(entryValue as JsonLike)}`).join(',')}}`;
  }
  return JSON.stringify(value);
}

export function toBase64UrlUtf8(input: string): string {
  return Buffer.from(input).toString('base64url');
}

export type { JsonLike };
