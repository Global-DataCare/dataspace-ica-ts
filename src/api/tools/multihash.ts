import { createHash } from 'node:crypto';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const MULTIHASH_SHA3_384_CODE = 0x15;
const MULTIHASH_SHA3_384_SIZE = 0x30;
const MULTIHASH_SHA3_256_CODE = 0x16;
const MULTIHASH_SHA3_256_SIZE = 0x20;

export function base58btcEncode(input: Buffer<ArrayBufferLike>): string {
  if (!input.length) return '';
  const digits: number[] = [0];
  for (const byte of input) {
    let carry = byte;
    for (let index = 0; index < digits.length; index += 1) {
      const value = digits[index] * 256 + carry;
      digits[index] = value % 58;
      carry = Math.floor(value / 58);
    }
    while (carry > 0) {
      digits.push(carry % 58);
      carry = Math.floor(carry / 58);
    }
  }
  let output = '';
  for (const byte of input) {
    if (byte === 0) output += BASE58_ALPHABET[0];
    else break;
  }
  for (let index = digits.length - 1; index >= 0; index -= 1) {
    output += BASE58_ALPHABET[digits[index]];
  }
  return output;
}

export function multibase58MultihashSha3_256(value: string): string {
  const normalized = value.trim();
  if (!normalized) {
    throw new Error('Cannot create multihash from empty value.');
  }
  const digest = createHash('sha3-256').update(normalized, 'utf8').digest();
  const multihash = Buffer.concat([Buffer.from([MULTIHASH_SHA3_256_CODE, MULTIHASH_SHA3_256_SIZE]), digest]);
  return `z${base58btcEncode(multihash)}`;
}

export function multibase58MultihashSha3_384Hex(hex: string): string {
  const normalized = hex.trim().toLowerCase();
  if (!normalized) {
    throw new Error('Cannot create sha3-384 multihash from empty digest.');
  }
  if (!/^[0-9a-f]+$/.test(normalized) || normalized.length !== MULTIHASH_SHA3_384_SIZE * 2) {
    throw new Error('sha3-384 digest hex must be 96 hexadecimal characters.');
  }
  const digest = Buffer.from(normalized, 'hex');
  const multihash = Buffer.concat([Buffer.from([MULTIHASH_SHA3_384_CODE, MULTIHASH_SHA3_384_SIZE]), digest]);
  return `z${base58btcEncode(multihash)}`;
}

function looksLikeBase58Multibase(value: string): boolean {
  return /^z\S+$/.test(value.trim());
}

function looksLikeEmail(value: string): boolean {
  const trimmed = value.trim();
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(trimmed);
}

export function normalizeSameAsHash(value: string): string {
  const trimmed = value.trim();
  if (!trimmed) return '';

  if (trimmed.toLowerCase().startsWith('urn:multibase:')) {
    const suffix = trimmed.slice('urn:multibase:'.length).trim();
    return looksLikeBase58Multibase(suffix) ? `urn:multibase:${suffix}` : trimmed;
  }

  if (looksLikeBase58Multibase(trimmed)) {
    return `urn:multibase:${trimmed}`;
  }

  if (looksLikeEmail(trimmed)) {
    return `urn:multibase:${multibase58MultihashSha3_256(trimmed.toLowerCase())}`;
  }

  return trimmed;
}

export function sameAsValuesEqual(left: string, right: string): boolean {
  const normalizeComparable = (value: string): string => {
    const normalized = normalizeSameAsHash(value);
    return normalized.toLowerCase().startsWith('urn:multibase:')
      ? normalized.slice('urn:multibase:'.length)
      : normalized;
  };
  const normalizedLeft = normalizeComparable(left);
  const normalizedRight = normalizeComparable(right);
  return !!normalizedLeft && normalizedLeft === normalizedRight;
}
