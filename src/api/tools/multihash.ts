import { createHash } from 'node:crypto';

const BASE58_ALPHABET = '123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz';
const MULTIHASH_SHA3_256_CODE = 0x16;
const MULTIHASH_SHA3_256_SIZE = 0x20;

function base58btcEncode(input: Buffer<ArrayBufferLike>): string {
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
