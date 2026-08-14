// Base32 and CRC32 — used by the MFA and API-key modules, not the core.
//
// Base32 (RFC 4648, no padding, upper-case) because these values are retyped by
// humans and pasted through shells, spreadsheets and mail clients: no case
// sensitivity, no `+/=`. Implemented here rather than pulled from a dependency
// so the API-key module carries no crypto library it does not need.

import { randomBytes } from 'node:crypto';

const ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

export function base32(bytes: Uint8Array): string {
  let bits = 0;
  let value = 0;
  let out = '';
  for (const b of bytes) {
    value = (value << 8) | b;
    bits += 8;
    while (bits >= 5) {
      bits -= 5;
      out += ALPHABET[(value >>> bits) & 31];
    }
    value &= (1 << bits) - 1; // keep value small so it never leaves the safe range
  }
  if (bits > 0) out += ALPHABET[(value << (5 - bits)) & 31];
  return out;
}

export const randomBase32 = (bytes: number): string => base32(randomBytes(bytes));

const CRC_TABLE = (() => {
  const table = new Uint32Array(256);
  for (let n = 0; n < 256; n += 1) {
    let c = n;
    for (let k = 0; k < 8; k += 1) c = c & 1 ? 0xedb88320 ^ (c >>> 1) : c >>> 1;
    table[n] = c >>> 0;
  }
  return table;
})();

/**
 * CRC32 of an ASCII string. Not integrity — trivially forgeable and not asked to
 * be otherwise. Its job is that a secret scanner can reject a typo or a partial
 * match without calling the API, so automated scanning does not file
 * false-positive reports against customers.
 */
export function crc32(value: string): number {
  let c = 0xffffffff;
  for (let i = 0; i < value.length; i += 1) {
    c = CRC_TABLE[(c ^ value.charCodeAt(i)) & 0xff]! ^ (c >>> 8);
  }
  return (c ^ 0xffffffff) >>> 0;
}
