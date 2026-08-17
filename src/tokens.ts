// Every bearer token in this library is the same shape, defined once.
//
//   32 random bytes    -> the plaintext, handed out exactly once
//   sha256(plaintext)  -> what is stored, as a primary key
//
// sha256 rather than argon2 for tokens, deliberately and in contrast to
// passwords: 256 bits of uniform entropy has no dictionary and nothing to guess,
// so a slow hash buys nothing, while running a memory-hard KDF on every
// authenticated request is a denial of service you build yourself.
//
// Hashing at rest still matters. A leaked backup or a SQL-injection read
// otherwise hands over live sessions and reset links for every customer. It also
// removes the timing question: the lookup is an index probe on the hash, so
// there is no secret left to compare in constant time.

import { createHash, randomBytes } from 'node:crypto';

/** A fresh bearer token and the value to store for it. */
export interface IssuedToken {
  /** Handed to the holder. Never stored, never logged. */
  plaintext: string;
  /** Stored. The primary key of the row it authenticates. */
  hash: string;
}

export const sha256 = (value: string): string => createHash('sha256').update(value, 'utf8').digest('hex');

export const issueToken = (): IssuedToken => {
  const plaintext = randomBytes(32).toString('base64url');
  return { plaintext, hash: sha256(plaintext) };
};

/** `seconds` from `from`. `from` is passed in so expiry is a function of the
 *  injected clock, never a hidden `new Date()`. */
export const expiresIn = (seconds: number, from: Date): Date => new Date(from.getTime() + seconds * 1000);
