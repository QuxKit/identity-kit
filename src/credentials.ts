// Password hashing.
//
// argon2id at RFC 9106's second recommended configuration, with `parallelism`
// pinned to 1. `p > 1` inside a single hash competes for the same libuv
// threadpool that concurrent logins need, so the resistance per unit of server
// capacity is better spent on `memoryCost`.
//
// The number to hold in your head: peak memory is 64 MiB x concurrent hashes.
// With the default UV_THREADPOOL_SIZE=4 that is 256 MiB, and it must be
// provisioned for, because an OOM during a login storm is an outage.
//
// These parameters are a floor, not a truth. They were measured at ~52 ms on a
// development laptop (node 24, darwin/arm64); on production hardware, measure
// and raise `memoryCost` until an interactive hash costs ~100 ms. `needsRehash`
// upgrades stored hashes on next login, so raising it later forces no resets.
//
// The whole module is created bound to config, not reading the environment: the
// pepper is a secret the host injects, and two instances in one process (a test
// and a worker) must be able to hold different ones.

import { createHmac } from 'node:crypto';
import { Algorithm, hash as argonHash, verify as argonVerify } from '@node-rs/argon2';
import { IdentityError } from './errors.ts';
import type { IdentityConfig } from './types.ts';

export const PARAMS = {
  algorithm: Algorithm.Argon2id,
  memoryCost: 65536,
  timeCost: 3,
  parallelism: 1,
  outputLen: 32,
} as const;

export interface Credentials {
  hashPassword(password: string): Promise<string>;
  verifyPassword(stored: string, password: string, pepperVersion: number): Promise<boolean>;
  /** Burn the same work as a real verification against a fixed dummy, and return
   *  false — so the timing of a failed login does not reveal whether the account
   *  exists. */
  verifyAgainstDummy(password: string): Promise<false>;
  needsRehash(stored: string, pepperVersion: number): boolean;
}

/**
 * NIST SP 800-63B, not the composition rules. No character-class requirements,
 * no forced rotation, no maximum below 64: complexity rules reliably produce
 * `Password1!`, while a length floor and a breach check (a caller's job, via a
 * k-anonymity range API) catch far more real compromise.
 */
export const passwordProblem = (password: string): string | null => {
  if (password.length < 8) return 'Password must be at least 8 characters.';
  if (password.length > 1024) return 'Password must be at most 1024 characters.';
  return null;
};

export function createCredentials(config: IdentityConfig): Credentials {
  /**
   * Pepper, then hash.
   *
   * The salt defends against precomputation. The pepper defends against the
   * common case where the attacker has the database and not the application host
   * — a stolen backup, a read replica, a SQL injection. Without it those hashes
   * are offline-crackable at leisure.
   *
   * HMAC before argon2 rather than argon2's own `secret` parameter, for one
   * concrete reason: HMAC-SHA-256 bounds the input to 32 bytes, so a submitted
   * "password" of several megabytes cannot make the server do proportionally
   * more work.
   *
   * The digest is base64'd rather than passed as bytes: `@node-rs/argon2`'s
   * `verify` decodes its argument as UTF-8 and throws on a raw digest, which
   * would make a hash that writes successfully and never verifies — every
   * password wrong, nothing in the logs.
   */
  const pepper = (password: string, version: number): string => {
    if (version !== config.pepperVersion) {
      throw new IdentityError({ code: 'pepper_version', stored: version, current: config.pepperVersion });
    }
    return createHmac('sha256', config.pepper).update(password, 'utf8').digest('base64');
  };

  // A hash of a value nobody knows, computed once and reused, so the
  // unknown-email path burns the same work as a real verification without
  // doubling the cost of the endpoint most likely to be under load.
  let dummy: Promise<string> | null = null;
  const dummyHash = (): Promise<string> => {
    dummy ??= argonHash(createHmac('sha256', config.pepper).update('dummy').digest('base64'), PARAMS);
    return dummy;
  };

  const verifyPassword = async (stored: string, password: string, pepperVersion: number): Promise<boolean> => {
    try {
      return await argonVerify(stored, pepper(password, pepperVersion), PARAMS);
    } catch {
      // A malformed stored hash fails as "wrong password", not as a 500 that
      // tells an attacker they found a row with a corrupt hash.
      return false;
    }
  };

  return {
    hashPassword: (password) => argonHash(pepper(password, config.pepperVersion), PARAMS),
    verifyPassword,
    verifyAgainstDummy: async (password) => {
      await verifyPassword(await dummyHash(), password, config.pepperVersion);
      return false;
    },
    needsRehash: (stored, pepperVersion) => {
      if (pepperVersion !== config.pepperVersion) return true;
      const match = /^\$argon2id\$v=19\$m=(\d+),t=(\d+),p=(\d+)\$/.exec(stored);
      if (!match) return true;
      const [, m, t, p] = match;
      return Number(m) < PARAMS.memoryCost || Number(t) < PARAMS.timeCost || Number(p) !== PARAMS.parallelism;
    },
  };
}
