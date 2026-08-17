// identity-kit/apikeys — API keys as their own principal.
//
// A key belongs to an opaque owner (a user id, or an organisation id — the host
// decides) and authenticates AS that owner. It never impersonates the person who
// created it and never inherits their session: if keys impersonated users, a
// leaked key would be account takeover rather than a scoped incident, and
// revoking it would not undo what it reached.
//
// identity-kit only AUTHENTICATES the key — resolves it to an owner and its
// opaque scopes. What those scopes permit is the host's (or tenant-kit's).

import { randomBytes } from 'node:crypto';
import { base32, crc32 } from './encoding.ts';
import { sha256 } from './tokens.ts';
import type { Clock, SqlExecutor } from './types.ts';

export type KeyEnvironment = 'live' | 'test';

/** 32 random bytes → 52 base32 chars, so a key survives case-mangling. */
const BODY_BYTES = 32;

export interface ApiKeysOptions {
  db: SqlExecutor;
  /**
   * A fixed, searchable, product-specific prefix (`idk`, `aim`, …). It is what
   * makes a key findable by GitHub secret scanning and gitleaks — register the
   * pattern and a key pushed to a public repo is revoked before a customer
   * notices. Lower-case letters and digits only.
   */
  prefix: string;
  clock?: Clock;
}

export interface CreateApiKeyInput {
  name: string;
  environment?: KeyEnvironment;
  scopes?: readonly string[];
  expiresAt?: Date;
  createdBy?: string;
}

export interface CreatedKey {
  id: string;
  /** Shown exactly once. Never stored, never retrievable. */
  key: string;
  displayPrefix: string;
}

export interface KeyPrincipal {
  apiKeyId: string;
  ownerId: string;
  scopes: string[];
}

export interface ApiKeySummary {
  id: string;
  name: string;
  displayPrefix: string;
  scopes: string[];
  createdAt: Date;
  expiresAt: Date | null;
  lastUsedAt: Date | null;
}

export interface ApiKeys {
  mint(environment?: KeyEnvironment): string;
  looksLikeKey(candidate: string): boolean;
  createApiKey(ownerId: string, input: CreateApiKeyInput): Promise<CreatedKey>;
  resolveApiKey(presented: string, now?: Date): Promise<KeyPrincipal | null>;
  revokeApiKey(id: string): Promise<void>;
  listApiKeys(ownerId: string): Promise<ApiKeySummary[]>;
}

/** Written at most once a minute — per request would put a write on the hottest
 *  path in the product for a timestamp nobody reads to the second. */
const LAST_USED_RESOLUTION_MS = 60_000;

export function createApiKeys(opts: ApiKeysOptions): ApiKeys {
  const { db, prefix } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  if (!/^[a-z0-9]+$/.test(prefix)) throw new Error('apikeys: prefix must be lower-case letters and digits');

  const shape = new RegExp(`^${prefix}_(live|test)_([A-Z2-7]{52})_([A-Z2-7]{7})$`);

  // The trailing checksum is not integrity — trivially forgeable, not asked to
  // be otherwise. It lets a secret scanner reject a typo without calling the API.
  const checksumOf = (stem: string): string => {
    const crc = crc32(stem);
    return base32(Buffer.from([(crc >>> 24) & 0xff, (crc >>> 16) & 0xff, (crc >>> 8) & 0xff, crc & 0xff]));
  };

  const mint = (environment: KeyEnvironment = 'live'): string => {
    const stem = `${prefix}_${environment}_${base32(randomBytes(BODY_BYTES))}`;
    return `${stem}_${checksumOf(stem)}`;
  };

  const looksLikeKey = (candidate: string): boolean => {
    const match = shape.exec(candidate);
    if (!match) return false;
    return checksumOf(candidate.slice(0, candidate.lastIndexOf('_'))) === match[3];
  };

  const touch = async (id: string, lastUsedAt: Date | null, now: Date): Promise<void> => {
    if (lastUsedAt && now.getTime() - lastUsedAt.getTime() < LAST_USED_RESOLUTION_MS) return;
    await db.query('UPDATE identity.api_keys SET last_used_at = $2 WHERE id = $1', [id, now]);
  };

  return {
    mint,
    looksLikeKey,

    async createApiKey(ownerId, input) {
      const key = mint(input.environment ?? 'live');
      const displayPrefix = key.slice(0, `${prefix}_live_`.length + 8);
      const rows = await db.query<{ id: string }>(
        `INSERT INTO identity.api_keys (owner_id, key_hash, display_prefix, name, scopes, created_by, expires_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7) RETURNING id`,
        [
          ownerId,
          sha256(key),
          displayPrefix,
          input.name,
          [...(input.scopes ?? [])],
          input.createdBy ?? null,
          input.expiresAt ?? null,
        ],
      );
      return { id: rows[0]!.id, key, displayPrefix };
    },

    /**
     * Authenticate a key. A single index probe on the sha256 — no scan, no
     * constant-time comparison left to make. A malformed key is rejected before
     * any database work, so the hottest unauthenticated path is not a free probe.
     */
    async resolveApiKey(presented, now = clock()) {
      if (!looksLikeKey(presented)) return null;
      const rows = await db.query<{
        id: string;
        owner_id: string;
        scopes: string[];
        expires_at: Date | null;
        revoked_at: Date | null;
        last_used_at: Date | null;
      }>(
        'SELECT id, owner_id, scopes, expires_at, revoked_at, last_used_at FROM identity.api_keys WHERE key_hash = $1',
        [sha256(presented)],
      );
      const row = rows[0];
      if (!row || row.revoked_at || (row.expires_at && row.expires_at <= now)) return null;
      await touch(row.id, row.last_used_at, now);
      return { apiKeyId: row.id, ownerId: row.owner_id, scopes: row.scopes };
    },

    /** Revocation is a DELETE, effective on the next request. Lookups are not
     *  cached; if they ever are, the TTL is the revocation window. */
    async revokeApiKey(id) {
      await db.query('DELETE FROM identity.api_keys WHERE id = $1', [id]);
    },

    async listApiKeys(ownerId) {
      const rows = await db.query<{
        id: string;
        name: string;
        display_prefix: string;
        scopes: string[];
        created_at: Date;
        expires_at: Date | null;
        last_used_at: Date | null;
      }>(
        `SELECT id, name, display_prefix, scopes, created_at, expires_at, last_used_at
           FROM identity.api_keys WHERE owner_id = $1 ORDER BY created_at DESC`,
        [ownerId],
      );
      return rows.map((r) => ({
        id: r.id,
        name: r.name,
        displayPrefix: r.display_prefix,
        scopes: r.scopes,
        createdAt: r.created_at,
        expiresAt: r.expires_at,
        lastUsedAt: r.last_used_at,
      }));
    },
  };
}
