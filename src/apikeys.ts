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
//
// A key is replaced by ROLLING it (sql/011_apikey_roll.sql): a successor with
// the same name, scopes and environment, while the old key keeps resolving for
// an overlap the caller chooses, so the systems that hold it can move over
// without an outage. Revocation stays available at any time and ends an
// overlap early: a key that leaked mid-roll dies on the next request.

import { randomBytes } from 'node:crypto';
import { base32, crc32 } from './encoding.ts';
import { IdentityError } from './errors.ts';
import { recordEvent } from './events.ts';
import { sha256 } from './tokens.ts';
import type { Clock, SessionMeta, SqlExecutor } from './types.ts';

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
  /** The issuing request's ip / user agent, recorded on the `api_key_issued`
   *  event (keyed by `ownerId`). */
  meta?: SessionMeta;
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

/** Where a key stands, for a dashboard. `rolling`: replaced, still resolving until `expiresAt`. */
export type ApiKeyState = 'active' | 'rolling' | 'expired' | 'revoked';

export interface ApiKeySummary {
  id: string;
  ownerId: string;
  name: string;
  displayPrefix: string;
  environment: KeyEnvironment;
  scopes: string[];
  createdAt: Date;
  expiresAt: Date | null;
  lastUsedAt: Date | null;
  /** Set by revokeApiKey. A revoked key stays listed (audit) and never resolves. */
  revokedAt: Date | null;
  /** The key this one replaced, when it was minted by rollApiKey. */
  rolledFrom: string | null;
  /** The key that replaced this one. Until `expiresAt` both resolve. */
  replacedBy: string | null;
  rolledAt: Date | null;
  state: ApiKeyState;
}

/** The overlaps a dashboard offers. Any duration up to MAX_ROLL_OVERLAP_MS is accepted. */
export const ROLL_OVERLAPS = [
  { label: 'Immediately', ms: 0 },
  { label: 'In 1 hour', ms: 3_600_000 },
  { label: 'In 24 hours', ms: 86_400_000 },
  { label: 'In 7 days', ms: 7 * 86_400_000 },
] as const;

/** Rolling is for moving callers over, not a second key that lives forever: at most 30 days. */
export const MAX_ROLL_OVERLAP_MS = 30 * 86_400_000;

export interface RollApiKeyInput {
  /**
   * How long the OLD key keeps working, from now. 0 cuts it off at once (the
   * replacement is still minted). Default 24 hours. Never extends a key past
   * the expiry it already had.
   */
  overlapMs?: number;
  /** The replacement's expiry. Default: an old key that expired keeps its
   *  lifetime (now + the old key's created→expires span); one that never
   *  expired gets none. */
  expiresAt?: Date | null;
  createdBy?: string;
  meta?: SessionMeta;
}

export interface RolledKey extends CreatedKey {
  /** The key it replaces. */
  replaces: string;
  /** When the old key stops resolving. */
  oldExpiresAt: Date;
}

export interface ApiKeys {
  mint(environment?: KeyEnvironment): string;
  looksLikeKey(candidate: string): boolean;
  createApiKey(ownerId: string, input: CreateApiKeyInput): Promise<CreatedKey>;
  resolveApiKey(presented: string, now?: Date): Promise<KeyPrincipal | null>;
  /** Soft revoke: sets `revoked_at`, effective on the next request. The row
   *  stays for the audit trail; a second call is a no-op. `meta` is recorded
   *  on the `api_key_revoked` event. Works at any time, on any key: on an old
   *  key mid-roll it ends the overlap at once. */
  revokeApiKey(id: string, now?: Date, meta?: SessionMeta): Promise<void>;
  /**
   * Replace a key: a successor with the same owner, name, scopes and
   * environment, shown once, while the old key keeps resolving for
   * `overlapMs`. Refused (`invalid_state`) for a revoked, expired or
   * already-rolled key; roll the replacement instead.
   */
  rollApiKey(id: string, input?: RollApiKeyInput, now?: Date): Promise<RolledKey>;
  /** Every key the owner holds that still resolves, revoked at once: the operator's stop button. Returns how many. */
  revokeAllApiKeys(ownerId: string, now?: Date, meta?: SessionMeta): Promise<number>;
  /** One key by id, whoever owns it, for an operator. Null when there is none. */
  getApiKey(id: string, now?: Date): Promise<ApiKeySummary | null>;
  /**
   * The key a presented secret names, in any state, for an operator handed a
   * leaked key. Unlike resolveApiKey it never marks the key used, and it finds
   * a revoked or expired key too, so "is this one dead?" has an answer.
   */
  findApiKey(presented: string, now?: Date): Promise<ApiKeySummary | null>;
  listApiKeys(ownerId: string, now?: Date): Promise<ApiKeySummary[]>;
}

const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

interface KeyRow {
  id: string;
  owner_id: string;
  name: string;
  display_prefix: string;
  scopes: string[];
  created_by: string | null;
  created_at: Date;
  expires_at: Date | null;
  last_used_at: Date | null;
  revoked_at: Date | null;
  rolled_from: string | null;
  replaced_by: string | null;
  rolled_at: Date | null;
}

const KEY_COLUMNS =
  'id, owner_id, name, display_prefix, scopes, created_by, created_at, expires_at, last_used_at, revoked_at, rolled_from, replaced_by, rolled_at';

const stateOf = (r: KeyRow, now: Date): ApiKeyState =>
  r.revoked_at ? 'revoked' : r.expires_at && r.expires_at <= now ? 'expired' : r.replaced_by ? 'rolling' : 'active';

/** Written at most once a minute — per request would put a write on the hottest
 *  path in the product for a timestamp nobody reads to the second. */
const LAST_USED_RESOLUTION_MS = 60_000;

export function createApiKeys(opts: ApiKeysOptions): ApiKeys {
  const { db, prefix } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  if (!/^[a-z0-9]+$/.test(prefix)) {
    throw new IdentityError({
      code: 'invalid_config',
      reason: 'apikeys: prefix must be lower-case letters and digits',
    });
  }

  const shape = new RegExp(`^${prefix}_(live|test)_([A-Z2-7]{52})_([A-Z2-7]{7})$`);

  // Several instances (one per prefix) may share identity.api_keys, and one
  // owner can hold keys of several kinds: a workspace's chat keys and its
  // registry tokens, say. Every call by id or by owner is narrowed to THIS
  // prefix, so one kind's list never shows another's keys and one kind's
  // revoke-all never revokes another's.
  const own = `${prefix}_`;

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

  /** The environment is in the key itself, so it is read back off the display prefix. */
  const environmentOf = (displayPrefix: string): KeyEnvironment =>
    displayPrefix.startsWith(`${prefix}_test_`) ? 'test' : 'live';

  const summaryOf = (r: KeyRow, now: Date): ApiKeySummary => ({
    id: r.id,
    ownerId: r.owner_id,
    name: r.name,
    displayPrefix: r.display_prefix,
    environment: environmentOf(r.display_prefix),
    scopes: r.scopes,
    createdAt: r.created_at,
    expiresAt: r.expires_at,
    lastUsedAt: r.last_used_at,
    revokedAt: r.revoked_at,
    rolledFrom: r.rolled_from,
    replacedBy: r.replaced_by,
    rolledAt: r.rolled_at,
    state: stateOf(r, now),
  });

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
      // biome-ignore lint/style/noNonNullAssertion: INSERT … RETURNING yields exactly one row
      const id = rows[0]!.id;
      await recordEvent(db, {
        userId: ownerId,
        kind: 'api_key_issued',
        meta: input.meta,
        at: clock(),
        metadata: { apiKeyId: id, name: input.name, displayPrefix, createdBy: input.createdBy ?? null },
      });
      return { id, key, displayPrefix };
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

    /** Effective on the next request. Lookups are not cached; if they ever
     *  are, the TTL is the revocation window. */
    async revokeApiKey(id, now = clock(), meta = {}) {
      if (typeof id !== 'string' || !UUID.test(id)) return;
      const rows = await db.query<{ owner_id: string; name: string }>(
        `UPDATE identity.api_keys SET revoked_at = $2
          WHERE id = $1 AND revoked_at IS NULL AND starts_with(display_prefix, $3) RETURNING owner_id, name`,
        [id, now, own],
      );
      const row = rows[0];
      if (!row) return;
      await recordEvent(db, {
        userId: row.owner_id,
        kind: 'api_key_revoked',
        meta,
        at: now,
        metadata: { apiKeyId: id, name: row.name },
      });
    },

    async rollApiKey(id, input = {}, now = clock()) {
      const overlapMs = input.overlapMs ?? 86_400_000;
      if (!Number.isFinite(overlapMs) || overlapMs < 0 || overlapMs > MAX_ROLL_OVERLAP_MS) {
        throw new IdentityError({
          code: 'invalid_request',
          reason: `apikeys: overlapMs must be between 0 and ${MAX_ROLL_OVERLAP_MS} (30 days)`,
        });
      }
      if (typeof id !== 'string' || !UUID.test(id)) throw new IdentityError({ code: 'not_found', what: 'API key' });
      const rolled = await db.transaction(async (tx) => {
        // The row is locked for the whole roll, so a revoke that lands at the
        // same moment waits and then wins, and two rolls cannot both proceed.
        const [old] = await tx.query<KeyRow>(
          `SELECT ${KEY_COLUMNS} FROM identity.api_keys WHERE id = $1 AND starts_with(display_prefix, $2) FOR UPDATE`,
          [id, own],
        );
        if (!old) throw new IdentityError({ code: 'not_found', what: 'API key' });
        const refuse = (reason: string): never => {
          throw new IdentityError({ code: 'invalid_state', what: 'API key', reason });
        };
        if (old.revoked_at) refuse('This key was revoked. Create a new key instead.');
        if (old.expires_at && old.expires_at <= now) refuse('This key has expired. Create a new key instead.');
        if (old.replaced_by) refuse('This key was already rolled. Roll its replacement instead.');

        const environment = environmentOf(old.display_prefix);
        const key = mint(environment);
        const displayPrefix = key.slice(0, `${prefix}_live_`.length + 8);
        const lifetime = old.expires_at !== null ? old.expires_at.getTime() - old.created_at.getTime() : null;
        const expiresAt =
          input.expiresAt !== undefined
            ? input.expiresAt
            : lifetime !== null
              ? new Date(now.getTime() + lifetime)
              : null;
        const until = now.getTime() + overlapMs;
        const oldExpiresAt = new Date(old.expires_at ? Math.min(old.expires_at.getTime(), until) : until);

        const [made] = await tx.query<{ id: string }>(
          `INSERT INTO identity.api_keys
             (owner_id, key_hash, display_prefix, name, scopes, created_by, expires_at, rolled_from, created_at)
           VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9) RETURNING id`,
          [
            old.owner_id,
            sha256(key),
            displayPrefix,
            old.name,
            old.scopes,
            input.createdBy ?? old.created_by,
            expiresAt,
            old.id,
            now,
          ],
        );
        // biome-ignore lint/style/noNonNullAssertion: INSERT … RETURNING yields exactly one row
        const newId = made!.id;
        await tx.query('UPDATE identity.api_keys SET replaced_by = $2, rolled_at = $3, expires_at = $4 WHERE id = $1', [
          old.id,
          newId,
          now,
          oldExpiresAt,
        ]);
        await recordEvent(tx, {
          userId: old.owner_id,
          kind: 'api_key_rolled',
          meta: input.meta,
          at: now,
          metadata: {
            apiKeyId: old.id,
            replacementId: newId,
            name: old.name,
            oldExpiresAt: oldExpiresAt.toISOString(),
            createdBy: input.createdBy ?? null,
          },
        });
        await recordEvent(tx, {
          userId: old.owner_id,
          kind: 'api_key_issued',
          meta: input.meta,
          at: now,
          metadata: {
            apiKeyId: newId,
            name: old.name,
            displayPrefix,
            createdBy: input.createdBy ?? old.created_by,
            rolledFrom: old.id,
          },
        });
        return { id: newId, key, displayPrefix, replaces: old.id, oldExpiresAt };
      });
      return rolled;
    },

    async revokeAllApiKeys(ownerId, now = clock(), meta = {}) {
      const rows = await db.query<{ id: string; name: string }>(
        `UPDATE identity.api_keys SET revoked_at = $2
          WHERE owner_id = $1 AND revoked_at IS NULL AND (expires_at IS NULL OR expires_at > $2)
            AND starts_with(display_prefix, $3)
          RETURNING id, name`,
        [ownerId, now, own],
      );
      for (const r of rows) {
        await recordEvent(db, {
          userId: ownerId,
          kind: 'api_key_revoked',
          meta,
          at: now,
          metadata: { apiKeyId: r.id, name: r.name, all: true },
        });
      }
      return rows.length;
    },

    async getApiKey(id, now = clock()) {
      if (typeof id !== 'string' || !UUID.test(id)) return null;
      const [row] = await db.query<KeyRow>(
        `SELECT ${KEY_COLUMNS} FROM identity.api_keys WHERE id = $1 AND starts_with(display_prefix, $2)`,
        [id, own],
      );
      return row ? summaryOf(row, now) : null;
    },

    async findApiKey(presented, now = clock()) {
      if (!looksLikeKey(presented)) return null;
      const [row] = await db.query<KeyRow>(`SELECT ${KEY_COLUMNS} FROM identity.api_keys WHERE key_hash = $1`, [
        sha256(presented),
      ]);
      return row ? summaryOf(row, now) : null;
    },

    async listApiKeys(ownerId, now = clock()) {
      const rows = await db.query<KeyRow>(
        `SELECT ${KEY_COLUMNS} FROM identity.api_keys WHERE owner_id = $1 AND starts_with(display_prefix, $2)
          ORDER BY created_at DESC`,
        [ownerId, own],
      );
      return rows.map((r) => summaryOf(r, now));
    },
  };
}
