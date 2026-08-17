// Server-side sessions.
//
// Stateless JWT saves no round trip here: every authenticated request already
// reads Postgres to do its work, and revocation — a removed seat, a reset
// password — has to take effect *now*, which a JWT can only fake with a denylist
// read on every request plus a stale window. Sessions are rows, so revocation is
// a DELETE that takes effect on the next request, and the row carries only
// `user_id`: identity, never entitlement.
//
// Expiry is enforced by comparison on read, never by the sweep. A cleanup job
// that stops running must not silently extend everyone's session.

import { DEFAULT_EVENT_RETENTION_MS, recordEvent, sweepEvents } from './events.ts';
import { issueToken, sha256 } from './tokens.ts';
import type { IdentityConfig, ResolvedSession, SessionMeta, SessionSummary, SqlExecutor, UserId } from './types.ts';

/** A session refreshed forever is a session never revoked. */
export const ABSOLUTE_LIFETIME_MS = 30 * 24 * 60 * 60 * 1000;
export const IDLE_LIFETIME_MS = 14 * 24 * 60 * 60 * 1000;

interface SessionRow {
  token_hash: string;
  user_id: string;
  expires_at: Date;
  absolute_expires_at: Date;
  authenticated_at: Date;
}

export interface ResolveOptions {
  /** Rotate the identifier when this read renews the idle window. The caller
   *  must then set `rotated.token` as the cookie. */
  rotateOnRenewal?: boolean;
}

export async function createSession(
  db: SqlExecutor,
  userId: UserId,
  meta: SessionMeta,
  now: Date,
): Promise<{ token: string; expiresAt: Date }> {
  const { plaintext, hash } = issueToken();
  const expiresAt = new Date(now.getTime() + IDLE_LIFETIME_MS);
  const absoluteExpiresAt = new Date(now.getTime() + ABSOLUTE_LIFETIME_MS);

  await db.query(
    `INSERT INTO identity.sessions
       (token_hash, user_id, expires_at, absolute_expires_at, ip_address, user_agent,
        created_at, last_seen_at, authenticated_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $7, $7)`,
    [hash, userId, expiresAt, absoluteExpiresAt, meta.ipAddress ?? null, meta.userAgent ?? null, now],
  );
  return { token: plaintext, expiresAt };
}

/**
 * Give a live session a fresh identifier: a new row with the same user, expiry
 * and metadata, the old row deleted, in one transaction. The old token is
 * invalid the moment this returns. Called on sliding renewal (so a token that
 * leaked early does not stay good for the whole idle window) and after a
 * privilege change on the current session (a password or MFA change). Returns
 * null when there is no such live session.
 *
 * `authenticatedAt` — pass it when the holder has just re-proved a credential
 * (a password change); otherwise the previous proof time carries forward.
 */
export async function rotateSession(
  db: SqlExecutor,
  tokenHash: string,
  now: Date,
  opts: { authenticatedAt?: Date } = {},
): Promise<{ token: string; tokenHash: string; expiresAt: Date } | null> {
  const { plaintext, hash } = issueToken();
  return db.transaction(async (tx) => {
    const rows = await tx.query<{ expires_at: Date }>(
      `INSERT INTO identity.sessions
         (token_hash, user_id, expires_at, absolute_expires_at, ip_address, user_agent,
          created_at, last_seen_at, authenticated_at)
       SELECT $2, user_id, expires_at, absolute_expires_at, ip_address, user_agent,
              created_at, $3, COALESCE($4, authenticated_at)
         FROM identity.sessions
        WHERE token_hash = $1 AND expires_at > $3 AND absolute_expires_at > $3
       RETURNING expires_at`,
      [tokenHash, hash, now, opts.authenticatedAt ?? null],
    );
    const inserted = rows[0];
    if (!inserted) return null;
    await tx.query('DELETE FROM identity.sessions WHERE token_hash = $1', [tokenHash]);
    return { token: plaintext, tokenHash: hash, expiresAt: inserted.expires_at };
  });
}

/**
 * Resolve a token to a session, or null. Expiry is checked here, by comparison.
 * The idle window slides only once past halfway, so a read-mostly table does not
 * become write-hot with an UPDATE in front of every page load.
 */
export async function resolveSession(
  db: SqlExecutor,
  token: string,
  now: Date,
  opts: ResolveOptions = {},
): Promise<ResolvedSession | null> {
  const tokenHash = sha256(token);
  const rows = await db.query<SessionRow>(
    `SELECT token_hash, user_id, expires_at, absolute_expires_at, authenticated_at
       FROM identity.sessions WHERE token_hash = $1`,
    [tokenHash],
  );
  const row = rows[0];
  if (!row) return null;

  if (row.expires_at <= now || row.absolute_expires_at <= now) {
    await db.query('DELETE FROM identity.sessions WHERE token_hash = $1', [tokenHash]);
    return null;
  }

  const resolved: ResolvedSession = {
    tokenHash: row.token_hash,
    userId: row.user_id,
    expiresAt: row.expires_at,
    absoluteExpiresAt: row.absolute_expires_at,
    authenticatedAt: row.authenticated_at,
  };

  if (row.expires_at.getTime() - now.getTime() < IDLE_LIFETIME_MS / 2) {
    const expiresAt = new Date(Math.min(now.getTime() + IDLE_LIFETIME_MS, row.absolute_expires_at.getTime()));
    await db.query('UPDATE identity.sessions SET expires_at = $2, last_seen_at = $3 WHERE token_hash = $1', [
      tokenHash,
      expiresAt,
      now,
    ]);
    resolved.expiresAt = expiresAt;
    if (opts.rotateOnRenewal) {
      // The renewal is the write we already pay for; rotating here bounds how
      // long a token that leaked early stays good, at no extra write on the
      // read-mostly path.
      const rotated = await rotateSession(db, tokenHash, now);
      if (rotated) {
        resolved.tokenHash = rotated.tokenHash;
        resolved.rotated = { token: rotated.token, expiresAt: rotated.expiresAt };
      }
    }
  }

  return resolved;
}

/** Revoke one session. Records `session_revoked` for its user when it existed;
 *  `meta` is the revoking request's ip / user agent, `now` its instant. */
export async function revokeSession(
  db: SqlExecutor,
  tokenHash: string,
  meta: SessionMeta = {},
  now?: Date,
): Promise<void> {
  const rows = await db.query<{ user_id: string }>(
    'DELETE FROM identity.sessions WHERE token_hash = $1 RETURNING user_id',
    [tokenHash],
  );
  const row = rows[0];
  if (!row) return;
  await recordEvent(db, { userId: row.user_id, kind: 'session_revoked', meta, at: now, metadata: { count: 1 } });
}

/**
 * Every session for a user, optionally sparing the one making the request.
 *
 * Fires on password change, password reset and email change — any change to
 * *how* the account authenticates invalidates everything that authenticated
 * under the old rules. Returns how many were revoked.
 */
export async function revokeAllSessions(
  db: SqlExecutor,
  userId: UserId,
  exceptTokenHash?: string,
  meta: SessionMeta = {},
  now?: Date,
): Promise<number> {
  const rows = exceptTokenHash
    ? await db.query<{ token_hash: string }>(
        'DELETE FROM identity.sessions WHERE user_id = $1 AND token_hash <> $2 RETURNING token_hash',
        [userId, exceptTokenHash],
      )
    : await db.query<{ token_hash: string }>('DELETE FROM identity.sessions WHERE user_id = $1 RETURNING token_hash', [
        userId,
      ]);
  if (rows.length > 0) {
    await recordEvent(db, {
      userId,
      kind: 'session_revoked',
      meta,
      at: now,
      metadata: { count: rows.length, keptOne: exceptTokenHash !== undefined },
    });
  }
  return rows.length;
}

export async function listSessions(db: SqlExecutor, userId: UserId): Promise<SessionSummary[]> {
  const rows = await db.query<{
    token_hash: string;
    ip_address: string | null;
    user_agent: string | null;
    created_at: Date;
    last_seen_at: Date;
    expires_at: Date;
  }>(
    `SELECT token_hash, ip_address, user_agent, created_at, last_seen_at, expires_at
       FROM identity.sessions WHERE user_id = $1 ORDER BY last_seen_at DESC`,
    [userId],
  );
  return rows.map((r) => ({
    tokenHash: r.token_hash,
    ipAddress: r.ip_address,
    userAgent: r.user_agent,
    createdAt: r.created_at,
    lastSeenAt: r.last_seen_at,
    expiresAt: r.expires_at,
  }));
}

/** Housekeeping only. Never the thing that makes an expired session invalid. */
export async function sweepExpiredSessions(db: SqlExecutor, now: Date): Promise<number> {
  const rows = await db.query<{ token_hash: string }>(
    'DELETE FROM identity.sessions WHERE expires_at <= $1 OR absolute_expires_at <= $1 RETURNING token_hash',
    [now],
  );
  return rows.length;
}

export interface SweepReport {
  sessions: number;
  passwordResetTokens: number;
  emailVerificationTokens: number;
  /** 0 when the MFA schema (sql/002_mfa.sql) is not applied. */
  pendingLogins: number;
  /** Rate-limit buckets idle for over a day. 0 when 005 is not applied. */
  rateLimits: number;
  /** Security events past retention (`config.eventRetentionMs`, default 90
   *  days). 0 when 006 is not applied. */
  events: number;
}

export interface SweepOptions {
  /** How long security events are kept. Default ninety days. */
  eventRetentionMs?: number;
}

/** Rate-limit rows idle this long are pruned; a bucket that has fully refilled
 *  is indistinguishable from no row at all. */
const RATE_LIMIT_IDLE_MS = 24 * 60 * 60 * 1000;

/**
 * Every sweeper in one call, for the one cron job a host runs. Each table is
 * expiry-checked on read as well, so this is housekeeping — but the token tables
 * only shrink here, and a reset or pending-login table that never shrinks is a
 * slow leak of a live-credential-shaped row per attempt.
 */
export async function sweepExpired(db: SqlExecutor, now: Date, opts: SweepOptions = {}): Promise<SweepReport> {
  const count = async (sql: string, params: readonly unknown[]): Promise<number> =>
    (await db.query<{ n: string }>(sql, params)).length;
  const exists = async (table: string): Promise<boolean> => {
    const rows = await db.query<{ ok: string | null }>('SELECT to_regclass($1)::text AS ok', [`identity.${table}`]);
    return rows[0]?.ok != null;
  };
  return {
    sessions: await sweepExpiredSessions(db, now),
    passwordResetTokens: await count(
      'DELETE FROM identity.password_reset_tokens WHERE expires_at <= $1 RETURNING token_hash',
      [now],
    ),
    emailVerificationTokens: await count(
      'DELETE FROM identity.email_verification_tokens WHERE expires_at <= $1 RETURNING token_hash',
      [now],
    ),
    pendingLogins: (await exists('pending_logins'))
      ? await count('DELETE FROM identity.pending_logins WHERE expires_at <= $1 RETURNING token_hash', [now])
      : 0,
    rateLimits: (await exists('rate_limits'))
      ? await count('DELETE FROM identity.rate_limits WHERE updated_at <= $1 RETURNING key', [
          new Date(now.getTime() - RATE_LIMIT_IDLE_MS),
        ])
      : 0,
    events: (await exists('events'))
      ? await sweepEvents(db, new Date(now.getTime() - (opts.eventRetentionMs ?? DEFAULT_EVENT_RETENTION_MS)))
      : 0,
  };
}

// --- cookies ----------------------------------------------------------------

/** `__Host-` is refused by the browser unless the cookie is also Secure, so the
 *  name follows `cookieSecure`; production (Secure on) always gets the prefix. */
export const cookieName = (config: IdentityConfig): string => (config.cookieSecure ? '__Host-session' : 'session');

/**
 * The Set-Cookie value. `__Host-` requires Secure, Path=/ and no Domain — that
 * last part stops a hostile subdomain from writing a cookie the apex accepts,
 * the standard route to session fixation on a shared domain. `SameSite=Lax`, not
 * Strict: Strict withholds the cookie from an emailed link and renders the page
 * logged out; Lax still blocks cross-site POST, the case that matters.
 */
export function sessionCookie(config: IdentityConfig, token: string, expiresAt: Date, now: Date): string {
  const maxAge = Math.max(0, Math.floor((expiresAt.getTime() - now.getTime()) / 1000));
  const parts = [`${cookieName(config)}=${token}`, 'HttpOnly', 'SameSite=Lax', 'Path=/', `Max-Age=${maxAge}`];
  if (config.cookieSecure) parts.push('Secure');
  return parts.join('; ');
}

export function clearedSessionCookie(config: IdentityConfig): string {
  const parts = [`${cookieName(config)}=`, 'HttpOnly', 'SameSite=Lax', 'Path=/', 'Max-Age=0'];
  if (config.cookieSecure) parts.push('Secure');
  return parts.join('; ');
}
