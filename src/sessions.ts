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
       (token_hash, user_id, expires_at, absolute_expires_at, ip_address, user_agent, created_at, last_seen_at)
     VALUES ($1, $2, $3, $4, $5, $6, $7, $7)`,
    [hash, userId, expiresAt, absoluteExpiresAt, meta.ipAddress ?? null, meta.userAgent ?? null, now],
  );
  return { token: plaintext, expiresAt };
}

/**
 * Resolve a token to a session, or null. Expiry is checked here, by comparison.
 * The idle window slides only once past halfway, so a read-mostly table does not
 * become write-hot with an UPDATE in front of every page load.
 */
export async function resolveSession(db: SqlExecutor, token: string, now: Date): Promise<ResolvedSession | null> {
  const tokenHash = sha256(token);
  const rows = await db.query<SessionRow>(
    `SELECT token_hash, user_id, expires_at, absolute_expires_at
       FROM identity.sessions WHERE token_hash = $1`,
    [tokenHash],
  );
  const row = rows[0];
  if (!row) return null;

  if (row.expires_at <= now || row.absolute_expires_at <= now) {
    await db.query('DELETE FROM identity.sessions WHERE token_hash = $1', [tokenHash]);
    return null;
  }

  let expiresAt = row.expires_at;
  if (row.expires_at.getTime() - now.getTime() < IDLE_LIFETIME_MS / 2) {
    expiresAt = new Date(Math.min(now.getTime() + IDLE_LIFETIME_MS, row.absolute_expires_at.getTime()));
    await db.query('UPDATE identity.sessions SET expires_at = $2, last_seen_at = $3 WHERE token_hash = $1', [
      tokenHash,
      expiresAt,
      now,
    ]);
  }

  return {
    tokenHash: row.token_hash,
    userId: row.user_id,
    expiresAt,
    absoluteExpiresAt: row.absolute_expires_at,
  };
}

export async function revokeSession(db: SqlExecutor, tokenHash: string): Promise<void> {
  await db.query('DELETE FROM identity.sessions WHERE token_hash = $1', [tokenHash]);
}

/**
 * Every session for a user, optionally sparing the one making the request.
 *
 * Fires on password change, password reset and email change — any change to
 * *how* the account authenticates invalidates everything that authenticated
 * under the old rules. Returns how many were revoked.
 */
export async function revokeAllSessions(db: SqlExecutor, userId: UserId, exceptTokenHash?: string): Promise<number> {
  const rows = exceptTokenHash
    ? await db.query<{ token_hash: string }>(
        'DELETE FROM identity.sessions WHERE user_id = $1 AND token_hash <> $2 RETURNING token_hash',
        [userId, exceptTokenHash],
      )
    : await db.query<{ token_hash: string }>('DELETE FROM identity.sessions WHERE user_id = $1 RETURNING token_hash', [
        userId,
      ]);
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
