// Security events — the account's audit trail.
//
// Every flow that changes how an account authenticates, or that authenticates
// it, appends a row here: a login (and a failed one), a password change or
// reset, an MFA enrolment or removal, an API key issued or revoked, a session
// revoked, a passkey registered, a magic link used. It is what a "recent
// activity" page shows the user and what an incident review reads afterwards.
//
// The log is append-only from the library's point of view; the only delete is
// the retention sweep and an account purge. Rows carry `ip` and `user_agent`
// when the caller had them (`SessionMeta`), and a small `metadata` object with
// the event-specific facts (which method logged in, why a login failed, which
// key was issued). Never a secret, never a token, never a password.

import type { Clock, SessionMeta, SqlExecutor, UserId } from './types.ts';

export type SecurityEventKind =
  | 'login_succeeded'
  | 'login_failed'
  | 'password_changed'
  | 'password_reset'
  | 'session_revoked'
  | 'mfa_enrolled'
  | 'mfa_removed'
  | 'api_key_issued'
  | 'api_key_revoked'
  | 'passkey_registered'
  | 'passkey_removed'
  | 'magic_link_used';

export interface SecurityEvent {
  /** Monotonic within the table; a string because it is a bigint. */
  id: string;
  /** The user (or, for API-key events, the opaque owner) the event is about. */
  userId: string;
  kind: SecurityEventKind;
  ip: string | null;
  userAgent: string | null;
  at: Date;
  metadata: Record<string, unknown>;
}

export interface RecordEventInput {
  userId: string;
  kind: SecurityEventKind;
  /** `ip` and `userAgent` are copied out of the request's `SessionMeta`. */
  meta?: SessionMeta;
  at?: Date;
  metadata?: Record<string, unknown>;
}

export interface ListEventsOptions {
  /** Default 50, capped at 200. */
  limit?: number;
  /** Only events strictly before this instant — pass the `at` of the last row
   *  seen to page backwards. */
  before?: Date;
}

const DEFAULT_LIMIT = 50;
const MAX_LIMIT = 200;

/** Ninety days: long enough to review an incident, short enough that the table
 *  is not a permanent record of every login ever made. */
export const DEFAULT_EVENT_RETENTION_MS = 90 * 24 * 60 * 60 * 1000;

interface EventRow {
  id: string;
  user_id: string;
  kind: SecurityEventKind;
  ip: string | null;
  user_agent: string | null;
  at: Date;
  metadata: Record<string, unknown>;
}

/**
 * Append one event. Pass the transaction's executor when the mutation being
 * recorded is transactional, so the event and the change commit — or roll back —
 * together. Needs `sql/006_events.sql`.
 */
export async function recordEvent(db: SqlExecutor, input: RecordEventInput): Promise<void> {
  await db.query(
    `INSERT INTO identity.events (user_id, kind, ip, user_agent, at, metadata)
     VALUES ($1, $2, $3, $4, COALESCE($5, now()), $6::jsonb)`,
    [
      input.userId,
      input.kind,
      input.meta?.ipAddress ?? null,
      input.meta?.userAgent ?? null,
      input.at ?? null,
      JSON.stringify(input.metadata ?? {}),
    ],
  );
}

/** Newest first. Keyset by `at`; equal timestamps break on id. */
export async function listEvents(
  db: SqlExecutor,
  userId: string,
  opts: ListEventsOptions = {},
): Promise<SecurityEvent[]> {
  const limit = Math.max(1, Math.min(MAX_LIMIT, Math.floor(opts.limit ?? DEFAULT_LIMIT)));
  const rows = await db.query<EventRow>(
    // `e.id` is qualified on purpose: a bare `id` in ORDER BY would bind to the
    // text alias in the SELECT list and sort "9" after "12".
    `SELECT e.id::text AS id, e.user_id, e.kind, e.ip, e.user_agent, e.at, e.metadata
       FROM identity.events e
      WHERE e.user_id = $1 AND ($2::timestamptz IS NULL OR e.at < $2)
      ORDER BY e.at DESC, e.id DESC
      LIMIT $3`,
    [userId, opts.before ?? null, limit],
  );
  return rows.map((r) => ({
    id: r.id,
    userId: r.user_id,
    kind: r.kind,
    ip: r.ip,
    userAgent: r.user_agent,
    at: r.at,
    metadata: r.metadata,
  }));
}

/** Delete events older than `before`. Returns how many went. */
export async function sweepEvents(db: SqlExecutor, before: Date): Promise<number> {
  const rows = await db.query<{ id: string }>('DELETE FROM identity.events WHERE at < $1 RETURNING id', [before]);
  return rows.length;
}

/** Everything about these subjects — used when an account is purged. */
export async function deleteEventsFor(db: SqlExecutor, userIds: readonly string[]): Promise<void> {
  if (userIds.length === 0) return;
  await db.query('DELETE FROM identity.events WHERE user_id = ANY($1::text[])', [userIds]);
}

/** The bound surface `createIdentity` exposes as `identity.events`. */
export interface Events {
  list(userId: UserId, opts?: ListEventsOptions): Promise<SecurityEvent[]>;
  /** Record a host-defined moment (`kind` is still one of ours) — e.g. a
   *  session revoked from a device-management page. */
  record(input: RecordEventInput): Promise<void>;
  /** Prune events older than `before` (default: now minus
   *  `config.eventRetentionMs`, ninety days). */
  sweep(before?: Date): Promise<number>;
}

export function createEvents(db: SqlExecutor, clock: Clock, retentionMs = DEFAULT_EVENT_RETENTION_MS): Events {
  return {
    list: (userId, opts) => listEvents(db, userId, opts),
    record: (input) => recordEvent(db, { at: clock(), ...input }),
    sweep: (before) => sweepEvents(db, before ?? new Date(clock().getTime() - retentionMs)),
  };
}
