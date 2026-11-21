// Revoking refresh-token families (sql/012_oidc_refresh.sql).
//
// A family is one sign-in on one device, issued by `identity-kit/provider` to a
// client that may hold refresh tokens. Revoking it is one statement: the family
// is marked, and the access tokens issued to it are deleted in the same breath,
// so "revoked" takes effect on the next request and not five minutes later.
//
// This lives outside provider.ts because the CORE revokes too. A password
// change, a reset, an email change, a deletion request and "sign out
// everywhere" all end every session a person has, and a refresh token on a
// phone is a session by another name; leaving it alive would make the phone the
// one device a stolen password still works from. The core must not import the
// provider (and its JOSE dependency) to say so, and must not assume the
// provider's tables exist, so the hook checks for them first.

import { recordEvent } from './events.ts';
import type { SessionMeta, SqlExecutor, UserId } from './types.ts';

/** Why a family ended, kept on the row and on the event for an incident review. */
export type FamilyRevocationReason =
  /** A retired refresh token was presented again: theft, or a client bug. */
  | 'reuse'
  /** The app or the person asked (the revoke endpoint, the devices page). */
  | 'revoked'
  /** Every session was revoked: sign out everywhere, or an email change. */
  | 'signed_out'
  | 'password_changed'
  | 'password_reset'
  | 'email_changed'
  /** The account is closing, or no longer exists. */
  | 'account'
  /** The client lost the right to hold refresh tokens. */
  | 'client';

export interface RevokedFamily {
  id: string;
  userId: string;
  clientId: string;
}

/** Which families. Exactly one of these names them; `exceptFamilyId` spares the
 *  device a person is holding when they sign out the others. */
export type FamilyTarget = { familyId: string } | { userId: UserId; exceptFamilyId?: string } | { clientId: string };

/**
 * Revoke the live families `target` names, and delete their access tokens, in
 * one statement. Returns the ones this call revoked: a family already revoked
 * is not returned, so the count is of what changed.
 *
 * `now` may be omitted, as it may be on `recordEvent`; the database's clock is
 * used then.
 */
export async function revokeFamilies(
  db: SqlExecutor,
  target: FamilyTarget,
  reason: FamilyRevocationReason,
  now?: Date,
): Promise<RevokedFamily[]> {
  const familyId = 'familyId' in target ? target.familyId : null;
  const userId = 'userId' in target ? target.userId : null;
  const clientId = 'clientId' in target ? target.clientId : null;
  const except = 'userId' in target ? (target.exceptFamilyId ?? null) : null;
  const rows = await db.query<{ id: string; user_id: string; client_id: string }>(
    // The CASE is the guard: a target naming nothing matches nothing, rather
    // than every family in the table.
    `WITH gone AS (
       UPDATE identity.oidc_refresh_families
          SET revoked_at = COALESCE($5::timestamptz, now()), revoked_reason = $4
        WHERE revoked_at IS NULL
          AND CASE
                WHEN $1::uuid IS NOT NULL THEN id = $1::uuid
                WHEN $2::uuid IS NOT NULL THEN user_id = $2::uuid AND ($6::uuid IS NULL OR id <> $6::uuid)
                WHEN $3::text IS NOT NULL THEN client_id = $3::text
                ELSE false
              END
        RETURNING id, user_id, client_id
     ), dead AS (
       DELETE FROM identity.oidc_access_tokens WHERE family_id IN (SELECT id FROM gone)
     )
     SELECT id::text AS id, user_id::text AS user_id, client_id FROM gone`,
    [familyId, userId, clientId, reason, now ?? null, except],
  );
  return rows.map((r) => ({ id: r.id, userId: r.user_id, clientId: r.client_id }));
}

/**
 * The core's hook: every refresh family a user has, gone. Called wherever the
 * core revokes every session. Safe on a database without the provider's
 * tables, where it does nothing. Records one `device_session_revoked` event
 * when anything was revoked. Returns how many.
 *
 * Pass the transaction's executor when the change that caused this is
 * transactional, so a new password and the end of the old sign-ins commit
 * together.
 */
export async function revokeUserRefreshFamilies(
  db: SqlExecutor,
  userId: UserId,
  reason: FamilyRevocationReason,
  now?: Date,
  meta: SessionMeta = {},
): Promise<number> {
  const present = await db.query<{ ok: string | null }>(
    `SELECT to_regclass('identity.oidc_refresh_families')::text AS ok`,
  );
  if (present[0]?.ok == null) return 0;
  const gone = await revokeFamilies(db, { userId }, reason, now);
  if (gone.length > 0) {
    await recordEvent(db, {
      userId,
      kind: 'device_session_revoked',
      meta,
      at: now,
      metadata: { count: gone.length, reason },
    });
  }
  return gone.length;
}
