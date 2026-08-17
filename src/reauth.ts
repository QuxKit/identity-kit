// Proof of recent authentication — shared by MFA enrolment and passkey
// registration.
//
// Adding a credential to an account is a privilege change: whoever holds the
// new authenticator holds the account. So it takes either the password, or a
// session whose holder proved a credential within `reauthWindowMs`. Without
// this, a session hijacked from a logged-in browser could quietly enrol the
// attacker's authenticator and keep the account after the password changes.

import type { Credentials } from './credentials.ts';
import { IdentityError } from './errors.ts';
import { resolveSession } from './sessions.ts';
import type { SqlExecutor, UserId } from './types.ts';

/** Either the password, or a session token that authenticated recently. */
export type EnrolmentProof = { password: string } | { sessionToken: string };

/** Ten minutes: long enough to get from the login page to security settings,
 *  short enough that a session left open is not a standing licence to enrol. */
export const DEFAULT_REAUTH_WINDOW_MS = 10 * 60 * 1000;

/**
 * Fresh proof of a credential, or `reauth_required`. Both branches burn the
 * same argon2 work as a real check when a password is offered, so the time
 * taken does not say whether the account has one.
 */
export async function requireRecentAuth(
  db: SqlExecutor,
  credentials: Credentials,
  userId: UserId,
  proof: EnrolmentProof,
  now: Date,
  reauthWindowMs: number = DEFAULT_REAUTH_WINDOW_MS,
): Promise<void> {
  if ('password' in proof) {
    const rows = await db.query<{ password_hash: string | null; pepper_version: number }>(
      'SELECT password_hash, pepper_version FROM identity.users WHERE id = $1',
      [userId],
    );
    const user = rows[0];
    const ok = user?.password_hash
      ? await credentials.verifyPassword(user.password_hash, proof.password, user.pepper_version)
      : await credentials.verifyAgainstDummy(proof.password);
    if (!ok) throw new IdentityError({ code: 'reauth_required' });
    return;
  }
  const session = await resolveSession(db, proof.sessionToken, now);
  if (!session || session.userId !== userId) throw new IdentityError({ code: 'reauth_required' });
  if (now.getTime() - session.authenticatedAt.getTime() > reauthWindowMs) {
    throw new IdentityError({ code: 'reauth_required' });
  }
}
