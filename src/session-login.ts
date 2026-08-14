// The one place a session is minted after authentication succeeds.
//
// Its own module because more than one caller needs it: password-only login
// (accounts.ts) and, once the MFA module is wired, TOTP and recovery-code
// verification. One function, so the callers cannot drift into three different
// notions of what "logged in" means — that drift is how one path skips the
// new-device notification or the fresh identifier and nobody notices until it
// matters.

import { createSession } from './sessions.ts';
import type { Mailer } from './mail.ts';
import type { Logger, SessionMeta, SqlExecutor, UserId } from './types.ts';

export async function finishLogin(
  db: SqlExecutor,
  mailer: Mailer,
  userId: UserId,
  email: string,
  meta: SessionMeta,
  now: Date,
  logger?: Logger,
): Promise<{ kind: 'session'; token: string; expiresAt: Date }> {
  // Checked before the session is created, or the session we are about to create
  // is itself the prior sighting and no notification is ever sent.
  let seenBefore = true;
  if (meta.userAgent != null) {
    const rows = await db.query<{ n: string }>(
      'SELECT count(*)::text AS n FROM identity.sessions WHERE user_id = $1 AND user_agent = $2',
      [userId, meta.userAgent],
    );
    seenBefore = Number(rows[0]!.n) > 0;
  }

  // A fresh identifier, always — no pre-authentication session exists for an
  // attacker to plant, which is the cleanest immunity to fixation.
  const session = await createSession(db, userId, meta, now);

  if (!seenBefore) {
    await mailer
      .newDeviceSignIn(email, meta.ipAddress ?? 'an unrecognised device')
      .catch((e) => logger?.warn(`new-device mail failed: ${String(e)}`));
  }
  return { kind: 'session', ...session };
}
