// May an account be created right now?
//
// There are exactly two doors into identity.users — `signup` for a password
// account and `linkOrCreate` for a social one — and a host that wants to close
// registration has to close both. Leaving that to each host is how the second
// one stays open: social sign-in reads as "logging in", so the branch of it
// that silently creates a user is the one everybody forgets. So the question
// belongs here, asked on both paths, from one setting.
//
// The default is `open`, which is what every host that has never heard of this
// file already does.
//
// Invite-only is a FUNCTION, not a mode. This kit has no invite store — the
// invitations that exist in the family belong to tenant-kit, and a waitlist's
// belong to whatever issued them — so a mode called `invite` here could only
// ever be a lie about who validates the token. A host that has invites writes
// the three lines that check one.

import { IdentityError } from './errors.ts';
import type { RegistrationAttempt, RegistrationDecision, RegistrationSetting } from './types.ts';

/** The setting as a function, whichever shape it was written in. */
export function registrationPolicy(
  setting: RegistrationSetting | undefined,
): (attempt: RegistrationAttempt) => Promise<RegistrationDecision> {
  if (setting === undefined || setting === 'open') return async () => ({ allow: true });
  if (setting === 'closed') {
    return async () => ({ allow: false, reason: 'New accounts are not being created at the moment.' });
  }
  if (typeof setting === 'function') return async (attempt) => setting(attempt);
  throw new IdentityError({
    code: 'invalid_config',
    reason: `registration must be 'open', 'closed' or a function; received ${typeof setting}`,
  });
}

/**
 * Ask, and throw if the answer is no.
 *
 * Used by the password path, where the caller gets an exception. The social
 * path asks `registrationPolicy` directly instead, because `linkOrCreate`
 * answers in a result union rather than throwing.
 */
export async function assertRegistrationAllowed(
  setting: RegistrationSetting | undefined,
  attempt: RegistrationAttempt,
): Promise<void> {
  const decision = await registrationPolicy(setting)(attempt);
  if (!decision.allow) {
    throw new IdentityError({ code: 'registration_closed', reason: decision.reason });
  }
}
