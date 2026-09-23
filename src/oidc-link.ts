// The account-linking policy — the one security-critical decision in OIDC, and
// the reason identity-kit owns an OIDC module at all rather than telling you to
// use a library directly.
//
// The classic social-login takeover: an attacker signs in with Google for an
// email they do not control and gets attached to an existing password account
// for that email. The defence is a rule that is easy to state and easy to get
// subtly wrong, so it lives here as one pure function, tested directly against
// crafted claims with no provider in the loop:
//
//   1. Already linked (provider + subject known) -> that user. Always safe.
//   2. Not linked, provider asserts a VERIFIED email that matches a LOCAL account
//      whose email is ALSO verified -> link them. Both sides proved the address.
//   3. Not linked, an email that matches a local account but either side is
//      unverified -> REFUSE (conflict). Linking here is the takeover; creating a
//      duplicate is impossible (unique email). The host asks the user to sign in
//      the existing way first, then link from settings.
//   4. Otherwise -> create a new user, email verified only if the provider
//      verified it. No password — subject to `registration`, because this is
//      the second door into identity.users and the one a host closing signups
//      forgets, social sign-in reading as "logging in".
//
// A provider that returns no email cannot create a user in this schema (email is
// NOT NULL, UNIQUE), so that is its own outcome rather than a swallowed error.

import { registrationPolicy } from './registration.ts';
import type { RegistrationSetting, SqlExecutor } from './types.ts';

export interface ProviderClaims {
  /** The provider key, e.g. 'google' or 'apple'. */
  provider: string;
  /** The provider's stable identifier for the user — the `sub` claim. Never the
   *  email, which can change and be reassigned. */
  subject: string;
  email: string | null;
  /** Whether the PROVIDER asserts the email is verified. Coerced by the caller
   *  from the `email_verified` claim (Google sends a boolean, Apple a string). */
  emailVerified: boolean;
}

export type LinkResult =
  | { kind: 'ok'; userId: string; isNewUser: boolean }
  /** An existing local account owns this email but the link is not safe to make
   *  automatically. The host should have the user authenticate the existing way
   *  and link from account settings. */
  | { kind: 'conflict'; email: string }
  /** The provider returned no email; this schema cannot create a user without
   *  one. Request the `email` scope. */
  | { kind: 'no_email' }
  /** No account exists for this identity and `registration` refused to create
   *  one. Only ever returned for a would-be NEW user: an existing account signs
   *  in through the branches above whatever registration says. */
  | { kind: 'registration_closed'; email: string; reason: string };

export interface LinkOptions {
  /**
   * Whether a NEW account may be created here. Omitted means open, which is
   * what this function did before the option existed.
   *
   * Prefer `identity.linkOrCreate(...)` on the instance, which passes the
   * configured policy for you — an optional argument on a free function is
   * exactly the thing a host forgets, and forgetting it here silently reopens
   * registration through the social door.
   */
  registration?: RegistrationSetting;
}

const normalise = (email: string) => email.trim().toLowerCase();

export async function linkOrCreate(
  db: SqlExecutor,
  claims: ProviderClaims,
  now: Date,
  options: LinkOptions = {},
): Promise<LinkResult> {
  // 1. Already linked — the only path that needs no email reasoning at all.
  const linked = await db.query<{ user_id: string }>(
    'SELECT user_id FROM identity.oauth_identities WHERE provider = $1 AND subject = $2',
    [claims.provider, claims.subject],
  );
  if (linked[0]) return { kind: 'ok', userId: linked[0].user_id, isNewUser: false };

  if (!claims.email) return { kind: 'no_email' };
  const email = normalise(claims.email);

  const local = await db.query<{ id: string; email_verified_at: Date | null }>(
    'SELECT id, email_verified_at FROM identity.users WHERE email = $1',
    [email],
  );
  const existing = local[0];

  if (existing) {
    // 2. Link only when BOTH sides verified the address. Never otherwise.
    if (claims.emailVerified && existing.email_verified_at) {
      await db.query(
        'INSERT INTO identity.oauth_identities (provider, subject, user_id, email) VALUES ($1, $2, $3, $4)',
        [claims.provider, claims.subject, existing.id, email],
      );
      return { kind: 'ok', userId: existing.id, isNewUser: false };
    }
    // 3. Same email, but a link would be unsafe and a duplicate is impossible.
    return { kind: 'conflict', email };
  }

  // 4. New user. Everything above this line is an EXISTING account signing in
  // and is never refused — closing registration locks the door, it does not
  // evict anyone.
  const decision = await registrationPolicy(options.registration)({ email, via: 'oidc' });
  if (!decision.allow) return { kind: 'registration_closed', email, reason: decision.reason };

  // No password; email verified only if the provider verified it.
  const created = await db.transaction(async (tx) => {
    const rows = await tx.query<{ id: string }>(
      `INSERT INTO identity.users (email, email_display, email_verified_at, password_hash)
       VALUES ($1, $2, $3, NULL) RETURNING id`,
      [email, claims.email, claims.emailVerified ? now : null],
    );
    // biome-ignore lint/style/noNonNullAssertion: INSERT … RETURNING yields exactly one row
    const userId = rows[0]!.id;
    await tx.query(
      'INSERT INTO identity.oauth_identities (provider, subject, user_id, email) VALUES ($1, $2, $3, $4)',
      [claims.provider, claims.subject, userId, email],
    );
    return userId;
  });
  return { kind: 'ok', userId: created, isNewUser: true };
}
