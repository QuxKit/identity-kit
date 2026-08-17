// The account lifecycle. Every step names the mistake it is built to avoid,
// because these are the mistakes that get shipped, not obscure ones.
//
// Ported from a Prisma implementation to raw SQL over the SqlExecutor, so an
// adopter carries no ORM. The security properties are unchanged and are the
// reason to read the comments: enumeration-safety on signup and reset, a timing
// oracle closed on login, tokens burned on any use, backoff that is not a
// denial-of-service against the victim.

import { type Credentials, passwordProblem } from './credentials.ts';
import { IdentityError } from './errors.ts';
import type { Mailer } from './mail.ts';
import { limiterKey, type RateLimiter } from './ratelimit.ts';
import { finishLogin } from './session-login.ts';
import { revokeAllSessions, rotateSession } from './sessions.ts';
import { expiresIn, issueToken, sha256 } from './tokens.ts';
import type {
  Clock,
  IdentityConfig,
  Logger,
  LoginResult,
  ResetResult,
  SecondFactor,
  SessionMeta,
  SignupInput,
  SqlExecutor,
  UserId,
} from './types.ts';

const VERIFICATION_TTL_S = 24 * 60 * 60;
/** Fifteen minutes, not a day: a reset token is a live credential in a way a
 *  verification token is not. */
const RESET_TTL_S = 15 * 60;
const DELETION_GRACE_MS = 7 * 24 * 60 * 60 * 1000;
const UNVERIFIED_TTL_MS = 7 * 24 * 60 * 60 * 1000;

/** After this many consecutive failures the wait starts doubling. Backoff, not
 *  a hard lock: a hard per-account lock is a DoS anyone who knows an address can
 *  point at its owner. */
const BACKOFF_AFTER = 5;
const BACKOFF_CAP_MS = 15 * 60 * 1000;

const normaliseEmail = (email: string) => email.trim().toLowerCase();

export interface AccountsDeps {
  db: SqlExecutor;
  config: IdentityConfig;
  credentials: Credentials;
  mailer: Mailer;
  clock: Clock;
  logger?: Logger;
  /** Optional. When present, a correct password on an account with a confirmed
   *  second factor returns `mfa_required` instead of a session. */
  secondFactor?: SecondFactor;
  /** Asked before signup, login, reset request and verification resend. `null`
   *  disables limiting (createIdentity supplies the Postgres one by default). */
  rateLimiter?: RateLimiter | null;
}

/** What `changePassword` reports. `rotated` is present only when
 *  `config.rotateSessions` is on and a `keepSessionHash` was given: that
 *  session now has a new token the host must set as the cookie. */
export interface PasswordChanged {
  rotated?: { token: string; tokenHash: string; expiresAt: Date };
}

export interface Accounts {
  signup(input: SignupInput): Promise<{ accepted: true }>;
  verifyEmail(token: string, now?: Date): Promise<boolean>;
  login(input: { email: string; password: string }, meta?: SessionMeta, now?: Date): Promise<LoginResult>;
  /** Re-send the verification link to an address whose account is unverified.
   *  Enumeration-safe: accepted either way, mail only to the address itself. */
  resendVerification(email: string, meta?: SessionMeta): Promise<{ accepted: true }>;
  requestPasswordReset(email: string, meta?: SessionMeta): Promise<{ accepted: true }>;
  resetPassword(token: string, newPassword: string, now?: Date): Promise<ResetResult>;
  changePassword(
    userId: UserId,
    current: string,
    next: string,
    keepSessionHash?: string,
    now?: Date,
  ): Promise<PasswordChanged>;
  requestDeletion(userId: UserId, now?: Date): Promise<void>;
  cancelDeletion(token: string, now?: Date): Promise<boolean>;
  purgeUnverified(now?: Date): Promise<number>;
  purgeDeleted(now?: Date): Promise<number>;
}

interface UserRow {
  id: string;
  email: string;
  password_hash: string | null;
  pepper_version: number;
  email_verified_at: Date | null;
  deletion_requested_at: Date | null;
  failed_logins: number;
  locked_until: Date | null;
}

export function createAccounts(deps: AccountsDeps): Accounts {
  const { db, config, credentials, mailer, clock } = deps;
  const warn = (msg: string) => deps.logger?.warn(msg);

  const findByEmail = async (email: string): Promise<UserRow | null> => {
    const rows = await db.query<UserRow>(
      `SELECT id, email, password_hash, pepper_version, email_verified_at,
              deletion_requested_at, failed_logins, locked_until
         FROM identity.users WHERE email = $1`,
      [email],
    );
    return rows[0] ?? null;
  };

  const issueVerification = async (
    exec: SqlExecutor,
    userId: UserId,
    purpose: 'verify_email' | 'cancel_deletion',
    expiresAt: Date,
    newEmail: string | null = null,
  ): Promise<string> => {
    const { plaintext, hash } = issueToken();
    // Issuing a new token deletes any outstanding one of the same purpose, so a
    // forwarded old email cannot be replayed after a fresh link is asked for.
    await exec.query('DELETE FROM identity.email_verification_tokens WHERE user_id = $1 AND purpose = $2', [
      userId,
      purpose,
    ]);
    await exec.query(
      `INSERT INTO identity.email_verification_tokens (token_hash, user_id, purpose, new_email, expires_at)
       VALUES ($1, $2, $3, $4, $5)`,
      [hash, userId, purpose, newEmail, expiresAt],
    );
    return plaintext;
  };

  /**
   * Refuse when the limiter says so. Runs before any database or argon2 work on
   * the paths it guards, so a limited request costs the server nothing.
   */
  const limit = async (key: string): Promise<void> => {
    if (!deps.rateLimiter) return;
    const decision = await deps.rateLimiter.hit(key);
    if (!decision.allowed) throw new IdentityError({ code: 'rate_limited', retryAfterMs: decision.retryAfterMs, key });
  };

  // Incremented in place and read back, never read-then-written: two wrong
  // passwords arriving together must both count, or backoff can be held off
  // indefinitely by keeping the requests concurrent.
  const recordFailure = async (userId: UserId, now: Date): Promise<void> => {
    const rows = await db.query<{ failed_logins: number }>(
      `UPDATE identity.users SET failed_logins = failed_logins + 1, last_failed_at = $2
        WHERE id = $1 RETURNING failed_logins`,
      [userId, now],
    );
    const failedLogins = rows[0]?.failed_logins ?? 0;
    const overshoot = failedLogins - BACKOFF_AFTER;
    if (overshoot < 0) return;
    const lockedUntil = new Date(now.getTime() + Math.min(1000 * 2 ** overshoot, BACKOFF_CAP_MS));
    // Only ever push the lock later, so a slower concurrent failure cannot pull
    // an already-longer lock back in.
    await db.query(
      `UPDATE identity.users SET locked_until = GREATEST(COALESCE(locked_until, $2), $2)
        WHERE id = $1`,
      [userId, lockedUntil],
    );
  };

  const clearFailures = (userId: UserId) =>
    db.query('UPDATE identity.users SET failed_logins = 0, locked_until = NULL WHERE id = $1', [userId]);

  return {
    /**
     * Sign up, without telling the caller whether the address was taken. A
     * `409 already registered` turns this into an oracle for who has an account;
     * timing does the same if only one path runs argon2. So argon2 runs once on
     * both paths, an email is sent on both paths, and the return value is
     * identical on both paths.
     *
     * The limiter and the existing-address lookup come BEFORE any hashing, so a
     * limited request costs nothing and the taken-address path never hashes a
     * password it will not store — it burns the same work as a verification
     * against a fixed dummy instead, which is what keeps the timing equal.
     */
    async signup(input) {
      const problem = passwordProblem(input.password);
      if (problem) throw new IdentityError({ code: 'weak_password', reason: problem });

      const email = normaliseEmail(input.email);
      await limit(limiterKey('signup', email, input.ipAddress));

      const existing = await findByEmail(email);
      if (existing) {
        await credentials.verifyAgainstDummy(input.password);
        await mailer.alreadyRegistered(email);
        return { accepted: true };
      }

      const passwordHash = await credentials.hashPassword(input.password);
      const inserted = await db.query<{ id: string }>(
        `INSERT INTO identity.users (email, email_display, name, password_hash, pepper_version)
         VALUES ($1, $2, $3, $4, $5) RETURNING id`,
        [email, input.email.trim(), input.name ?? null, passwordHash, config.pepperVersion],
      );
      // biome-ignore lint/style/noNonNullAssertion: INSERT … RETURNING yields exactly one row
      const userId = inserted[0]!.id;
      const token = await issueVerification(db, userId, 'verify_email', expiresIn(VERIFICATION_TTL_S, clock()));
      await mailer.verifyAddress(email, token);
      return { accepted: true };
    },

    /**
     * Verify an address — and return nothing that authenticates. Making the
     * link a login turns any read access to the mailbox into account takeover
     * with no credential. Consumed in the same transaction that sets
     * email_verified_at, so a crash cannot leave a burned token on an unverified
     * account.
     */
    async verifyEmail(token, now = clock()) {
      const tokenHash = sha256(token);
      return db.transaction(async (tx) => {
        const rows = await tx.query<{ user_id: string; purpose: string; new_email: string | null; expires_at: Date }>(
          'SELECT user_id, purpose, new_email, expires_at FROM identity.email_verification_tokens WHERE token_hash = $1',
          [tokenHash],
        );
        const row = rows[0];
        if (row?.purpose !== 'verify_email' || row.expires_at <= now) return false;

        await tx.query('DELETE FROM identity.email_verification_tokens WHERE token_hash = $1', [tokenHash]);
        if (row.new_email) {
          await tx.query(
            'UPDATE identity.users SET email = $2, email_display = $3, email_verified_at = $4 WHERE id = $1',
            [row.user_id, normaliseEmail(row.new_email), row.new_email, now],
          );
          // An email change is a change to how the account authenticates.
          await tx.query('DELETE FROM identity.sessions WHERE user_id = $1', [row.user_id]);
        } else {
          await tx.query('UPDATE identity.users SET email_verified_at = $2 WHERE id = $1', [row.user_id, now]);
        }
        return true;
      });
    },

    /**
     * Log in. Closes a timing oracle, session fixation, and lockout-as-DoS.
     *
     * Unknown email: the password is verified against a fixed dummy hash so work
     * and time match. Unverified or deletion-pending accounts get the same
     * generic failure as a wrong password — anything else re-opens enumeration.
     */
    async login(input, meta = {}, now = clock()) {
      const email = normaliseEmail(input.email);
      // Address + IP together: neither a distant attacker locking one victim
      // out, nor one IP spraying many accounts, gets an unmetered budget.
      await limit(limiterKey('login', email, meta.ipAddress));
      const user = await findByEmail(email);

      if (!user?.password_hash) {
        await credentials.verifyAgainstDummy(input.password);
        return { kind: 'failed' };
      }
      if (user.locked_until && user.locked_until > now) {
        // Still burn the work — an instant return while locked leaks that the
        // account exists and is under attack.
        await credentials.verifyAgainstDummy(input.password);
        return { kind: 'backoff', retryAfterSeconds: Math.ceil((user.locked_until.getTime() - now.getTime()) / 1000) };
      }

      const ok = await credentials.verifyPassword(user.password_hash, input.password, user.pepper_version);
      if (!ok) {
        await recordFailure(user.id, now);
        return { kind: 'failed' };
      }

      // After the password check and returning the same generic failure: an
      // unverified or deletion-pending account must not be distinguishable from
      // a wrong password by anyone who does not already know it.
      if (!user.email_verified_at || user.deletion_requested_at) {
        await clearFailures(user.id);
        return { kind: 'failed' };
      }

      await clearFailures(user.id);

      if (credentials.needsRehash(user.password_hash, user.pepper_version)) {
        // The one moment the plaintext is available.
        const rehashed = await credentials.hashPassword(input.password);
        await db.query('UPDATE identity.users SET password_hash = $2, pepper_version = $3 WHERE id = $1', [
          user.id,
          rehashed,
          config.pepperVersion,
        ]);
      }

      // A confirmed second factor stops here with a pending token, never a
      // session — the intermediate state is the MFA module's single-purpose
      // table, never a half-privileged session (see identity-kit/mfa).
      if (deps.secondFactor) {
        const pending = await deps.secondFactor.pendingFor(user.id, now);
        if (pending) return { kind: 'mfa_required', pendingToken: pending };
      }

      return finishLogin(db, mailer, user.id, user.email, meta, now, deps.logger);
    },

    /**
     * Ask for a reset link. Same acceptance whether or not the address exists,
     * with an email either way — the unknown-address email is safe because it
     * goes only to the address itself.
     */
    async resendVerification(rawEmail, meta = {}) {
      const email = normaliseEmail(rawEmail);
      await limit(limiterKey('verification_resend', email, meta.ipAddress));
      const user = await findByEmail(email);
      // Only an unverified account gets a link, and only at its own address; a
      // verified or unknown address gets nothing and the same acceptance.
      if (user && !user.email_verified_at) {
        const token = await issueVerification(db, user.id, 'verify_email', expiresIn(VERIFICATION_TTL_S, clock()));
        await mailer.verifyAddress(email, token);
      }
      return { accepted: true };
    },

    async requestPasswordReset(rawEmail, meta = {}) {
      const email = normaliseEmail(rawEmail);
      await limit(limiterKey('password_reset', email, meta.ipAddress));
      const user = await findByEmail(email);
      if (!user) {
        await mailer.resetUnknownAddress(email);
        return { accepted: true };
      }

      const { plaintext, hash } = issueToken();
      await db.transaction(async (tx) => {
        // One live token per user.
        await tx.query('DELETE FROM identity.password_reset_tokens WHERE user_id = $1', [user.id]);
        await tx.query(
          'INSERT INTO identity.password_reset_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)',
          [hash, user.id, expiresIn(RESET_TTL_S, clock())],
        );
      });
      await mailer.resetPassword(email, plaintext);
      return { accepted: true };
    },

    /**
     * Complete a reset. The token is burned on *any* use — success or failure —
     * inside the same transaction as the password write, so a link cannot be
     * replayed out of a mail archive, and a crash cannot leave a burned token
     * with the old password. A reset also proves control of the mailbox, so it
     * verifies the address and signs out every session.
     */
    async resetPassword(token, newPassword, now = clock()) {
      const tokenHash = sha256(token);
      const outcome = await db.transaction<
        { kind: 'invalid' } | { kind: 'weak'; message: string } | { kind: 'ok'; email: string }
      >(async (tx) => {
        const rows = await tx.query<{ user_id: string; expires_at: Date }>(
          'SELECT user_id, expires_at FROM identity.password_reset_tokens WHERE token_hash = $1',
          [tokenHash],
        );
        const row = rows[0];
        if (!row) return { kind: 'invalid' };

        // Burned first — the alternative "burned only on failures we recognise"
        // grows an exception that leaves the token live.
        await tx.query('DELETE FROM identity.password_reset_tokens WHERE user_id = $1', [row.user_id]);
        if (row.expires_at <= now) return { kind: 'invalid' };

        const problem = passwordProblem(newPassword);
        if (problem) return { kind: 'weak', message: problem };

        const passwordHash = await credentials.hashPassword(newPassword);
        const updated = await tx.query<{ email: string }>(
          `UPDATE identity.users
              SET password_hash = $2, pepper_version = $3, failed_logins = 0,
                  locked_until = NULL, email_verified_at = $4
            WHERE id = $1 RETURNING email`,
          [row.user_id, passwordHash, config.pepperVersion, now],
        );
        await tx.query('DELETE FROM identity.sessions WHERE user_id = $1', [row.user_id]);
        // biome-ignore lint/style/noNonNullAssertion: UPDATE … RETURNING on the row the token named
        return { kind: 'ok', email: updated[0]!.email };
      });

      if (outcome.kind === 'invalid') return { kind: 'invalid' };
      if (outcome.kind === 'weak') return { kind: 'weak_password', message: outcome.message };
      await mailer.passwordChanged(outcome.email).catch((e) => warn(`password-changed mail failed: ${String(e)}`));
      return { kind: 'done' };
    },

    /**
     * Change the password with the current one in hand. Every other session is
     * revoked; the one named by `keepSessionHash` survives — and, with
     * `config.rotateSessions`, is rotated (it just re-proved a credential, so
     * the identifier is renewed and `authenticatedAt` is refreshed).
     */
    async changePassword(userId, current, next, keepSessionHash, now = clock()) {
      const problem = passwordProblem(next);
      if (problem) throw new IdentityError({ code: 'weak_password', reason: problem });

      const rows = await db.query<{ email: string; password_hash: string | null; pepper_version: number }>(
        'SELECT email, password_hash, pepper_version FROM identity.users WHERE id = $1',
        [userId],
      );
      const user = rows[0];
      if (!user?.password_hash) throw new IdentityError({ code: 'no_password' });

      const ok = await credentials.verifyPassword(user.password_hash, current, user.pepper_version);
      if (!ok) throw new IdentityError({ code: 'bad_credentials' });

      const passwordHash = await credentials.hashPassword(next);
      await db.query('UPDATE identity.users SET password_hash = $2, pepper_version = $3 WHERE id = $1', [
        userId,
        passwordHash,
        config.pepperVersion,
      ]);
      await revokeAllSessions(db, userId, keepSessionHash);
      const result: PasswordChanged = {};
      if (keepSessionHash && config.rotateSessions) {
        const rotated = await rotateSession(db, keepSessionHash, now, { authenticatedAt: now });
        if (rotated) result.rotated = rotated;
      } else if (keepSessionHash) {
        await db.query('UPDATE identity.sessions SET authenticated_at = $2 WHERE token_hash = $1', [
          keepSessionHash,
          now,
        ]);
      }
      await mailer.passwordChanged(user.email).catch((e) => warn(`password-changed mail failed: ${String(e)}`));
      return result;
    },

    /**
     * Request deletion. Sessions go immediately and the account can no longer
     * authenticate; the 7-day grace exists because deletion is the one
     * irreversible action and a favourite of an attacker covering their tracks.
     * `purgeDeleted` then hard-deletes, freeing the address for re-registration.
     */
    async requestDeletion(userId, now = clock()) {
      const rows = await db.query<{ email: string }>(
        'UPDATE identity.users SET deletion_requested_at = $2 WHERE id = $1 RETURNING email',
        [userId, now],
      );
      const user = rows[0];
      if (!user) throw new IdentityError({ code: 'not_found', what: `user ${userId}` });
      await revokeAllSessions(db, userId);
      const token = await issueVerification(db, userId, 'cancel_deletion', new Date(now.getTime() + DELETION_GRACE_MS));
      await mailer.deletionRequested(user.email, token);
    },

    async cancelDeletion(token, now = clock()) {
      const tokenHash = sha256(token);
      return db.transaction(async (tx) => {
        const rows = await tx.query<{ user_id: string; purpose: string; expires_at: Date }>(
          'SELECT user_id, purpose, expires_at FROM identity.email_verification_tokens WHERE token_hash = $1',
          [tokenHash],
        );
        const row = rows[0];
        if (row?.purpose !== 'cancel_deletion' || row.expires_at <= now) return false;
        await tx.query('DELETE FROM identity.email_verification_tokens WHERE token_hash = $1', [tokenHash]);
        await tx.query('UPDATE identity.users SET deletion_requested_at = NULL WHERE id = $1', [row.user_id]);
        return true;
      });
    },

    /** Unverified accounts are purged, or the users table accumulates a
     *  permanent squatting layer over addresses their owners never registered. */
    async purgeUnverified(now = clock()) {
      const rows = await db.query<{ id: string }>(
        'DELETE FROM identity.users WHERE email_verified_at IS NULL AND created_at < $1 RETURNING id',
        [new Date(now.getTime() - UNVERIFIED_TTL_MS)],
      );
      return rows.length;
    },

    /** Hard delete past the grace period. Identity is removed outright; any
     *  financial rows are a billing-side concern that anonymises rather than
     *  deletes, and lives with the ledger. */
    async purgeDeleted(now = clock()) {
      const rows = await db.query<{ id: string }>(
        'DELETE FROM identity.users WHERE deletion_requested_at < $1 RETURNING id',
        [new Date(now.getTime() - DELETION_GRACE_MS)],
      );
      return rows.length;
    },
  };
}
