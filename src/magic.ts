// identity-kit/magic — passwordless sign-in by emailed link.
//
// A magic link is a password that travels by mail, so it gets the reset
// token's discipline: fifteen minutes, one live token per user, sha256 at rest,
// burned on any use inside the transaction that mints the session. Requesting
// one is enumeration-safe the same way a reset request is — the same acceptance
// and a mail on both branches, the unknown-address mail going only to the
// address itself.
//
// Only a VERIFIED account gets a link. An unverified signup may be a squat on
// someone else's address; mailing that address a login would hand the squatter's
// account — with the squatter's password still on it — to the victim. Verify
// first (the ordinary link), then magic links work. And a link does NOT bypass
// a second factor: with `secondFactor` wired, an enrolled user gets
// `mfa_required` exactly as after a password.

import { createCredentials } from './credentials.ts';
import { IdentityError } from './errors.ts';
import { recordEvent } from './events.ts';
import { createMailer, type Mailer } from './mail.ts';
import { createPgRateLimiter, limiterKey, type RateLimiter } from './ratelimit.ts';
import { finishLogin } from './session-login.ts';
import { expiresIn, issueToken, sha256 } from './tokens.ts';
import type {
  Clock,
  IdentityConfig,
  Logger,
  MailSender,
  SecondFactor,
  SessionMeta,
  SqlExecutor,
  UserId,
} from './types.ts';

/** Fifteen minutes — a live credential, like a reset token. */
export const MAGIC_LINK_TTL_S = 15 * 60;

export interface MagicOptions {
  db: SqlExecutor;
  config: IdentityConfig;
  mail: MailSender;
  clock?: Clock;
  logger?: Logger;
  /** Wire identity-kit/mfa's hook so an enrolled user still gets `mfa_required`. */
  secondFactor?: SecondFactor;
  /** In front of `request`, keyed by address + ip. Omit for the shipped Postgres
   *  limiter over `db`; `null` disables. */
  rateLimiter?: RateLimiter | null;
}

export type MagicResult =
  | { kind: 'session'; token: string; expiresAt: Date }
  | { kind: 'mfa_required'; pendingToken: string }
  /** Unknown, spent, expired — or the account cannot sign in. One answer. */
  | { kind: 'invalid' };

export interface Magic {
  /** Enumeration-safe: accepted either way; the mail differs only at the
   *  address itself. */
  request(input: { email: string; ipAddress?: string | null }, now?: Date): Promise<{ accepted: true }>;
  /** Redeem the link. Records `magic_link_used` and, through `finishLogin`,
   *  `login_succeeded` (`via: 'magic_link'`). */
  consume(input: { token: string }, meta?: SessionMeta, now?: Date): Promise<MagicResult>;
  /** Housekeeping; `sweepExpired` does this too. */
  sweep(now?: Date): Promise<number>;
}

const normaliseEmail = (email: string) => email.trim().toLowerCase();

export function createMagic(opts: MagicOptions): Magic {
  const { db, config } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  const mailer: Mailer = createMailer(config, opts.mail);
  // Constructed for parity with the other modules (a host passes the same
  // config everywhere); it also validates the pepper keyring up front.
  createCredentials(config);
  const rateLimiter = opts.rateLimiter === undefined ? createPgRateLimiter({ db, clock }) : opts.rateLimiter;
  const limit = async (key: string): Promise<void> => {
    if (!rateLimiter) return;
    const decision = await rateLimiter.hit(key);
    if (!decision.allowed) throw new IdentityError({ code: 'rate_limited', retryAfterMs: decision.retryAfterMs, key });
  };

  return {
    async request(input, now = clock()) {
      const email = normaliseEmail(input.email);
      await limit(limiterKey('magic_link', email, input.ipAddress));
      const rows = await db.query<{ id: string; deletion_requested_at: Date | null; email_verified_at: Date | null }>(
        'SELECT id, deletion_requested_at, email_verified_at FROM identity.users WHERE email = $1',
        [email],
      );
      const user = rows[0];
      // An unverified or deletion-pending account gets the unknown-address mail:
      // it cannot sign in this way, and saying so more precisely would
      // distinguish it from no account.
      if (!user || user.deletion_requested_at || !user.email_verified_at) {
        await mailer.magicLinkUnknownAddress(email);
        return { accepted: true };
      }
      const { plaintext, hash } = issueToken();
      await db.transaction(async (tx) => {
        await tx.query('DELETE FROM identity.magic_link_tokens WHERE user_id = $1', [user.id]);
        await tx.query('INSERT INTO identity.magic_link_tokens (token_hash, user_id, expires_at) VALUES ($1, $2, $3)', [
          hash,
          user.id,
          expiresIn(MAGIC_LINK_TTL_S, now),
        ]);
      });
      await mailer.magicLink(email, plaintext);
      return { accepted: true };
    },

    async consume(input, meta = {}, now = clock()) {
      const tokenHash = sha256(input.token);
      const outcome = await db.transaction<{ kind: 'invalid' } | { kind: 'ok'; userId: UserId; email: string }>(
        async (tx) => {
          const rows = await tx.query<{ user_id: string; expires_at: Date }>(
            'SELECT user_id, expires_at FROM identity.magic_link_tokens WHERE token_hash = $1',
            [tokenHash],
          );
          const row = rows[0];
          if (!row) return { kind: 'invalid' };
          // Burned on any use, before anything is decided.
          await tx.query('DELETE FROM identity.magic_link_tokens WHERE user_id = $1', [row.user_id]);
          if (row.expires_at <= now) return { kind: 'invalid' };
          const users = await tx.query<{
            email: string;
            deletion_requested_at: Date | null;
            email_verified_at: Date | null;
          }>('SELECT email, deletion_requested_at, email_verified_at FROM identity.users WHERE id = $1', [row.user_id]);
          const user = users[0];
          // Re-checked at consume time: the account may have changed since the
          // link was issued.
          if (!user || user.deletion_requested_at || !user.email_verified_at) return { kind: 'invalid' };
          await recordEvent(tx, { userId: row.user_id, kind: 'magic_link_used', meta, at: now });
          return { kind: 'ok', userId: row.user_id, email: user.email };
        },
      );
      if (outcome.kind === 'invalid') return { kind: 'invalid' };
      if (opts.secondFactor) {
        const pending = await opts.secondFactor.pendingFor(outcome.userId, now);
        if (pending) return { kind: 'mfa_required', pendingToken: pending };
      }
      return finishLogin(db, mailer, outcome.userId, outcome.email, meta, now, opts.logger, 'magic_link');
    },

    async sweep(now = clock()) {
      const rows = await db.query<{ token_hash: string }>(
        'DELETE FROM identity.magic_link_tokens WHERE expires_at <= $1 RETURNING token_hash',
        [now],
      );
      return rows.length;
    },
  };
}
