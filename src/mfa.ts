// identity-kit/mfa — TOTP, recovery codes, and the state between "password
// correct" and "second factor correct".
//
// That intermediate state is where MFA is usually bypassed. The mistake is a
// half-privileged session: if it is a real session row with an `mfaPending`
// flag, correctness depends on every endpoint checking the flag, and the first
// one that forgets is a complete bypass. Here it is a separate table accepted by
// exactly two functions — a token structurally incapable of authenticating
// anything else.
//
// Wire `createMfa(...).secondFactor` into `createIdentity({ secondFactor })` and
// login returns `mfa_required` instead of a session for an enrolled user.

import { createCipheriv, createDecipheriv, randomBytes, timingSafeEqual } from 'node:crypto';
import { Secret, TOTP } from 'otpauth';

import { type Credentials, createCredentials } from './credentials.ts';
import { randomBase32 } from './encoding.ts';
import { createMailer, type Mailer } from './mail.ts';
import { finishLogin } from './session-login.ts';
import { revokeAllSessions } from './sessions.ts';
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

const PENDING_TTL_S = 5 * 60;
/** Five guesses per password authentication. This bound, not a rate limit, is
 *  what makes six digits safe: a per-minute limiter still permits a patient walk
 *  through a meaningful fraction of a million. */
const MAX_PENDING_ATTEMPTS = 5;

const PERIOD = 30;
const DIGITS = 6;
/** SHA-1 not because it is good but because authenticator apps overwhelmingly
 *  implement only SHA-1; a SHA-256 secret silently never matches in Google
 *  Authenticator. HMAC-SHA-1 is unaffected by the collision attacks that retired
 *  SHA-1 for signatures. */
const ALGORITHM = 'SHA1';
const WINDOW = 1; // +/- one step: ninety seconds of acceptance
const RECOVERY_CODE_COUNT = 10;

export interface TotpConfig {
  /** 32-byte AES key as 64 hex chars (`openssl rand -hex 32`). Held OUTSIDE the
   *  database — it is what a leaked backup does not include. */
  key: string;
  keyVersion: number;
  /** Shown in the authenticator app entry (`issuer:label`). */
  issuer: string;
}

export interface MfaOptions {
  db: SqlExecutor;
  config: IdentityConfig;
  mail: MailSender;
  totp: TotpConfig;
  clock?: Clock;
  logger?: Logger;
}

export interface Enrolment {
  /** For a QR code. Contains the secret — never log it, never store it. */
  uri: string;
  /** For manual entry when the camera will not cooperate. */
  secret: string;
}

export type SecondFactorResult =
  | { kind: 'session'; token: string; expiresAt: Date }
  | { kind: 'failed' }
  /** The pending token is gone; the user restarts from the password — the bound
   *  that actually defeats brute force against six digits. */
  | { kind: 'restart' };

export interface Mfa {
  /** Plug this into `createIdentity({ secondFactor })`. */
  secondFactor: SecondFactor;
  issuePendingLogin(userId: UserId, now?: Date): Promise<string>;
  beginTotpEnrolment(userId: UserId): Promise<Enrolment>;
  confirmTotpEnrolment(userId: UserId, code: string, now?: Date): Promise<string[]>;
  removeTotp(userId: UserId, password: string): Promise<void>;
  verifyTotp(pendingToken: string, code: string, meta?: SessionMeta, now?: Date): Promise<SecondFactorResult>;
  verifyRecoveryCode(pendingToken: string, code: string, meta?: SessionMeta, now?: Date): Promise<SecondFactorResult>;
  remainingRecoveryCodes(userId: UserId): Promise<number>;
}

interface TotpRow {
  secret_cipher: Buffer;
  secret_iv: Buffer;
  secret_tag: Buffer;
  last_used_step: string;
  confirmed_at: Date | null;
}

export function createMfa(opts: MfaOptions): Mfa {
  const { db, config, totp } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  const credentials: Credentials = createCredentials(config);
  const mailer: Mailer = createMailer(config, opts.mail);
  const warn = (m: string) => opts.logger?.warn(m);

  const key = Buffer.from(totp.key, 'hex');
  if (key.length !== 32) {
    throw new Error('mfa: totp.key must be 32 bytes as 64 hex chars (openssl rand -hex 32)');
  }

  const seal = (secretBase32: string): { cipher: Buffer; iv: Buffer; tag: Buffer } => {
    const iv = randomBytes(12);
    const c = createCipheriv('aes-256-gcm', key, iv);
    const cipher = Buffer.concat([c.update(secretBase32, 'utf8'), c.final()]);
    return { cipher, iv, tag: c.getAuthTag() };
  };
  const unseal = (row: TotpRow): string => {
    const d = createDecipheriv('aes-256-gcm', key, row.secret_iv);
    d.setAuthTag(row.secret_tag);
    return Buffer.concat([d.update(row.secret_cipher), d.final()]).toString('utf8');
  };

  const totpFor = (secretBase32: string, label: string) =>
    new TOTP({
      issuer: totp.issuer,
      label,
      algorithm: ALGORITHM,
      digits: DIGITS,
      period: PERIOD,
      secret: Secret.fromBase32(secretBase32),
    });

  /**
   * Check a code and say which step it came from. Written out rather than
   * `TOTP.validate` because the step is needed for replay prevention, and a
   * true/false validator cannot supply it. Every candidate is compared
   * (timingSafeEqual, no early return) so the loop runs the same either way.
   */
  const checkCode = (secretBase32: string, code: string, now: Date): { step: number } | null => {
    const submitted = code.replace(/\s+/g, '');
    if (!/^\d{6}$/.test(submitted)) return null;
    const t = totpFor(secretBase32, 'check');
    const current = Math.floor(now.getTime() / 1000 / PERIOD);
    const submittedBytes = Buffer.from(submitted, 'utf8');
    let found: number | null = null;
    for (let delta = -WINDOW; delta <= WINDOW; delta += 1) {
      const step = current + delta;
      const expected = Buffer.from(t.generate({ timestamp: step * PERIOD * 1000 }), 'utf8');
      if (expected.length === submittedBytes.length && timingSafeEqual(expected, submittedBytes)) found = step;
    }
    return found === null ? null : { step: found };
  };

  const issuePendingLogin = async (userId: UserId, now: Date = clock()): Promise<string> => {
    const { plaintext, hash } = issueToken();
    await db.transaction(async (tx) => {
      // One live pending login per user.
      await tx.query('DELETE FROM identity.pending_logins WHERE user_id = $1', [userId]);
      await tx.query('INSERT INTO identity.pending_logins (token_hash, user_id, expires_at) VALUES ($1, $2, $3)', [
        hash,
        userId,
        expiresIn(PENDING_TTL_S, now),
      ]);
    });
    return plaintext;
  };

  type Pending =
    | { kind: 'ok'; userId: string; tokenHash: string; attempt: number }
    | { kind: 'invalid' }
    | { kind: 'exhausted' };

  // Charge one attempt, in its own committed transaction, BEFORE the factor is
  // checked — so a crash or a thrown error still costs the attacker the attempt.
  const chargeAttempt = async (token: string, now: Date): Promise<Pending> => {
    const tokenHash = sha256(token);
    return db.transaction(async (tx) => {
      const rows = await tx.query<{ user_id: string; attempts: number; expires_at: Date }>(
        'SELECT user_id, attempts, expires_at FROM identity.pending_logins WHERE token_hash = $1',
        [tokenHash],
      );
      const row = rows[0];
      if (!row || row.expires_at <= now) return { kind: 'invalid' };
      if (row.attempts >= MAX_PENDING_ATTEMPTS) {
        await tx.query('DELETE FROM identity.pending_logins WHERE token_hash = $1', [tokenHash]);
        return { kind: 'exhausted' };
      }
      const updated = await tx.query<{ attempts: number }>(
        'UPDATE identity.pending_logins SET attempts = attempts + 1 WHERE token_hash = $1 RETURNING attempts',
        [tokenHash],
      );
      return { kind: 'ok', userId: row.user_id, tokenHash, attempt: updated[0]!.attempts };
    });
  };

  // The factor was wrong. Destroy the token if that was the last allowed guess.
  // Every failing return goes through here — including the ones that reject
  // before the code is compared, where an "only count real mismatches"
  // implementation leaks free attempts.
  const failFactor = async (p: { tokenHash: string; attempt: number }): Promise<SecondFactorResult> => {
    if (p.attempt >= MAX_PENDING_ATTEMPTS) {
      await db.query('DELETE FROM identity.pending_logins WHERE token_hash = $1', [p.tokenHash]);
      return { kind: 'restart' };
    }
    return { kind: 'failed' };
  };

  const userEmail = async (userId: UserId): Promise<string | null> => {
    const rows = await db.query<{ email: string }>('SELECT email FROM identity.users WHERE id = $1', [userId]);
    return rows[0]?.email ?? null;
  };

  const readFactor = async (userId: UserId): Promise<TotpRow | null> => {
    const rows = await db.query<TotpRow>(
      'SELECT secret_cipher, secret_iv, secret_tag, last_used_step, confirmed_at FROM identity.totp_factors WHERE user_id = $1',
      [userId],
    );
    return rows[0] ?? null;
  };

  return {
    secondFactor: {
      pendingFor: async (userId, now) => {
        const rows = await db.query(
          'SELECT 1 FROM identity.totp_factors WHERE user_id = $1 AND confirmed_at IS NOT NULL',
          [userId],
        );
        return rows.length === 0 ? null : issuePendingLogin(userId, now);
      },
    },

    issuePendingLogin,

    /**
     * Begin enrolment: the factor is created but NOT confirmed. Confirmation
     * requires a verified code, or a mis-scanned QR enables MFA against a secret
     * the user does not hold and bricks the account at the next login.
     */
    async beginTotpEnrolment(userId) {
      const email = await userEmail(userId);
      if (!email) throw new Error('no such user');
      const secret = randomBase32(20);
      const sealed = seal(secret);
      await db.query(
        `INSERT INTO identity.totp_factors (user_id, secret_cipher, secret_iv, secret_tag, key_version, last_used_step, confirmed_at)
         VALUES ($1, $2, $3, $4, $5, 0, NULL)
         ON CONFLICT (user_id) DO UPDATE SET
           secret_cipher = EXCLUDED.secret_cipher, secret_iv = EXCLUDED.secret_iv,
           secret_tag = EXCLUDED.secret_tag, key_version = EXCLUDED.key_version,
           last_used_step = 0, confirmed_at = NULL`,
        [userId, sealed.cipher, sealed.iv, sealed.tag, totp.keyVersion],
      );
      return { uri: totpFor(secret, email).toString(), secret };
    },

    /** Confirm enrolment with a code, and hand back recovery codes (argon2id-
     *  hashed). Enrolling a second factor revokes every existing session. */
    async confirmTotpEnrolment(userId, code, now = clock()) {
      const factor = await readFactor(userId);
      if (!factor) throw new Error('enrolment has not been started');
      const hit = checkCode(unseal(factor), code, now);
      if (!hit) throw new Error('that code is not valid');

      const codes = Array.from({ length: RECOVERY_CODE_COUNT }, () => randomBase32(10));
      const hashes = await Promise.all(codes.map((c) => credentials.hashPassword(c)));

      await db.transaction(async (tx) => {
        await tx.query('UPDATE identity.totp_factors SET confirmed_at = $2, last_used_step = $3 WHERE user_id = $1', [
          userId,
          now,
          String(hit.step),
        ]);
        await tx.query('DELETE FROM identity.recovery_codes WHERE user_id = $1', [userId]);
        for (const codeHash of hashes) {
          await tx.query('INSERT INTO identity.recovery_codes (user_id, code_hash) VALUES ($1, $2)', [
            userId,
            codeHash,
          ]);
        }
      });
      await revokeAllSessions(db, userId);
      return codes;
    },

    async removeTotp(userId, password) {
      const rows = await db.query<{ password_hash: string | null; pepper_version: number }>(
        'SELECT password_hash, pepper_version FROM identity.users WHERE id = $1',
        [userId],
      );
      const user = rows[0];
      if (!user?.password_hash) throw new Error('no such user');
      if (!(await credentials.verifyPassword(user.password_hash, password, user.pepper_version))) {
        throw new Error('password is incorrect');
      }
      await db.transaction(async (tx) => {
        await tx.query('DELETE FROM identity.totp_factors WHERE user_id = $1', [userId]);
        await tx.query('DELETE FROM identity.recovery_codes WHERE user_id = $1', [userId]);
      });
      await revokeAllSessions(db, userId);
    },

    async verifyTotp(pendingToken, code, meta = {}, now = clock()) {
      const pending = await chargeAttempt(pendingToken, now);
      if (pending.kind === 'exhausted') return { kind: 'restart' };
      if (pending.kind === 'invalid') return { kind: 'failed' };

      const factor = await readFactor(pending.userId);
      if (!factor?.confirmed_at) return failFactor(pending);

      const hit = checkCode(unseal(factor), code, now);
      // A code is valid for up to ninety seconds across the window. Without this
      // comparison an attacker who phishes a code in real time can reuse it
      // inside that window. One integer column, one whole class of attack closed.
      if (!hit || BigInt(hit.step) <= BigInt(factor.last_used_step)) return failFactor(pending);

      const email = await userEmail(pending.userId);
      if (!email) return failFactor(pending);

      await db.transaction(async (tx) => {
        await tx.query('UPDATE identity.totp_factors SET last_used_step = $2 WHERE user_id = $1', [
          pending.userId,
          String(hit.step),
        ]);
        await tx.query('DELETE FROM identity.pending_logins WHERE token_hash = $1', [pending.tokenHash]);
      });
      return finishLogin(db, mailer, pending.userId, email, meta, now, opts.logger);
    },

    async verifyRecoveryCode(pendingToken, code, meta = {}, now = clock()) {
      const pending = await chargeAttempt(pendingToken, now);
      if (pending.kind === 'exhausted') return { kind: 'restart' };
      if (pending.kind === 'invalid') return { kind: 'failed' };

      const candidate = code.replace(/[\s-]/g, '').toUpperCase();
      const unused = await db.query<{ id: string; code_hash: string }>(
        'SELECT id, code_hash FROM identity.recovery_codes WHERE user_id = $1 AND used_at IS NULL',
        [pending.userId],
      );

      // Linear over at most ten argon2 verifications: slow and irrelevant, this
      // runs a handful of times per account per lifetime and is bounded by the
      // pending-login attempt counter, not by speed.
      let matched: string | null = null;
      for (const row of unused) {
        if (await credentials.verifyPassword(row.code_hash, candidate, config.pepperVersion)) {
          matched = row.id;
          break;
        }
      }
      if (!matched) return failFactor(pending);

      const email = await userEmail(pending.userId);
      if (!email) return failFactor(pending);

      await db.transaction(async (tx) => {
        await tx.query('UPDATE identity.recovery_codes SET used_at = $2 WHERE id = $1', [matched, now]);
        await tx.query('DELETE FROM identity.pending_logins WHERE token_hash = $1', [pending.tokenHash]);
      });
      // An unexpected one of these is a takeover in progress, and the mail is the
      // only place the user would find out.
      await mailer
        .recoveryCodeUsed(email, unused.length - 1)
        .catch((e) => warn(`recovery-code mail failed: ${String(e)}`));
      return finishLogin(db, mailer, pending.userId, email, meta, now, opts.logger);
    },

    async remainingRecoveryCodes(userId) {
      const rows = await db.query<{ n: string }>(
        'SELECT count(*)::text AS n FROM identity.recovery_codes WHERE user_id = $1 AND used_at IS NULL',
        [userId],
      );
      return Number(rows[0]!.n);
    },
  };
}
