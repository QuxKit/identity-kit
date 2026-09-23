// identity-kit/passkeys — WebAuthn credentials: register, authenticate, manage.
//
// The protocol is NOT hand-rolled: options generation, attestation and
// assertion verification are @simplewebauthn/server's. What identity-kit owns
// is the state around it, which is where deployments go wrong:
//
//   - the challenge is stored server-side with a TTL and spent on use, so a host
//     keeps no per-request state and a response cannot be replayed;
//   - registration requires recent authentication (the same proof MFA enrolment
//     takes), so a hijacked session cannot quietly add an attacker's key;
//   - the signature counter is checked before verification and a regression is
//     a typed error, not a swallowed `verified: false`;
//   - a successful assertion goes through `finishLogin`, the same door as a
//     password, so it gets the same session, the same new-device mail and the
//     same event.
//
// A passkey with user verification is two factors in one authenticator, so a
// passkey login never asks for TOTP.

import {
  type AuthenticationResponseJSON,
  type AuthenticatorTransport,
  generateAuthenticationOptions,
  generateRegistrationOptions,
  type PublicKeyCredentialCreationOptionsJSON,
  type PublicKeyCredentialRequestOptionsJSON,
  type RegistrationResponseJSON,
  verifyAuthenticationResponse,
  verifyRegistrationResponse,
} from '@simplewebauthn/server';
import { decodeClientDataJSON, isoBase64URL, parseAuthenticatorData } from '@simplewebauthn/server/helpers';

import { type Credentials, createCredentials } from './credentials.ts';
import { IdentityError } from './errors.ts';
import { recordEvent } from './events.ts';
import { createMailer, type Mailer } from './mail.ts';
import { createPgRateLimiter, limiterKey, type RateLimiter } from './ratelimit.ts';
import { DEFAULT_REAUTH_WINDOW_MS, type EnrolmentProof, requireRecentAuth } from './reauth.ts';
import { finishLogin } from './session-login.ts';
import { sha256 } from './tokens.ts';
import type { Clock, IdentityConfig, Logger, MailSender, SessionMeta, SqlExecutor, UserId } from './types.ts';

export type { AuthenticationResponseJSON, RegistrationResponseJSON } from '@simplewebauthn/server';

/** The relying party — this application, as the browser identifies it. */
export interface RelyingParty {
  /** The RP ID: a registrable domain (`example.com`); credentials are scoped to
   *  it and its subdomains. */
  id: string;
  /** Shown by the authenticator's UI. */
  name: string;
  /** Every origin a ceremony may be completed from (`https://app.example.com`). */
  origin: string | string[];
}

export interface PasskeysOptions {
  db: SqlExecutor;
  config: IdentityConfig;
  mail: MailSender;
  rp: RelyingParty;
  clock?: Clock;
  logger?: Logger;
  /** How long a challenge stays redeemable. Default five minutes. */
  challengeTtlMs?: number;
  /**
   * Whether the authenticator must verify the user (PIN, biometric). Default
   * `'preferred'` for the ceremony and **required at verification** — a passkey
   * that stands in for password + second factor must prove a person, not just
   * presence. Set `'discouraged'` to accept presence-only security keys.
   */
  userVerification?: 'required' | 'preferred' | 'discouraged';
  /** In front of `authenticateFinish`, keyed by ip. Omit for the shipped
   *  Postgres limiter over `db`; `null` disables. */
  rateLimiter?: RateLimiter | null;
}

export interface PasskeySummary {
  id: string;
  name: string;
  transports: string[];
  aaguid: string | null;
  deviceType: string | null;
  backedUp: boolean;
  createdAt: Date;
  lastUsedAt: Date | null;
}

export type PasskeyLoginResult = { kind: 'session'; token: string; expiresAt: Date } | { kind: 'failed' };

export interface Passkeys {
  /**
   * Begin registration for a signed-in user. Requires recent authentication —
   * the password, or a session that authenticated inside `reauthWindowMs`.
   * Hand `options` to `navigator.credentials.create({ publicKey })` (via
   * `@simplewebauthn/browser`'s `startRegistration`).
   */
  registerBegin(userId: UserId, proof: EnrolmentProof, now?: Date): Promise<PublicKeyCredentialCreationOptionsJSON>;
  /** Finish registration with the browser's response. Records
   *  `passkey_registered`. */
  registerFinish(
    userId: UserId,
    response: RegistrationResponseJSON,
    opts?: { name?: string; meta?: SessionMeta; now?: Date },
  ): Promise<PasskeySummary>;
  /**
   * Begin a login. With `userId`, `allowCredentials` names that user's passkeys
   * (a second-step flow); without, the browser offers discoverable credentials
   * (usernameless / autofill). Hand `options` to `navigator.credentials.get`.
   */
  authenticateBegin(opts?: { userId?: UserId; now?: Date }): Promise<PublicKeyCredentialRequestOptionsJSON>;
  /** Finish a login. A verified assertion mints a session through
   *  `finishLogin` (event `login_succeeded`, `via: 'passkey'`). */
  authenticateFinish(response: AuthenticationResponseJSON, meta?: SessionMeta, now?: Date): Promise<PasskeyLoginResult>;
  list(userId: UserId): Promise<PasskeySummary[]>;
  rename(userId: UserId, credentialId: string, name: string): Promise<void>;
  /** Records `passkey_removed`. */
  remove(userId: UserId, credentialId: string, meta?: SessionMeta, now?: Date): Promise<void>;
  /** Housekeeping: prune expired challenges. `sweepExpired` does this too. */
  sweepChallenges(now?: Date): Promise<number>;
}

const DEFAULT_CHALLENGE_TTL_MS = 5 * 60 * 1000;

interface PasskeyRow {
  id: string;
  user_id: string;
  public_key: Buffer;
  counter: string;
  transports: string[];
  aaguid: string | null;
  name: string;
  device_type: string | null;
  backed_up: boolean;
  created_at: Date;
  last_used_at: Date | null;
}

const summarise = (r: PasskeyRow): PasskeySummary => ({
  id: r.id,
  name: r.name,
  transports: r.transports,
  aaguid: r.aaguid,
  deviceType: r.device_type,
  backedUp: r.backed_up,
  createdAt: r.created_at,
  lastUsedAt: r.last_used_at,
});

export function createPasskeys(opts: PasskeysOptions): Passkeys {
  const { db, config, rp } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  const credentials: Credentials = createCredentials(config);
  const mailer: Mailer = createMailer(config, opts.mail);
  const ttlMs = opts.challengeTtlMs ?? DEFAULT_CHALLENGE_TTL_MS;
  const userVerification = opts.userVerification ?? 'preferred';
  const requireUV = userVerification !== 'discouraged';
  const reauthWindowMs = config.reauthWindowMs ?? DEFAULT_REAUTH_WINDOW_MS;
  const origins = Array.isArray(rp.origin) ? rp.origin : [rp.origin];

  const rateLimiter = opts.rateLimiter === undefined ? createPgRateLimiter({ db, clock }) : opts.rateLimiter;
  const limit = async (key: string): Promise<void> => {
    if (!rateLimiter) return;
    const decision = await rateLimiter.hit(key);
    if (!decision.allowed) throw new IdentityError({ code: 'rate_limited', retryAfterMs: decision.retryAfterMs, key });
  };

  const userRow = async (userId: UserId) => {
    const rows = await db.query<{ id: string; email: string; deletion_requested_at: Date | null }>(
      'SELECT id, email, deletion_requested_at FROM identity.users WHERE id = $1',
      [userId],
    );
    return rows[0] ?? null;
  };

  const listRows = async (userId: UserId): Promise<PasskeyRow[]> =>
    db.query<PasskeyRow>(
      `SELECT id, user_id, public_key, counter::text AS counter, transports, aaguid, name, device_type, backed_up,
              created_at, last_used_at
         FROM identity.passkeys WHERE user_id = $1 ORDER BY created_at`,
      [userId],
    );

  const storeChallenge = async (
    challenge: string,
    purpose: 'register' | 'authenticate',
    userId: UserId | null,
    now: Date,
  ): Promise<void> => {
    await db.query(
      `INSERT INTO identity.webauthn_challenges (challenge_hash, purpose, user_id, expires_at)
       VALUES ($1, $2, $3, $4)`,
      [sha256(challenge), purpose, userId, new Date(now.getTime() + ttlMs)],
    );
  };

  /**
   * Spend the challenge the browser echoed back in clientDataJSON. Deleted
   * first, then checked, so a response can be replayed exactly zero times —
   * even a failing one burns it. Returns the challenge string for
   * `expectedChallenge`.
   */
  const spendChallenge = async (
    clientDataJSON: string,
    purpose: 'register' | 'authenticate',
    userId: UserId | null,
    now: Date,
  ): Promise<string> => {
    let challenge: string;
    try {
      challenge = decodeClientDataJSON(clientDataJSON).challenge;
    } catch {
      throw new IdentityError({ code: 'invalid_challenge', reason: 'unknown' });
    }
    const rows = await db.query<{ purpose: string; user_id: string | null; expires_at: Date }>(
      'DELETE FROM identity.webauthn_challenges WHERE challenge_hash = $1 RETURNING purpose, user_id, expires_at',
      [sha256(challenge)],
    );
    const row = rows[0];
    if (!row) throw new IdentityError({ code: 'invalid_challenge', reason: 'unknown' });
    if (row.expires_at <= now) throw new IdentityError({ code: 'invalid_challenge', reason: 'expired' });
    if (row.purpose !== purpose) throw new IdentityError({ code: 'invalid_challenge', reason: 'purpose' });
    // A registration challenge is bound to its user; a login challenge is bound
    // only when begun for a named user.
    if (row.user_id !== null && row.user_id !== userId) {
      throw new IdentityError({ code: 'invalid_challenge', reason: 'user' });
    }
    return challenge;
  };

  const fail = (reason: string): never => {
    throw new IdentityError({ code: 'passkey_verification_failed', reason });
  };

  return {
    async registerBegin(userId, proof, now = clock()) {
      await requireRecentAuth(db, credentials, userId, proof, now, reauthWindowMs);
      const user = await userRow(userId);
      if (!user) throw new IdentityError({ code: 'not_found', what: `user ${userId}` });
      const existing = await listRows(userId);
      const options = await generateRegistrationOptions({
        rpName: rp.name,
        rpID: rp.id,
        // The user handle: our opaque id, so the authenticator's record carries
        // no PII and a renamed email does not orphan the credential.
        userID: new TextEncoder().encode(userId),
        userName: user.email,
        attestationType: 'none',
        // Refuse to re-register an authenticator that is already on the account.
        excludeCredentials: existing.map((r) => ({
          id: r.id,
          transports: r.transports as AuthenticatorTransportFuture[],
        })),
        authenticatorSelection: { residentKey: 'preferred', userVerification },
        timeout: ttlMs,
      });
      await storeChallenge(options.challenge, 'register', userId, now);
      return options;
    },

    async registerFinish(userId, response, o = {}) {
      const now = o.now ?? clock();
      const expectedChallenge = await spendChallenge(response.response.clientDataJSON, 'register', userId, now);
      let verification: Awaited<ReturnType<typeof verifyRegistrationResponse>>;
      try {
        verification = await verifyRegistrationResponse({
          response,
          expectedChallenge,
          expectedOrigin: origins,
          expectedRPID: rp.id,
          requireUserVerification: requireUV,
        });
      } catch (e) {
        return fail(e instanceof Error ? e.message : String(e));
      }
      if (!verification.verified) return fail('registration response did not verify');
      const info = verification.registrationInfo;
      const name = o.name?.trim() || `Passkey ${now.toISOString().slice(0, 10)}`;
      const rows = await db.query<PasskeyRow>(
        `INSERT INTO identity.passkeys
           (id, user_id, public_key, counter, transports, aaguid, name, device_type, backed_up, created_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (id) DO NOTHING
         RETURNING id, user_id, public_key, counter::text AS counter, transports, aaguid, name, device_type,
                   backed_up, created_at, last_used_at`,
        [
          info.credential.id,
          userId,
          Buffer.from(info.credential.publicKey),
          info.credential.counter,
          info.credential.transports ?? [],
          info.aaguid,
          name,
          info.credentialDeviceType,
          info.credentialBackedUp,
          now,
        ],
      );
      const row = rows[0];
      if (!row) return fail('credential already registered');
      await recordEvent(db, {
        userId,
        kind: 'passkey_registered',
        meta: o.meta,
        at: now,
        metadata: { credentialId: row.id, name: row.name, aaguid: row.aaguid, deviceType: row.device_type },
      });
      return summarise(row);
    },

    async authenticateBegin(o = {}) {
      const now = o.now ?? clock();
      const allow = o.userId ? await listRows(o.userId) : [];
      const options = await generateAuthenticationOptions({
        rpID: rp.id,
        userVerification,
        timeout: ttlMs,
        allowCredentials: allow.map((r) => ({ id: r.id, transports: r.transports as AuthenticatorTransportFuture[] })),
      });
      await storeChallenge(options.challenge, 'authenticate', o.userId ?? null, now);
      return options;
    },

    async authenticateFinish(response, meta = {}, now = clock()) {
      await limit(limiterKey('passkey_auth', meta.ipAddress ?? 'anon'));
      const rows = await db.query<PasskeyRow>(
        `SELECT id, user_id, public_key, counter::text AS counter, transports, aaguid, name, device_type, backed_up,
                created_at, last_used_at
           FROM identity.passkeys WHERE id = $1`,
        [response.id],
      );
      const cred = rows[0];
      // Unknown credential: still spend the challenge (if any), and say nothing
      // more specific than "failed".
      const expectedChallenge = await spendChallenge(
        response.response.clientDataJSON,
        'authenticate',
        cred?.user_id ?? null,
        now,
      );
      if (!cred) return { kind: 'failed' };
      const stored = Number(cred.counter);
      const failed = (reason: string) =>
        recordEvent(db, {
          userId: cred.user_id,
          kind: 'login_failed',
          meta,
          at: now,
          metadata: { reason, credentialId: cred.id },
        });

      // Counter first, before the signature: a regression is its own finding
      // (a cloned authenticator), not one more "did not verify".
      let presented: number;
      try {
        presented = parseAuthenticatorData(isoBase64URL.toBuffer(response.response.authenticatorData)).counter;
      } catch {
        await failed('passkey_malformed');
        return { kind: 'failed' };
      }
      if ((stored > 0 || presented > 0) && presented <= stored) {
        await failed('passkey_counter_regression');
        throw new IdentityError({ code: 'passkey_counter_regression', credentialId: cred.id, stored, presented });
      }

      let verified = false;
      let newCounter = stored;
      try {
        const v = await verifyAuthenticationResponse({
          response,
          expectedChallenge,
          expectedOrigin: origins,
          expectedRPID: rp.id,
          requireUserVerification: requireUV,
          credential: {
            id: cred.id,
            publicKey: new Uint8Array(cred.public_key),
            counter: stored,
            transports: cred.transports as AuthenticatorTransportFuture[],
          },
        });
        verified = v.verified;
        newCounter = v.authenticationInfo.newCounter;
      } catch (e) {
        opts.logger?.debug(`passkey assertion rejected: ${e instanceof Error ? e.message : String(e)}`);
      }
      if (!verified) {
        await failed('passkey_verification_failed');
        return { kind: 'failed' };
      }

      const user = await userRow(cred.user_id);
      if (!user || user.deletion_requested_at) {
        await failed('deletion_pending');
        return { kind: 'failed' };
      }
      await db.query('UPDATE identity.passkeys SET counter = $2, last_used_at = $3 WHERE id = $1', [
        cred.id,
        newCounter,
        now,
      ]);
      return finishLogin(db, mailer, user.id, user.email, meta, now, opts.logger, 'passkey');
    },

    async list(userId) {
      return (await listRows(userId)).map(summarise);
    },

    async rename(userId, credentialId, name) {
      const trimmed = name.trim();
      if (!trimmed) throw new IdentityError({ code: 'invalid_config', reason: 'passkeys: name must not be empty' });
      const rows = await db.query<{ id: string }>(
        'UPDATE identity.passkeys SET name = $3 WHERE id = $1 AND user_id = $2 RETURNING id',
        [credentialId, userId, trimmed],
      );
      if (!rows[0]) throw new IdentityError({ code: 'not_found', what: `passkey ${credentialId}` });
    },

    async remove(userId, credentialId, meta = {}, now = clock()) {
      const rows = await db.query<{ id: string; name: string }>(
        'DELETE FROM identity.passkeys WHERE id = $1 AND user_id = $2 RETURNING id, name',
        [credentialId, userId],
      );
      const row = rows[0];
      if (!row) throw new IdentityError({ code: 'not_found', what: `passkey ${credentialId}` });
      await recordEvent(db, {
        userId,
        kind: 'passkey_removed',
        meta,
        at: now,
        metadata: { credentialId: row.id, name: row.name },
      });
    },

    async sweepChallenges(now = clock()) {
      const rows = await db.query<{ challenge_hash: string }>(
        'DELETE FROM identity.webauthn_challenges WHERE expires_at <= $1 RETURNING challenge_hash',
        [now],
      );
      return rows.length;
    },
  };
}
