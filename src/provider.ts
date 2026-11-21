// Being the issuer.
//
// src/oidc.ts is the client half: sign in against Google, Apple, Keycloak. This
// is the other direction, so that one app in a family can hold the accounts and
// the rest can sign in against it. The protocol is the same one, which is the
// point: the consuming app uses the client we already ship, and there is no
// bespoke handoff to review once per app.
//
// What this deliberately is NOT:
//
//   No refresh tokens for a web app. A consuming app exchanges the code, reads
//   the ID token and mints its OWN session; nothing there needs a credential
//   that outlives that exchange. (A phone or desktop app is the exception, and
//   an opt-in one: see "A sign-in that renews" below.)
//   No implicit or hybrid flow. Both hand tokens to a browser through a URL.
//   No consent screen, and therefore no third-party clients: a client marked
//   first-party skips consent because asking somebody to authorise us to be
//   ourselves is theatre, and anything else is REFUSED rather than silently
//   consented on a user's behalf.
//   No dynamic registration. Clients are rows an operator writes.
//
// PKCE is required of every client, confidential ones included. A confidential
// client's secret protects the token request; PKCE protects the code itself,
// and the code is the part that travels through a browser.
//
// A sign-in that renews (sql/012_oidc_refresh.sql)
//
// A phone app has no server to keep a session on, and a five-minute access
// token would send its owner back through the browser every five minutes. So a
// client an operator has marked `allowRefresh`, on an issuer created with
// `refreshTokens`, is handed a refresh token when the authorization asked for
// `offline_access`. Everything about it assumes it will be stolen one day:
//
//   Rotation. Every refresh retires the presented token and returns a new one,
//   so a token is good for one use and a family has exactly one current token.
//   Reuse detection. A retired token presented again means two parties hold the
//   chain, and nothing here can tell which is the thief. The whole family is
//   revoked, with its access tokens, and the person signs in again.
//   The benign race. A response lost on a train is not theft. For a few seconds
//   after a rotation (`reuseGraceMs`), and only while the successor has not
//   itself been used, presenting the retired token again returns the SAME
//   successor. The successor is not kept in the clear to do that: it is sealed
//   under a key derived from the retired token's plaintext, which the database
//   never holds.
//   Two clocks. An idle expiry, moved by each refresh, and an absolute one
//   from the sign-in that nothing moves.
//   Bound to its client. A token presented under another client's id is
//   refused and nothing else happens: a client id is public, so the wrong one
//   is evidence of a misconfigured build, not of theft, and a thief would send
//   the right one.

import { createCipheriv, createDecipheriv, createHash, createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

import * as jose from 'jose';

import { IdentityError } from './errors.ts';
import { recordEvent } from './events.ts';
import { revokeFamilies } from './refresh-families.ts';
import type { Clock, SessionMeta, SqlExecutor } from './types.ts';

/** How long an authorization code lives. Long enough for a redirect and a
 *  server-to-server exchange, short enough that a leaked one is usually dead:
 *  the spec says ten minutes maximum and recommends one. */
const CODE_TTL_MS = 60_000;
/** The access token exists to serve `userinfo`, which a consuming app calls
 *  once, immediately. */
const ACCESS_TTL_MS = 5 * 60_000;
const ID_TOKEN_TTL_S = 300;
const ALG = 'ES256';

const DAY_MS = 24 * 60 * 60 * 1000;
/** Ninety days from the sign-in, whatever happens in between. Long enough that
 *  somebody who opens the app most weeks signs in about four times a year;
 *  short enough that a forgotten phone in a drawer stops being a credential. */
export const REFRESH_ABSOLUTE_TTL_MS = 90 * DAY_MS;
/** Thirty days without a refresh ends the sign-in: an app nobody has opened
 *  for a month is one whose owner will not be surprised to sign in again, and
 *  it bounds how long a token lifted from an abandoned device stays useful. */
export const REFRESH_IDLE_TTL_MS = 30 * DAY_MS;
/** Ten seconds: longer than a retry after a dropped response, far shorter than
 *  the five minutes between an app's refreshes. */
export const REFRESH_REUSE_GRACE_MS = 10_000;
/** A grace longer than this is not a grace, it is two valid tokens. */
const MAX_REUSE_GRACE_MS = 60_000;
const MAX_DEVICE_LABEL = 120;
const OFFLINE_ACCESS = 'offline_access';
const UUID = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

const sha256 = (value: string): string => createHash('sha256').update(value).digest('base64url');

/** Constant-time compare of two secrets of the same shape. */
function sameSecret(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

// The successor of a rotated refresh token, sealed so that only somebody
// holding the token it replaced can read it. The key is an HMAC of that token's
// plaintext; what the database stores of the token is its sha256, and one does
// not give the other. AES-256-GCM, a fresh nonce per seal.
const sealKey = (parent: string): Buffer =>
  createHmac('sha256', 'identity-kit/refresh-successor/v1').update(parent).digest();

function seal(parent: string, successor: string): string {
  const iv = randomBytes(12);
  const cipher = createCipheriv('aes-256-gcm', sealKey(parent), iv);
  const body = Buffer.concat([cipher.update(successor, 'utf8'), cipher.final()]);
  return Buffer.concat([iv, cipher.getAuthTag(), body]).toString('base64url');
}

/** Null when it does not open: a row somebody has written to is not a reason
 *  to hand out a token. */
function unseal(parent: string, sealed: string): string | null {
  try {
    const raw = Buffer.from(sealed, 'base64url');
    const decipher = createDecipheriv('aes-256-gcm', sealKey(parent), raw.subarray(0, 12));
    decipher.setAuthTag(raw.subarray(12, 28));
    return Buffer.concat([decipher.update(raw.subarray(28)), decipher.final()]).toString('utf8');
  } catch {
    return null;
  }
}

/** What an app called the device, made safe to show back: no control
 *  characters, bounded, and null rather than empty. */
function deviceLabelOf(raw: string | undefined): string | null {
  const clean = (raw ?? '')
    .replace(/\p{Cc}+/gu, ' ')
    .trim()
    .slice(0, MAX_DEVICE_LABEL)
    .trim();
  return clean === '' ? null : clean;
}

export type { FamilyRevocationReason } from './refresh-families.ts';

export interface ClientInput {
  clientId: string;
  name: string;
  /** Omit for a public client, which is then PKCE-only. */
  secret?: string;
  redirectUris: readonly string[];
  firstParty?: boolean;
  /** Let this client hold refresh tokens (sql/012_oidc_refresh.sql). Default
   *  false. Only a first-party client may, and only on an issuer created with
   *  `refreshTokens`. Registering a client again WITHOUT it revokes every
   *  refresh family the client holds. */
  allowRefresh?: boolean;
}

export interface ClientRecord {
  clientId: string;
  name: string;
  confidential: boolean;
  redirectUris: readonly string[];
  firstParty: boolean;
  allowRefresh: boolean;
  disabledAt: Date | null;
}

export interface AuthorizeInput {
  clientId: string;
  redirectUri: string;
  /** The user this code is for. The HOST resolves its own session and passes
   *  the id: the provider never reads a cookie, because whose session it is
   *  is the host's question, not the protocol's. */
  userId: string;
  scope?: string;
  state?: string;
  nonce?: string;
  codeChallenge: string;
  codeChallengeMethod?: string;
}

export interface AuthorizeResult {
  code: string;
  /** Where to send the browser, with `code` and `state` already attached. */
  redirectTo: string;
}

/** The token request, both grants. A route can pass the form's fields straight
 *  through: which ones matter is decided by `grantType`. */
export interface TokenInput {
  grantType: string;
  clientId: string;
  clientSecret?: string;
  /** `authorization_code`: the code, the redirect_uri it was minted for, and
   *  the PKCE verifier. All three are required for that grant. */
  code?: string;
  redirectUri?: string;
  codeVerifier?: string;
  /** `authorization_code`, for a client with `allowRefresh`: what to call this
   *  device in the person's list of devices ("Ada's iPhone"). Not an OAuth
   *  parameter; the app sends it as an extra form field. */
  deviceLabel?: string;
  /** `refresh_token`: the token to rotate. */
  refreshToken?: string;
}

export interface RefreshInput {
  refreshToken: string;
  clientId: string;
  clientSecret?: string;
}

export interface TokenResult {
  idToken: string;
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  scope: string;
  /** Present only for a client with `allowRefresh` whose authorization asked
   *  for `offline_access`. Shown once; replaces any refresh token the app
   *  already held. */
  refreshToken?: string;
  /** Present with `refreshToken`: the id of this sign-in in `deviceSessions`,
   *  so an app can mark "this device" in the list. Not a credential. */
  sessionId?: string;
}

export interface UserClaims {
  sub: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
  /** Present when the access token belongs to a refresh family: its id in
   *  `deviceSessions`. */
  sessionId?: string;
}

/** RFC 7009. */
export interface RevokeInput {
  /** A refresh token (the whole sign-in goes) or an access token (only it). */
  token: string;
  clientId: string;
  clientSecret?: string;
}

/** One sign-in on one device, as a person sees it in a list of their devices. */
export interface DeviceSession {
  /** The family id. Pass it to `revokeDeviceSession`. Not a credential. */
  id: string;
  clientId: string;
  clientName: string;
  /** What the app called the device at sign-in, if it said. */
  label: string | null;
  scope: string;
  createdAt: Date;
  /** The last refresh (or the sign-in, if there has been none). */
  lastUsedAt: Date;
  /** When it ends if nothing refreshes it: the sooner of the idle and the
   *  absolute expiry. */
  expiresAt: Date;
}

export interface RefreshOptions {
  /** How long a sign-in lasts from the code exchange, however often it is
   *  refreshed. Default ninety days. */
  absoluteTtlMs?: number;
  /** How long a sign-in survives without a refresh. Default thirty days; never
   *  longer than `absoluteTtlMs`. */
  idleTtlMs?: number;
  /**
   * For how long after a rotation the retired token may be presented again and
   * be answered with the same successor, instead of revoking the family.
   * Default ten seconds, at most sixty. `0` is strict: any second presentation
   * revokes, including a retry after a lost response and two requests racing.
   */
  reuseGraceMs?: number;
}

export interface ProviderOptions {
  db: SqlExecutor;
  /** The issuer URL, exactly as it will appear in `iss` and in discovery. */
  issuer: string;
  clock?: Clock;
  /** Where the routes live under the issuer. Defaults to the conventional
   *  paths; a host that mounts them elsewhere says so here. */
  paths?: Partial<Paths>;
  /**
   * Turn on refresh tokens (sql/012_oidc_refresh.sql) for the clients
   * registered with `allowRefresh`. `true` takes the defaults. Omitted, the
   * issuer is exactly what it was: no client may be given `allowRefresh`, the
   * refresh grant is an unsupported grant_type, and discovery advertises
   * neither it nor `offline_access` nor the revocation endpoint.
   */
  refreshTokens?: boolean | RefreshOptions;
}

export interface Paths {
  authorization: string;
  token: string;
  jwks: string;
  userinfo: string;
  /** RFC 7009. Advertised only when `refreshTokens` is on. */
  revocation: string;
}

const DEFAULT_PATHS: Paths = {
  authorization: '/oidc/authorize',
  token: '/oidc/token',
  jwks: '/oidc/jwks',
  userinfo: '/oidc/userinfo',
  revocation: '/oidc/revoke',
};

export interface OidcIssuer {
  registerClient(input: ClientInput): Promise<ClientRecord>;
  clients(): Promise<ClientRecord[]>;
  /** Mint a code for an already-authenticated user. */
  authorize(input: AuthorizeInput): Promise<AuthorizeResult>;
  /** Redeem it. Single-use, PKCE-checked, bound to client and redirect_uri.
   *  With `grantType: 'refresh_token'` this is `refresh`. */
  token(input: TokenInput): Promise<TokenResult>;
  /**
   * Rotate a refresh token: the presented one is retired and a new one comes
   * back with a fresh access token and ID token. Presenting a retired token
   * revokes its whole family (see `RefreshOptions.reuseGraceMs` for the one
   * exception). Every refusal is `invalid_grant`, and none says which.
   */
  refresh(input: RefreshInput): Promise<TokenResult>;
  /**
   * RFC 7009. A refresh token, current or retired, ends its whole family and
   * the family's access tokens; an access token ends only itself. Resolves
   * whether or not the token was known, as the RFC asks, and does nothing to a
   * token that belongs to another client.
   */
  revoke(input: RevokeInput, meta?: SessionMeta): Promise<void>;
  /** A person's live sign-ins on phone and desktop apps, most recent first. */
  deviceSessions(userId: string): Promise<DeviceSession[]>;
  /** End one of them. False when it is not theirs, or already over. */
  revokeDeviceSession(userId: string, sessionId: string, meta?: SessionMeta): Promise<boolean>;
  /** End all of them, optionally sparing the one the person is holding.
   *  Returns how many ended. The core calls the same thing on a password
   *  change, a reset, an email change, a deletion request and
   *  `revokeAllSessions`; this is for a host with a rule of its own, such as
   *  suspending an account. */
  revokeDeviceSessions(userId: string, opts?: { exceptSessionId?: string }, meta?: SessionMeta): Promise<number>;
  /** The claims behind an access token, for `userinfo`. */
  userinfo(accessToken: string): Promise<UserClaims>;
  discovery(): Record<string, unknown>;
  jwks(): Promise<{ keys: jose.JWK[] }>;
  /** Retire the active key and start signing with a new one. The old key keeps
   *  appearing in JWKS until `sweep` drops it, so tokens already out there
   *  still verify. */
  rotateKey(): Promise<string>;
  /** Delete expired codes and access tokens, keys retired long enough that
   *  nothing they signed can still be alive, and refresh families that are
   *  revoked, past their absolute expiry, or idle past their idle expiry. */
  sweep(): Promise<{ codes: number; accessTokens: number; keys: number; refreshFamilies: number }>;
}

interface ClientRow {
  client_id: string;
  name: string;
  secret_hash: string | null;
  redirect_uris: string[];
  first_party: boolean;
  allow_refresh: boolean;
  disabled_at: Date | null;
}

interface AccountRow {
  id: string;
  email: string;
  email_verified_at: Date | null;
  name: string | null;
}

interface RefreshSettings {
  absoluteTtlMs: number;
  idleTtlMs: number;
  reuseGraceMs: number;
}

function refreshSettings(option: boolean | RefreshOptions | undefined): RefreshSettings | null {
  if (option === undefined || option === false) return null;
  const given = option === true ? {} : option;
  const settings: RefreshSettings = {
    absoluteTtlMs: given.absoluteTtlMs ?? REFRESH_ABSOLUTE_TTL_MS,
    idleTtlMs: given.idleTtlMs ?? Math.min(REFRESH_IDLE_TTL_MS, given.absoluteTtlMs ?? REFRESH_IDLE_TTL_MS),
    reuseGraceMs: given.reuseGraceMs ?? REFRESH_REUSE_GRACE_MS,
  };
  const bad = (reason: string): never => {
    throw new IdentityError({ code: 'invalid_config', reason: `refreshTokens: ${reason}` });
  };
  if (!(Number.isFinite(settings.absoluteTtlMs) && settings.absoluteTtlMs > 0))
    bad('absoluteTtlMs must be a positive number of milliseconds');
  if (!(Number.isFinite(settings.idleTtlMs) && settings.idleTtlMs > 0))
    bad('idleTtlMs must be a positive number of milliseconds');
  if (settings.idleTtlMs > settings.absoluteTtlMs) bad('idleTtlMs cannot be longer than absoluteTtlMs');
  if (!(settings.reuseGraceMs >= 0 && settings.reuseGraceMs <= MAX_REUSE_GRACE_MS))
    bad(`reuseGraceMs must be between 0 and ${MAX_REUSE_GRACE_MS}`);
  return settings;
}

const toClient = (r: ClientRow): ClientRecord => ({
  clientId: r.client_id,
  name: r.name,
  confidential: r.secret_hash !== null,
  redirectUris: r.redirect_uris,
  firstParty: r.first_party,
  allowRefresh: r.allow_refresh,
  disabledAt: r.disabled_at,
});

const CLIENT_COLUMNS = 'client_id, name, secret_hash, redirect_uris, first_party, allow_refresh, disabled_at';
/** One message for every refusal of a refresh token: telling a caller WHICH is
 *  telling an attacker which. */
const REFRESH_REFUSED = 'the refresh token is unknown, expired, revoked, or was not issued to this client';

export function createOidcIssuer(opts: ProviderOptions): OidcIssuer {
  const { db } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  const issuer = opts.issuer.replace(/\/$/, '');
  const paths: Paths = { ...DEFAULT_PATHS, ...opts.paths };
  /** Null when the issuer was not created with `refreshTokens`. */
  const refresh = refreshSettings(opts.refreshTokens);
  const url = (path: string): string => `${issuer}${path}`;

  /** Every refusal here is one of OAuth's, so a route handler can answer in the
   *  spec's terms without translating. */
  const refuse = (code: 'invalid_request' | 'invalid_grant' | 'invalid_client', reason: string): never => {
    throw new IdentityError({ code, reason });
  };

  async function clientOf(clientId: string): Promise<ClientRow> {
    const rows = await db.query<ClientRow>(
      `SELECT ${CLIENT_COLUMNS}
         FROM identity.oidc_clients WHERE client_id = $1`,
      [clientId],
    );
    const row = rows[0];
    if (!row || row.disabled_at) refuse('invalid_request', 'unknown client');
    return row as ClientRow;
  }

  /** The client, having proved it is the client. A public one has nothing to
   *  prove here: PKCE, and a refresh token's own secrecy, stand in. */
  async function authenticatedClient(clientId: string, clientSecret: string | undefined): Promise<ClientRow> {
    const client = await clientOf(clientId);
    if (client.secret_hash) {
      if (!clientSecret || !sameSecret(sha256(clientSecret), client.secret_hash)) {
        refuse('invalid_client', 'client authentication failed');
      }
    }
    return client;
  }

  /** The signing key, made on first use. */
  async function activeKey(): Promise<{ kid: string; privateJwk: jose.JWK }> {
    const rows = await db.query<{ kid: string; private_jwk: jose.JWK }>(
      `SELECT kid, private_jwk FROM identity.oidc_keys
        WHERE retired_at IS NULL ORDER BY created_at DESC LIMIT 1`,
    );
    const existing = rows[0];
    if (existing) return { kid: existing.kid, privateJwk: existing.private_jwk };

    const { privateKey, publicKey } = await jose.generateKeyPair(ALG, { extractable: true });
    const privateJwk = await jose.exportJWK(privateKey);
    const publicJwk = await jose.exportJWK(publicKey);
    const kid = randomBytes(8).toString('hex');
    // ON CONFLICT so two processes starting at once do not both insert; the
    // loser reads the winner's key on the next call rather than signing with a
    // key nobody can verify against.
    await db.query(
      `INSERT INTO identity.oidc_keys (kid, alg, private_jwk, public_jwk)
       VALUES ($1, $2, $3::jsonb, $4::jsonb) ON CONFLICT (kid) DO NOTHING`,
      [
        kid,
        ALG,
        JSON.stringify({ ...privateJwk, kid, alg: ALG }),
        JSON.stringify({ ...publicJwk, kid, alg: ALG, use: 'sig' }),
      ],
    );
    return { kid, privateJwk: { ...privateJwk, kid, alg: ALG } };
  }

  async function signIdToken(account: AccountRow, clientId: string, now: Date, nonce: string | null): Promise<string> {
    const { kid, privateJwk } = await activeKey();
    const key = await jose.importJWK(privateJwk, ALG);
    return new jose.SignJWT({
      email: account.email,
      email_verified: account.email_verified_at !== null,
      ...(account.name ? { name: account.name } : {}),
      ...(nonce ? { nonce } : {}),
    })
      .setProtectedHeader({ alg: ALG, kid, typ: 'JWT' })
      .setIssuer(issuer)
      .setSubject(account.id)
      .setAudience(clientId)
      .setIssuedAt(Math.floor(now.getTime() / 1000))
      .setExpirationTime(Math.floor(now.getTime() / 1000) + ID_TOKEN_TTL_S)
      .sign(key);
  }

  /** An access token for a family. It never outlives the family's absolute
   *  expiry, and it is deleted the moment the family is revoked. */
  async function familyAccessToken(
    tx: SqlExecutor,
    family: { id: string; clientId: string; userId: string; scope: string; absoluteExpiresAt: Date },
    now: Date,
  ): Promise<{ accessToken: string; expiresIn: number }> {
    const accessToken = randomBytes(32).toString('base64url');
    const expiresAt = new Date(Math.min(now.getTime() + ACCESS_TTL_MS, family.absoluteExpiresAt.getTime()));
    await tx.query(
      `INSERT INTO identity.oidc_access_tokens (token_hash, client_id, user_id, scope, expires_at, family_id)
       VALUES ($1, $2, $3, $4, $5, $6)`,
      [sha256(accessToken), family.clientId, family.userId, family.scope, expiresAt, family.id],
    );
    return { accessToken, expiresIn: Math.floor((expiresAt.getTime() - now.getTime()) / 1000) };
  }

  type RefreshOutcome =
    | { kind: 'refused' }
    | {
        kind: 'rotated';
        refreshToken: string;
        accessToken: string;
        expiresIn: number;
        scope: string;
        sessionId: string;
        account: AccountRow;
      };

  /**
   * The refresh grant. One transaction, serialised per family by a row lock on
   * the family, so two requests carrying the same token cannot both rotate it.
   *
   * It RETURNS a refusal rather than throwing one, because a refusal can carry
   * a write (reuse revokes the family) and a throw would roll that write back.
   */
  async function rotate(settings: RefreshSettings, input: RefreshInput): Promise<TokenResult> {
    const client = await authenticatedClient(input.clientId, input.clientSecret);
    if (!input.refreshToken) refuse('invalid_request', 'refresh_token is required');
    const now = clock();
    const presented = input.refreshToken;
    const presentedHash = sha256(presented);

    const outcome = await db.transaction(async (tx): Promise<RefreshOutcome> => {
      const named = await tx.query<{ family_id: string }>(
        `SELECT family_id::text AS family_id FROM identity.oidc_refresh_tokens WHERE token_hash = $1`,
        [presentedHash],
      );
      const familyId = named[0]?.family_id;
      if (!familyId) return { kind: 'refused' };

      // The family row is the lock, taken before any token row is read for a
      // decision: whoever is second sees what the first one wrote.
      const families = await tx.query<{
        client_id: string;
        user_id: string;
        scope: string;
        absolute_expires_at: Date;
        revoked_at: Date | null;
      }>(
        `SELECT client_id, user_id::text AS user_id, scope, absolute_expires_at, revoked_at
           FROM identity.oidc_refresh_families WHERE id = $1 FOR UPDATE`,
        [familyId],
      );
      const tokens = await tx.query<{
        parent_hash: string | null;
        expires_at: Date;
        rotated_at: Date | null;
        sealed_successor: string | null;
      }>(
        `SELECT parent_hash, expires_at, rotated_at, sealed_successor
           FROM identity.oidc_refresh_tokens WHERE token_hash = $1`,
        [presentedHash],
      );
      const family = families[0];
      const token = tokens[0];
      if (!family || !token) return { kind: 'refused' };

      // Another client's token: refused, and nothing is touched. Not rotated,
      // not revoked. See the header.
      if (family.client_id !== client.client_id) return { kind: 'refused' };
      if (family.revoked_at) return { kind: 'refused' };
      // The flag was taken away (registerClient revokes on that path; this is
      // for a row an operator edited by hand).
      if (!client.allow_refresh || !client.first_party) return { kind: 'refused' };

      const bound = {
        id: familyId,
        clientId: family.client_id,
        userId: family.user_id,
        scope: family.scope,
        absoluteExpiresAt: family.absolute_expires_at,
      };
      const users = await tx.query<AccountRow & { deletion_requested_at: Date | null }>(
        `SELECT id, email, email_verified_at, name, deletion_requested_at FROM identity.users WHERE id = $1`,
        [family.user_id],
      );
      const found = users[0];
      // An account that is closing cannot authenticate, and this is
      // authenticating.
      const account = found && !found.deletion_requested_at ? found : null;

      if (token.rotated_at) {
        // A retired token. Inside the grace, and only while its successor is
        // unused (the seal is cleared when the successor is used), this is a
        // retry: answer it with the same successor.
        const inGrace = now.getTime() - token.rotated_at.getTime() <= settings.reuseGraceMs;
        const successor = inGrace && token.sealed_successor ? unseal(presented, token.sealed_successor) : null;
        if (successor && account && now < family.absolute_expires_at) {
          const access = await familyAccessToken(tx, bound, now);
          return {
            kind: 'rotated',
            refreshToken: successor,
            ...access,
            scope: family.scope,
            sessionId: familyId,
            account,
          };
        }
        // Otherwise two parties hold this chain. End it for both.
        await revokeFamilies(tx, { familyId }, 'reuse', now);
        await recordEvent(tx, {
          userId: family.user_id,
          kind: 'refresh_token_reuse',
          at: now,
          metadata: { familyId, clientId: family.client_id },
        });
        return { kind: 'refused' };
      }

      if (now >= token.expires_at || now >= family.absolute_expires_at) return { kind: 'refused' };

      // requestDeletion already revoked; this covers a family that slipped in
      // after it.
      if (!account) {
        await revokeFamilies(tx, { familyId }, 'account', now);
        return { kind: 'refused' };
      }

      const next = randomBytes(32).toString('base64url');
      await tx.query(
        `UPDATE identity.oidc_refresh_tokens SET rotated_at = $2, sealed_successor = $3 WHERE token_hash = $1`,
        [presentedHash, now, settings.reuseGraceMs > 0 ? seal(presented, next) : null],
      );
      await tx.query(
        `INSERT INTO identity.oidc_refresh_tokens (token_hash, family_id, parent_hash, created_at, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [
          sha256(next),
          familyId,
          presentedHash,
          now,
          new Date(Math.min(now.getTime() + settings.idleTtlMs, family.absolute_expires_at.getTime())),
        ],
      );
      // The presented token was itself a successor, and it has now been used:
      // its holder plainly received it, so the retry it was sealed for is over.
      if (token.parent_hash) {
        await tx.query(`UPDATE identity.oidc_refresh_tokens SET sealed_successor = NULL WHERE token_hash = $1`, [
          token.parent_hash,
        ]);
      }
      await tx.query(`UPDATE identity.oidc_refresh_families SET last_used_at = $2 WHERE id = $1`, [familyId, now]);
      const access = await familyAccessToken(tx, bound, now);
      return { kind: 'rotated', refreshToken: next, ...access, scope: family.scope, sessionId: familyId, account };
    });

    if (outcome.kind === 'refused') return refuse('invalid_grant', REFRESH_REFUSED);
    return {
      // No nonce: a nonce binds an ID token to one authorization request, and
      // this is not one.
      idToken: await signIdToken(outcome.account, client.client_id, now, null),
      accessToken: outcome.accessToken,
      tokenType: 'Bearer',
      expiresIn: outcome.expiresIn,
      scope: outcome.scope,
      refreshToken: outcome.refreshToken,
      sessionId: outcome.sessionId,
    };
  }

  /** Record that device sessions ended, when any did. */
  async function ended(
    tx: SqlExecutor,
    userId: string,
    count: number,
    reason: string,
    now: Date,
    meta: SessionMeta,
  ): Promise<void> {
    if (count === 0) return;
    await recordEvent(tx, { userId, kind: 'device_session_revoked', meta, at: now, metadata: { count, reason } });
  }

  return {
    async registerClient(input) {
      if (input.redirectUris.length === 0) refuse('invalid_request', 'a client needs at least one redirect_uri');
      for (const uri of input.redirectUris) {
        let parsed: URL;
        try {
          parsed = new URL(uri);
        } catch {
          return refuse('invalid_request', `redirect_uri is not a URL: ${uri}`);
        }
        // http is allowed only on loopback, the same rule the client half
        // applies to issuers, and for the same reason.
        const loopback =
          parsed.hostname === 'localhost' || parsed.hostname === '127.0.0.1' || parsed.hostname === '[::1]';
        if (parsed.protocol !== 'https:' && !(parsed.protocol === 'http:' && loopback)) {
          refuse('invalid_request', `redirect_uri must be https (or http on loopback): ${uri}`);
        }
        if (parsed.hash) refuse('invalid_request', `redirect_uri must not carry a fragment: ${uri}`);
      }
      const allowRefresh = input.allowRefresh ?? false;
      if (allowRefresh && !refresh) {
        refuse('invalid_request', 'allowRefresh needs an issuer created with refreshTokens');
      }
      if (allowRefresh && !(input.firstParty ?? false)) {
        // A refresh token is standing access, and there is no consent screen on
        // which a third party could be granted that.
        refuse('invalid_request', 'only a first-party client may be given allowRefresh');
      }
      return db.transaction(async (tx) => {
        const rows = await tx.query<ClientRow>(
          `INSERT INTO identity.oidc_clients (client_id, name, secret_hash, redirect_uris, first_party, allow_refresh)
           VALUES ($1, $2, $3, $4::text[], $5, $6)
           ON CONFLICT (client_id) DO UPDATE
             SET name = EXCLUDED.name, secret_hash = EXCLUDED.secret_hash,
                 redirect_uris = EXCLUDED.redirect_uris, first_party = EXCLUDED.first_party,
                 allow_refresh = EXCLUDED.allow_refresh, disabled_at = NULL
           RETURNING ${CLIENT_COLUMNS}`,
          [
            input.clientId,
            input.name,
            input.secret ? sha256(input.secret) : null,
            input.redirectUris,
            input.firstParty ?? false,
            allowRefresh,
          ],
        );
        // Taking the flag away ends what was issued under it, in the same
        // transaction: otherwise turning it back on would revive old sign-ins.
        if (!allowRefresh) await revokeFamilies(tx, { clientId: input.clientId }, 'client', clock());
        return toClient(rows[0] as ClientRow);
      });
    },

    async clients() {
      const rows = await db.query<ClientRow>(
        `SELECT ${CLIENT_COLUMNS}
           FROM identity.oidc_clients ORDER BY created_at`,
      );
      return rows.map(toClient);
    },

    async authorize(input) {
      const client = await clientOf(input.clientId);
      // Exact match, never a prefix: prefix matching on a redirect_uri is how an
      // open redirect becomes an account takeover.
      if (!client.redirect_uris.includes(input.redirectUri)) {
        refuse('invalid_request', 'redirect_uri is not registered for this client');
      }
      if (!client.first_party) {
        // There is no consent screen, so there is no honest way to serve a
        // third party. Refusing is the truthful answer until there is one.
        refuse('invalid_request', 'this client is not first-party, and consent is not implemented');
      }
      if ((input.codeChallengeMethod ?? 'S256') !== 'S256')
        refuse('invalid_request', 'code_challenge_method must be S256');
      if (!input.codeChallenge) refuse('invalid_request', 'PKCE is required');

      const code = randomBytes(32).toString('base64url');
      const now = clock();
      await db.query(
        `INSERT INTO identity.oidc_codes
           (code_hash, client_id, user_id, redirect_uri, code_challenge, code_challenge_method, nonce, scope, expires_at)
         VALUES ($1, $2, $3, $4, $5, 'S256', $6, $7, $8)`,
        [
          sha256(code),
          input.clientId,
          input.userId,
          input.redirectUri,
          input.codeChallenge,
          input.nonce ?? null,
          input.scope ?? 'openid',
          new Date(now.getTime() + CODE_TTL_MS),
        ],
      );
      const redirect = new URL(input.redirectUri);
      redirect.searchParams.set('code', code);
      if (input.state) redirect.searchParams.set('state', input.state);
      return { code, redirectTo: redirect.toString() };
    },

    async token(input) {
      // Only on an issuer that has refresh tokens on. Anywhere else the grant
      // is what it always was: unsupported.
      if (input.grantType === 'refresh_token' && refresh) {
        return rotate(refresh, {
          refreshToken: input.refreshToken ?? '',
          clientId: input.clientId,
          clientSecret: input.clientSecret,
        });
      }
      if (input.grantType !== 'authorization_code') refuse('invalid_request', 'unsupported grant_type');
      const client = await authenticatedClient(input.clientId, input.clientSecret);

      const now = clock();
      // Consume and read in ONE guarded UPDATE. A SELECT then an UPDATE lets two
      // simultaneous redemptions both pass the check, which is the replay this
      // is here to prevent.
      const rows = await db.query<{
        client_id: string;
        user_id: string;
        redirect_uri: string;
        code_challenge: string;
        nonce: string | null;
        scope: string;
        expires_at: Date;
      }>(
        `UPDATE identity.oidc_codes SET consumed_at = $2
          WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > $2
          RETURNING client_id, user_id, redirect_uri, code_challenge, nonce, scope, expires_at`,
        [sha256(input.code ?? ''), now],
      );
      const row = rows[0];
      if (!row) refuse('invalid_grant', 'the code is unknown, already used, or expired');
      const found = row as NonNullable<typeof row>;
      if (found.redirect_uri !== input.redirectUri)
        refuse('invalid_grant', 'redirect_uri does not match the one the code was minted for');
      // PKCE: the verifier must hash to the challenge presented at authorize.
      if (sha256(input.codeVerifier ?? '') !== found.code_challenge)
        refuse('invalid_grant', 'PKCE verification failed');

      const users = await db.query<AccountRow>(
        `SELECT id, email, email_verified_at, name FROM identity.users WHERE id = $1`,
        [found.user_id],
      );
      const user = users[0];
      if (!user) refuse('invalid_grant', 'the account behind this code no longer exists');
      const account = user as NonNullable<typeof user>;

      const idToken = await signIdToken(account, input.clientId, now, found.nonce);

      // A sign-in that renews: only on an issuer with refresh tokens on, only
      // for a first-party client an operator has given the flag, only when the
      // authorization asked for it, and only for the client the code was
      // minted for. Anything less takes the path below, which is unchanged.
      if (
        refresh &&
        client.allow_refresh &&
        client.first_party &&
        found.client_id === client.client_id &&
        found.scope.split(/\s+/).includes(OFFLINE_ACCESS)
      ) {
        const refreshToken = randomBytes(32).toString('base64url');
        const absoluteExpiresAt = new Date(now.getTime() + refresh.absoluteTtlMs);
        const idleExpiresAt = new Date(now.getTime() + refresh.idleTtlMs);
        const issued = await db.transaction(async (tx) => {
          const families = await tx.query<{ id: string }>(
            `INSERT INTO identity.oidc_refresh_families
               (client_id, user_id, scope, device_label, created_at, last_used_at, absolute_expires_at)
             VALUES ($1, $2, $3, $4, $5, $5, $6) RETURNING id::text AS id`,
            [client.client_id, account.id, found.scope, deviceLabelOf(input.deviceLabel), now, absoluteExpiresAt],
          );
          const sessionId = (families[0] as { id: string }).id;
          await tx.query(
            `INSERT INTO identity.oidc_refresh_tokens (token_hash, family_id, created_at, expires_at)
             VALUES ($1, $2, $3, $4)`,
            [sha256(refreshToken), sessionId, now, idleExpiresAt],
          );
          const access = await familyAccessToken(
            tx,
            { id: sessionId, clientId: client.client_id, userId: account.id, scope: found.scope, absoluteExpiresAt },
            now,
          );
          return { sessionId, ...access };
        });
        return {
          idToken,
          accessToken: issued.accessToken,
          tokenType: 'Bearer',
          expiresIn: issued.expiresIn,
          scope: found.scope,
          refreshToken,
          sessionId: issued.sessionId,
        };
      }

      const accessToken = randomBytes(32).toString('base64url');
      await db.query(
        `INSERT INTO identity.oidc_access_tokens (token_hash, client_id, user_id, scope, expires_at)
         VALUES ($1, $2, $3, $4, $5)`,
        [sha256(accessToken), input.clientId, account.id, found.scope, new Date(now.getTime() + ACCESS_TTL_MS)],
      );

      return {
        idToken,
        accessToken,
        tokenType: 'Bearer',
        expiresIn: Math.floor(ACCESS_TTL_MS / 1000),
        scope: found.scope,
      };
    },

    async userinfo(accessToken) {
      const rows = await db.query<{
        email: string;
        email_verified_at: Date | null;
        name: string | null;
        user_id: string;
        family_id: string | null;
      }>(
        // A token issued to a family answers only while the family is live.
        // Revoking deletes the family's access tokens as well; this is the
        // second lock on the same door.
        `SELECT u.email, u.email_verified_at, u.name, t.user_id, t.family_id::text AS family_id
           FROM identity.oidc_access_tokens t
           JOIN identity.users u ON u.id = t.user_id
           LEFT JOIN identity.oidc_refresh_families f ON f.id = t.family_id
          WHERE t.token_hash = $1 AND t.expires_at > $2
            AND (t.family_id IS NULL OR f.revoked_at IS NULL)`,
        [sha256(accessToken), clock()],
      );
      const row = rows[0];
      if (!row) refuse('invalid_client', 'unknown or expired access token');
      const found = row as NonNullable<typeof row>;
      return {
        sub: found.user_id,
        email: found.email,
        emailVerified: found.email_verified_at !== null,
        ...(found.name ? { name: found.name } : {}),
        ...(found.family_id ? { sessionId: found.family_id } : {}),
      };
    },

    async refresh(input) {
      if (!refresh) return refuse('invalid_request', 'unsupported grant_type');
      return rotate(refresh, input);
    },

    async revoke(input, meta = {}) {
      const client = await authenticatedClient(input.clientId, input.clientSecret);
      if (!input.token) return;
      const now = clock();
      const hash = sha256(input.token);
      // A refresh token first, current or retired: either names the sign-in,
      // and the sign-in is what the person means to end. Narrowed to this
      // client, so one client cannot end another's.
      const named = await db.query<{ family_id: string; user_id: string }>(
        `SELECT f.id::text AS family_id, f.user_id::text AS user_id
           FROM identity.oidc_refresh_tokens t
           JOIN identity.oidc_refresh_families f ON f.id = t.family_id
          WHERE t.token_hash = $1 AND f.client_id = $2`,
        [hash, client.client_id],
      );
      const family = named[0];
      if (family) {
        await db.transaction(async (tx) => {
          const gone = await revokeFamilies(tx, { familyId: family.family_id }, 'revoked', now);
          await ended(tx, family.user_id, gone.length, 'revoked', now, meta);
        });
        return;
      }
      await db.query(`DELETE FROM identity.oidc_access_tokens WHERE token_hash = $1 AND client_id = $2`, [
        hash,
        client.client_id,
      ]);
    },

    async deviceSessions(userId) {
      const rows = await db.query<{
        id: string;
        client_id: string;
        client_name: string;
        device_label: string | null;
        scope: string;
        created_at: Date;
        last_used_at: Date;
        expires_at: Date;
      }>(
        // The current token is the one not yet rotated; its expiry is the idle
        // expiry. A family with no live current token is over, listed or not.
        `SELECT f.id::text AS id, f.client_id, c.name AS client_name, f.device_label, f.scope,
                f.created_at, f.last_used_at, LEAST(f.absolute_expires_at, t.expires_at) AS expires_at
           FROM identity.oidc_refresh_families f
           JOIN identity.oidc_clients c ON c.client_id = f.client_id
           JOIN identity.oidc_refresh_tokens t ON t.family_id = f.id AND t.rotated_at IS NULL
          WHERE f.user_id = $1 AND f.revoked_at IS NULL
            AND f.absolute_expires_at > $2 AND t.expires_at > $2
          ORDER BY f.last_used_at DESC, f.created_at DESC`,
        [userId, clock()],
      );
      return rows.map((r) => ({
        id: r.id,
        clientId: r.client_id,
        clientName: r.client_name,
        label: r.device_label,
        scope: r.scope,
        createdAt: r.created_at,
        lastUsedAt: r.last_used_at,
        expiresAt: r.expires_at,
      }));
    },

    async revokeDeviceSession(userId, sessionId, meta = {}) {
      // An id from a URL: one that is not a uuid names nothing, and must not
      // reach a uuid cast to say so as a database error.
      if (!UUID.test(sessionId)) return false;
      const now = clock();
      return db.transaction(async (tx) => {
        // The user id is part of the question, so one person cannot end
        // another's sign-in by guessing an id.
        const owned = await tx.query<{ id: string }>(
          `SELECT id FROM identity.oidc_refresh_families
            WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL FOR UPDATE`,
          [sessionId, userId],
        );
        if (owned.length === 0) return false;
        const gone = await revokeFamilies(tx, { familyId: sessionId }, 'revoked', now);
        await ended(tx, userId, gone.length, 'revoked', now, meta);
        return gone.length > 0;
      });
    },

    async revokeDeviceSessions(userId, options = {}, meta = {}) {
      const except = options.exceptSessionId;
      const now = clock();
      return db.transaction(async (tx) => {
        const gone = await revokeFamilies(
          tx,
          { userId, ...(except && UUID.test(except) ? { exceptFamilyId: except } : {}) },
          'signed_out',
          now,
        );
        await ended(tx, userId, gone.length, 'signed_out', now, meta);
        return gone.length;
      });
    },

    discovery() {
      if (refresh) {
        return {
          issuer,
          authorization_endpoint: url(paths.authorization),
          token_endpoint: url(paths.token),
          jwks_uri: url(paths.jwks),
          userinfo_endpoint: url(paths.userinfo),
          revocation_endpoint: url(paths.revocation),
          response_types_supported: ['code'],
          grant_types_supported: ['authorization_code', 'refresh_token'],
          subject_types_supported: ['public'],
          id_token_signing_alg_values_supported: [ALG],
          // A client asks for offline_access to be given a refresh token, and
          // is given one only if it was registered with allowRefresh.
          scopes_supported: ['openid', 'email', 'profile', OFFLINE_ACCESS],
          token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
          revocation_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
          code_challenge_methods_supported: ['S256'],
          claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'email_verified', 'name'],
        };
      }
      return {
        issuer,
        authorization_endpoint: url(paths.authorization),
        token_endpoint: url(paths.token),
        jwks_uri: url(paths.jwks),
        userinfo_endpoint: url(paths.userinfo),
        response_types_supported: ['code'],
        grant_types_supported: ['authorization_code'],
        subject_types_supported: ['public'],
        id_token_signing_alg_values_supported: [ALG],
        scopes_supported: ['openid', 'email', 'profile'],
        token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
        // Advertised because it is REQUIRED here, not merely supported. A client
        // that reads this and omits PKCE is refused.
        code_challenge_methods_supported: ['S256'],
        claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'email_verified', 'name'],
      };
    },

    async jwks() {
      const rows = await db.query<{ public_jwk: jose.JWK }>(
        `SELECT public_jwk FROM identity.oidc_keys ORDER BY created_at DESC`,
      );
      // A retired key stays published: tokens it signed are still valid until
      // they expire, and a verifier that cannot find the key rejects them.
      if (rows.length === 0) {
        await activeKey();
        const made = await db.query<{ public_jwk: jose.JWK }>(`SELECT public_jwk FROM identity.oidc_keys`);
        return { keys: made.map((r) => r.public_jwk) };
      }
      return { keys: rows.map((r) => r.public_jwk) };
    },

    async rotateKey() {
      const now = clock();
      await db.query(`UPDATE identity.oidc_keys SET retired_at = $1 WHERE retired_at IS NULL`, [now]);
      const { kid } = await activeKey();
      return kid;
    },

    async sweep() {
      const now = clock();
      const codes = await db.query(`DELETE FROM identity.oidc_codes WHERE expires_at < $1 RETURNING 1`, [now]);
      const tokens = await db.query(`DELETE FROM identity.oidc_access_tokens WHERE expires_at < $1 RETURNING 1`, [now]);
      // A key is only droppable once nothing it signed can still be alive.
      const cutoff = new Date(now.getTime() - ID_TOKEN_TTL_S * 1000);
      const keys = await db.query(
        `DELETE FROM identity.oidc_keys WHERE retired_at IS NOT NULL AND retired_at < $1 RETURNING 1`,
        [cutoff],
      );
      // Housekeeping only: every one of these is already refused on read. A
      // family goes when it is revoked, past its absolute expiry, or has no
      // token that could still be presented. Its tokens and access tokens
      // cascade. Until then its retired tokens are kept, because they are how a
      // replay is recognised.
      const families = await db.query(
        `DELETE FROM identity.oidc_refresh_families f
          WHERE f.revoked_at IS NOT NULL OR f.absolute_expires_at <= $1
             OR NOT EXISTS (SELECT 1 FROM identity.oidc_refresh_tokens t
                             WHERE t.family_id = f.id AND t.rotated_at IS NULL AND t.expires_at > $1)
          RETURNING 1`,
        [now],
      );
      return { codes: codes.length, accessTokens: tokens.length, keys: keys.length, refreshFamilies: families.length };
    },
  };
}
