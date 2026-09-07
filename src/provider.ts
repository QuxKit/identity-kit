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
//   No refresh tokens. A consuming app exchanges the code, reads the ID token
//   and mints its OWN session; nothing here needs a credential that outlives
//   that exchange, and a refresh token is a long-lived bearer credential to
//   store, rotate and revoke.
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

import { createHash, randomBytes, timingSafeEqual } from 'node:crypto';

import * as jose from 'jose';

import { IdentityError } from './errors.ts';
import type { Clock, SqlExecutor } from './types.ts';

/** How long an authorization code lives. Long enough for a redirect and a
 *  server-to-server exchange, short enough that a leaked one is usually dead:
 *  the spec says ten minutes maximum and recommends one. */
const CODE_TTL_MS = 60_000;
/** The access token exists to serve `userinfo`, which a consuming app calls
 *  once, immediately. */
const ACCESS_TTL_MS = 5 * 60_000;
const ID_TOKEN_TTL_S = 300;
const ALG = 'ES256';

const sha256 = (value: string): string => createHash('sha256').update(value).digest('base64url');

/** Constant-time compare of two secrets of the same shape. */
function sameSecret(a: string, b: string): boolean {
  const left = Buffer.from(a);
  const right = Buffer.from(b);
  return left.length === right.length && timingSafeEqual(left, right);
}

export interface ClientInput {
  clientId: string;
  name: string;
  /** Omit for a public client, which is then PKCE-only. */
  secret?: string;
  redirectUris: readonly string[];
  firstParty?: boolean;
}

export interface ClientRecord {
  clientId: string;
  name: string;
  confidential: boolean;
  redirectUris: readonly string[];
  firstParty: boolean;
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

export interface TokenInput {
  grantType: string;
  code: string;
  redirectUri: string;
  clientId: string;
  clientSecret?: string;
  codeVerifier: string;
}

export interface TokenResult {
  idToken: string;
  accessToken: string;
  tokenType: 'Bearer';
  expiresIn: number;
  scope: string;
}

export interface UserClaims {
  sub: string;
  email?: string;
  emailVerified?: boolean;
  name?: string;
}

export interface ProviderOptions {
  db: SqlExecutor;
  /** The issuer URL, exactly as it will appear in `iss` and in discovery. */
  issuer: string;
  clock?: Clock;
  /** Where the routes live under the issuer. Defaults to the conventional
   *  paths; a host that mounts them elsewhere says so here. */
  paths?: Partial<Paths>;
}

export interface Paths {
  authorization: string;
  token: string;
  jwks: string;
  userinfo: string;
}

const DEFAULT_PATHS: Paths = {
  authorization: '/oidc/authorize',
  token: '/oidc/token',
  jwks: '/oidc/jwks',
  userinfo: '/oidc/userinfo',
};

export interface OidcIssuer {
  registerClient(input: ClientInput): Promise<ClientRecord>;
  clients(): Promise<ClientRecord[]>;
  /** Mint a code for an already-authenticated user. */
  authorize(input: AuthorizeInput): Promise<AuthorizeResult>;
  /** Redeem it. Single-use, PKCE-checked, bound to client and redirect_uri. */
  token(input: TokenInput): Promise<TokenResult>;
  /** The claims behind an access token, for `userinfo`. */
  userinfo(accessToken: string): Promise<UserClaims>;
  discovery(): Record<string, unknown>;
  jwks(): Promise<{ keys: jose.JWK[] }>;
  /** Retire the active key and start signing with a new one. The old key keeps
   *  appearing in JWKS until `sweep` drops it, so tokens already out there
   *  still verify. */
  rotateKey(): Promise<string>;
  /** Delete expired codes and access tokens, and keys retired long enough that
   *  nothing they signed can still be alive. */
  sweep(): Promise<{ codes: number; accessTokens: number; keys: number }>;
}

interface ClientRow {
  client_id: string;
  name: string;
  secret_hash: string | null;
  redirect_uris: string[];
  first_party: boolean;
  disabled_at: Date | null;
}

const toClient = (r: ClientRow): ClientRecord => ({
  clientId: r.client_id,
  name: r.name,
  confidential: r.secret_hash !== null,
  redirectUris: r.redirect_uris,
  firstParty: r.first_party,
  disabledAt: r.disabled_at,
});

export function createOidcIssuer(opts: ProviderOptions): OidcIssuer {
  const { db } = opts;
  const clock: Clock = opts.clock ?? (() => new Date());
  const issuer = opts.issuer.replace(/\/$/, '');
  const paths: Paths = { ...DEFAULT_PATHS, ...opts.paths };
  const url = (path: string): string => `${issuer}${path}`;

  /** Every refusal here is one of OAuth's, so a route handler can answer in the
   *  spec's terms without translating. */
  const refuse = (code: 'invalid_request' | 'invalid_grant' | 'invalid_client', reason: string): never => {
    throw new IdentityError({ code, reason });
  };

  async function clientOf(clientId: string): Promise<ClientRow> {
    const rows = await db.query<ClientRow>(
      `SELECT client_id, name, secret_hash, redirect_uris, first_party, disabled_at
         FROM identity.oidc_clients WHERE client_id = $1`,
      [clientId],
    );
    const row = rows[0];
    if (!row || row.disabled_at) refuse('invalid_request', 'unknown client');
    return row as ClientRow;
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
      const rows = await db.query<ClientRow>(
        `INSERT INTO identity.oidc_clients (client_id, name, secret_hash, redirect_uris, first_party)
         VALUES ($1, $2, $3, $4::text[], $5)
         ON CONFLICT (client_id) DO UPDATE
           SET name = EXCLUDED.name, secret_hash = EXCLUDED.secret_hash,
               redirect_uris = EXCLUDED.redirect_uris, first_party = EXCLUDED.first_party,
               disabled_at = NULL
         RETURNING client_id, name, secret_hash, redirect_uris, first_party, disabled_at`,
        [
          input.clientId,
          input.name,
          input.secret ? sha256(input.secret) : null,
          input.redirectUris,
          input.firstParty ?? false,
        ],
      );
      return toClient(rows[0] as ClientRow);
    },

    async clients() {
      const rows = await db.query<ClientRow>(
        `SELECT client_id, name, secret_hash, redirect_uris, first_party, disabled_at
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
      if (input.grantType !== 'authorization_code') refuse('invalid_request', 'unsupported grant_type');
      const client = await clientOf(input.clientId);
      if (client.secret_hash) {
        if (!input.clientSecret || !sameSecret(sha256(input.clientSecret), client.secret_hash)) {
          refuse('invalid_client', 'client authentication failed');
        }
      }

      const now = clock();
      // Consume and read in ONE guarded UPDATE. A SELECT then an UPDATE lets two
      // simultaneous redemptions both pass the check, which is the replay this
      // is here to prevent.
      const rows = await db.query<{
        user_id: string;
        redirect_uri: string;
        code_challenge: string;
        nonce: string | null;
        scope: string;
        expires_at: Date;
      }>(
        `UPDATE identity.oidc_codes SET consumed_at = $2
          WHERE code_hash = $1 AND consumed_at IS NULL AND expires_at > $2
          RETURNING user_id, redirect_uri, code_challenge, nonce, scope, expires_at`,
        [sha256(input.code), now],
      );
      const row = rows[0];
      if (!row) refuse('invalid_grant', 'the code is unknown, already used, or expired');
      const found = row as NonNullable<typeof row>;
      if (found.redirect_uri !== input.redirectUri)
        refuse('invalid_grant', 'redirect_uri does not match the one the code was minted for');
      // PKCE: the verifier must hash to the challenge presented at authorize.
      if (sha256(input.codeVerifier) !== found.code_challenge) refuse('invalid_grant', 'PKCE verification failed');

      const users = await db.query<{ id: string; email: string; email_verified_at: Date | null; name: string | null }>(
        `SELECT id, email, email_verified_at, name FROM identity.users WHERE id = $1`,
        [found.user_id],
      );
      const user = users[0];
      if (!user) refuse('invalid_grant', 'the account behind this code no longer exists');
      const account = user as NonNullable<typeof user>;

      const { kid, privateJwk } = await activeKey();
      const key = await jose.importJWK(privateJwk, ALG);
      const idToken = await new jose.SignJWT({
        email: account.email,
        email_verified: account.email_verified_at !== null,
        ...(account.name ? { name: account.name } : {}),
        ...(found.nonce ? { nonce: found.nonce } : {}),
      })
        .setProtectedHeader({ alg: ALG, kid, typ: 'JWT' })
        .setIssuer(issuer)
        .setSubject(account.id)
        .setAudience(input.clientId)
        .setIssuedAt(Math.floor(now.getTime() / 1000))
        .setExpirationTime(Math.floor(now.getTime() / 1000) + ID_TOKEN_TTL_S)
        .sign(key);

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
      }>(
        `SELECT u.email, u.email_verified_at, u.name, t.user_id
           FROM identity.oidc_access_tokens t
           JOIN identity.users u ON u.id = t.user_id
          WHERE t.token_hash = $1 AND t.expires_at > $2`,
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
      };
    },

    discovery() {
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
      return { codes: codes.length, accessTokens: tokens.length, keys: keys.length };
    },
  };
}
