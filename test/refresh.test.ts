// A sign-in that renews: refresh tokens for the issuer's phone and desktop apps.
//
// Against a real Postgres, because every property worth having here is a
// property of the rows: one current token per family, a retired token that
// revokes when it comes back, an access token that is gone the moment its
// family is. Time is a clock the test moves, never a sleep.

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { readFile } from 'node:fs/promises';
import { after, describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import * as jose from 'jose';

import { IdentityError } from '../src/errors.ts';
import { createIdentity, type Identity } from '../src/instance.ts';
import {
  createOidcIssuer,
  type OidcIssuer,
  REFRESH_ABSOLUTE_TTL_MS,
  REFRESH_IDLE_TTL_MS,
  REFRESH_REUSE_GRACE_MS,
  type TokenResult,
} from '../src/provider.ts';
import { revokeFamilies, revokeUserRefreshFamilies } from '../src/refresh-families.ts';
import { sha256 as sessionHash } from '../src/tokens.ts';
import type { SqlExecutor } from '../src/types.ts';
import { MailCollector, one, SKIP_REASON, setupDatabase, testConfig, tokenFrom } from './harness.ts';

const ISSUER = 'https://accounts.test';
const PHONE_CB = 'https://app.quxkit.test/oidc/callback';
const PORTAL_CB = 'https://quxkit.test/api/auth/callback';
const PASSWORD = 'correct horse battery staple';
const DAY = 24 * 60 * 60 * 1000;
const verifier = () => randomBytes(32).toString('base64url');
const challengeFor = (v: string) => createHash('sha256').update(v).digest('base64url');
const b64 = (v: string) => createHash('sha256').update(v).digest('base64url');

const harness = await setupDatabase();
const skip = harness === null ? SKIP_REASON : false;
const db: SqlExecutor = harness?.db as SqlExecutor;
const mail = new MailCollector();

// One clock for every issuer in this file; a test moves it and puts it back.
const T0 = new Date('2026-03-01T00:00:00Z');
let now = T0;
const clock = () => now;
const at = (ms: number) => {
  now = new Date(T0.getTime() + ms);
};

let issuer: OidcIssuer = undefined as unknown as OidcIssuer;
/** The issuer as it was before this feature: created without `refreshTokens`. */
let plain: OidcIssuer = undefined as unknown as OidcIssuer;
/** No grace: any second presentation of a token revokes. */
let strict: OidcIssuer = undefined as unknown as OidcIssuer;
let identity: Identity = undefined as unknown as Identity;
let ada = '';

async function newUser(email: string): Promise<string> {
  await identity.signup({ email, password: PASSWORD });
  return one(await db.query<{ id: string }>(`SELECT id FROM identity.users WHERE email = $1`, [email]), 'user').id;
}

if (harness) {
  issuer = createOidcIssuer({ db, issuer: ISSUER, clock, refreshTokens: true });
  plain = createOidcIssuer({ db, issuer: ISSUER, clock });
  strict = createOidcIssuer({ db, issuer: ISSUER, clock, refreshTokens: { reuseGraceMs: 0 } });
  identity = createIdentity({ db, config: testConfig, mail, rateLimiter: null });
  ada = await newUser('ada@example.test');
  await issuer.registerClient({
    clientId: 'phone',
    name: 'The phone app',
    redirectUris: [PHONE_CB],
    firstParty: true,
    allowRefresh: true,
  });
  await issuer.registerClient({
    clientId: 'desktop',
    name: 'The desktop app',
    redirectUris: ['http://127.0.0.1:53682/callback'],
    firstParty: true,
    allowRefresh: true,
  });
  await issuer.registerClient({
    clientId: 'console',
    name: 'A confidential app',
    secret: 'console-secret',
    redirectUris: ['https://console.quxkit.test/cb'],
    firstParty: true,
    allowRefresh: true,
  });
  await issuer.registerClient({
    clientId: 'portal',
    name: 'The portal',
    secret: 'a-confidential-secret',
    redirectUris: [PORTAL_CB],
    firstParty: true,
  });
}

after(async () => {
  await harness?.close();
});

interface SignInOptions {
  iss?: OidcIssuer;
  clientId?: string;
  redirectUri?: string;
  clientSecret?: string;
  scope?: string;
  userId?: string;
  deviceLabel?: string;
}

/** The whole browser leg and the code exchange, as the app would do them. */
async function signIn(o: SignInOptions = {}): Promise<TokenResult> {
  const iss = o.iss ?? issuer;
  const clientId = o.clientId ?? 'phone';
  const redirectUri = o.redirectUri ?? PHONE_CB;
  const v = verifier();
  const { code } = await iss.authorize({
    clientId,
    redirectUri,
    userId: o.userId ?? ada,
    scope: o.scope ?? 'openid offline_access',
    codeChallenge: challengeFor(v),
    nonce: 'n-1',
  });
  return iss.token({
    grantType: 'authorization_code',
    code,
    redirectUri,
    clientId,
    clientSecret: o.clientSecret,
    codeVerifier: v,
    deviceLabel: o.deviceLabel,
  });
}

const refreshOf = (t: TokenResult): string => {
  assert.ok(t.refreshToken, 'expected a refresh token');
  return t.refreshToken as string;
};

const family = async (id: string | undefined) =>
  one(
    await db.query<{ revoked_at: Date | null; revoked_reason: string | null; last_used_at: Date }>(
      `SELECT revoked_at, revoked_reason, last_used_at FROM identity.oidc_refresh_families WHERE id = $1`,
      [id],
    ),
    'family',
  );

const refused = (p: Promise<unknown>) =>
  assert.rejects(p, (e: unknown) => {
    assert.ok(IdentityError.hasCode(e, 'invalid_grant'), `expected invalid_grant, got ${String(e)}`);
    // One message for every refusal, so a refusal never says which.
    assert.match((e as Error).message, /unknown, expired, revoked, or was not issued to this client/);
    return true;
  });

const eventsOf = async (userId: string, kind: string) =>
  db.query<{ metadata: Record<string, unknown>; ip: string | null }>(
    `SELECT metadata, ip FROM identity.events WHERE user_id = $1 AND kind = $2 ORDER BY id`,
    [userId, kind],
  );

describe('who may hold a refresh token', { skip }, () => {
  it('is a per-client flag, off by default, and only for a first-party client', async () => {
    const all = await issuer.clients();
    assert.equal(all.find((c) => c.clientId === 'phone')?.allowRefresh, true);
    assert.equal(all.find((c) => c.clientId === 'portal')?.allowRefresh, false);

    await assert.rejects(
      () =>
        issuer.registerClient({
          clientId: 'third',
          name: 'Someone else',
          redirectUris: ['https://third.test/cb'],
          firstParty: false,
          allowRefresh: true,
        }),
      /only a first-party client/,
    );
    // The database says so too, for a row an operator writes by hand.
    await assert.rejects(
      () =>
        db.query(
          `INSERT INTO identity.oidc_clients (client_id, name, redirect_uris, first_party, allow_refresh)
           VALUES ('by-hand', 'x', ARRAY['https://x.test/cb'], false, true)`,
        ),
      /oidc_clients_refresh_first_party/,
    );
  });

  it('cannot be given by an issuer that was not created with refreshTokens', async () => {
    await assert.rejects(
      () =>
        plain.registerClient({
          clientId: 'phone-2',
          name: 'x',
          redirectUris: [PHONE_CB],
          firstParty: true,
          allowRefresh: true,
        }),
      /needs an issuer created with refreshTokens/,
    );
  });

  it('keeps redirect URIs https or loopback: a custom scheme is still refused', async () => {
    await assert.rejects(
      () =>
        issuer.registerClient({
          clientId: 'scheme',
          name: 'x',
          redirectUris: ['ai.quxkit.ezy://callback'],
          firstParty: true,
          allowRefresh: true,
        }),
      /https/,
    );
  });

  it('has lifetimes that are checked when the issuer is made', () => {
    assert.equal(REFRESH_ABSOLUTE_TTL_MS, 90 * DAY);
    assert.equal(REFRESH_IDLE_TTL_MS, 30 * DAY);
    assert.equal(REFRESH_REUSE_GRACE_MS, 10_000);
    for (const bad of [
      { absoluteTtlMs: 0 },
      { idleTtlMs: -1 },
      { idleTtlMs: Number.NaN },
      { absoluteTtlMs: DAY, idleTtlMs: 2 * DAY },
      { reuseGraceMs: -1 },
      { reuseGraceMs: 61_000 },
    ]) {
      assert.throws(
        () => createOidcIssuer({ db, issuer: ISSUER, refreshTokens: bad }),
        (e: unknown) => IdentityError.hasCode(e, 'invalid_config'),
        JSON.stringify(bad),
      );
    }
    // A short absolute lifetime pulls the default idle one in with it, rather
    // than failing somebody who only set one number.
    createOidcIssuer({ db, issuer: ISSUER, refreshTokens: { absoluteTtlMs: DAY } });
    createOidcIssuer({ db, issuer: ISSUER, refreshTokens: false });
  });
});

describe('issuing one', { skip }, () => {
  it('needs the flag AND the offline_access scope', async () => {
    const both = await signIn();
    assert.ok(both.refreshToken);
    assert.ok(both.sessionId);
    assert.equal(both.scope, 'openid offline_access');
    assert.equal(both.expiresIn, 300, 'the access token is still five minutes');

    // The flag without the scope.
    const noScope = await signIn({ scope: 'openid' });
    assert.equal('refreshToken' in noScope, false);
    assert.equal('sessionId' in noScope, false);

    // The scope without the flag.
    const noFlag = await signIn({
      clientId: 'portal',
      redirectUri: PORTAL_CB,
      clientSecret: 'a-confidential-secret',
    });
    assert.equal('refreshToken' in noFlag, false);

    // Both, on an issuer that never turned refresh tokens on.
    const noIssuer = await signIn({ iss: plain });
    assert.equal('refreshToken' in noIssuer, false);
  });

  it('is not issued when the code was minted for another client', async () => {
    // The code is for the portal (no flag); the phone (flag) redeems it.
    await issuer.registerClient({
      clientId: 'phone-shared',
      name: 'x',
      redirectUris: [PORTAL_CB],
      firstParty: true,
      allowRefresh: true,
    });
    const v = verifier();
    const { code } = await issuer.authorize({
      clientId: 'portal',
      redirectUri: PORTAL_CB,
      userId: ada,
      scope: 'openid offline_access',
      codeChallenge: challengeFor(v),
    });
    const tokens = await issuer.token({
      grantType: 'authorization_code',
      code,
      redirectUri: PORTAL_CB,
      clientId: 'phone-shared',
      codeVerifier: v,
    });
    assert.equal('refreshToken' in tokens, false);
  });

  it('records what the app called the device, made safe to show back', async () => {
    const user = await newUser('label@example.test');
    await signIn({ userId: user, deviceLabel: `  Ada's\u0000 iPhone\n${'x'.repeat(200)}` });
    await signIn({ userId: user, deviceLabel: ' \t ' });
    const labels = (await issuer.deviceSessions(user)).map((s) => s.label);
    const named = labels.find((l) => l !== null) as string;
    assert.match(named, /^Ada's {2}iPhone x+$/);
    assert.equal(named.length, 120);
    assert.ok(labels.includes(null), 'an empty label is null, not an empty string');
  });
});

describe('a client without the flag is exactly what it was', { skip }, () => {
  it('gets the same token response, the same access-token row, the same userinfo', async () => {
    at(0);
    for (const iss of [plain, issuer]) {
      const tokens = await signIn({
        iss,
        clientId: 'portal',
        redirectUri: PORTAL_CB,
        clientSecret: 'a-confidential-secret',
        scope: 'openid email',
      });
      assert.deepEqual(Object.keys(tokens), ['idToken', 'accessToken', 'tokenType', 'expiresIn', 'scope']);
      assert.deepEqual(
        { tokenType: tokens.tokenType, expiresIn: tokens.expiresIn, scope: tokens.scope },
        { tokenType: 'Bearer', expiresIn: 300, scope: 'openid email' },
      );
      const row = one(
        await db.query<{ family_id: string | null; expires_at: Date; client_id: string; scope: string }>(
          `SELECT family_id, expires_at, client_id, scope FROM identity.oidc_access_tokens WHERE token_hash = $1`,
          [b64(tokens.accessToken)],
        ),
      );
      assert.deepEqual(row, {
        family_id: null,
        expires_at: new Date(T0.getTime() + 300_000),
        client_id: 'portal',
        scope: 'openid email',
      });
      assert.deepEqual(await iss.userinfo(tokens.accessToken), {
        sub: ada,
        email: 'ada@example.test',
        emailVerified: false,
      });
      const { payload, protectedHeader } = await jose.jwtVerify(
        tokens.idToken,
        jose.createLocalJWKSet(await iss.jwks()),
        { issuer: ISSUER, audience: 'portal', currentDate: now },
      );
      assert.deepEqual(Object.keys(payload).sort(), [
        'aud',
        'email',
        'email_verified',
        'exp',
        'iat',
        'iss',
        'nonce',
        'sub',
      ]);
      assert.equal(protectedHeader.typ, 'JWT');
      // It asked for offline_access? Still nothing: see "issuing one".
    }
  });

  it('is refused the refresh grant in the words it always was, on an issuer without refresh tokens', async () => {
    const unsupported = (e: unknown) =>
      IdentityError.hasCode(e, 'invalid_request') && (e as Error).message === 'unsupported grant_type';
    await assert.rejects(
      () => plain.token({ grantType: 'refresh_token', clientId: 'portal', refreshToken: 'anything' }),
      unsupported,
    );
    await assert.rejects(() => plain.refresh({ clientId: 'portal', refreshToken: 'anything' }), unsupported);
    await assert.rejects(() => issuer.token({ grantType: 'password', clientId: 'portal' }), unsupported);
    // On an issuer that has them, a client without the flag holds no token to
    // present, and is refused like any other stranger.
    await refused(
      issuer.refresh({ clientId: 'portal', clientSecret: 'a-confidential-secret', refreshToken: 'anything' }),
    );
  });

  it('reads the same discovery document from an issuer without refresh tokens', () => {
    assert.deepEqual(plain.discovery(), {
      issuer: ISSUER,
      authorization_endpoint: `${ISSUER}/oidc/authorize`,
      token_endpoint: `${ISSUER}/oidc/token`,
      jwks_uri: `${ISSUER}/oidc/jwks`,
      userinfo_endpoint: `${ISSUER}/oidc/userinfo`,
      response_types_supported: ['code'],
      grant_types_supported: ['authorization_code'],
      subject_types_supported: ['public'],
      id_token_signing_alg_values_supported: ['ES256'],
      scopes_supported: ['openid', 'email', 'profile'],
      token_endpoint_auth_methods_supported: ['client_secret_post', 'none'],
      code_challenge_methods_supported: ['S256'],
      claims_supported: ['sub', 'iss', 'aud', 'exp', 'iat', 'email', 'email_verified', 'name'],
    });
  });
});

describe('discovery, with refresh tokens on', { skip }, () => {
  it('advertises the grant, the scope and the revocation endpoint', () => {
    const doc = issuer.discovery();
    assert.deepEqual(doc.grant_types_supported, ['authorization_code', 'refresh_token']);
    assert.deepEqual(doc.scopes_supported, ['openid', 'email', 'profile', 'offline_access']);
    assert.equal(doc.revocation_endpoint, `${ISSUER}/oidc/revoke`);
    assert.deepEqual(doc.revocation_endpoint_auth_methods_supported, ['client_secret_post', 'none']);
    // PKCE is still required, and still the only method.
    assert.deepEqual(doc.code_challenge_methods_supported, ['S256']);
    const moved = createOidcIssuer({ db, issuer: ISSUER, refreshTokens: true, paths: { revocation: '/o/revoke' } });
    assert.equal(moved.discovery().revocation_endpoint, `${ISSUER}/o/revoke`);
  });
});

describe('rotation', { skip }, () => {
  it('returns a new refresh token and retires the one presented', async () => {
    at(0);
    const first = await signIn();
    at(4 * 60_000);
    const second = await issuer.token({
      grantType: 'refresh_token',
      clientId: 'phone',
      refreshToken: refreshOf(first),
    });
    assert.notEqual(second.refreshToken, first.refreshToken);
    assert.notEqual(second.accessToken, first.accessToken);
    assert.equal(second.sessionId, first.sessionId, 'the same sign-in');
    assert.equal(second.scope, 'openid offline_access');
    assert.equal(second.expiresIn, 300);
    assert.equal(second.tokenType, 'Bearer');

    // The new access token works, and says which sign-in it belongs to.
    const claims = await issuer.userinfo(second.accessToken);
    assert.equal(claims.sub, ada);
    assert.equal(claims.sessionId, first.sessionId);

    // A fresh ID token for the same person and client, with no nonce: there
    // was no authorization request for one to bind to.
    const { payload } = await jose.jwtVerify(second.idToken, jose.createLocalJWKSet(await issuer.jwks()), {
      issuer: ISSUER,
      audience: 'phone',
      currentDate: now,
    });
    assert.equal(payload.sub, ada);
    assert.equal(payload.nonce, undefined);

    const rows = await db.query<{ token_hash: string; parent_hash: string | null; rotated_at: Date | null }>(
      `SELECT token_hash, parent_hash, rotated_at FROM identity.oidc_refresh_tokens
        WHERE family_id = $1 ORDER BY created_at`,
      [first.sessionId],
    );
    assert.equal(rows.length, 2);
    assert.deepEqual(rows[0]?.rotated_at, now, 'the presented token is retired');
    assert.equal(rows[1]?.parent_hash, rows[0]?.token_hash, 'the successor names its parent');
    assert.equal(rows[1]?.rotated_at, null);
    assert.deepEqual((await family(first.sessionId)).last_used_at, now);

    // And the chain goes on.
    at(9 * 60_000);
    const third = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(second) });
    assert.notEqual(third.refreshToken, second.refreshToken);
  });

  it('refuses a token nobody issued, and a request without one', async () => {
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: randomBytes(32).toString('base64url') }));
    await assert.rejects(
      () => issuer.token({ grantType: 'refresh_token', clientId: 'phone' }),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_request') && /refresh_token is required/.test(String(e)),
    );
  });

  it('needs the secret of a confidential client, and gives nothing away without it', async () => {
    const tokens = await signIn({
      clientId: 'console',
      redirectUri: 'https://console.quxkit.test/cb',
      clientSecret: 'console-secret',
    });
    for (const clientSecret of [undefined, 'not-it']) {
      await assert.rejects(
        () => issuer.refresh({ clientId: 'console', clientSecret, refreshToken: refreshOf(tokens) }),
        (e: unknown) => IdentityError.hasCode(e, 'invalid_client'),
      );
    }
    // A failed client authentication did not spend the token.
    const next = await issuer.refresh({
      clientId: 'console',
      clientSecret: 'console-secret',
      refreshToken: refreshOf(tokens),
    });
    assert.ok(next.refreshToken);
  });
});

describe('reuse of a retired token', { skip }, () => {
  it('revokes the whole family and its access tokens, and is refused', async () => {
    at(0);
    const user = await newUser('reuse@example.test');
    const first = await signIn({ userId: user });
    at(5 * 60_000);
    const second = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) });
    // Well past the grace: somebody else is holding the first token.
    at(5 * 60_000 + REFRESH_REUSE_GRACE_MS + 1);
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) }));

    // The honest holder of the newest token is signed out too: nothing here
    // can tell which of the two is the thief.
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(second) }));
    await assert.rejects(() => issuer.userinfo(second.accessToken), /unknown or expired/);
    const row = await family(first.sessionId);
    assert.equal(row.revoked_reason, 'reuse');
    assert.deepEqual(row.revoked_at, now);
    assert.deepEqual(await issuer.deviceSessions(user), []);

    // The refusal was thrown AFTER the revocation was committed, and the
    // incident is on the account's record.
    const events = await eventsOf(user, 'refresh_token_reuse');
    assert.equal(events.length, 1, 'one event: the second refusal found a family already revoked');
    assert.deepEqual(events[0]?.metadata, { familyId: first.sessionId, clientId: 'phone' });
  });

  it('revokes even inside the grace once the successor has itself been used', async () => {
    at(0);
    const first = await signIn();
    const second = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) });
    await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(second) });
    // Same instant, so inside any grace. But the successor was used, so its
    // holder received it, so this is not a retry.
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) }));
    assert.equal((await family(first.sessionId)).revoked_reason, 'reuse');
  });

  it('revokes when the sealed successor does not open', async () => {
    at(0);
    const first = await signIn();
    await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) });
    await db.query(`UPDATE identity.oidc_refresh_tokens SET sealed_successor = 'tampered' WHERE token_hash = $1`, [
      b64(refreshOf(first)),
    ]);
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) }));
    assert.equal((await family(first.sessionId)).revoked_reason, 'reuse');
  });
});

describe('the benign race: a retry is not a theft', { skip }, () => {
  it('answers a second presentation inside the grace with the same successor', async () => {
    at(0);
    const first = await signIn();
    at(60_000);
    const won = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) });
    // The response was lost; the app retries with the token it still holds.
    at(60_000 + REFRESH_REUSE_GRACE_MS);
    const retry = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) });
    assert.equal(retry.refreshToken, won.refreshToken, 'the same successor, not a second one');
    assert.equal(retry.sessionId, won.sessionId);
    assert.equal((await issuer.userinfo(retry.accessToken)).sub, ada);
    assert.equal((await family(first.sessionId)).revoked_at, null);
    const rows = await db.query(`SELECT 1 FROM identity.oidc_refresh_tokens WHERE family_id = $1`, [first.sessionId]);
    assert.equal(rows.length, 2, 'still one successor');

    // One millisecond later it is reuse.
    at(60_000 + REFRESH_REUSE_GRACE_MS + 1);
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) }));
    assert.equal((await family(first.sessionId)).revoked_reason, 'reuse');
  });

  it('lets one of two simultaneous requests rotate, and gives both the same successor', async () => {
    at(0);
    const first = await signIn();
    const results = await Promise.all(
      [1, 2, 3, 4].map(() => issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) })),
    );
    assert.equal(new Set(results.map((r) => r.refreshToken)).size, 1, 'one rotation, one successor');
    const rows = await db.query<{ rotated_at: Date | null }>(
      `SELECT rotated_at FROM identity.oidc_refresh_tokens WHERE family_id = $1`,
      [first.sessionId],
    );
    assert.equal(rows.length, 2);
    assert.equal(rows.filter((r) => r.rotated_at === null).length, 1, 'exactly one current token');
    assert.equal((await family(first.sessionId)).revoked_at, null);
  });

  it('with reuseGraceMs 0, lets exactly one win and revokes for the rest', async () => {
    at(0);
    const first = await signIn({ iss: strict });
    const settled = await Promise.allSettled(
      [1, 2, 3].map(() => strict.refresh({ clientId: 'phone', refreshToken: refreshOf(first) })),
    );
    assert.equal(settled.filter((s) => s.status === 'fulfilled').length, 1, 'one winner');
    for (const s of settled) {
      if (s.status === 'rejected') assert.ok(IdentityError.hasCode(s.reason, 'invalid_grant'));
    }
    // Strict means strict: the losers were reuse, so the winner's token is dead too.
    assert.equal((await family(first.sessionId)).revoked_reason, 'reuse');
    const sealed = await db.query(
      `SELECT 1 FROM identity.oidc_refresh_tokens WHERE family_id = $1 AND sealed_successor IS NOT NULL`,
      [first.sessionId],
    );
    assert.equal(sealed.length, 0, 'nothing is sealed when there is no grace to serve');
  });

  it('clears the seal as soon as the successor is used', async () => {
    at(0);
    const first = await signIn();
    const second = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) });
    const sealedOn = async (token: string) =>
      one(
        await db.query<{ sealed_successor: string | null }>(
          `SELECT sealed_successor FROM identity.oidc_refresh_tokens WHERE token_hash = $1`,
          [b64(token)],
        ),
      ).sealed_successor;
    assert.ok(await sealedOn(refreshOf(first)));
    await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(second) });
    assert.equal(await sealedOn(refreshOf(first)), null);
  });
});

describe('expiry', { skip }, () => {
  it('ends a sign-in nobody has refreshed for the idle lifetime', async () => {
    at(0);
    const user = await newUser('idle@example.test');
    const first = await signIn({ userId: user });
    assert.deepEqual(one(await issuer.deviceSessions(user)).expiresAt, new Date(T0.getTime() + REFRESH_IDLE_TTL_MS));

    // One millisecond short of thirty days: alive, and the refresh moves the
    // idle expiry on from now.
    at(REFRESH_IDLE_TTL_MS - 1);
    const second = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) });
    assert.deepEqual(
      one(await issuer.deviceSessions(user)).expiresAt,
      new Date(T0.getTime() + 2 * REFRESH_IDLE_TTL_MS - 1),
    );

    // Thirty days after THAT refresh, to the millisecond: dead.
    at(2 * REFRESH_IDLE_TTL_MS - 1);
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(second) }));
    assert.deepEqual(await issuer.deviceSessions(user), []);
    // Expired is not reuse: nothing was revoked, there was nothing left to.
    assert.equal((await family(first.sessionId)).revoked_at, null);
  });

  it('ends a sign-in at the absolute lifetime however often it is refreshed', async () => {
    at(0);
    const user = await newUser('absolute@example.test');
    let tokens = await signIn({ userId: user });
    for (const day of [20, 40, 60, 80]) {
      at(day * DAY);
      tokens = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(tokens) });
    }
    // The idle expiry would be day 110. The absolute one is day 90, and wins.
    assert.deepEqual(
      one(await issuer.deviceSessions(user)).expiresAt,
      new Date(T0.getTime() + REFRESH_ABSOLUTE_TTL_MS),
    );

    // Two minutes before the end, the access token is two minutes long: it
    // never outlives the sign-in it belongs to.
    at(REFRESH_ABSOLUTE_TTL_MS - 120_000);
    tokens = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(tokens) });
    assert.equal(tokens.expiresIn, 120);

    at(REFRESH_ABSOLUTE_TTL_MS);
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(tokens) }));
    await assert.rejects(() => issuer.userinfo(tokens.accessToken), /unknown or expired/);
    assert.deepEqual(await issuer.deviceSessions(user), []);
  });

  it('takes its lifetimes from the issuer', async () => {
    at(0);
    const short = createOidcIssuer({
      db,
      issuer: ISSUER,
      clock,
      refreshTokens: { absoluteTtlMs: 2 * DAY, idleTtlMs: DAY },
    });
    const first = await signIn({ iss: short });
    at(DAY);
    await refused(short.refresh({ clientId: 'phone', refreshToken: refreshOf(first) }));

    at(0);
    let tokens = await signIn({ iss: short });
    at(DAY - 1);
    tokens = await short.refresh({ clientId: 'phone', refreshToken: refreshOf(tokens) });
    at(2 * DAY - 2);
    tokens = await short.refresh({ clientId: 'phone', refreshToken: refreshOf(tokens) });
    at(2 * DAY);
    await refused(short.refresh({ clientId: 'phone', refreshToken: refreshOf(tokens) }));
  });
});

describe("another client's refresh token", { skip }, () => {
  it('is refused, and nothing happens to it: not rotated, not revoked', async () => {
    at(0);
    const tokens = await signIn();
    // The desktop app may hold refresh tokens of its own. Not this one.
    await refused(issuer.refresh({ clientId: 'desktop', refreshToken: refreshOf(tokens) }));
    await refused(
      issuer.refresh({ clientId: 'console', clientSecret: 'console-secret', refreshToken: refreshOf(tokens) }),
    );

    const row = await family(tokens.sessionId);
    assert.equal(row.revoked_at, null, 'a wrong client id is a misconfiguration, not a theft');
    assert.equal((await issuer.userinfo(tokens.accessToken)).sub, ada, 'its access token still works');
    // Its owner can still use it, once.
    const next = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(tokens) });
    assert.ok(next.refreshToken);
  });
});

describe('the revocation endpoint (RFC 7009)', { skip }, () => {
  it('ends the whole sign-in for a refresh token, at once', async () => {
    at(0);
    const user = await newUser('revoke@example.test');
    const tokens = await signIn({ userId: user });
    await issuer.revoke({ token: refreshOf(tokens), clientId: 'phone' }, { ipAddress: '203.0.113.9' });

    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(tokens) }));
    await assert.rejects(() => issuer.userinfo(tokens.accessToken), /unknown or expired/);
    assert.equal((await family(tokens.sessionId)).revoked_reason, 'revoked');
    const events = await eventsOf(user, 'device_session_revoked');
    assert.deepEqual(events[0]?.metadata, { count: 1, reason: 'revoked' });
    assert.equal(events[0]?.ip, '203.0.113.9');

    // Twice is fine, and silent: the RFC asks for 200 either way.
    await issuer.revoke({ token: refreshOf(tokens), clientId: 'phone' });
    assert.equal((await eventsOf(user, 'device_session_revoked')).length, 1);
  });

  it('ends it for a RETIRED refresh token too: an app revokes with whatever it holds', async () => {
    at(0);
    const first = await signIn();
    const second = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) });
    await issuer.revoke({ token: refreshOf(first), clientId: 'phone' });
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(second) }));
    assert.equal((await family(first.sessionId)).revoked_reason, 'revoked');
  });

  it('ends only the access token when given an access token', async () => {
    at(0);
    const tokens = await signIn();
    await issuer.revoke({ token: tokens.accessToken, clientId: 'phone' });
    await assert.rejects(() => issuer.userinfo(tokens.accessToken), /unknown or expired/);
    const next = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(tokens) });
    assert.equal((await issuer.userinfo(next.accessToken)).sub, ada);

    // The portal's access tokens (no family) can be revoked the same way.
    const web = await signIn({ clientId: 'portal', redirectUri: PORTAL_CB, clientSecret: 'a-confidential-secret' });
    await issuer.revoke({ token: web.accessToken, clientId: 'portal', clientSecret: 'a-confidential-secret' });
    await assert.rejects(() => issuer.userinfo(web.accessToken), /unknown or expired/);
  });

  it("does nothing to another client's token, and answers the same", async () => {
    at(0);
    const tokens = await signIn();
    await issuer.revoke({ token: refreshOf(tokens), clientId: 'desktop' });
    await issuer.revoke({ token: tokens.accessToken, clientId: 'desktop' });
    assert.equal((await family(tokens.sessionId)).revoked_at, null);
    assert.equal((await issuer.userinfo(tokens.accessToken)).sub, ada);
  });

  it('resolves for a token it has never seen, and for none at all', async () => {
    await issuer.revoke({ token: 'never-issued', clientId: 'phone' });
    await issuer.revoke({ token: '', clientId: 'phone' });
  });

  it('authenticates a confidential client, and refuses an unknown one', async () => {
    await assert.rejects(
      () => issuer.revoke({ token: 'x', clientId: 'console', clientSecret: 'not-it' }),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_client'),
    );
    await assert.rejects(() => issuer.revoke({ token: 'x', clientId: 'nobody' }), /unknown client/);
  });
});

describe("a person's devices", { skip }, () => {
  it('lists live sign-ins, most recently used first, and revokes one', async () => {
    at(0);
    const user = await newUser('devices@example.test');
    const other = await newUser('other@example.test');
    const phone = await signIn({ userId: user, deviceLabel: "Ada's iPhone" });
    at(60_000);
    const laptop = await signIn({
      userId: user,
      clientId: 'desktop',
      redirectUri: 'http://127.0.0.1:53682/callback',
      deviceLabel: 'Work laptop',
    });
    await signIn({ userId: other });

    const listed = await issuer.deviceSessions(user);
    assert.deepEqual(
      listed.map((s) => ({ ...s })),
      [
        {
          id: laptop.sessionId,
          clientId: 'desktop',
          clientName: 'The desktop app',
          label: 'Work laptop',
          scope: 'openid offline_access',
          createdAt: new Date(T0.getTime() + 60_000),
          lastUsedAt: new Date(T0.getTime() + 60_000),
          expiresAt: new Date(T0.getTime() + 60_000 + REFRESH_IDLE_TTL_MS),
        },
        {
          id: phone.sessionId,
          clientId: 'phone',
          clientName: 'The phone app',
          label: "Ada's iPhone",
          scope: 'openid offline_access',
          createdAt: T0,
          lastUsedAt: T0,
          expiresAt: new Date(T0.getTime() + REFRESH_IDLE_TTL_MS),
        },
      ],
    );

    // Using the phone moves it to the top.
    at(120_000);
    const phone2 = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(phone) });
    assert.equal((await issuer.deviceSessions(user))[0]?.id, phone.sessionId);

    // Somebody else cannot end it, and an id that is not an id names nothing.
    assert.equal(await issuer.revokeDeviceSession(other, phone.sessionId as string), false);
    assert.equal(await issuer.revokeDeviceSession(user, "'; DROP TABLE identity.users; --"), false);
    assert.equal(await issuer.revokeDeviceSession(user, '00000000-0000-4000-8000-000000000000'), false);
    assert.equal((await issuer.deviceSessions(user)).length, 2);

    assert.equal(
      await issuer.revokeDeviceSession(user, phone.sessionId as string, { userAgent: 'devices page' }),
      true,
    );
    assert.equal(await issuer.revokeDeviceSession(user, phone.sessionId as string), false, 'already over');
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(phone2) }));
    await assert.rejects(() => issuer.userinfo(phone2.accessToken), /unknown or expired/);

    // The laptop was not touched.
    assert.deepEqual(
      (await issuer.deviceSessions(user)).map((s) => s.id),
      [laptop.sessionId],
    );
    assert.equal((await issuer.userinfo(laptop.accessToken)).sessionId, laptop.sessionId);
    assert.equal((await issuer.deviceSessions(other)).length, 1);
  });

  it('signs out every device, or every device but the one in hand', async () => {
    at(0);
    const user = await newUser('everywhere@example.test');
    const a = await signIn({ userId: user });
    const b = await signIn({ userId: user });
    const c = await signIn({ userId: user });

    assert.equal(await issuer.revokeDeviceSessions(user, { exceptSessionId: a.sessionId }), 2);
    assert.deepEqual(
      (await issuer.deviceSessions(user)).map((s) => s.id),
      [a.sessionId],
    );
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(b) }));
    await assert.rejects(() => issuer.userinfo(c.accessToken), /unknown or expired/);
    assert.deepEqual((await eventsOf(user, 'device_session_revoked'))[0]?.metadata, { count: 2, reason: 'signed_out' });

    // An exception that is not an id spares nothing.
    assert.equal(await issuer.revokeDeviceSessions(user, { exceptSessionId: 'not-an-id' }), 1);
    assert.equal(await issuer.revokeDeviceSessions(user), 0);
    assert.equal((await eventsOf(user, 'device_session_revoked')).length, 2, 'nothing ended, nothing recorded');
  });
});

describe('the core ends them when it ends every session', { skip }, () => {
  /** Sign a fresh person in on two devices and hand back what to check. */
  const twoDevices = async (email: string) => {
    at(0);
    const user = await newUser(email);
    const phone = await signIn({ userId: user, deviceLabel: 'phone' });
    const laptop = await signIn({ userId: user, clientId: 'desktop', redirectUri: 'http://127.0.0.1:53682/callback' });
    assert.equal((await issuer.deviceSessions(user)).length, 2);
    return { user, phone, laptop };
  };
  const allGone = async (
    s: { user: string; phone: TokenResult; laptop: TokenResult },
    reason: string,
  ): Promise<void> => {
    assert.deepEqual(await issuer.deviceSessions(s.user), []);
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(s.phone) }));
    await refused(issuer.refresh({ clientId: 'desktop', refreshToken: refreshOf(s.laptop) }));
    await assert.rejects(() => issuer.userinfo(s.phone.accessToken), /unknown or expired/);
    await assert.rejects(() => issuer.userinfo(s.laptop.accessToken), /unknown or expired/);
    assert.equal((await family(s.phone.sessionId)).revoked_reason, reason);
    assert.deepEqual((await eventsOf(s.user, 'device_session_revoked'))[0]?.metadata, { count: 2, reason });
  };

  it('on a password change, even when the browser session is kept', async () => {
    const s = await twoDevices('change@example.test');
    await db.query(`UPDATE identity.users SET email_verified_at = now() WHERE id = $1`, [s.user]);
    const login = await identity.login({ email: 'change@example.test', password: PASSWORD });
    assert.equal(login.kind, 'session');
    const kept = sessionHash((login as { token: string }).token);
    await identity.changePassword(s.user, PASSWORD, 'a different long password', kept);
    // The browser session that changed the password survives. No refresh
    // family is that session, so none does.
    assert.equal((await identity.listSessions(s.user)).length, 1);
    await allGone(s, 'password_changed');
  });

  it('on a password reset, in the same transaction as the new password', async () => {
    const s = await twoDevices('reset@example.test');
    await identity.requestPasswordReset('reset@example.test');
    const token = tokenFrom(mail.first('reset@example.test').body);
    mail.clear();
    await identity.requestPasswordReset('reset@example.test');
    const second = tokenFrom(mail.first('reset@example.test').body);
    assert.notEqual(token, second);
    const done = await identity.resetPassword(second, 'another long password', undefined, {
      ipAddress: '198.51.100.7',
    });
    assert.equal(done.kind, 'done');
    await allGone(s, 'password_reset');
    assert.equal((await eventsOf(s.user, 'device_session_revoked'))[0]?.ip, '198.51.100.7');
  });

  it('on an email change', async () => {
    const s = await twoDevices('before@example.test');
    const raw = randomBytes(32).toString('base64url');
    await db.query(
      `INSERT INTO identity.email_verification_tokens (token_hash, user_id, purpose, new_email, expires_at)
       VALUES ($1, $2, 'verify_email', 'after@example.test', now() + interval '1 hour')`,
      [sessionHash(raw), s.user],
    );
    assert.equal(await identity.verifyEmail(raw), true);
    await allGone(s, 'email_changed');
  });

  it('on a deletion request, after which the account can no longer authenticate', async () => {
    const s = await twoDevices('leaving@example.test');
    await identity.requestDeletion(s.user);
    await allGone(s, 'account');
  });

  it('on sign out everywhere', async () => {
    const s = await twoDevices('signout@example.test');
    await identity.revokeAllSessions(s.user);
    await allGone(s, 'signed_out');
  });

  it('refuses a refresh for an account that is closing, and revokes on the way out', async () => {
    at(0);
    const user = await newUser('closing@example.test');
    const tokens = await signIn({ userId: user });
    // Marked by hand, so the family is still live when the refresh arrives.
    await db.query(`UPDATE identity.users SET deletion_requested_at = now() WHERE id = $1`, [user]);
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(tokens) }));
    assert.equal((await family(tokens.sessionId)).revoked_reason, 'account');
    await assert.rejects(() => issuer.userinfo(tokens.accessToken), /unknown or expired/);
  });

  it('takes everything with a purged account', async () => {
    at(0);
    const user = await newUser('purged@example.test');
    const tokens = await signIn({ userId: user });
    await db.query(`DELETE FROM identity.users WHERE id = $1`, [user]);
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(tokens) }));
    const left = await db.query(`SELECT 1 FROM identity.oidc_refresh_families WHERE id = $1`, [tokens.sessionId]);
    assert.equal(left.length, 0);
  });
});

describe('taking the flag away', { skip }, () => {
  it('revokes what the client holds, so giving it back revives nothing', async () => {
    at(0);
    await issuer.registerClient({
      clientId: 'tablet',
      name: 'The tablet app',
      redirectUris: [PHONE_CB],
      firstParty: true,
      allowRefresh: true,
    });
    const tokens = await signIn({ clientId: 'tablet' });
    const phone = await signIn();

    // A row edited by hand: refused, though nothing has revoked it yet.
    await db.query(`UPDATE identity.oidc_clients SET allow_refresh = false WHERE client_id = 'tablet'`);
    await refused(issuer.refresh({ clientId: 'tablet', refreshToken: refreshOf(tokens) }));
    assert.equal((await family(tokens.sessionId)).revoked_at, null);

    await issuer.registerClient({
      clientId: 'tablet',
      name: 'The tablet app',
      redirectUris: [PHONE_CB],
      firstParty: true,
    });
    assert.equal((await family(tokens.sessionId)).revoked_reason, 'client');
    await assert.rejects(() => issuer.userinfo(tokens.accessToken), /unknown or expired/);

    await issuer.registerClient({
      clientId: 'tablet',
      name: 'The tablet app',
      redirectUris: [PHONE_CB],
      firstParty: true,
      allowRefresh: true,
    });
    await refused(issuer.refresh({ clientId: 'tablet', refreshToken: refreshOf(tokens) }));
    // Another client's families were not touched.
    assert.equal((await family(phone.sessionId)).revoked_at, null);
  });

  it('refuses a disabled client outright', async () => {
    at(0);
    await issuer.registerClient({
      clientId: 'retired-app',
      name: 'x',
      redirectUris: [PHONE_CB],
      firstParty: true,
      allowRefresh: true,
    });
    const tokens = await signIn({ clientId: 'retired-app' });
    await db.query(`UPDATE identity.oidc_clients SET disabled_at = now() WHERE client_id = 'retired-app'`);
    await assert.rejects(
      () => issuer.refresh({ clientId: 'retired-app', refreshToken: refreshOf(tokens) }),
      /unknown client/,
    );
  });
});

describe('at rest', { skip }, () => {
  it('holds no token in the clear, in any column of any table', async () => {
    at(0);
    const first = await signIn({ deviceLabel: 'at rest' });
    const second = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(first) });
    const third = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(second) });
    // `second` is retired with its successor sealed beside it, which is the
    // column most likely to be holding something it should not.
    const secrets = [first, second, third].flatMap((t) => [refreshOf(t), t.accessToken]);

    const dump = (
      await db.query<{ row: string }>(
        `SELECT row_to_json(t)::text AS row FROM identity.oidc_refresh_tokens t
         UNION ALL SELECT row_to_json(f)::text FROM identity.oidc_refresh_families f
         UNION ALL SELECT row_to_json(a)::text FROM identity.oidc_access_tokens a
         UNION ALL SELECT row_to_json(c)::text FROM identity.oidc_codes c
         UNION ALL SELECT row_to_json(e)::text FROM identity.events e`,
      )
    )
      .map((r) => r.row)
      .join('\n');
    assert.ok(dump.includes(b64(refreshOf(third))), 'the dump is of the right tables');
    for (const secret of secrets) assert.ok(!dump.includes(secret), 'a token is stored in the clear');

    // What is stored is the sha256, as for every other token the issuer holds.
    const stored = await db.query<{ token_hash: string; sealed_successor: string | null }>(
      `SELECT token_hash, sealed_successor FROM identity.oidc_refresh_tokens WHERE family_id = $1`,
      [first.sessionId],
    );
    assert.deepEqual(
      stored.map((r) => r.token_hash).sort(),
      [first, second, third].map((t) => b64(refreshOf(t))).sort(),
    );
    // The seal is ciphertext: a fresh nonce each time, and not the successor.
    const sealed = stored.find((r) => r.token_hash === b64(refreshOf(second)))?.sealed_successor as string;
    assert.ok(sealed);
    assert.ok(!Buffer.from(sealed, 'base64url').toString('latin1').includes(refreshOf(third)));
  });
});

describe('housekeeping', { skip }, () => {
  it('sweeps families that are revoked, expired or idle, and keeps the live ones whole', async () => {
    at(0);
    const user = await newUser('sweep@example.test');
    const live = await signIn({ userId: user });
    const liveNext = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(live) });
    const revoked = await signIn({ userId: user });
    await issuer.revoke({ token: refreshOf(revoked), clientId: 'phone' });
    const short = createOidcIssuer({ db, issuer: ISSUER, clock, refreshTokens: { absoluteTtlMs: DAY } });
    const expired = await signIn({ iss: short, userId: user });

    at(DAY + 1);
    const report = await issuer.sweep();
    assert.ok(report.refreshFamilies >= 2);
    const left = await db.query<{ id: string }>(
      `SELECT id::text AS id FROM identity.oidc_refresh_families WHERE user_id = $1`,
      [user],
    );
    assert.deepEqual(
      left.map((r) => r.id),
      [live.sessionId],
    );
    assert.ok(![revoked.sessionId, expired.sessionId].includes(left[0]?.id));
    // The live family kept its retired token: a replay is still recognised.
    at(DAY + 2);
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(live) }));
    assert.equal((await family(live.sessionId)).revoked_reason, 'reuse');
    await refused(issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(liveNext) }));

    at(DAY + 2 + REFRESH_IDLE_TTL_MS);
    const idle = await signIn({ userId: user });
    at(DAY + 2 + 2 * REFRESH_IDLE_TTL_MS);
    assert.ok((await issuer.sweep()).refreshFamilies >= 1);
    const gone = await db.query(`SELECT 1 FROM identity.oidc_refresh_families WHERE id = $1`, [idle.sessionId]);
    assert.equal(gone.length, 0, 'an idle family is swept');
  });
});

describe('the migration', { skip }, () => {
  it('is re-runnable, and leaves what is there alone', async () => {
    at(0);
    const tokens = await signIn();
    const sql = await readFile(fileURLToPath(new URL('../sql/012_oidc_refresh.sql', import.meta.url)), 'utf8');
    const counts = () =>
      db.query<{ families: string; tokens: string; clients: string }>(
        `SELECT (SELECT count(*) FROM identity.oidc_refresh_families)::text AS families,
                (SELECT count(*) FROM identity.oidc_refresh_tokens)::text AS tokens,
                (SELECT count(*) FROM identity.oidc_clients WHERE allow_refresh)::text AS clients`,
      );
    const before = await counts();
    await db.query(sql);
    await db.query(sql);
    assert.deepEqual(await counts(), before);
    const constraints = await db.query(
      `SELECT 1 FROM pg_constraint WHERE conname = 'oidc_clients_refresh_first_party'`,
    );
    assert.equal(constraints.length, 1);
    // And the token issued before it still works after it.
    const next = await issuer.refresh({ clientId: 'phone', refreshToken: refreshOf(tokens) });
    assert.ok(next.refreshToken);
  });
});

describe('revoking, underneath', { skip }, () => {
  it('names nothing when given nothing, rather than everything', async () => {
    at(0);
    const tokens = await signIn();
    const gone = await revokeFamilies(db, {} as { clientId: string }, 'revoked', now);
    assert.deepEqual(gone, []);
    assert.equal((await family(tokens.sessionId)).revoked_at, null);
  });

  // LAST in the file: it drops the provider's tables. The next file rebuilds
  // the schema, as every file does.
  it('is a no-op for a host that never applied the provider schema', async () => {
    const user = await newUser('no-provider@example.test');
    await db.query(`UPDATE identity.users SET email_verified_at = now() WHERE id = $1`, [user]);
    const login = await identity.login({ email: 'no-provider@example.test', password: PASSWORD });
    assert.equal(login.kind, 'session');
    await db.query(
      `DROP TABLE identity.oidc_access_tokens, identity.oidc_refresh_tokens, identity.oidc_refresh_families,
                  identity.oidc_codes, identity.oidc_clients CASCADE`,
    );
    assert.equal(await revokeUserRefreshFamilies(db, user, 'signed_out'), 0);
    // The core's own revocation is untouched by the missing tables.
    assert.equal(await identity.revokeAllSessions(user), 1);
    await identity.changePassword(user, PASSWORD, 'yet another long password');
  });
});
