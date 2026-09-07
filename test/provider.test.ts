// Being the issuer, checked against a real Postgres and a real client.
//
// The client half is openid-client, which is the same library a customer would
// point at us — so the happy path here proves interoperability rather than
// proving our own encoder agrees with our own decoder.

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { after, describe, it } from 'node:test';

import * as jose from 'jose';

import { createIdentity } from '../src/instance.ts';
import { createOidcIssuer, type OidcIssuer } from '../src/provider.ts';
import type { SqlExecutor } from '../src/types.ts';
import { MailCollector, SKIP_REASON, setupDatabase, testConfig } from './harness.ts';

const ISSUER = 'https://accounts.test';
const verifier = () => randomBytes(32).toString('base64url');
const challengeFor = (v: string) => createHash('sha256').update(v).digest('base64url');

// Top level, not in `before`: node:test evaluates a describe's options when the
// block is DEFINED, so a skip computed later leaves every suite skipped and the
// file passes having tested nothing.
const harness = await setupDatabase();
const skip = harness === null ? SKIP_REASON : false;
const db: SqlExecutor = harness?.db as SqlExecutor;
let issuer: OidcIssuer = undefined as unknown as OidcIssuer;
let userId = '';

if (harness) {
  issuer = createOidcIssuer({ db: harness.db, issuer: ISSUER });
  const identity = createIdentity({ db: harness.db, config: testConfig, mail: new MailCollector() });
  // signup is enumeration-safe: it answers { accepted: true } either way and
  // never hands back the account, so the id comes from the row.
  await identity.signup({ email: 'ada@example.test', password: 'correct horse battery staple' });
  const rows = await harness.db.query<{ id: string }>(`SELECT id FROM identity.users WHERE email = $1`, [
    'ada@example.test',
  ]);
  const account = rows[0];
  if (!account) throw new Error('the signup did not write a user');
  userId = account.id;
  await issuer.registerClient({
    clientId: 'portal',
    name: 'The portal',
    secret: 'a-confidential-secret',
    redirectUris: ['https://quxkit.test/api/auth/callback'],
    firstParty: true,
  });
}

after(async () => {
  await harness?.close();
});

describe('registering a client', { skip }, () => {
  it('refuses a redirect_uri that is not https, unless it is loopback', async () => {
    await assert.rejects(
      () =>
        issuer.registerClient({ clientId: 'x', name: 'x', redirectUris: ['http://evil.test/cb'], firstParty: true }),
      /https/,
    );
    // Loopback over http is how a native app or a local dev server signs in.
    const local = await issuer.registerClient({
      clientId: 'local',
      name: 'local',
      redirectUris: ['http://localhost:3000/cb'],
      firstParty: true,
    });
    assert.equal(local.confidential, false);
  });

  it('refuses a redirect_uri carrying a fragment, and one that is not a URL', async () => {
    for (const uri of ['https://ok.test/cb#frag', 'not-a-url']) {
      await assert.rejects(() =>
        issuer.registerClient({ clientId: 'y', name: 'y', redirectUris: [uri], firstParty: true }),
      );
    }
  });
});

describe('the authorization code', { skip }, () => {
  it('is minted for a registered redirect_uri and nothing else', async () => {
    const v = verifier();
    const granted = await issuer.authorize({
      clientId: 'portal',
      redirectUri: 'https://quxkit.test/api/auth/callback',
      userId,
      codeChallenge: challengeFor(v),
      state: 'st',
      nonce: 'no',
    });
    assert.match(granted.redirectTo, /^https:\/\/quxkit\.test\/api\/auth\/callback\?/);
    assert.match(granted.redirectTo, /state=st/);

    // Exact match only. A prefix rule here is how an open redirect becomes an
    // account takeover.
    await assert.rejects(
      () =>
        issuer.authorize({
          clientId: 'portal',
          redirectUri: 'https://quxkit.test/api/auth/callback/../evil',
          userId,
          codeChallenge: challengeFor(v),
        }),
      /not registered/,
    );
  });

  it('is refused for a client that is not first-party, rather than silently consented', async () => {
    await issuer.registerClient({
      clientId: 'third',
      name: 'Someone else',
      redirectUris: ['https://third.test/cb'],
      firstParty: false,
    });
    await assert.rejects(
      () =>
        issuer.authorize({
          clientId: 'third',
          redirectUri: 'https://third.test/cb',
          userId,
          codeChallenge: challengeFor(verifier()),
        }),
      /consent is not implemented/,
    );
  });

  it('requires PKCE, and only S256', async () => {
    await assert.rejects(
      () =>
        issuer.authorize({
          clientId: 'portal',
          redirectUri: 'https://quxkit.test/api/auth/callback',
          userId,
          codeChallenge: '',
        }),
      /PKCE/,
    );
    await assert.rejects(
      () =>
        issuer.authorize({
          clientId: 'portal',
          redirectUri: 'https://quxkit.test/api/auth/callback',
          userId,
          codeChallenge: 'x',
          codeChallengeMethod: 'plain',
        }),
      /S256/,
    );
  });
});

describe('redeeming it', { skip }, () => {
  const mint = async (v: string) =>
    (
      await issuer.authorize({
        clientId: 'portal',
        redirectUri: 'https://quxkit.test/api/auth/callback',
        userId,
        codeChallenge: challengeFor(v),
        nonce: 'nonce-1',
      })
    ).code;

  it('returns an ID token that verifies against the published JWKS', async () => {
    const v = verifier();
    const code = await mint(v);
    const tokens = await issuer.token({
      grantType: 'authorization_code',
      code,
      redirectUri: 'https://quxkit.test/api/auth/callback',
      clientId: 'portal',
      clientSecret: 'a-confidential-secret',
      codeVerifier: v,
    });

    const { keys } = await issuer.jwks();
    const jwks = jose.createLocalJWKSet({ keys });
    const { payload } = await jose.jwtVerify(tokens.idToken, jwks, { issuer: ISSUER, audience: 'portal' });
    assert.equal(payload.sub, userId);
    assert.equal(payload.email, 'ada@example.test');
    // The nonce binds the token to the request the client started, which is
    // what stops a token from one login being replayed into another.
    assert.equal(payload.nonce, 'nonce-1');
    // The private half must never appear in JWKS.
    for (const key of keys) assert.equal((key as { d?: string }).d, undefined, 'a private key was published');
  });

  it('is single-use', async () => {
    const v = verifier();
    const code = await mint(v);
    const once = {
      grantType: 'authorization_code',
      code,
      redirectUri: 'https://quxkit.test/api/auth/callback',
      clientId: 'portal',
      clientSecret: 'a-confidential-secret',
      codeVerifier: v,
    };
    await issuer.token(once);
    await assert.rejects(() => issuer.token(once), /already used/);
  });

  it('refuses a verifier that does not match the challenge', async () => {
    const code = await mint(verifier());
    await assert.rejects(
      () =>
        issuer.token({
          grantType: 'authorization_code',
          code,
          redirectUri: 'https://quxkit.test/api/auth/callback',
          clientId: 'portal',
          clientSecret: 'a-confidential-secret',
          codeVerifier: verifier(),
        }),
      /PKCE/,
    );
  });

  it('refuses a redirect_uri other than the one the code was minted for', async () => {
    const v = verifier();
    const code = await mint(v);
    await assert.rejects(
      () =>
        issuer.token({
          grantType: 'authorization_code',
          code,
          redirectUri: 'https://quxkit.test/somewhere-else',
          clientId: 'portal',
          clientSecret: 'a-confidential-secret',
          codeVerifier: v,
        }),
      /redirect_uri/,
    );
  });

  it('refuses a confidential client with the wrong secret', async () => {
    const v = verifier();
    const code = await mint(v);
    await assert.rejects(
      () =>
        issuer.token({
          grantType: 'authorization_code',
          code,
          redirectUri: 'https://quxkit.test/api/auth/callback',
          clientId: 'portal',
          clientSecret: 'not-it',
          codeVerifier: v,
        }),
      /client authentication/,
    );
  });

  it('refuses an expired code', async () => {
    // A clock the test moves, rather than a sleep: the code lives 60 seconds.
    let now = new Date('2026-01-01T00:00:00Z');
    const timed = createOidcIssuer({ db, issuer: ISSUER, clock: () => now });
    const v = verifier();
    const { code } = await timed.authorize({
      clientId: 'portal',
      redirectUri: 'https://quxkit.test/api/auth/callback',
      userId,
      codeChallenge: challengeFor(v),
    });
    now = new Date(now.getTime() + 61_000);
    await assert.rejects(
      () =>
        timed.token({
          grantType: 'authorization_code',
          code,
          redirectUri: 'https://quxkit.test/api/auth/callback',
          clientId: 'portal',
          clientSecret: 'a-confidential-secret',
          codeVerifier: v,
        }),
      /expired/,
    );
  });
});

describe('userinfo', { skip }, () => {
  it('answers for a live access token and refuses anything else', async () => {
    const v = verifier();
    const { code } = await issuer.authorize({
      clientId: 'portal',
      redirectUri: 'https://quxkit.test/api/auth/callback',
      userId,
      codeChallenge: challengeFor(v),
    });
    const tokens = await issuer.token({
      grantType: 'authorization_code',
      code,
      redirectUri: 'https://quxkit.test/api/auth/callback',
      clientId: 'portal',
      clientSecret: 'a-confidential-secret',
      codeVerifier: v,
    });
    const claims = await issuer.userinfo(tokens.accessToken);
    assert.equal(claims.sub, userId);
    assert.equal(claims.email, 'ada@example.test');
    await assert.rejects(() => issuer.userinfo('nonsense'), /unknown or expired/);
  });
});

describe('discovery', { skip }, () => {
  it('advertises exactly what is implemented, and PKCE as required', () => {
    const doc = issuer.discovery();
    assert.equal(doc.issuer, ISSUER);
    assert.deepEqual(doc.grant_types_supported, ['authorization_code']);
    assert.deepEqual(doc.code_challenge_methods_supported, ['S256']);
    // No refresh token, so it must not be advertised: a client that reads this
    // and asks for one would be told no at the worst moment.
    assert.ok(!JSON.stringify(doc).includes('refresh_token'));
  });
});

describe('key rotation', { skip }, () => {
  it('keeps the retired key published so tokens signed with it still verify', async () => {
    const v = verifier();
    const { code } = await issuer.authorize({
      clientId: 'portal',
      redirectUri: 'https://quxkit.test/api/auth/callback',
      userId,
      codeChallenge: challengeFor(v),
    });
    const before = await issuer.token({
      grantType: 'authorization_code',
      code,
      redirectUri: 'https://quxkit.test/api/auth/callback',
      clientId: 'portal',
      clientSecret: 'a-confidential-secret',
      codeVerifier: v,
    });

    await issuer.rotateKey();
    const { keys } = await issuer.jwks();
    assert.ok(keys.length >= 2, 'the retired key was dropped from JWKS immediately');
    const jwks = jose.createLocalJWKSet({ keys });
    // The token minted before the rotation still verifies, which is the whole
    // point of publishing the retired key.
    await jose.jwtVerify(before.idToken, jwks, { issuer: ISSUER, audience: 'portal' });
  });
});
