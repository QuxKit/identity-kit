// OIDC. The protocol (discovery, PKCE, state/nonce, ID-token validation) is
// openid-client's and is exercised against a live provider, not here. What IS
// tested here — directly, with crafted claims and no network — is the part
// identity-kit owns and the part that is a takeover vector if wrong: the
// account-linking policy.

import assert from 'node:assert/strict';
import { createHash, randomBytes } from 'node:crypto';
import { after, describe, it } from 'node:test';

import { IdentityError } from '../src/errors.ts';
import { createOidc } from '../src/oidc.ts';
import { linkOrCreate } from '../src/oidc-link.ts';
import { type Harness, one, SKIP_REASON, setupDatabase } from './harness.ts';
import { startMockIssuer } from './mock-issuer.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

const NOW = new Date('2026-08-15T12:00:00Z');

describe('identity-kit/oidc — wiring (no network)', () => {
  it('an unknown provider is a typed error before any discovery', async () => {
    const oidc = createOidc({
      db: { query: async () => [], transaction: async (fn) => fn({} as never) },
      providers: {},
    });
    await assert.rejects(
      () => oidc.begin('nope'),
      (e: unknown) => IdentityError.hasCode(e, 'unknown_provider') && e.failure.provider === 'nope',
    );
    await assert.rejects(
      () => oidc.complete('nope', 'https://app.test/cb?code=x&state=y', { state: 'y', nonce: 'n', codeVerifier: 'v' }),
      (e: unknown) => IdentityError.hasCode(e, 'unknown_provider'),
    );
  });

  it('allowInsecureRequests is refused for anything but loopback', async () => {
    const oidc = createOidc({
      db: { query: async () => [], transaction: async (fn) => fn({} as never) },
      providers: {
        remote: {
          issuer: 'http://accounts.example.com',
          clientId: 'c',
          redirectUri: 'https://app.test/cb',
          allowInsecureRequests: true,
        },
      },
    });
    await assert.rejects(
      () => oidc.begin('remote'),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_config') && /loopback/.test(e.failure.reason),
    );
  });
});

describe('identity-kit/oidc — account linking', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;

  // A local password account, optionally email-verified.
  const localUser = async (email: string, verified: boolean): Promise<string> => {
    const rows = await h.db.query<{ id: string }>(
      `INSERT INTO identity.users (email, email_display, email_verified_at, password_hash)
       VALUES ($1, $2, $3, 'x') RETURNING id`,
      [email, email, verified ? NOW : null],
    );
    return one(rows).id;
  };

  const claims = (over: Partial<Parameters<typeof linkOrCreate>[1]> = {}) => ({
    provider: 'google',
    subject: `sub-${Math.random().toString(36).slice(2)}`,
    email: 'user@example.com',
    emailVerified: true,
    ...over,
  });

  it('creates a new user, verified only if the provider verified the email', async () => {
    const r = await linkOrCreate(h.db, claims({ email: 'new-verified@example.com', emailVerified: true }), NOW);
    assert.equal(r.kind, 'ok');
    if (r.kind !== 'ok') return;
    assert.equal(r.isNewUser, true);
    const rows = await h.db.query<{ email_verified_at: Date | null; password_hash: string | null }>(
      'SELECT email_verified_at, password_hash FROM identity.users WHERE id = $1',
      [r.userId],
    );
    assert.ok(one(rows).email_verified_at, 'provider-verified email is verified');
    assert.equal(one(rows).password_hash, null, 'an oauth account has no password');

    const unv = await linkOrCreate(h.db, claims({ email: 'new-unverified@example.com', emailVerified: false }), NOW);
    if (unv.kind !== 'ok') return assert.fail('expected ok');
    const urows = await h.db.query<{ email_verified_at: Date | null }>(
      'SELECT email_verified_at FROM identity.users WHERE id = $1',
      [unv.userId],
    );
    assert.equal(one(urows).email_verified_at, null, 'provider-unverified email stays unverified');
  });

  it('returns the same user for an already-linked identity', async () => {
    const c = claims({ email: 'repeat@example.com' });
    const first = await linkOrCreate(h.db, c, NOW);
    const second = await linkOrCreate(h.db, c, NOW);
    assert.equal(first.kind, 'ok');
    assert.equal(second.kind, 'ok');
    if (first.kind === 'ok' && second.kind === 'ok') {
      assert.equal(second.userId, first.userId);
      assert.equal(second.isNewUser, false);
    }
  });

  it('links to an existing account only when BOTH sides verified the email', async () => {
    const userId = await localUser('both-verified@example.com', true);
    const r = await linkOrCreate(h.db, claims({ email: 'both-verified@example.com', emailVerified: true }), NOW);
    assert.equal(r.kind, 'ok');
    if (r.kind === 'ok') {
      assert.equal(r.userId, userId, 'linked to the existing account');
      assert.equal(r.isNewUser, false);
    }
  });

  it('REFUSES to link when the provider email is unverified (the takeover)', async () => {
    await localUser('victim@example.com', true);
    const r = await linkOrCreate(h.db, claims({ email: 'victim@example.com', emailVerified: false }), NOW);
    assert.equal(r.kind, 'conflict', 'an unverified provider email must never attach to an existing account');
  });

  it('REFUSES to link when the existing account is unverified', async () => {
    await localUser('squatted@example.com', false);
    const r = await linkOrCreate(h.db, claims({ email: 'squatted@example.com', emailVerified: true }), NOW);
    assert.equal(r.kind, 'conflict', 'a provider login must not take over a squatted unverified signup');
  });

  it('reports no_email when the provider returns none', async () => {
    const r = await linkOrCreate(h.db, claims({ email: null }), NOW);
    assert.equal(r.kind, 'no_email');
  });
});

// --- end to end, against an in-process issuer --------------------------------
//
// The linking policy above is the security decision; this is the wiring. Both
// matter: a policy that is never reached because `nonce` is dropped on the way
// to the provider is just as broken. The issuer is `test/mock-issuer.ts` —
// discovery, JWKS, authorize and token, RS256 via node:crypto, no new deps.

describe('identity-kit/oidc — end to end against a mock issuer', {
  skip: harness === null ? SKIP_REASON : false,
}, () => {
  const h = harness as Harness;

  const withIssuer = async <T>(
    opts: Parameters<typeof startMockIssuer>[0] & { redirectUri?: string },
    fn: (issuer: Awaited<ReturnType<typeof startMockIssuer>>, oidc: ReturnType<typeof createOidc>) => Promise<T>,
  ): Promise<T> => {
    const issuer = await startMockIssuer(opts);
    const oidc = createOidc({
      db: h.db,
      providers: {
        mock: {
          issuer: issuer.url,
          clientId: opts.clientId,
          clientSecret: opts.clientSecret,
          redirectUri: opts.redirectUri ?? 'https://app.test/callback',
          allowInsecureRequests: true,
        },
      },
      clock: () => NOW,
    });
    try {
      return await fn(issuer, oidc);
    } finally {
      await issuer.close();
    }
  };

  const CLIENT = { clientId: 'client-abc', clientSecret: 'shhh' };

  it('begin sends PKCE S256, state and nonce; complete exchanges the code and links the account', async () => {
    await withIssuer(
      { ...CLIENT, claims: { sub: 'sub-e2e-1', email: 'e2e-new@example.com', email_verified: true } },
      async (issuer, oidc) => {
        const begun = await oidc.begin('mock');
        const sent = new URL(begun.url).searchParams;
        assert.equal(sent.get('client_id'), CLIENT.clientId);
        assert.equal(sent.get('redirect_uri'), 'https://app.test/callback');
        assert.equal(sent.get('scope'), 'openid email profile');
        assert.equal(sent.get('state'), begun.state);
        assert.equal(sent.get('nonce'), begun.nonce);
        assert.equal(sent.get('code_challenge_method'), 'S256');
        // the challenge really is S256(verifier) — not the verifier itself
        assert.equal(
          sent.get('code_challenge'),
          createHash('sha256').update(begun.codeVerifier).digest('base64url'),
          'PKCE challenge is the hash of the verifier',
        );
        assert.notEqual(sent.get('code_challenge'), begun.codeVerifier);

        const callback = issuer.authorize(begun.url);
        const { outcome, claims } = await oidc.complete('mock', callback, begun);
        assert.equal(claims.subject, 'sub-e2e-1');
        assert.equal(claims.email, 'e2e-new@example.com');
        assert.equal(claims.emailVerified, true);
        assert.equal(outcome.kind, 'ok');
        if (outcome.kind !== 'ok') return;
        assert.equal(outcome.isNewUser, true);
        // the row the policy wrote
        const rows = await h.db.query<{ user_id: string; email: string }>(
          'SELECT user_id, email FROM identity.oauth_identities WHERE provider = $1 AND subject = $2',
          ['mock', 'sub-e2e-1'],
        );
        assert.equal(one(rows).user_id, outcome.userId);
        // the code is spent: a second complete with the same callback fails
        await assert.rejects(() => oidc.complete('mock', callback, begun));

        // a second full round trip for the same subject returns the same user
        const again = await oidc.begin('mock');
        const second = await oidc.complete('mock', issuer.authorize(again.url), again);
        assert.equal(second.outcome.kind, 'ok');
        if (second.outcome.kind === 'ok') {
          assert.equal(second.outcome.userId, outcome.userId);
          assert.equal(second.outcome.isNewUser, false);
        }
      },
    );
  });

  it('refuses a mismatched state, nonce or PKCE verifier', async () => {
    await withIssuer(
      { ...CLIENT, claims: { sub: 'sub-e2e-2', email: 'e2e-checks@example.com' } },
      async (issuer, oidc) => {
        const begun = await oidc.begin('mock');
        const callback = issuer.authorize(begun.url);
        await assert.rejects(
          () => oidc.complete('mock', callback, { ...begun, state: 'not-the-state' }),
          'a state that does not match the one we issued is a CSRF attempt',
        );

        const b2 = await oidc.begin('mock');
        const cb2 = issuer.authorize(b2.url);
        await assert.rejects(
          () => oidc.complete('mock', cb2, { ...b2, nonce: 'not-the-nonce' }),
          'a nonce that does not match binds the ID token to another request',
        );

        const b3 = await oidc.begin('mock');
        const cb3 = issuer.authorize(b3.url);
        await assert.rejects(
          () => oidc.complete('mock', cb3, { ...b3, codeVerifier: randomBytes(32).toString('base64url') }),
          'a verifier that does not hash to the challenge means the code was intercepted',
        );
      },
    );
  });

  it('refuses an ID token signed by a key the JWKS does not publish', async () => {
    await withIssuer({ ...CLIENT, wrongKey: true, claims: { sub: 'sub-e2e-3' } }, async (issuer, oidc) => {
      const begun = await oidc.begin('mock');
      await assert.rejects(() => oidc.complete('mock', issuer.authorize(begun.url), begun));
    });
  });

  it('refuses a token response with a missing nonce claim, and reports one with no ID token', async () => {
    await withIssuer({ ...CLIENT, omitNonce: true, claims: { sub: 'sub-e2e-4' } }, async (issuer, oidc) => {
      const begun = await oidc.begin('mock');
      await assert.rejects(() => oidc.complete('mock', issuer.authorize(begun.url), begun));
    });
    await withIssuer({ ...CLIENT, omitIdToken: true, claims: { sub: 'sub-e2e-5' } }, async (issuer, oidc) => {
      const begun = await oidc.begin('mock');
      await assert.rejects(
        () => oidc.complete('mock', issuer.authorize(begun.url), begun),
        (e: unknown) => e instanceof Error,
      );
    });
  });

  it('coerces Apple’s string email_verified, and carries a provider-unverified email through as unverified', async () => {
    await withIssuer(
      { ...CLIENT, claims: { sub: 'sub-e2e-6', email: 'e2e-apple@example.com', email_verified: 'true' } },
      async (issuer, oidc) => {
        const begun = await oidc.begin('mock');
        const { claims, outcome } = await oidc.complete('mock', issuer.authorize(begun.url), begun);
        assert.equal(claims.emailVerified, true, 'the string "true" is a verified email');
        assert.equal(outcome.kind, 'ok');
        if (outcome.kind !== 'ok') return;
        const rows = await h.db.query<{ email_verified_at: Date | null }>(
          'SELECT email_verified_at FROM identity.users WHERE id = $1',
          [outcome.userId],
        );
        assert.ok(one(rows).email_verified_at);
      },
    );
    await withIssuer(
      { ...CLIENT, claims: { sub: 'sub-e2e-7', email: 'e2e-unverified@example.com', email_verified: false } },
      async (issuer, oidc) => {
        const begun = await oidc.begin('mock');
        const { claims, outcome } = await oidc.complete('mock', issuer.authorize(begun.url), begun);
        assert.equal(claims.emailVerified, false);
        if (outcome.kind !== 'ok') return assert.fail('expected ok');
        const rows = await h.db.query<{ email_verified_at: Date | null }>(
          'SELECT email_verified_at FROM identity.users WHERE id = $1',
          [outcome.userId],
        );
        assert.equal(one(rows).email_verified_at, null);
      },
    );
  });

  it('the takeover is refused end to end: an unverified provider email over a verified local account', async () => {
    const rows = await h.db.query<{ id: string }>(
      `INSERT INTO identity.users (email, email_display, email_verified_at, password_hash)
       VALUES ($1, $1, $2, 'x') RETURNING id`,
      ['e2e-victim@example.com', NOW],
    );
    const victim = one(rows).id;
    await withIssuer(
      { ...CLIENT, claims: { sub: 'sub-e2e-8', email: 'e2e-victim@example.com', email_verified: false } },
      async (issuer, oidc) => {
        const begun = await oidc.begin('mock');
        const { outcome } = await oidc.complete('mock', issuer.authorize(begun.url), begun);
        assert.equal(outcome.kind, 'conflict');
        const linked = await h.db.query('SELECT 1 FROM identity.oauth_identities WHERE user_id = $1', [victim]);
        assert.equal(linked.length, 0, 'nothing was linked to the victim');
      },
    );
    // ...and accepted once the provider does verify it
    await withIssuer(
      { ...CLIENT, claims: { sub: 'sub-e2e-9', email: 'e2e-victim@example.com', email_verified: true } },
      async (issuer, oidc) => {
        const begun = await oidc.begin('mock');
        const { outcome } = await oidc.complete('mock', issuer.authorize(begun.url), begun);
        assert.equal(outcome.kind, 'ok');
        if (outcome.kind === 'ok') assert.equal(outcome.userId, victim);
      },
    );
  });

  it('a provider with no email cannot create a user, and custom scopes are forwarded', async () => {
    const issuer = await startMockIssuer({ ...CLIENT, claims: { sub: 'sub-e2e-10', email: null } });
    const oidc = createOidc({
      db: h.db,
      providers: {
        mock: {
          issuer: issuer.url,
          clientId: CLIENT.clientId,
          clientSecret: CLIENT.clientSecret,
          redirectUri: 'https://app.test/callback',
          scopes: ['openid', 'email'],
          allowInsecureRequests: true,
        },
      },
    });
    try {
      const begun = await oidc.begin('mock');
      assert.equal(new URL(begun.url).searchParams.get('scope'), 'openid email');
      const { outcome } = await oidc.complete('mock', issuer.authorize(begun.url), begun);
      assert.equal(outcome.kind, 'no_email');
    } finally {
      await issuer.close();
    }
  });
});
