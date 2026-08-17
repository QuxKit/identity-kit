// OIDC. The protocol (discovery, PKCE, state/nonce, ID-token validation) is
// openid-client's and is exercised against a live provider, not here. What IS
// tested here — directly, with crafted claims and no network — is the part
// identity-kit owns and the part that is a takeover vector if wrong: the
// account-linking policy.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import { IdentityError } from '../src/errors.ts';
import { createOidc } from '../src/oidc.ts';
import { linkOrCreate } from '../src/oidc-link.ts';
import { type Harness, one, SKIP_REASON, setupDatabase } from './harness.ts';

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
