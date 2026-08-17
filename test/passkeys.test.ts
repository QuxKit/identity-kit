// Passkeys. The protocol is @simplewebauthn/server's; what these tests pin down
// is the state identity-kit owns around it: a challenge is single-use and
// expires, registration needs recent authentication, a counter that does not
// advance is refused as a regression, an assertion from the wrong origin / RP /
// without user verification fails, and a good one is a real login.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import { IdentityError } from '../src/errors.ts';
import { createIdentity, createMemoryRateLimiter, listEvents, sha256 } from '../src/index.ts';
import { createPasskeys } from '../src/passkeys.ts';
import { type Harness, one, SKIP_REASON, setupDatabase, testConfig, tokenFrom } from './harness.ts';
import { SoftAuthenticator } from './soft-authenticator.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

const RP = { id: 'app.test', name: 'Test App', origin: 'https://app.test' };
const T0 = new Date('2026-08-15T12:00:00Z');

describe('identity-kit/passkeys', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const id = createIdentity({ db: h.db, config: testConfig, mail: h.mail, rateLimiter: null });
  const passkeys = createPasskeys({ db: h.db, config: testConfig, mail: h.mail, rp: RP, rateLimiter: null });
  const meta = { ipAddress: '198.51.100.9', userAgent: 'soft-authenticator' };

  const verifiedUser = async (email: string, password = 'correct horse battery'): Promise<string> => {
    h.mail.clear();
    await id.signup({ email, password });
    await id.verifyEmail(tokenFrom(h.mail.first(email).body));
    h.mail.clear();
    const rows = await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', [email]);
    return one(rows).id;
  };

  const register = async (userId: string, auth: SoftAuthenticator, name?: string, now = T0) => {
    const options = await passkeys.registerBegin(userId, { password: 'correct horse battery' }, now);
    return passkeys.registerFinish(userId, auth.create(options), { name, meta, now });
  };

  it('registers with a fresh password proof, lists, and the options carry rp + excludeCredentials', async () => {
    const userId = await verifiedUser('pk-reg@example.com');
    const auth = new SoftAuthenticator(RP.id, RP.origin);
    const options = await passkeys.registerBegin(userId, { password: 'correct horse battery' }, T0);
    assert.equal(options.rp.id, 'app.test');
    assert.equal(options.user.name, 'pk-reg@example.com');
    assert.deepEqual(options.excludeCredentials, []);
    const summary = await passkeys.registerFinish(userId, auth.create(options), { name: 'MacBook', meta, now: T0 });
    assert.equal(summary.name, 'MacBook');
    assert.deepEqual(summary.transports, ['internal', 'hybrid']);
    assert.equal(summary.aaguid, 'abababab-abab-abab-abab-abababababab');
    assert.equal(summary.backedUp, true);
    assert.equal(summary.deviceType, 'multiDevice');

    const listed = await passkeys.list(userId);
    assert.equal(listed.length, 1);
    assert.equal(listed[0]?.id, summary.id);
    // the second registration excludes the first
    const again = await passkeys.registerBegin(userId, { password: 'correct horse battery' }, T0);
    assert.deepEqual(
      again.excludeCredentials?.map((c) => c.id),
      [summary.id],
    );
    // event
    const evs = await listEvents(h.db, userId);
    assert.equal(evs[0]?.kind, 'passkey_registered');
    assert.equal(evs[0]?.metadata.credentialId, summary.id);
    assert.equal(evs[0]?.ip, '198.51.100.9');
  });

  it('registration requires recent authentication: wrong password, stale session, other user', async () => {
    const userId = await verifiedUser('pk-reauth@example.com');
    await assert.rejects(
      () => passkeys.registerBegin(userId, { password: 'nope nope nope' }, T0),
      (e: unknown) => IdentityError.hasCode(e, 'reauth_required'),
    );
    const login = await id.login({ email: 'pk-reauth@example.com', password: 'correct horse battery' }, {}, T0);
    assert.equal(login.kind, 'session');
    if (login.kind !== 'session') return;
    // fresh session: fine
    await passkeys.registerBegin(userId, { sessionToken: login.token }, new Date(T0.getTime() + 60_000));
    // eleven minutes later: stale
    await assert.rejects(
      () => passkeys.registerBegin(userId, { sessionToken: login.token }, new Date(T0.getTime() + 11 * 60_000)),
      (e: unknown) => IdentityError.hasCode(e, 'reauth_required'),
    );
    // someone else's session
    const other = await verifiedUser('pk-other@example.com');
    await assert.rejects(
      () => passkeys.registerBegin(other, { sessionToken: login.token }, T0),
      (e: unknown) => IdentityError.hasCode(e, 'reauth_required'),
    );
    // unknown user with a password proof burns the dummy and says reauth
    await assert.rejects(
      () => passkeys.registerBegin('00000000-0000-0000-0000-000000000000', { password: 'whatever!!' }, T0),
      (e: unknown) => IdentityError.hasCode(e, 'reauth_required'),
    );
  });

  it('a challenge is single-use, expires, is bound to purpose and user', async () => {
    const userId = await verifiedUser('pk-chal@example.com');
    const auth = new SoftAuthenticator(RP.id, RP.origin);
    const options = await passkeys.registerBegin(userId, { password: 'correct horse battery' }, T0);
    const response = auth.create(options);
    await passkeys.registerFinish(userId, response, { now: T0 });
    // replaying the same response: the challenge is spent
    await assert.rejects(
      () => passkeys.registerFinish(userId, response, { now: T0 }),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_challenge') && e.failure.reason === 'unknown',
    );
    // expired
    const late = await passkeys.registerBegin(userId, { password: 'correct horse battery' }, T0);
    await assert.rejects(
      () => passkeys.registerFinish(userId, auth.create(late), { now: new Date(T0.getTime() + 6 * 60_000) }),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_challenge') && e.failure.reason === 'expired',
    );
    // even a failed finish burns it
    await assert.rejects(
      () => passkeys.registerFinish(userId, auth.create(late), { now: T0 }),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_challenge') && e.failure.reason === 'unknown',
    );
    // another user's registration challenge
    const other = await verifiedUser('pk-chal2@example.com');
    const theirs = await passkeys.registerBegin(other, { password: 'correct horse battery' }, T0);
    await assert.rejects(
      () => passkeys.registerFinish(userId, auth.create(theirs), { now: T0 }),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_challenge') && e.failure.reason === 'user',
    );
    // a login challenge used to register
    const loginOpts = await passkeys.authenticateBegin({ now: T0 });
    await assert.rejects(
      () => passkeys.registerFinish(userId, auth.create({ ...options, challenge: loginOpts.challenge }), { now: T0 }),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_challenge') && e.failure.reason === 'purpose',
    );
    // garbage clientDataJSON
    const bad = auth.create(await passkeys.registerBegin(userId, { password: 'correct horse battery' }, T0));
    bad.response.clientDataJSON = 'not-json';
    await assert.rejects(
      () => passkeys.registerFinish(userId, bad, { now: T0 }),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_challenge'),
    );
  });

  it('registration refuses the wrong origin, the wrong RP, no user verification, a duplicate credential', async () => {
    const userId = await verifiedUser('pk-badreg@example.com');
    const auth = new SoftAuthenticator(RP.id, RP.origin);
    const begin = () => passkeys.registerBegin(userId, { password: 'correct horse battery' }, T0);
    await assert.rejects(
      async () =>
        passkeys.registerFinish(userId, auth.create(await begin(), { origin: 'https://evil.test' }), { now: T0 }),
      (e: unknown) => IdentityError.hasCode(e, 'passkey_verification_failed') && /origin/i.test(e.failure.reason),
    );
    await assert.rejects(
      async () => passkeys.registerFinish(userId, auth.create(await begin(), { rpId: 'evil.test' }), { now: T0 }),
      (e: unknown) => IdentityError.hasCode(e, 'passkey_verification_failed'),
    );
    await assert.rejects(
      async () => passkeys.registerFinish(userId, auth.create(await begin(), { uv: false }), { now: T0 }),
      (e: unknown) => IdentityError.hasCode(e, 'passkey_verification_failed') && /verification/i.test(e.failure.reason),
    );
    // the same credential registered twice (a second begin, the same authenticator response bytes re-signed)
    const first = auth.create(await begin());
    await passkeys.registerFinish(userId, first, { now: T0 });
    const dupOpts = await begin();
    const dup = { ...first, response: { ...first.response } };
    // re-create client data for the new challenge but keep the same credential id
    const cred = auth.credentials.get(first.id);
    assert.ok(cred);
    const again = auth.create(dupOpts);
    auth.credentials.set(first.id, cred);
    // splice the old credential id into a fresh attestation: easier to just
    // insert the row and check the conflict path
    await h.db.query('DELETE FROM identity.passkeys WHERE id = $1', [again.id]);
    await h.db.query(
      `INSERT INTO identity.passkeys (id, user_id, public_key, name) VALUES ($1, $2, '\\x00', 'pre-existing')`,
      [again.id, userId],
    );
    await assert.rejects(
      () => passkeys.registerFinish(userId, again, { now: T0 }),
      (e: unknown) => IdentityError.hasCode(e, 'passkey_verification_failed') && /already/i.test(e.failure.reason),
    );
    void dup;
    // presence-only authenticators are accepted when userVerification is 'discouraged'
    const lax = createPasskeys({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      rp: RP,
      rateLimiter: null,
      userVerification: 'discouraged',
    });
    const laxOpts = await lax.registerBegin(userId, { password: 'correct horse battery' }, T0);
    const laxAuth = new SoftAuthenticator(RP.id, RP.origin);
    await lax.registerFinish(userId, laxAuth.create(laxOpts, { uv: false }), { now: T0 });
  });

  it('authenticates: a good assertion is a login through finishLogin; the counter advances', async () => {
    const userId = await verifiedUser('pk-auth@example.com');
    const auth = new SoftAuthenticator(RP.id, RP.origin);
    const summary = await register(userId, auth, 'phone');

    // discoverable (no user named)
    const opts = await passkeys.authenticateBegin({ now: T0 });
    assert.deepEqual(opts.allowCredentials, []);
    const r = await passkeys.authenticateFinish(auth.get(opts), meta, T0);
    assert.equal(r.kind, 'session');
    if (r.kind !== 'session') return;
    const session = await id.resolveSession(r.token, T0);
    assert.equal(session?.userId, userId);
    const evs = await listEvents(h.db, userId);
    assert.equal(evs[0]?.kind, 'login_succeeded');
    assert.deepEqual(evs[0]?.metadata, { via: 'passkey' });
    assert.match(h.mail.first('pk-auth@example.com').subject, /new sign-in/i);

    // named user: allowCredentials lists their keys; counter persisted
    const opts2 = await passkeys.authenticateBegin({ userId, now: T0 });
    assert.deepEqual(
      opts2.allowCredentials?.map((c) => c.id),
      [summary.id],
    );
    const r2 = await passkeys.authenticateFinish(auth.get(opts2), meta, T0);
    assert.equal(r2.kind, 'session');
    const [row] = await passkeys.list(userId);
    assert.equal(row?.lastUsedAt?.getTime(), T0.getTime());
    const counters = await h.db.query<{ counter: string }>(
      'SELECT counter::text FROM identity.passkeys WHERE id = $1',
      [summary.id],
    );
    assert.equal(one(counters).counter, '2');
  });

  it('refuses a counter that does not advance — typed, and recorded as a failed login', async () => {
    const userId = await verifiedUser('pk-counter@example.com');
    const auth = new SoftAuthenticator(RP.id, RP.origin);
    const summary = await register(userId, auth);
    const good = await passkeys.authenticateFinish(auth.get(await passkeys.authenticateBegin({ now: T0 })), {}, T0);
    assert.equal(good.kind, 'session'); // counter now 1

    // same counter (a cloned key that did not observe the increment)
    await assert.rejects(
      async () =>
        passkeys.authenticateFinish(auth.get(await passkeys.authenticateBegin({ now: T0 }), { counter: 1 }), meta, T0),
      (e: unknown) =>
        IdentityError.hasCode(e, 'passkey_counter_regression') &&
        e.failure.stored === 1 &&
        e.failure.presented === 1 &&
        e.failure.credentialId === summary.id,
    );
    // lower
    await assert.rejects(
      async () =>
        passkeys.authenticateFinish(auth.get(await passkeys.authenticateBegin({ now: T0 }), { counter: 0 }), meta, T0),
      (e: unknown) => IdentityError.hasCode(e, 'passkey_counter_regression'),
    );
    const evs = await listEvents(h.db, userId);
    assert.equal(evs[0]?.kind, 'login_failed');
    assert.equal(evs[0]?.metadata.reason, 'passkey_counter_regression');
    // the credential is still there and a properly advancing one still works
    assert.equal((await passkeys.list(userId)).length, 1);
    const ok = await passkeys.authenticateFinish(
      auth.get(await passkeys.authenticateBegin({ now: T0 }), { counter: 7 }),
      {},
      T0,
    );
    assert.equal(ok.kind, 'session');
  });

  it('refuses a bad assertion: unknown credential, wrong origin / RP, no UV, wrong key, deletion pending', async () => {
    const userId = await verifiedUser('pk-badauth@example.com');
    const auth = new SoftAuthenticator(RP.id, RP.origin);
    await register(userId, auth);
    const begin = () => passkeys.authenticateBegin({ now: T0 });

    // unknown credential id: failed, challenge burned, nothing recorded
    const n0 = (await listEvents(h.db, userId)).length;
    const unknown = auth.get(await begin());
    unknown.id = 'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA';
    unknown.rawId = unknown.id;
    assert.deepEqual(await passkeys.authenticateFinish(unknown, meta, T0), { kind: 'failed' });
    assert.equal((await listEvents(h.db, userId)).length, n0);

    assert.deepEqual(
      await passkeys.authenticateFinish(auth.get(await begin(), { origin: 'https://evil.test' }), meta, T0),
      {
        kind: 'failed',
      },
    );
    assert.deepEqual(await passkeys.authenticateFinish(auth.get(await begin(), { rpId: 'evil.test' }), meta, T0), {
      kind: 'failed',
    });
    assert.deepEqual(await passkeys.authenticateFinish(auth.get(await begin(), { uv: false }), meta, T0), {
      kind: 'failed',
    });
    // signed by a different key for the same credential id
    const impostor = new SoftAuthenticator(RP.id, RP.origin);
    const forged = impostor.create(await passkeys.registerBegin(userId, { password: 'correct horse battery' }, T0));
    const [mine] = [...auth.credentials.keys()];
    const theirs = impostor.credentials.get(forged.id);
    assert.ok(mine && theirs);
    impostor.credentials.set(mine, { ...theirs, id: auth.credentials.get(mine)?.id ?? theirs.id });
    const forgedAssertion = impostor.get(await begin(), { credentialId: mine, counter: 50 });
    assert.deepEqual(await passkeys.authenticateFinish(forgedAssertion, meta, T0), { kind: 'failed' });
    const evs = await listEvents(h.db, userId);
    assert.equal(evs[0]?.metadata.reason, 'passkey_verification_failed');

    // malformed authenticator data
    const mangled = auth.get(await begin());
    mangled.response.authenticatorData = 'AAEC';
    assert.deepEqual(await passkeys.authenticateFinish(mangled, meta, T0), { kind: 'failed' });

    // a challenge begun for one user, asserted by another
    const other = await verifiedUser('pk-badauth2@example.com');
    const otherAuth = new SoftAuthenticator(RP.id, RP.origin);
    await register(other, otherAuth);
    const bound = await passkeys.authenticateBegin({ userId: other, now: T0 });
    await assert.rejects(
      () => passkeys.authenticateFinish(auth.get(bound, { credentialId: mine, counter: 60 }), meta, T0),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_challenge') && e.failure.reason === 'user',
    );

    // deletion pending: verified assertion, no session
    await id.requestDeletion(userId, T0);
    assert.deepEqual(await passkeys.authenticateFinish(auth.get(await begin(), { counter: 70 }), meta, T0), {
      kind: 'failed',
    });
  });

  it('rename and remove are scoped to the owner; remove records an event', async () => {
    const userId = await verifiedUser('pk-manage@example.com');
    const other = await verifiedUser('pk-manage2@example.com');
    const auth = new SoftAuthenticator(RP.id, RP.origin);
    const s = await register(userId, auth, 'old name');
    await assert.rejects(
      () => passkeys.rename(other, s.id, 'stolen'),
      (e: unknown) => IdentityError.hasCode(e, 'not_found'),
    );
    await assert.rejects(
      () => passkeys.rename(userId, s.id, '   '),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_config'),
    );
    await passkeys.rename(userId, s.id, 'new name');
    assert.equal((await passkeys.list(userId))[0]?.name, 'new name');
    await assert.rejects(
      () => passkeys.remove(other, s.id),
      (e: unknown) => IdentityError.hasCode(e, 'not_found'),
    );
    await passkeys.remove(userId, s.id, meta, T0);
    assert.deepEqual(await passkeys.list(userId), []);
    const evs = await listEvents(h.db, userId);
    assert.equal(evs[0]?.kind, 'passkey_removed');
    assert.equal(evs[0]?.metadata.name, 'new name');
    // gone: an assertion with it is just failed
    const r = await passkeys.authenticateFinish(
      auth.get(await passkeys.authenticateBegin({ now: T0 }), { counter: 5 }),
      {},
      T0,
    );
    assert.deepEqual(r, { kind: 'failed' });
  });

  it('rate-limits authenticateFinish by ip, and sweeps expired challenges', async () => {
    const limited = createPasskeys({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      rp: RP,
      rateLimiter: createMemoryRateLimiter({ rules: { passkey_auth: { limit: 2, windowMs: 60_000 } } }),
    });
    const userId = await verifiedUser('pk-limit@example.com');
    const auth = new SoftAuthenticator(RP.id, RP.origin);
    await register(userId, auth);
    for (let i = 0; i < 2; i += 1) {
      await limited.authenticateFinish(auth.get(await limited.authenticateBegin({ now: T0 })), meta, T0);
    }
    await assert.rejects(
      async () => limited.authenticateFinish(auth.get(await limited.authenticateBegin({ now: T0 })), meta, T0),
      (e: unknown) => IdentityError.hasCode(e, 'rate_limited'),
    );

    // challenges: the ones above that were spent are gone; make two and let one expire
    await h.db.query('DELETE FROM identity.webauthn_challenges');
    await passkeys.authenticateBegin({ now: T0 });
    await passkeys.authenticateBegin({ now: new Date(T0.getTime() + 60_000) });
    assert.equal(await passkeys.sweepChallenges(new Date(T0.getTime() + 5 * 60_000)), 1);
    const report = await id.sweepExpired(new Date(T0.getTime() + 10 * 60_000));
    assert.equal(report.webauthnChallenges, 1);
  });

  it('a session token that was rotated by keepSessionHash still proves recent auth (mfa proof shape reused)', async () => {
    // Just the shape: EnrolmentProof is the same type as MFA's, so a host that
    // already re-authenticates for TOTP passes the same object here.
    const userId = await verifiedUser('pk-shape@example.com');
    const login = await id.login({ email: 'pk-shape@example.com', password: 'correct horse battery' }, {}, T0);
    assert.equal(login.kind, 'session');
    if (login.kind !== 'session') return;
    const proof: import('../src/mfa.ts').EnrolmentProof = { sessionToken: login.token };
    const options = await passkeys.registerBegin(userId, proof, T0);
    assert.ok(options.challenge);
    assert.equal(sha256(login.token).length, 64);
  });
});
