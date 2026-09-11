// MFA: the second factor, and the state between the two factors. The properties
// that matter are replay prevention (a phished code cannot be reused in its
// window) and the attempt bound (six digits are only safe because guesses are
// counted), so those are what the tests pin down.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { Secret, TOTP } from 'otpauth';

import { createIdentity, IdentityError, sha256 } from '../src/index.ts';
import { createMfa } from '../src/mfa.ts';
import { type Harness, one, SKIP_REASON, setupDatabase, testConfig, testTotpKey, tokenFrom } from './harness.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

const codeFor = (secret: string, when: Date): string =>
  new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: Secret.fromBase32(secret) }).generate({
    timestamp: when.getTime(),
  });

describe('identity-kit/mfa', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const mfa = createMfa({
    db: h.db,
    config: testConfig,
    mail: h.mail,
    totp: { key: testTotpKey, keyVersion: 1, issuer: 'test' },
  });
  const id = createIdentity({
    db: h.db,
    config: testConfig,
    mail: h.mail,
    secondFactor: mfa.secondFactor,
    rateLimiter: null,
  });

  const verifiedUser = async (email: string, password: string): Promise<string> => {
    h.mail.clear();
    await id.signup({ email, password });
    await id.verifyEmail(tokenFrom(h.mail.first(email).body));
    h.mail.clear();
    const rows = await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', [email]);
    return one(rows).id;
  };

  it('enrols with a verified code and returns recovery codes', async () => {
    const userId = await verifiedUser('mona@example.com', 'correct horse battery');
    const { secret } = await mfa.beginTotpEnrolment(userId, { password: 'correct horse battery' });
    const t0 = new Date('2026-08-15T12:00:00Z');
    const { recoveryCodes: codes } = await mfa.confirmTotpEnrolment(userId, codeFor(secret, t0), t0);
    assert.equal(codes.length, 10);
    // a bad code at enrolment is rejected, so a mis-scanned QR does not brick it
    await assert.rejects(
      () => mfa.confirmTotpEnrolment(userId, '000000', t0),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_code'),
    );
  });

  it('login requires the second factor, and a fresh code completes it', async () => {
    const userId = await verifiedUser('nate@example.com', 'correct horse battery');
    const { secret } = await mfa.beginTotpEnrolment(userId, { password: 'correct horse battery' });
    const t0 = new Date('2026-08-15T12:00:00Z');
    await mfa.confirmTotpEnrolment(userId, codeFor(secret, t0), t0);

    const t1 = new Date(t0.getTime() + 31_000);
    const login = await id.login({ email: 'nate@example.com', password: 'correct horse battery' }, {}, t1);
    assert.equal(login.kind, 'mfa_required', 'password alone does not sign in an enrolled user');
    if (login.kind !== 'mfa_required') return;

    const done = await mfa.verifyTotp(login.pendingToken, codeFor(secret, t1), {}, t1);
    assert.equal(done.kind, 'session');
    if (done.kind === 'session') assert.ok(await id.resolveSession(done.token, t1), 'the MFA-completed session resolves at its own clock');
  });

  it('rejects a replayed code inside its own window', async () => {
    const userId = await verifiedUser('olga@example.com', 'correct horse battery');
    const { secret } = await mfa.beginTotpEnrolment(userId, { password: 'correct horse battery' });
    const t0 = new Date('2026-08-15T12:00:00Z');
    await mfa.confirmTotpEnrolment(userId, codeFor(secret, t0), t0);

    const t1 = new Date(t0.getTime() + 31_000);
    const code = codeFor(secret, t1);
    const l1 = await id.login({ email: 'olga@example.com', password: 'correct horse battery' }, {}, t1);
    await mfa.verifyTotp(l1.kind === 'mfa_required' ? l1.pendingToken : '', code, {}, t1);

    // same code, same window, new pending token — must not work again
    const l2 = await id.login({ email: 'olga@example.com', password: 'correct horse battery' }, {}, t1);
    const replay = await mfa.verifyTotp(l2.kind === 'mfa_required' ? l2.pendingToken : '', code, {}, t1);
    assert.notEqual(replay.kind, 'session', 'a code cannot be used twice');
  });

  it('accepts a recovery code once and warns by email', async () => {
    const userId = await verifiedUser('pat@example.com', 'correct horse battery');
    const { secret } = await mfa.beginTotpEnrolment(userId, { password: 'correct horse battery' });
    const t0 = new Date('2026-08-15T12:00:00Z');
    const { recoveryCodes: codes } = await mfa.confirmTotpEnrolment(userId, codeFor(secret, t0), t0);

    h.mail.clear();
    const login = await id.login({ email: 'pat@example.com', password: 'correct horse battery' }, {}, t0);
    const done = await mfa.verifyRecoveryCode(
      login.kind === 'mfa_required' ? login.pendingToken : '',
      one(codes),
      {},
      t0,
    );
    assert.equal(done.kind, 'session');
    assert.equal(await mfa.remainingRecoveryCodes(userId), 9);
    assert.match(h.mail.first('pat@example.com').subject, /recovery code/i);
  });

  it('bounds guesses: five wrong codes restart the login', async () => {
    const userId = await verifiedUser('quinn@example.com', 'correct horse battery');
    const { secret } = await mfa.beginTotpEnrolment(userId, { password: 'correct horse battery' });
    const t0 = new Date('2026-08-15T12:00:00Z');
    await mfa.confirmTotpEnrolment(userId, codeFor(secret, t0), t0);

    const login = await id.login({ email: 'quinn@example.com', password: 'correct horse battery' }, {}, t0);
    const pending = login.kind === 'mfa_required' ? login.pendingToken : '';
    for (let i = 0; i < 4; i++) {
      assert.equal((await mfa.verifyTotp(pending, '000000', {}, t0)).kind, 'failed');
    }
    assert.equal((await mfa.verifyTotp(pending, '000000', {}, t0)).kind, 'restart', 'the token is spent');
  });

  it('enrolment requires recent authentication: password, or a session that authenticated recently', async () => {
    const userId = await verifiedUser('rita@example.com', 'correct horse battery');
    const t0 = new Date('2026-08-15T12:00:00Z');
    const reauth = (e: unknown) => IdentityError.hasCode(e, 'reauth_required');

    await assert.rejects(() => mfa.beginTotpEnrolment(userId, { password: 'wrong' }, t0), reauth);
    await assert.rejects(() => mfa.beginTotpEnrolment(userId, { sessionToken: 'not-a-session' }, t0), reauth);

    const login = await id.login({ email: 'rita@example.com', password: 'correct horse battery' }, {}, t0);
    if (login.kind !== 'session') return assert.fail('login');
    // fresh session: fine
    await mfa.beginTotpEnrolment(userId, { sessionToken: login.token }, new Date(t0.getTime() + 5 * 60_000));
    // stale session (past the 10-minute window): refused
    await assert.rejects(
      () => mfa.beginTotpEnrolment(userId, { sessionToken: login.token }, new Date(t0.getTime() + 11 * 60_000)),
      reauth,
    );
    // someone else's session: refused
    const other = await verifiedUser('rita2@example.com', 'correct horse battery');
    await assert.rejects(() => mfa.beginTotpEnrolment(other, { sessionToken: login.token }, t0), reauth);
    // a custom window is honoured
    const strict = createMfa({
      db: h.db,
      config: { ...testConfig, reauthWindowMs: 1000 },
      mail: h.mail,
      totp: { key: testTotpKey, keyVersion: 1, issuer: 'test' },
    });
    await assert.rejects(
      () => strict.beginTotpEnrolment(userId, { sessionToken: login.token }, new Date(t0.getTime() + 2000)),
      reauth,
    );
    // the password path still works, and an unknown user is a typed not_found... after the proof
    await mfa.beginTotpEnrolment(userId, { password: 'correct horse battery' }, t0);
  });

  it('confirm before begin, and a bad seal key, are typed errors', async () => {
    const userId = await verifiedUser('sam@example.com', 'correct horse battery');
    await assert.rejects(
      () => mfa.confirmTotpEnrolment(userId, '000000'),
      (e: unknown) => IdentityError.hasCode(e, 'enrolment_not_started'),
    );
    assert.throws(
      () =>
        createMfa({ db: h.db, config: testConfig, mail: h.mail, totp: { key: 'abcd', keyVersion: 1, issuer: 't' } }),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_config'),
    );
  });

  it('enrolment and removal keep + rotate the current session and revoke the rest', async () => {
    const userId = await verifiedUser('tess@example.com', 'correct horse battery');
    const t0 = new Date('2026-08-15T12:00:00Z');
    const a = await id.login({ email: 'tess@example.com', password: 'correct horse battery' }, {}, t0);
    const b = await id.login({ email: 'tess@example.com', password: 'correct horse battery' }, {}, t0);
    if (a.kind !== 'session' || b.kind !== 'session') return assert.fail('login');

    const { secret } = await mfa.beginTotpEnrolment(userId, { password: 'correct horse battery' }, t0);
    const done = await mfa.confirmTotpEnrolment(userId, codeFor(secret, t0), t0, sha256(a.token));
    assert.equal(done.recoveryCodes.length, 10);
    assert.ok(done.rotated, 'the kept session was rotated');
    if (!done.rotated) return;
    const kept = done.rotated;
    assert.equal(await id.resolveSession(a.token, t0), null, 'old token dead');
    assert.equal(await id.resolveSession(b.token, t0), null, 'other session revoked');
    const cur = await id.resolveSession(kept.token, t0);
    assert.equal(cur?.userId, userId);

    // removeTotp: wrong password is bad_credentials; right one removes and rotates
    await assert.rejects(
      () => mfa.removeTotp(userId, 'wrong', kept.tokenHash, t0),
      (e: unknown) => IdentityError.hasCode(e, 'bad_credentials'),
    );
    const removed = await mfa.removeTotp(userId, 'correct horse battery', kept.tokenHash, t0);
    assert.ok(removed.rotated);
    if (!removed.rotated) return;
    assert.equal(await id.resolveSession(kept.token, t0), null);
    assert.ok(await id.resolveSession(removed.rotated.token, t0));
    assert.equal(await mfa.remainingRecoveryCodes(userId), 0, 'recovery codes gone with the factor');
    const login = await id.login({ email: 'tess@example.com', password: 'correct horse battery' }, {}, t0);
    assert.equal(login.kind, 'session', 'no second factor asked any more');
    // no keep hash: everything is revoked, nothing rotated
    const c = await id.login({ email: 'tess@example.com', password: 'correct horse battery' }, {}, t0);
    const again = await mfa.beginTotpEnrolment(userId, { password: 'correct horse battery' }, t0);
    const done2 = await mfa.confirmTotpEnrolment(userId, codeFor(again.secret, t0), t0);
    assert.equal(done2.rotated, undefined);
    assert.equal(await id.resolveSession(c.kind === 'session' ? c.token : '', t0), null);
    await assert.rejects(
      () => mfa.removeTotp('00000000-0000-0000-0000-000000000000', 'x', undefined, t0),
      (e: unknown) => IdentityError.hasCode(e, 'not_found'),
    );
  });

  it('seal-key rotation: an old key in previousKeys still unseals, and the row is re-sealed on the next verify', async () => {
    const userId = await verifiedUser('uma@example.com', 'correct horse battery');
    const t0 = new Date('2026-08-15T12:00:00Z');
    const { secret } = await mfa.beginTotpEnrolment(userId, { password: 'correct horse battery' }, t0);
    await mfa.confirmTotpEnrolment(userId, codeFor(secret, t0), t0);
    const keyVersion = async () =>
      one(
        await h.db.query<{ key_version: number }>('SELECT key_version FROM identity.totp_factors WHERE user_id = $1', [
          userId,
        ]),
      ).key_version;
    assert.equal(await keyVersion(), 1);

    const newKey = 'ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100';
    // a process with only the new key cannot read the row: typed, not a crash
    const without = createMfa({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      totp: { key: newKey, keyVersion: 2, issuer: 'test' },
    });
    const t1 = new Date(t0.getTime() + 60_000);
    const l1 = await id.login({ email: 'uma@example.com', password: 'correct horse battery' }, {}, t1);
    if (l1.kind !== 'mfa_required') return assert.fail('mfa expected');
    await assert.rejects(
      () => without.verifyTotp(l1.pendingToken, codeFor(secret, t1), {}, t1),
      (e: unknown) => IdentityError.hasCode(e, 'totp_key_version') && e.failure.stored === 1,
    );

    // the rotated process holds both: verifies, and re-seals under v2
    const rotated = createMfa({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      totp: { key: newKey, keyVersion: 2, previousKeys: { 1: testTotpKey }, issuer: 'test' },
    });
    const t2 = new Date(t1.getTime() + 60_000);
    const l2 = await id.login({ email: 'uma@example.com', password: 'correct horse battery' }, {}, t2);
    if (l2.kind !== 'mfa_required') return assert.fail('mfa expected');
    const ok = await rotated.verifyTotp(l2.pendingToken, codeFor(secret, t2), {}, t2);
    assert.equal(ok.kind, 'session');
    assert.equal(await keyVersion(), 2, 're-sealed under the current key');
    // and now the new-key-only process can read it
    const t3 = new Date(t2.getTime() + 60_000);
    const l3 = await id.login({ email: 'uma@example.com', password: 'correct horse battery' }, {}, t3);
    if (l3.kind !== 'mfa_required') return assert.fail('mfa expected');
    assert.equal((await without.verifyTotp(l3.pendingToken, codeFor(secret, t3), {}, t3)).kind, 'session');
  });

  it('recovery codes: any position matches, is spent once, and every candidate is checked', async () => {
    const userId = await verifiedUser('vic@example.com', 'correct horse battery');
    const t0 = new Date('2026-08-15T12:00:00Z');
    const { secret } = await mfa.beginTotpEnrolment(userId, { password: 'correct horse battery' }, t0);
    const { recoveryCodes } = await mfa.confirmTotpEnrolment(userId, codeFor(secret, t0), t0);
    const last = recoveryCodes[recoveryCodes.length - 1] ?? '';
    const l1 = await id.login({ email: 'vic@example.com', password: 'correct horse battery' }, {}, t0);
    // lower-case with dashes is normalised
    const r1 = await mfa.verifyRecoveryCode(
      l1.kind === 'mfa_required' ? l1.pendingToken : '',
      `${last.slice(0, 4)}-${last.slice(4).toLowerCase()}`,
      {},
      t0,
    );
    assert.equal(r1.kind, 'session', 'the last code works, not just the first');
    assert.equal(await mfa.remainingRecoveryCodes(userId), 9);
    const used = await h.db.query('SELECT 1 FROM identity.recovery_codes WHERE user_id = $1 AND used_at IS NOT NULL', [
      userId,
    ]);
    assert.equal(used.length, 1, 'exactly one code marked used');
    const l2 = await id.login({ email: 'vic@example.com', password: 'correct horse battery' }, {}, t0);
    const replay = await mfa.verifyRecoveryCode(l2.kind === 'mfa_required' ? l2.pendingToken : '', last, {}, t0);
    assert.equal(replay.kind, 'failed', 'a spent code does not work again');
  });
});
