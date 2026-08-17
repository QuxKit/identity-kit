// MFA: the second factor, and the state between the two factors. The properties
// that matter are replay prevention (a phished code cannot be reused in its
// window) and the attempt bound (six digits are only safe because guesses are
// counted), so those are what the tests pin down.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { Secret, TOTP } from 'otpauth';

import { createIdentity, IdentityError } from '../src/index.ts';
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
  const id = createIdentity({ db: h.db, config: testConfig, mail: h.mail, secondFactor: mfa.secondFactor });

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
    if (done.kind === 'session') assert.ok(await id.resolveSession(done.token));
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
});
