// The behaviours worth asserting are the security properties, because those are
// the ones that fail silently: an enumeration oracle, a timing leak, a reset
// token that survives its use, a session that outlives a password change.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { IdentityError } from '../src/errors.ts';
import { createIdentity } from '../src/index.ts';
import { type Harness, one, SKIP_REASON, setupDatabase, testConfig, tokenFrom } from './harness.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

describe('identity-kit', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const id = createIdentity({ db: h.db, config: testConfig, mail: h.mail, rateLimiter: null });

  const userCount = async (email: string): Promise<number> => {
    const rows = await h.db.query<{ n: string }>('SELECT count(*)::text AS n FROM identity.users WHERE email = $1', [
      email.toLowerCase(),
    ]);
    return Number(one(rows).n);
  };

  const makeVerifiedUser = async (email: string, password: string): Promise<void> => {
    h.mail.clear();
    await id.signup({ email, password });
    const token = tokenFrom(h.mail.first(email).body);
    await id.verifyEmail(token);
    h.mail.clear();
  };

  it('signup creates a user and emails a verification link', async () => {
    const r = await id.signup({ email: 'Alice@Example.com', password: 'correct horse battery' });
    assert.deepEqual(r, { accepted: true });
    assert.equal(await userCount('alice@example.com'), 1);
    const mail = h.mail.to('alice@example.com');
    assert.equal(mail.length, 1);
    assert.match(one(mail).subject, /confirm/i);
  });

  it('signup is enumeration-safe: a taken address accepts and emails, never errors', async () => {
    h.mail.clear();
    const r = await id.signup({ email: 'alice@example.com', password: 'a different password' });
    assert.deepEqual(r, { accepted: true }, 'same shape as a fresh signup');
    assert.equal(await userCount('alice@example.com'), 1, 'no second row');
    assert.match(h.mail.first('alice@example.com').subject, /tried to create/i);
  });

  it('signup rejects a weak password', async () => {
    await assert.rejects(
      () => id.signup({ email: 'weak@example.com', password: 'short' }),
      (e: unknown) => IdentityError.hasCode(e, 'weak_password'),
    );
  });

  it('verifyEmail verifies the address and returns nothing that authenticates', async () => {
    h.mail.clear();
    await id.signup({ email: 'bob@example.com', password: 'correct horse battery' });
    const token = tokenFrom(h.mail.first('bob@example.com').body);

    const result = await id.verifyEmail(token);
    assert.equal(result, true);
    assert.equal(typeof result, 'boolean', 'no session token comes back from verification');
    // reusing a consumed token does nothing
    assert.equal(await id.verifyEmail(token), false);
  });

  it('login fails on an unknown email (and burns the work)', async () => {
    const r = await id.login({ email: 'nobody@example.com', password: 'whatever' });
    assert.deepEqual(r, { kind: 'failed' });
  });

  it('login fails on a wrong password and counts the failure', async () => {
    await makeVerifiedUser('carol@example.com', 'correct horse battery');
    const r = await id.login({ email: 'carol@example.com', password: 'wrong' });
    assert.deepEqual(r, { kind: 'failed' });
    const rows = await h.db.query<{ failed_logins: number }>(
      'SELECT failed_logins FROM identity.users WHERE email = $1',
      ['carol@example.com'],
    );
    assert.equal(one(rows).failed_logins, 1);
  });

  it('login fails on an unverified account even with the right password', async () => {
    h.mail.clear();
    await id.signup({ email: 'dave@example.com', password: 'correct horse battery' });
    const r = await id.login({ email: 'dave@example.com', password: 'correct horse battery' });
    assert.deepEqual(r, { kind: 'failed' }, 'indistinguishable from a wrong password');
  });

  it('login succeeds for a verified account and mints a resolvable session', async () => {
    await makeVerifiedUser('erin@example.com', 'correct horse battery');
    const r = await id.login({ email: 'erin@example.com', password: 'correct horse battery' });
    assert.equal(r.kind, 'session');
    if (r.kind !== 'session') return;
    const resolved = await id.resolveSession(r.token);
    assert.ok(resolved, 'the session token resolves');
    const rows = await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', [
      'erin@example.com',
    ]);
    assert.equal(resolved?.userId, one(rows).id);
  });

  it('counts concurrent failed logins exactly (the counter is incremented in place)', async () => {
    await makeVerifiedUser('con@example.com', 'correct horse battery');
    const now = new Date();
    const N = 8;
    const results = await Promise.all(
      Array.from({ length: N }, () => id.login({ email: 'con@example.com', password: 'wrong' }, {}, now)),
    );
    assert.ok(results.every((r) => r.kind === 'failed'));
    const row = one(
      await h.db.query<{ failed_logins: number; last_failed_at: Date | null; locked_until: Date | null }>(
        'SELECT failed_logins, last_failed_at, locked_until FROM identity.users WHERE email = $1',
        ['con@example.com'],
      ),
    );
    assert.equal(row.failed_logins, N, 'no increment lost to a concurrent read-then-write');
    assert.ok(row.last_failed_at, 'last_failed_at is stamped');
    // 8 failures = 3 past the threshold; the lock is the longest one computed
    assert.ok(
      row.locked_until && row.locked_until.getTime() - now.getTime() >= 4000,
      'lock reflects the highest count',
    );
    // and a correct password clears it once the lock lapses
    const later = new Date(now.getTime() + 60_000);
    assert.equal(
      (await id.login({ email: 'con@example.com', password: 'correct horse battery' }, {}, later)).kind,
      'session',
    );
  });

  it('re-peppers a hash made under an older pepper version on next login', async () => {
    await makeVerifiedUser('pepper@example.com', 'correct horse battery');
    const version = async () =>
      one(
        await h.db.query<{ pepper_version: number }>('SELECT pepper_version FROM identity.users WHERE email = $1', [
          'pepper@example.com',
        ]),
      ).pepper_version;
    assert.equal(await version(), 1);

    // A process without the old key: the cause surfaces, not a "wrong password".
    const noOldKey = createIdentity({
      db: h.db,
      config: { ...testConfig, pepper: 'pepper-two', pepperVersion: 2 },
      mail: h.mail,
      rateLimiter: null,
    });
    await assert.rejects(
      () => noOldKey.login({ email: 'pepper@example.com', password: 'correct horse battery' }),
      (e: unknown) => IdentityError.hasCode(e, 'pepper_version') && e.failure.stored === 1 && e.failure.current === 2,
    );

    // A rotated process holding both keys: the login succeeds and re-peppers.
    const rotated = createIdentity({
      db: h.db,
      config: { ...testConfig, pepper: 'pepper-two', pepperVersion: 2, previousPeppers: { 1: testConfig.pepper } },
      mail: h.mail,
      rateLimiter: null,
    });
    assert.equal(
      (await rotated.login({ email: 'pepper@example.com', password: 'correct horse battery' })).kind,
      'session',
    );
    assert.equal(await version(), 2, 'the hash was re-peppered under the current version');
    assert.equal(
      (await rotated.login({ email: 'pepper@example.com', password: 'correct horse battery' })).kind,
      'session',
    );
    await assert.rejects(
      () => id.login({ email: 'pepper@example.com', password: 'correct horse battery' }),
      (e: unknown) => IdentityError.hasCode(e, 'pepper_version') && e.failure.stored === 2,
      'a process still on v1 cannot verify the re-peppered hash — legibly',
    );
  });

  it('backs off after repeated failures instead of hard-locking', async () => {
    await makeVerifiedUser('frank@example.com', 'correct horse battery');
    const now = new Date();
    for (let i = 0; i < 5; i++) {
      await id.login({ email: 'frank@example.com', password: 'wrong' }, {}, now);
    }
    const r = await id.login({ email: 'frank@example.com', password: 'wrong' }, {}, now);
    assert.equal(r.kind, 'backoff');
    if (r.kind === 'backoff') assert.ok(r.retryAfterSeconds > 0);
  });

  it('password reset: burns the token, revokes sessions, and lets the new password in', async () => {
    await makeVerifiedUser('grace@example.com', 'old password here');
    // an active session that the reset must kill
    const login = await id.login({ email: 'grace@example.com', password: 'old password here' });
    assert.equal(login.kind, 'session');
    const oldToken = login.kind === 'session' ? login.token : '';

    h.mail.clear();
    await id.requestPasswordReset('grace@example.com');
    const resetToken = tokenFrom(h.mail.first('grace@example.com').body);

    const done = await id.resetPassword(resetToken, 'a brand new password');
    assert.deepEqual(done, { kind: 'done' });

    assert.equal(await id.resolveSession(oldToken), null, 'the old session is revoked');
    assert.equal((await id.resetPassword(resetToken, 'again')).kind, 'invalid', 'the token is burned');
    assert.equal(
      (await id.login({ email: 'grace@example.com', password: 'a brand new password' })).kind,
      'session',
      'the new password works',
    );
  });

  it('reset with a weak password is spent and reported, not thrown', async () => {
    await makeVerifiedUser('heidi@example.com', 'old password here');
    h.mail.clear();
    await id.requestPasswordReset('heidi@example.com');
    const token = tokenFrom(h.mail.first('heidi@example.com').body);
    const r = await id.resetPassword(token, 'short');
    assert.equal(r.kind, 'weak_password');
    // and it is still burned
    assert.equal((await id.resetPassword(token, 'a proper password now')).kind, 'invalid');
  });

  it('requestPasswordReset is enumeration-safe for an unknown address', async () => {
    h.mail.clear();
    const r = await id.requestPasswordReset('ghost@example.com');
    assert.deepEqual(r, { accepted: true });
    assert.match(h.mail.first('ghost@example.com').subject, /reset/i);
  });

  it('changePassword refuses a wrong current password and revokes sessions on success', async () => {
    await makeVerifiedUser('ivan@example.com', 'old password here');
    const login = await id.login({ email: 'ivan@example.com', password: 'old password here' });
    const kept = login.kind === 'session' ? await id.resolveSession(login.token) : null;

    const rows = await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', [
      'ivan@example.com',
    ]);
    const userId = one(rows).id;

    await assert.rejects(
      () => id.changePassword(userId, 'not the password', 'a new password here'),
      (e: unknown) => IdentityError.hasCode(e, 'bad_credentials'),
    );

    // a second session that should be revoked
    const other = await id.login({ email: 'ivan@example.com', password: 'old password here' });
    const otherToken = other.kind === 'session' ? other.token : '';
    await id.changePassword(userId, 'old password here', 'a new password here', kept?.tokenHash);
    assert.equal(await id.resolveSession(otherToken), null, 'other sessions revoked');
  });

  it('deletion revokes sessions and blocks login; cancel restores it', async () => {
    await makeVerifiedUser('judy@example.com', 'correct horse battery');
    const login = await id.login({ email: 'judy@example.com', password: 'correct horse battery' });
    const token = login.kind === 'session' ? login.token : '';
    const rows = await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', [
      'judy@example.com',
    ]);
    const userId = one(rows).id;

    h.mail.clear();
    await id.requestDeletion(userId);
    assert.equal(await id.resolveSession(token), null, 'sessions gone on deletion request');
    assert.equal(
      (await id.login({ email: 'judy@example.com', password: 'correct horse battery' })).kind,
      'failed',
      'a deletion-pending account cannot log in',
    );

    const cancelToken = tokenFrom(h.mail.first('judy@example.com').body);
    assert.equal(await id.cancelDeletion(cancelToken), true);
    assert.equal(
      (await id.login({ email: 'judy@example.com', password: 'correct horse battery' })).kind,
      'session',
      'login works again after cancelling',
    );
  });

  it('a new device gets a sign-in notification; a seen user agent does not', async () => {
    await makeVerifiedUser('kim@example.com', 'correct horse battery');
    h.mail.clear();
    const first = await id.login(
      { email: 'kim@example.com', password: 'correct horse battery' },
      { userAgent: 'Phone/1', ipAddress: '9.9.9.9' },
    );
    assert.equal(first.kind, 'session');
    const mail = h.mail.first('kim@example.com');
    assert.match(mail.subject, /new sign-in/i);
    assert.match(mail.body, /9\.9\.9\.9/);
    h.mail.clear();
    await id.login({ email: 'kim@example.com', password: 'correct horse battery' }, { userAgent: 'Phone/1' });
    assert.equal(h.mail.sent.length, 0, 'the same device again: no mail');
    await id.login({ email: 'kim@example.com', password: 'correct horse battery' }, { userAgent: 'Laptop/2' });
    assert.match(h.mail.first('kim@example.com').body, /unrecognised device/, 'no IP given: a generic phrase');
  });

  it('purgeUnverified and purgeDeleted remove only what is past its window', async () => {
    const now = new Date();
    const week = 7 * 24 * 60 * 60 * 1000;
    h.mail.clear();
    await id.signup({ email: 'stale@example.com', password: 'correct horse battery' });
    await h.db.query('UPDATE identity.users SET created_at = $2 WHERE email = $1', [
      'stale@example.com',
      new Date(now.getTime() - week - 1000),
    ]);
    await id.signup({ email: 'fresh@example.com', password: 'correct horse battery' });
    assert.ok((await id.purgeUnverified(now)) >= 1);
    assert.equal(await userCount('stale@example.com'), 0);
    assert.equal(await userCount('fresh@example.com'), 1, 'inside the window, kept');

    await makeVerifiedUser('gone@example.com', 'correct horse battery');
    const uid = one(
      await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', ['gone@example.com']),
    ).id;
    await id.requestDeletion(uid, new Date(now.getTime() - week - 1000));
    await makeVerifiedUser('pending@example.com', 'correct horse battery');
    const pid = one(
      await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', ['pending@example.com']),
    ).id;
    await id.requestDeletion(pid, now);
    assert.ok((await id.purgeDeleted(now)) >= 1);
    assert.equal(await userCount('gone@example.com'), 0);
    assert.equal(await userCount('pending@example.com'), 1, 'still in its grace period');
    await assert.rejects(
      () => id.requestDeletion('00000000-0000-0000-0000-000000000000'),
      (e: unknown) => IdentityError.hasCode(e, 'not_found'),
    );
  });
});
