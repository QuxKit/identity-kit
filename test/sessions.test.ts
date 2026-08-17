// Sessions: the lifetimes (checked on read, never by the sweep), listing and
// bulk revocation, rotation, and the cookie helpers. Time is injected
// throughout, so a fourteen-day idle window is a number, not a wait.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import {
  ABSOLUTE_LIFETIME_MS,
  clearedSessionCookie,
  cookieName,
  createIdentity,
  createSession,
  IDLE_LIFETIME_MS,
  listSessions,
  resolveSession,
  revokeAllSessions,
  rotateSession,
  sessionCookie,
  sha256,
  sweepExpired,
  sweepExpiredSessions,
} from '../src/index.ts';
import { type Harness, one, SKIP_REASON, setupDatabase, testConfig, tokenFrom } from './harness.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

const T0 = new Date('2026-08-15T12:00:00Z');
const at = (ms: number) => new Date(T0.getTime() + ms);
const DAY = 24 * 60 * 60 * 1000;

describe('cookie helpers (no database)', () => {
  it('__Host- prefix and Secure follow cookieSecure', () => {
    assert.equal(cookieName(testConfig), '__Host-session');
    assert.equal(cookieName({ ...testConfig, cookieSecure: false }), 'session');
    const c = sessionCookie(testConfig, 'tok', at(90_000), T0);
    assert.equal(c, '__Host-session=tok; HttpOnly; SameSite=Lax; Path=/; Max-Age=90; Secure');
    const dev = sessionCookie({ ...testConfig, cookieSecure: false }, 'tok', at(90_000), T0);
    assert.equal(dev, 'session=tok; HttpOnly; SameSite=Lax; Path=/; Max-Age=90');
    assert.ok(!dev.includes('Domain='), 'never a Domain attribute');
  });

  it('Max-Age never goes negative; the cleared cookie is Max-Age=0', () => {
    assert.match(sessionCookie(testConfig, 'tok', at(-5000), T0), /Max-Age=0/);
    assert.equal(
      clearedSessionCookie(testConfig),
      '__Host-session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0; Secure',
    );
    assert.equal(
      clearedSessionCookie({ ...testConfig, cookieSecure: false }),
      'session=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0',
    );
  });
});

describe('sessions', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const db = h.db;

  const user = async (email: string): Promise<string> =>
    one(
      await db.query<{ id: string }>(
        `INSERT INTO identity.users (email, email_display, email_verified_at) VALUES ($1, $1, $2) RETURNING id`,
        [email, T0],
      ),
    ).id;

  it('idle lifetime: expires after 14 idle days, slides once past halfway, and is checked on read', async () => {
    const uid = await user('idle@example.com');
    const { token, expiresAt } = await createSession(db, uid, {}, T0);
    assert.equal(expiresAt.getTime(), T0.getTime() + IDLE_LIFETIME_MS);

    // early in the window: no write, same expiry
    const early = await resolveSession(db, token, at(DAY));
    assert.equal(early?.expiresAt.getTime(), expiresAt.getTime());
    assert.equal(early?.authenticatedAt.getTime(), T0.getTime());

    // past halfway: slides to now + 14d
    const mid = await resolveSession(db, token, at(8 * DAY));
    assert.equal(mid?.expiresAt.getTime(), at(8 * DAY).getTime() + IDLE_LIFETIME_MS);
    assert.equal(mid?.rotated, undefined, 'no rotation unless asked');

    // idle past the window: gone, and the row is deleted on that read
    assert.equal(await resolveSession(db, token, at(8 * DAY + IDLE_LIFETIME_MS)), null);
    assert.equal((await db.query('SELECT 1 FROM identity.sessions WHERE token_hash = $1', [sha256(token)])).length, 0);
  });

  it('absolute lifetime: 30 days from creation no matter how active', async () => {
    const uid = await user('absolute@example.com');
    const { token } = await createSession(db, uid, {}, T0);
    let t = 0;
    while (t + 5 * DAY < ABSOLUTE_LIFETIME_MS) {
      t += 5 * DAY;
      const r = await resolveSession(db, token, at(t));
      assert.ok(r, `still valid at day ${t / DAY}`);
      assert.ok(
        r.expiresAt.getTime() <= T0.getTime() + ABSOLUTE_LIFETIME_MS,
        'the slide never passes the absolute cap',
      );
    }
    assert.equal(await resolveSession(db, token, at(ABSOLUTE_LIFETIME_MS)), null, 'dead at 30 days');
  });

  it('listSessions shows metadata, never tokens, most recent first', async () => {
    const uid = await user('list@example.com');
    await createSession(db, uid, { ipAddress: '1.1.1.1', userAgent: 'A' }, T0);
    await createSession(db, uid, { ipAddress: '2.2.2.2', userAgent: 'B' }, at(1000));
    const list = await listSessions(db, uid);
    assert.equal(list.length, 2);
    assert.equal(list[0]?.userAgent, 'B');
    assert.equal(list[1]?.ipAddress, '1.1.1.1');
    assert.match(list[0]?.tokenHash ?? '', /^[0-9a-f]{64}$/, 'the hash, which authenticates nothing');
    assert.equal('token' in (list[0] ?? {}), false);
  });

  it('revokeAllSessions spares exactly the excepted one and reports the count', async () => {
    const uid = await user('revoke@example.com');
    const keep = await createSession(db, uid, {}, T0);
    await createSession(db, uid, {}, T0);
    await createSession(db, uid, {}, T0);
    assert.equal(await revokeAllSessions(db, uid, sha256(keep.token)), 2);
    assert.ok(await resolveSession(db, keep.token, T0), 'the kept one still resolves');
    assert.equal(await revokeAllSessions(db, uid), 1);
    assert.equal(await resolveSession(db, keep.token, T0), null);
  });

  it('sweepExpiredSessions removes only idle- or absolutely-expired rows', async () => {
    const uid = await user('sweep@example.com');
    const live = await createSession(db, uid, {}, at(10 * DAY));
    const idle = await createSession(db, uid, {}, T0); // idle-expired at T0+14d
    const old = await createSession(db, uid, {}, at(-ABSOLUTE_LIFETIME_MS)); // absolutely expired
    // keep `old` idle-fresh so only the absolute rule can catch it
    await db.query('UPDATE identity.sessions SET expires_at = $2 WHERE token_hash = $1', [
      sha256(old.token),
      at(20 * DAY),
    ]);
    const n = await sweepExpiredSessions(db, at(15 * DAY));
    assert.ok(n >= 2, `swept ${n} (the table is shared with the other suites)`);
    const rows = async (token: string) =>
      (await db.query('SELECT 1 FROM identity.sessions WHERE token_hash = $1', [sha256(token)])).length;
    assert.equal(await rows(live.token), 1, 'the live one stays');
    assert.equal(await rows(idle.token), 0, 'idle-expired swept');
    assert.equal(await rows(old.token), 0, 'absolutely-expired swept');
    assert.ok(await resolveSession(db, live.token, at(15 * DAY)));
  });

  it('rotateSession: a new token for the same session; the old one is dead immediately', async () => {
    const uid = await user('rotate@example.com');
    const s = await createSession(db, uid, { userAgent: 'UA' }, T0);
    const before = await resolveSession(db, s.token, at(1000));
    const rotated = await rotateSession(db, sha256(s.token), at(2000));
    assert.ok(rotated);
    assert.notEqual(rotated.token, s.token);
    assert.equal(rotated.tokenHash, sha256(rotated.token));
    assert.equal(await resolveSession(db, s.token, at(3000)), null, 'old token invalid');
    const after = await resolveSession(db, rotated.token, at(3000));
    assert.equal(after?.userId, uid);
    assert.equal(after?.expiresAt.getTime(), before?.expiresAt.getTime(), 'same expiry');
    assert.equal(after?.absoluteExpiresAt.getTime(), before?.absoluteExpiresAt.getTime(), 'same absolute cap');
    assert.equal(after?.authenticatedAt.getTime(), T0.getTime(), 'the proof time carries forward');
    assert.equal((await listSessions(db, uid)).length, 1, 'one row, not two');
    assert.equal(one(await listSessions(db, uid)).userAgent, 'UA');
    // rotating an unknown or expired token yields null
    assert.equal(await rotateSession(db, sha256('nope'), T0), null);
    assert.equal(await rotateSession(db, rotated.tokenHash, at(ABSOLUTE_LIFETIME_MS)), null);
  });

  it('with rotateSessions on: sliding renewal rotates and hands back the new token', async () => {
    const id = createIdentity({
      db,
      config: { ...testConfig, rotateSessions: true },
      mail: h.mail,
      rateLimiter: null,
      clock: () => T0,
    });
    const uid = await user('renew@example.com');
    const s = await createSession(db, uid, {}, T0);
    const early = await id.resolveSession(s.token, at(DAY));
    assert.equal(early?.rotated, undefined, 'no renewal, no rotation');
    const renewed = await id.resolveSession(s.token, at(8 * DAY));
    assert.ok(renewed?.rotated, 'renewal rotated');
    assert.equal(renewed.tokenHash, sha256(renewed.rotated.token), 'tokenHash is already the new one');
    assert.equal(await id.resolveSession(s.token, at(8 * DAY + 1)), null, 'the old cookie is dead');
    assert.equal((await id.resolveSession(renewed.rotated.token, at(8 * DAY + 1)))?.userId, uid);
    // and via the bound helper
    const again = await id.rotateSession(renewed.rotated.token, at(9 * DAY));
    assert.ok(again && (await id.resolveSession(again.token, at(9 * DAY))));
  });

  it('changePassword rotates the kept session (rotateSessions on) and refreshes authenticatedAt', async () => {
    const id = createIdentity({ db, config: { ...testConfig, rotateSessions: true }, mail: h.mail, rateLimiter: null });
    h.mail.clear();
    await id.signup({ email: 'cp-rotate@example.com', password: 'old password here' });
    await id.verifyEmail(tokenFrom(h.mail.first('cp-rotate@example.com').body));
    const login = await id.login({ email: 'cp-rotate@example.com', password: 'old password here' }, {}, T0);
    assert.equal(login.kind, 'session');
    if (login.kind !== 'session') return;
    const uid = one(
      await db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', ['cp-rotate@example.com']),
    ).id;
    const other = await id.login({ email: 'cp-rotate@example.com', password: 'old password here' }, {}, T0);

    const r = await id.changePassword(uid, 'old password here', 'a new password here', sha256(login.token), at(60_000));
    assert.ok(r.rotated, 'the kept session was rotated');
    assert.equal(await id.resolveSession(login.token, at(61_000)), null, 'old token dead');
    assert.equal(
      await id.resolveSession(other.kind === 'session' ? other.token : '', at(61_000)),
      null,
      'others revoked',
    );
    const fresh = await id.resolveSession(r.rotated.token, at(61_000));
    assert.equal(fresh?.userId, uid);
    assert.equal(fresh?.authenticatedAt.getTime(), at(60_000).getTime(), 'the password change is a fresh proof');

    // rotateSessions off: the kept session survives untouched, nothing rotated
    const plain = createIdentity({ db, config: testConfig, mail: h.mail, rateLimiter: null });
    const l2 = await plain.login({ email: 'cp-rotate@example.com', password: 'a new password here' }, {}, at(120_000));
    if (l2.kind !== 'session') return assert.fail('login');
    const r2 = await plain.changePassword(
      uid,
      'a new password here',
      'yet another password',
      sha256(l2.token),
      at(130_000),
    );
    assert.equal(r2.rotated, undefined);
    const kept = await plain.resolveSession(l2.token, at(131_000));
    assert.ok(kept, 'the kept token still works');
    assert.equal(kept.authenticatedAt.getTime(), at(130_000).getTime(), 'but its proof time is refreshed');
  });

  it('sweepExpired: every table in one call, only expired rows', async () => {
    const uid = await user('sweepall@example.com');
    const now = at(100 * DAY);
    await createSession(db, uid, {}, at(50 * DAY)); // idle-expired by now
    await createSession(db, uid, {}, at(99 * DAY)); // live
    const tok = async (table: string, expires: Date, extra = '') => {
      await db.query(
        `INSERT INTO identity.${table} (token_hash, user_id, expires_at${extra}) VALUES ($1, $2, $3${extra ? ", 'verify_email'" : ''})`,
        [sha256(`${table}-${expires.toISOString()}-${Math.random()}`), uid, expires],
      );
    };
    await tok('password_reset_tokens', at(99 * DAY));
    await tok('password_reset_tokens', now);
    await tok('email_verification_tokens', at(1), ', purpose');
    await tok('email_verification_tokens', at(101 * DAY), ', purpose');
    await tok('pending_logins', at(1));
    await tok('pending_logins', at(101 * DAY));
    await db.query('INSERT INTO identity.rate_limits (key, tokens, updated_at) VALUES ($1, 1, $2), ($3, 1, $4)', [
      'stale:1',
      at(98 * DAY),
      'fresh:1',
      at(99.9 * DAY),
    ]);

    const report = await sweepExpired(db, now);
    assert.equal(report.sessions >= 1, true);
    assert.equal(report.passwordResetTokens, 2, 'expires_at <= now, both go');
    assert.equal(report.emailVerificationTokens, 1);
    assert.equal(report.pendingLogins, 1);
    assert.equal(report.rateLimits, 1, 'only the bucket idle for over a day');
    const left = one(
      await db.query<{ n: string }>('SELECT count(*)::text AS n FROM identity.rate_limits WHERE key IN ($1, $2)', [
        'stale:1',
        'fresh:1',
      ]),
    );
    assert.equal(Number(left.n), 1);
    // and via the bound instance, with the injected clock
    const id = createIdentity({ db, config: testConfig, mail: h.mail, rateLimiter: null, clock: () => now });
    const second = await id.sweepExpired();
    assert.equal(second.passwordResetTokens + second.emailVerificationTokens + second.pendingLogins, 0, 'idempotent');
  });
});
