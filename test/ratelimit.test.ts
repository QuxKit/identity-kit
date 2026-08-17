// The rate-limit seam and both implementations, then the paths it guards.
// The memory limiter is exercised without a database; the Postgres one against
// the real table, including a burst from concurrent hits (which is the whole
// point of doing it in one statement).

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import {
  createIdentity,
  createMemoryRateLimiter,
  createPgRateLimiter,
  DEFAULT_RATE_LIMITS,
  IdentityError,
  limiterKey,
  type RateLimiter,
} from '../src/index.ts';
import { createMfa } from '../src/mfa.ts';
import { type Harness, one, SKIP_REASON, setupDatabase, testConfig, testTotpKey, tokenFrom } from './harness.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

const rules = { default: { limit: 3, windowMs: 3000 } };
/** The same rule for every action — the tests below tighten all the guarded paths at once. */
const every = (limit: number, windowMs = 60_000) => {
  const rule = { limit, windowMs };
  return {
    signup: rule,
    login: rule,
    password_reset: rule,
    verification_resend: rule,
    mfa_verify: rule,
    default: rule,
  };
};

describe('rate limiter (memory)', () => {
  it('limiterKey namespaces by action and joins the parts', () => {
    assert.equal(limiterKey('login', 'a@x.io', '1.2.3.4'), 'login:a@x.io|1.2.3.4');
    assert.equal(limiterKey('signup', 'a@x.io', null, undefined, ''), 'signup:a@x.io');
  });

  it('is a token bucket: burst to the limit, then refills over the window', async () => {
    let t = 1_000_000;
    const rl = createMemoryRateLimiter({ rules, clock: () => new Date(t) });
    for (let i = 0; i < 3; i++) assert.equal((await rl.hit('x:k')).allowed, true);
    const denied = await rl.hit('x:k');
    assert.equal(denied.allowed, false);
    assert.ok(denied.retryAfterMs > 0 && denied.retryAfterMs <= 1000, `retryAfter ${denied.retryAfterMs}`);
    // a denied hit does not consume tokens: exactly one refills after 1s
    t += 1000;
    assert.equal((await rl.hit('x:k')).allowed, true);
    assert.equal((await rl.hit('x:k')).allowed, false);
    // keys are independent, and the action prefix picks the rule
    assert.equal((await rl.hit('x:other')).allowed, true);
    assert.equal(DEFAULT_RATE_LIMITS.login.limit, 10);
  });

  it('honours cost, and refuses a cost above capacity outright', async () => {
    const rl = createMemoryRateLimiter({ rules, clock: () => new Date(0) });
    assert.equal((await rl.hit('x:k', 2)).allowed, true);
    assert.equal((await rl.hit('x:k', 2)).allowed, false);
    assert.equal((await rl.hit('x:k', 1)).allowed, true);
    assert.equal((await rl.hit('x:big', 4)).allowed, false);
  });
});

describe('rate limiter (postgres) and the guarded paths', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;

  it('pg limiter: same bucket semantics, and an exact count under a concurrent burst', async () => {
    let t = 5_000_000;
    const rl = createPgRateLimiter({
      db: h.db,
      rules: { default: { limit: 5, windowMs: 5000 } },
      clock: () => new Date(t),
    });
    const burst = await Promise.all(Array.from({ length: 12 }, () => rl.hit('burst:k')));
    assert.equal(burst.filter((d) => d.allowed).length, 5, 'exactly the capacity is admitted, no more, no less');
    const denied = burst.find((d) => !d.allowed);
    assert.ok(denied && denied.retryAfterMs > 0);
    t += 2000; // two tokens back
    assert.equal((await rl.hit('burst:k')).allowed, true);
    assert.equal((await rl.hit('burst:k')).allowed, true);
    assert.equal((await rl.hit('burst:k')).allowed, false);
    // the row is what a sweep would prune later
    const rows = await h.db.query<{ tokens: number }>('SELECT tokens FROM identity.rate_limits WHERE key = $1', [
      'burst:k',
    ]);
    assert.equal(rows.length, 1);
  });

  const withLimiter = (rl: RateLimiter | null) =>
    createIdentity({ db: h.db, config: testConfig, mail: h.mail, rateLimiter: rl });

  const isLimited = (e: unknown) =>
    IdentityError.hasCode(e, 'rate_limited') && e.failure.retryAfterMs > 0 && typeof e.failure.key === 'string';

  it('signup: the limiter runs before any hashing or mail; a limited request creates nothing', async () => {
    const rl = createMemoryRateLimiter({ rules: every(2) });
    const id = withLimiter(rl);
    h.mail.clear();
    await id.signup({ email: 'rl-a@example.com', password: 'correct horse battery', ipAddress: '10.0.0.1' });
    await id.signup({ email: 'rl-a@example.com', password: 'correct horse battery', ipAddress: '10.0.0.1' });
    const before = h.mail.sent.length;
    const t0 = Date.now();
    await assert.rejects(
      () => id.signup({ email: 'rl-a@example.com', password: 'correct horse battery', ipAddress: '10.0.0.1' }),
      isLimited,
    );
    assert.ok(Date.now() - t0 < 40, 'a limited signup does not pay for argon2');
    assert.equal(h.mail.sent.length, before, 'and sends no mail');
    // a different key (another IP) is not affected
    await id.signup({ email: 'rl-a@example.com', password: 'correct horse battery', ipAddress: '10.0.0.2' });
  });

  it('login: keyed by address + IP; a limited attempt is refused before the password is checked', async () => {
    const rl = createMemoryRateLimiter({ rules: every(2) });
    const id = withLimiter(rl);
    h.mail.clear();
    await id.signup({ email: 'rl-b@example.com', password: 'correct horse battery' });
    await id.verifyEmail(tokenFrom(h.mail.first('rl-b@example.com').body));
    const meta = { ipAddress: '10.0.0.9' };
    await id.login({ email: 'rl-b@example.com', password: 'wrong' }, meta);
    await id.login({ email: 'rl-b@example.com', password: 'wrong' }, meta);
    await assert.rejects(
      () => id.login({ email: 'rl-b@example.com', password: 'correct horse battery' }, meta),
      isLimited,
    );
    const failed = one(
      await h.db.query<{ failed_logins: number }>('SELECT failed_logins FROM identity.users WHERE email = $1', [
        'rl-b@example.com',
      ]),
    ).failed_logins;
    assert.equal(failed, 2, 'the refused attempt was not counted as a failure either');
    // same address from elsewhere still works: the victim is not locked out remotely
    const other = await id.login(
      { email: 'rl-b@example.com', password: 'correct horse battery' },
      { ipAddress: '10.0.0.10' },
    );
    assert.equal(other.kind, 'session');
  });

  it('password reset request and verification resend are limited per address', async () => {
    const rl = createMemoryRateLimiter({ rules: every(1) });
    const id = withLimiter(rl);
    await id.requestPasswordReset('rl-c@example.com');
    await assert.rejects(() => id.requestPasswordReset('rl-c@example.com'), isLimited);
    await id.resendVerification('rl-c@example.com');
    await assert.rejects(() => id.resendVerification('rl-c@example.com'), isLimited);
  });

  it('resendVerification: a fresh link for an unverified account, nothing for verified or unknown, same acceptance', async () => {
    const id = withLimiter(null);
    h.mail.clear();
    await id.signup({ email: 'rl-d@example.com', password: 'correct horse battery' });
    const first = tokenFrom(h.mail.first('rl-d@example.com').body);
    h.mail.clear();
    assert.deepEqual(await id.resendVerification('rl-d@example.com'), { accepted: true });
    const second = tokenFrom(h.mail.first('rl-d@example.com').body);
    assert.notEqual(second, first);
    assert.equal(await id.verifyEmail(first), false, 'the superseded link is dead');
    assert.equal(await id.verifyEmail(second), true);
    h.mail.clear();
    assert.deepEqual(await id.resendVerification('rl-d@example.com'), { accepted: true });
    assert.deepEqual(await id.resendVerification('nobody-rl@example.com'), { accepted: true });
    assert.equal(h.mail.sent.length, 0, 'verified and unknown addresses get no mail');
  });

  it('mfa verify: a per-user ceiling across pending tokens', async () => {
    const rl = createMemoryRateLimiter({ rules: every(2) });
    const mfa = createMfa({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      totp: { key: testTotpKey, keyVersion: 1, issuer: 'test' },
      rateLimiter: rl,
    });
    const id = createIdentity({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      secondFactor: mfa.secondFactor,
      rateLimiter: null,
    });
    h.mail.clear();
    await id.signup({ email: 'rl-e@example.com', password: 'correct horse battery' });
    await id.verifyEmail(tokenFrom(h.mail.first('rl-e@example.com').body));
    const login = await id.login({ email: 'rl-e@example.com', password: 'correct horse battery' });
    assert.equal(login.kind, 'session', 'not enrolled yet');
    const userId = one(
      await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', ['rl-e@example.com']),
    ).id;
    const pending = await mfa.issuePendingLogin(userId);
    assert.equal((await mfa.verifyTotp(pending, '000000')).kind, 'failed');
    assert.equal((await mfa.verifyRecoveryCode(pending, 'NOPE')).kind, 'failed');
    await assert.rejects(() => mfa.verifyTotp(pending, '000000'), isLimited);
  });
});
