// Magic links. A link is a credential that travels by mail, so the properties
// are the reset token's: single-use, short-lived, one live per user, burned on
// any use; the request is enumeration-safe; only a verified account gets one;
// a second factor is not bypassed.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { Secret, TOTP } from 'otpauth';

import { IdentityError } from '../src/errors.ts';
import { createIdentity, createMemoryRateLimiter, listEvents } from '../src/index.ts';
import { createMagic } from '../src/magic.ts';
import { createMfa } from '../src/mfa.ts';
import { type Harness, one, SKIP_REASON, setupDatabase, testConfig, testTotpKey, tokenFrom } from './harness.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

const T0 = new Date('2026-08-15T12:00:00Z');
const later = (ms: number) => new Date(T0.getTime() + ms);

describe('identity-kit/magic', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const id = createIdentity({ db: h.db, config: testConfig, mail: h.mail, rateLimiter: null });
  const magic = createMagic({ db: h.db, config: testConfig, mail: h.mail, rateLimiter: null });
  const meta = { ipAddress: '192.0.2.4', userAgent: 'mail-client' };

  const verifiedUser = async (email: string): Promise<string> => {
    h.mail.clear();
    await id.signup({ email, password: 'correct horse battery' });
    await id.verifyEmail(tokenFrom(h.mail.first(email).body));
    h.mail.clear();
    const rows = await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', [email]);
    return one(rows).id;
  };
  const tokenCount = async (userId: string) =>
    (await h.db.query('SELECT 1 FROM identity.magic_link_tokens WHERE user_id = $1', [userId])).length;

  it('request mails a link (token in the URL, sha256 at rest); consume signs in through finishLogin', async () => {
    const userId = await verifiedUser('ml-ok@example.com');
    const r = await magic.request({ email: 'ML-OK@example.com ', ipAddress: meta.ipAddress }, T0);
    assert.deepEqual(r, { accepted: true });
    const mail = h.mail.first('ml-ok@example.com');
    assert.match(mail.subject, /sign-in link/i);
    assert.match(mail.body, /https:\/\/app\.test\/magic\?token=/);
    const token = tokenFrom(mail.body);
    const stored = await h.db.query<{ token_hash: string }>(
      'SELECT token_hash FROM identity.magic_link_tokens WHERE user_id = $1',
      [userId],
    );
    assert.notEqual(one(stored).token_hash, token, 'plaintext is not stored');
    assert.equal(one(stored).token_hash.length, 64);

    h.mail.clear();
    const login = await magic.consume({ token }, meta, later(60_000));
    assert.equal(login.kind, 'session');
    if (login.kind !== 'session') return;
    const session = await id.resolveSession(login.token, later(60_000));
    assert.equal(session?.userId, userId);
    assert.equal(await tokenCount(userId), 0, 'burned');
    assert.match(h.mail.first('ml-ok@example.com').subject, /new sign-in/i);
    const evs = await listEvents(h.db, userId);
    assert.deepEqual(
      evs.slice(0, 2).map((e) => e.kind),
      ['login_succeeded', 'magic_link_used'],
    );
    assert.deepEqual(evs[0]?.metadata, { via: 'magic_link' });
    assert.equal(evs[1]?.ip, '192.0.2.4');
    // spent: a second consume is invalid
    assert.deepEqual(await magic.consume({ token }, meta, later(61_000)), { kind: 'invalid' });
  });

  it('is enumeration-safe: unknown, unverified and deletion-pending addresses all accept and get the other mail', async () => {
    h.mail.clear();
    assert.deepEqual(await magic.request({ email: 'ghost@example.com' }, T0), { accepted: true });
    assert.match(h.mail.first('ghost@example.com').subject, /requested/i);
    assert.doesNotMatch(h.mail.first('ghost@example.com').body, /token=/);

    h.mail.clear();
    await id.signup({ email: 'ml-unverified@example.com', password: 'correct horse battery' });
    h.mail.clear();
    await magic.request({ email: 'ml-unverified@example.com' }, T0);
    assert.doesNotMatch(h.mail.first('ml-unverified@example.com').body, /token=/, 'no link for an unverified squat');
    assert.equal((await h.db.query('SELECT 1 FROM identity.magic_link_tokens')).length, 0);

    const userId = await verifiedUser('ml-deleting@example.com');
    await id.requestDeletion(userId, T0);
    h.mail.clear();
    await magic.request({ email: 'ml-deleting@example.com' }, T0);
    assert.doesNotMatch(h.mail.first('ml-deleting@example.com').body, /token=/);
  });

  it('one live token per user; expiry is checked on consume; expired links burn too', async () => {
    const userId = await verifiedUser('ml-one@example.com');
    await magic.request({ email: 'ml-one@example.com' }, T0);
    const first = tokenFrom(h.mail.first('ml-one@example.com').body);
    h.mail.clear();
    await magic.request({ email: 'ml-one@example.com' }, T0);
    const second = tokenFrom(h.mail.first('ml-one@example.com').body);
    assert.equal(await tokenCount(userId), 1);
    assert.deepEqual(await magic.consume({ token: first }, {}, T0), { kind: 'invalid' }, 'the older link is dead');
    // 15 minutes + 1s: expired, and burned by the attempt
    assert.deepEqual(await magic.consume({ token: second }, {}, later(15 * 60_000 + 1000)), { kind: 'invalid' });
    assert.equal(await tokenCount(userId), 0);
    // garbage
    assert.deepEqual(await magic.consume({ token: 'nope' }, {}, T0), { kind: 'invalid' });
  });

  it('a link issued before deletion is refused at consume time', async () => {
    const userId = await verifiedUser('ml-race@example.com');
    await magic.request({ email: 'ml-race@example.com' }, T0);
    const token = tokenFrom(h.mail.first('ml-race@example.com').body);
    await id.requestDeletion(userId, T0);
    assert.deepEqual(await magic.consume({ token }, {}, later(1000)), { kind: 'invalid' });
  });

  it('does not bypass a second factor: an enrolled user gets mfa_required', async () => {
    const mfa = createMfa({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      totp: { key: testTotpKey, keyVersion: 1, issuer: 'test' },
      rateLimiter: null,
    });
    const magicMfa = createMagic({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      rateLimiter: null,
      secondFactor: mfa.secondFactor,
    });
    const userId = await verifiedUser('ml-mfa@example.com');
    const { secret } = await mfa.beginTotpEnrolment(userId, { password: 'correct horse battery' });
    const code = (when: Date) =>
      new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: Secret.fromBase32(secret) }).generate({
        timestamp: when.getTime(),
      });
    await mfa.confirmTotpEnrolment(userId, code(T0), T0);
    h.mail.clear();
    await magicMfa.request({ email: 'ml-mfa@example.com' }, T0);
    const token = tokenFrom(h.mail.first('ml-mfa@example.com').body);
    const r = await magicMfa.consume({ token }, meta, later(31_000));
    assert.equal(r.kind, 'mfa_required');
    if (r.kind !== 'mfa_required') return;
    const done = await mfa.verifyTotp(r.pendingToken, code(later(31_000)), meta, later(31_000));
    assert.equal(done.kind, 'session');
  });

  it('request is rate-limited by address + ip through the seam; sweep prunes expired tokens', async () => {
    const limited = createMagic({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      rateLimiter: createMemoryRateLimiter({ rules: { magic_link: { limit: 2, windowMs: 60_000 } } }),
    });
    await limited.request({ email: 'ml-limit@example.com', ipAddress: '10.0.0.1' }, T0);
    await limited.request({ email: 'ml-limit@example.com', ipAddress: '10.0.0.1' }, T0);
    await assert.rejects(
      () => limited.request({ email: 'ml-limit@example.com', ipAddress: '10.0.0.1' }, T0),
      (e: unknown) => IdentityError.hasCode(e, 'rate_limited') && e.failure.retryAfterMs > 0,
    );
    // a different ip has its own budget
    await limited.request({ email: 'ml-limit@example.com', ipAddress: '10.0.0.2' }, T0);

    await verifiedUser('ml-sweep@example.com');
    await magic.request({ email: 'ml-sweep@example.com' }, T0);
    assert.equal(await magic.sweep(later(14 * 60_000)), 0);
    assert.equal(await magic.sweep(later(16 * 60_000)), 1);
    await magic.request({ email: 'ml-sweep@example.com' }, T0);
    const report = await id.sweepExpired(later(16 * 60_000));
    assert.equal(report.magicLinkTokens, 1);
  });
});
