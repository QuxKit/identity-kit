// The security-events log. What matters: every flow that authenticates an
// account or changes how it authenticates leaves a row, with the request's ip
// and user agent when they were given; nothing about an unknown address is ever
// written (that would make the log an enumeration record); the list pages
// newest-first; retention and purge actually delete.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';
import { Secret, TOTP } from 'otpauth';

import { createApiKeys } from '../src/apikeys.ts';
import { createIdentity, listEvents, recordEvent, sha256, sweepEvents } from '../src/index.ts';
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

describe('security events', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const id = createIdentity({ db: h.db, config: testConfig, mail: h.mail, rateLimiter: null });
  const meta = { ipAddress: '203.0.113.7', userAgent: 'test-agent/1.0' };

  const verifiedUser = async (email: string, password: string): Promise<string> => {
    h.mail.clear();
    await id.signup({ email, password });
    await id.verifyEmail(tokenFrom(h.mail.first(email).body));
    h.mail.clear();
    const rows = await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', [email]);
    return one(rows).id;
  };
  const kinds = async (userId: string) => (await id.events.list(userId)).map((e) => e.kind);

  it('records login_succeeded with the method, ip and user agent', async () => {
    const userId = await verifiedUser('ev-login@example.com', 'correct horse battery');
    const r = await id.login({ email: 'ev-login@example.com', password: 'correct horse battery' }, meta);
    assert.equal(r.kind, 'session');
    const [ev] = await id.events.list(userId);
    assert.ok(ev);
    assert.equal(ev.kind, 'login_succeeded');
    assert.equal(ev.ip, '203.0.113.7');
    assert.equal(ev.userAgent, 'test-agent/1.0');
    assert.deepEqual(ev.metadata, { via: 'password' });
    assert.equal(ev.userId, userId);
    assert.ok(ev.at instanceof Date);
    assert.match(ev.id, /^\d+$/);
  });

  it('records login_failed with a reason: bad password, unverified, backoff', async () => {
    const userId = await verifiedUser('ev-fail@example.com', 'correct horse battery');
    await id.login({ email: 'ev-fail@example.com', password: 'wrong' }, meta);
    let evs = await id.events.list(userId);
    assert.equal(evs[0]?.kind, 'login_failed');
    assert.deepEqual(evs[0]?.metadata, { reason: 'bad_password' });
    assert.equal(evs[0]?.ip, '203.0.113.7');

    // five more wrong ones cross the backoff threshold; the next attempt is
    // refused with backoff and recorded as such
    for (let i = 0; i < 5; i += 1) await id.login({ email: 'ev-fail@example.com', password: 'wrong' });
    const r = await id.login({ email: 'ev-fail@example.com', password: 'wrong' });
    assert.equal(r.kind, 'backoff');
    evs = await id.events.list(userId);
    assert.deepEqual(evs[0]?.metadata, { reason: 'backoff' });

    // unverified account: correct password, still failed, recorded as unverified
    h.mail.clear();
    await id.signup({ email: 'ev-unverified@example.com', password: 'correct horse battery' });
    const rows = await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', [
      'ev-unverified@example.com',
    ]);
    const unverifiedId = one(rows).id;
    const u = await id.login({ email: 'ev-unverified@example.com', password: 'correct horse battery' });
    assert.equal(u.kind, 'failed');
    const uev = await id.events.list(unverifiedId);
    assert.deepEqual(
      uev.map((e) => e.metadata),
      [{ reason: 'unverified' }],
    );
  });

  it('writes nothing for an unknown address — the log is not an enumeration record', async () => {
    const before = await h.db.query<{ n: string }>('SELECT count(*)::text AS n FROM identity.events');
    const r = await id.login({ email: 'nobody-here@example.com', password: 'whatever!!' }, meta);
    assert.equal(r.kind, 'failed');
    const after_ = await h.db.query<{ n: string }>('SELECT count(*)::text AS n FROM identity.events');
    assert.equal(one(after_).n, one(before).n);
  });

  it('records password_changed and the sessions it revoked', async () => {
    const userId = await verifiedUser('ev-change@example.com', 'correct horse battery');
    const a = await id.login({ email: 'ev-change@example.com', password: 'correct horse battery' });
    const b = await id.login({ email: 'ev-change@example.com', password: 'correct horse battery' });
    assert.ok(a.kind === 'session' && b.kind === 'session');
    await id.changePassword(
      userId,
      'correct horse battery',
      'a brand new passphrase',
      sha256(a.token),
      undefined,
      meta,
    );
    const evs = await id.events.list(userId);
    assert.deepEqual(
      evs.slice(0, 2).map((e) => e.kind),
      ['session_revoked', 'password_changed'],
    );
    assert.deepEqual(evs[0]?.metadata, { count: 1, keptOne: true });
    assert.equal(evs[1]?.ip, '203.0.113.7');
  });

  it('records password_reset in the same transaction as the reset', async () => {
    const userId = await verifiedUser('ev-reset@example.com', 'correct horse battery');
    h.mail.clear();
    await id.requestPasswordReset('ev-reset@example.com');
    const token = tokenFrom(h.mail.first('ev-reset@example.com').body);
    const r = await id.resetPassword(token, 'another fine passphrase', undefined, meta);
    assert.deepEqual(r, { kind: 'done' });
    const [ev] = await id.events.list(userId);
    assert.equal(ev?.kind, 'password_reset');
    assert.equal(ev?.userAgent, 'test-agent/1.0');

    // a burned/invalid token records nothing
    const n0 = (await id.events.list(userId)).length;
    await id.resetPassword(token, 'yet another passphrase');
    assert.equal((await id.events.list(userId)).length, n0);
  });

  it('records session_revoked from revokeSession and revokeAllSessions (only when something went)', async () => {
    const userId = await verifiedUser('ev-revoke@example.com', 'correct horse battery');
    const a = await id.login({ email: 'ev-revoke@example.com', password: 'correct horse battery' });
    const b = await id.login({ email: 'ev-revoke@example.com', password: 'correct horse battery' });
    assert.ok(a.kind === 'session' && b.kind === 'session');
    await id.revokeSession(sha256(a.token), meta);
    await id.revokeSession(sha256(a.token), meta); // already gone: no second event
    let evs = await id.events.list(userId);
    assert.equal(evs.filter((e) => e.kind === 'session_revoked').length, 1);
    assert.equal(evs[0]?.ip, '203.0.113.7');

    assert.equal(await id.revokeAllSessions(userId), 1);
    assert.equal(await id.revokeAllSessions(userId), 0);
    evs = await id.events.list(userId);
    assert.equal(evs.filter((e) => e.kind === 'session_revoked').length, 2);
    assert.deepEqual(evs[0]?.metadata, { count: 1, keptOne: false });
  });

  it('records mfa_enrolled / mfa_removed and login via totp', async () => {
    const mfa = createMfa({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      totp: { key: testTotpKey, keyVersion: 1, issuer: 'test' },
      rateLimiter: null,
    });
    const idm = createIdentity({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      secondFactor: mfa.secondFactor,
      rateLimiter: null,
    });
    const userId = await verifiedUser('ev-mfa@example.com', 'correct horse battery');
    const { secret } = await mfa.beginTotpEnrolment(userId, { password: 'correct horse battery' });
    const t0 = new Date('2026-08-15T12:00:00Z');
    await mfa.confirmTotpEnrolment(userId, codeFor(secret, t0), t0, undefined, meta);
    assert.equal((await id.events.list(userId))[0]?.kind, 'mfa_enrolled');
    assert.deepEqual((await id.events.list(userId))[0]?.metadata, { factor: 'totp' });

    const t1 = new Date(t0.getTime() + 31_000);
    const login = await idm.login({ email: 'ev-mfa@example.com', password: 'correct horse battery' }, meta, t1);
    assert.equal(login.kind, 'mfa_required');
    if (login.kind !== 'mfa_required') return;
    const done = await mfa.verifyTotp(login.pendingToken, codeFor(secret, t1), meta, t1);
    assert.equal(done.kind, 'session');
    const [ev] = await id.events.list(userId);
    assert.equal(ev?.kind, 'login_succeeded');
    assert.deepEqual(ev?.metadata, { via: 'totp' });

    await mfa.removeTotp(userId, 'correct horse battery', undefined, undefined, meta);
    assert.ok((await kinds(userId)).includes('mfa_removed'));
  });

  it('records api_key_issued / api_key_revoked keyed by the owner', async () => {
    const keys = createApiKeys({ db: h.db, prefix: 'evk' });
    const owner = 'org_42';
    const { id: keyId } = await keys.createApiKey(owner, { name: 'CI', meta });
    await keys.revokeApiKey(keyId, undefined, meta);
    await keys.revokeApiKey(keyId, undefined, meta); // no-op, no second event
    const evs = await listEvents(h.db, owner);
    assert.deepEqual(
      evs.map((e) => e.kind),
      ['api_key_revoked', 'api_key_issued'],
    );
    assert.equal(evs[1]?.metadata.apiKeyId, keyId);
    assert.equal(evs[1]?.metadata.name, 'CI');
    assert.equal(evs[0]?.ip, '203.0.113.7');
  });

  it('equal timestamps break on the numeric id, not its text form (9 < 10 < 12)', async () => {
    const userId = 'tie-subject';
    const at = new Date('2026-02-02T00:00:00Z');
    // enough rows that ids cross a digit boundary within the same instant
    for (let i = 0; i < 12; i += 1) {
      await recordEvent(h.db, { userId, kind: 'login_failed', at, metadata: { i } });
    }
    const evs = await listEvents(h.db, userId);
    const ids = evs.map((e) => Number(e.id));
    assert.deepEqual(
      ids,
      [...ids].sort((a, b) => b - a),
      'newest (highest id) first, numerically',
    );
    assert.equal(evs[0]?.metadata.i, 11);
  });

  it('list pages newest-first with limit and before; the limit is capped', async () => {
    const userId = 'paging-subject';
    const base = new Date('2026-01-01T00:00:00Z');
    for (let i = 0; i < 12; i += 1) {
      await recordEvent(h.db, { userId, kind: 'login_succeeded', at: new Date(base.getTime() + i * 1000) });
    }
    const page1 = await listEvents(h.db, userId, { limit: 5 });
    assert.equal(page1.length, 5);
    assert.equal(page1[0]?.at.getTime(), base.getTime() + 11_000);
    const last = page1[page1.length - 1];
    assert.ok(last);
    const page2 = await listEvents(h.db, userId, { limit: 5, before: last.at });
    assert.equal(page2[0]?.at.getTime(), last.at.getTime() - 1000);
    assert.equal((await listEvents(h.db, userId)).length, 12);
    assert.equal((await listEvents(h.db, userId, { limit: 0 })).length, 1, 'floor of 1');
    // the cap: ask for 1000, get at most 200
    for (let i = 0; i < 200; i += 1) {
      await recordEvent(h.db, { userId, kind: 'login_failed', at: new Date(base.getTime() + 100_000 + i) });
    }
    assert.equal((await listEvents(h.db, userId, { limit: 1000 })).length, 200);
  });

  it('sweeps by age, through sweepExpired too, and record() stamps the clock', async () => {
    const userId = 'sweep-subject';
    const old = new Date('2020-01-01T00:00:00Z');
    await recordEvent(h.db, { userId, kind: 'login_succeeded', at: old });
    await recordEvent(h.db, { userId, kind: 'login_succeeded', at: new Date('2026-08-01T00:00:00Z') });
    assert.equal(await sweepEvents(h.db, new Date('2021-01-01T00:00:00Z')), 1);
    assert.equal((await listEvents(h.db, userId)).length, 1);

    const clockNow = new Date('2026-08-17T00:00:00Z');
    const idc = createIdentity({
      db: h.db,
      config: { ...testConfig, eventRetentionMs: 24 * 60 * 60 * 1000 },
      mail: h.mail,
      clock: () => clockNow,
      rateLimiter: null,
    });
    await idc.events.record({ userId, kind: 'session_revoked' });
    const [latest] = await idc.events.list(userId);
    assert.equal(latest?.at.getTime(), clockNow.getTime());
    const report = await idc.sweepExpired();
    assert.ok(report.events >= 1, 'the 2026-08-01 row is older than the one-day retention');
    assert.equal((await idc.events.list(userId)).length, 1);
    assert.equal(await idc.events.sweep(), 0);
    // the sweep is global (every subject), so count is >= the one row left here
    assert.ok((await idc.events.sweep(new Date('2030-01-01T00:00:00Z'))) >= 1);
    assert.equal((await idc.events.list(userId)).length, 0);
  });

  it('purging accounts deletes their events', async () => {
    const clockNow = new Date('2026-08-17T00:00:00Z');
    const idc = createIdentity({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      clock: () => clockNow,
      rateLimiter: null,
    });
    const userId = await verifiedUser('ev-purge@example.com', 'correct horse battery');
    await id.login({ email: 'ev-purge@example.com', password: 'correct horse battery' });
    assert.ok((await listEvents(h.db, userId)).length > 0);
    await idc.requestDeletion(userId);
    assert.equal(await idc.purgeDeleted(new Date(clockNow.getTime() + 8 * 24 * 60 * 60 * 1000)), 1);
    assert.equal((await listEvents(h.db, userId)).length, 0);

    // purgeUnverified: same
    h.mail.clear();
    await idc.signup({ email: 'ev-stale@example.com', password: 'correct horse battery' });
    const rows = await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', [
      'ev-stale@example.com',
    ]);
    const staleId = one(rows).id;
    await idc.login({ email: 'ev-stale@example.com', password: 'correct horse battery' });
    assert.equal((await listEvents(h.db, staleId)).length, 1);
    assert.ok((await idc.purgeUnverified(new Date(clockNow.getTime() + 8 * 24 * 60 * 60 * 1000))) >= 1);
    assert.equal((await listEvents(h.db, staleId)).length, 0);
  });
});
