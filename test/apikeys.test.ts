// API keys authenticate as an owner, not as a user, and are rejected structurally
// before any database work. The tests cover the shape/checksum gate, the
// once-only reveal, resolution to the owner + scopes, expiry and revocation.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import { createApiKeys } from '../src/apikeys.ts';
import { IdentityError } from '../src/errors.ts';
import { type Harness, one, SKIP_REASON, setupDatabase } from './harness.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

describe('identity-kit/apikeys', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const keys = createApiKeys({ db: h.db, prefix: 'idk' });

  it('mints a well-formed key that passes its own checksum gate', () => {
    const key = keys.mint('live');
    assert.match(key, /^idk_live_[A-Z2-7]{52}_[A-Z2-7]{7}$/);
    assert.equal(keys.looksLikeKey(key), true);
    // a tampered key fails structurally, with no database work. Flip the last
    // char to a guaranteed-different one, or the "tamper" is a no-op when the
    // checksum already ends in the char we picked.
    assert.equal(keys.looksLikeKey(key.slice(0, -1) + (key.at(-1) === 'A' ? 'B' : 'A')), false);
    assert.equal(keys.looksLikeKey('not-a-key'), false);
  });

  it('creates a key, reveals it once, and resolves it to owner + scopes', async () => {
    const created = await keys.createApiKey('org_42', { name: 'CI', scopes: ['read', 'write'] });
    assert.match(created.key, /^idk_live_/);
    assert.ok(created.displayPrefix.length > 0 && created.key.startsWith(created.displayPrefix));

    const principal = await keys.resolveApiKey(created.key);
    assert.ok(principal);
    assert.equal(principal?.ownerId, 'org_42');
    assert.equal(principal?.apiKeyId, created.id);
    assert.deepEqual(principal?.scopes, ['read', 'write']);

    // the full key is not retrievable — a listing shows only the display prefix
    const listed = await keys.listApiKeys('org_42');
    assert.equal(listed.length, 1);
    assert.equal(one(listed).displayPrefix, created.displayPrefix);
    assert.equal((listed[0] as unknown as Record<string, unknown>).key, undefined);
  });

  it('refuses an expired key and a revoked key', async () => {
    const past = new Date(Date.now() - 1000);
    const expired = await keys.createApiKey('org_42', { name: 'old', expiresAt: past });
    assert.equal(await keys.resolveApiKey(expired.key), null, 'expired key does not resolve');

    const live = await keys.createApiKey('org_42', { name: 'to-revoke' });
    assert.ok(await keys.resolveApiKey(live.key));
    const when = new Date('2026-08-15T12:00:00Z');
    await keys.revokeApiKey(live.id, when);
    assert.equal(await keys.resolveApiKey(live.key), null, 'revoked key does not resolve');
    // soft: the row stays for audit, stamped once
    const listed = (await keys.listApiKeys('org_42')).find((k) => k.id === live.id);
    assert.equal(listed?.revokedAt?.getTime(), when.getTime());
    await keys.revokeApiKey(live.id, new Date(when.getTime() + 1000));
    const again = (await keys.listApiKeys('org_42')).find((k) => k.id === live.id);
    assert.equal(again?.revokedAt?.getTime(), when.getTime(), 'a second revoke does not move the timestamp');
    const row = one(
      await h.db.query<{ revoked_at: Date | null }>('SELECT revoked_at FROM identity.api_keys WHERE id = $1', [
        live.id,
      ]),
    );
    assert.ok(row.revoked_at, 'revoked_at is real');
  });

  it('a bad prefix is a typed configuration error', () => {
    assert.throws(
      () => createApiKeys({ db: h.db, prefix: 'Bad-Prefix' }),
      (e: unknown) => IdentityError.hasCode(e, 'invalid_config'),
    );
  });

  it('does not resolve a structurally invalid key (no probe on the hot path)', async () => {
    assert.equal(await keys.resolveApiKey('idk_live_short'), null);
    assert.equal(await keys.resolveApiKey('garbage'), null);
  });
});

describe('identity-kit/apikeys — rolling and revoking at any time', {
  skip: harness === null ? SKIP_REASON : false,
}, () => {
  const h = harness as Harness;
  const keys = createApiKeys({ db: h.db, prefix: 'idr' });
  const t0 = new Date('2026-11-15T12:00:00Z');
  const at = (ms: number) => new Date(t0.getTime() + ms);
  const HOUR = 3_600_000;

  it('rolls a key: same name, scopes and environment, both resolve through the overlap, then only the new one', async () => {
    const old = await keys.createApiKey('org_roll', { name: 'deploy', scopes: ['read'], environment: 'test' });
    const rolled = await keys.rollApiKey(old.id, { overlapMs: HOUR }, t0);
    assert.notEqual(rolled.key, old.key);
    assert.match(rolled.key, /^idr_test_/, 'the environment carries over');
    assert.equal(rolled.replaces, old.id);
    assert.equal(rolled.oldExpiresAt.getTime(), at(HOUR).getTime());

    const during = at(HOUR - 1);
    assert.equal((await keys.resolveApiKey(old.key, during))?.apiKeyId, old.id, 'the old key still works mid-overlap');
    const fresh = await keys.resolveApiKey(rolled.key, during);
    assert.deepEqual([fresh?.ownerId, fresh?.scopes], ['org_roll', ['read']]);
    assert.equal(await keys.resolveApiKey(old.key, at(HOUR)), null, 'and stops at the end of it');
    assert.ok(await keys.resolveApiKey(rolled.key, at(HOUR)));

    const listed = await keys.listApiKeys('org_roll', during);
    const newest = listed.find((k) => k.id === rolled.id);
    const oldest = listed.find((k) => k.id === old.id);
    assert.deepEqual(
      [newest?.id, newest?.name, newest?.rolledFrom, newest?.state, newest?.environment],
      [rolled.id, 'deploy', old.id, 'active', 'test'],
    );
    assert.deepEqual([oldest?.replacedBy, oldest?.state], [rolled.id, 'rolling']);
    assert.equal((await keys.getApiKey(old.id, at(HOUR)))?.state, 'expired');
  });

  it('an overlap of 0 cuts the old key off at once; the overlap never extends an earlier expiry', async () => {
    const a = await keys.createApiKey('org_roll2', { name: 'now' });
    const ra = await keys.rollApiKey(a.id, { overlapMs: 0 }, t0);
    assert.equal(await keys.resolveApiKey(a.key, t0), null);
    assert.ok(await keys.resolveApiKey(ra.key, t0));

    const b = await keys.createApiKey('org_roll2', { name: 'short', expiresAt: at(10 * 60_000) });
    const rb = await keys.rollApiKey(b.id, { overlapMs: 7 * 24 * HOUR }, t0);
    assert.equal(rb.oldExpiresAt.getTime(), at(10 * 60_000).getTime(), 'the old expiry stands');
  });

  it('revokes at any time: the old key mid-overlap dies on the next request, the replacement lives on', async () => {
    const old = await keys.createApiKey('org_leak', { name: 'leaked' });
    const rolled = await keys.rollApiKey(old.id, { overlapMs: 24 * HOUR }, t0);
    await keys.revokeApiKey(old.id, at(60_000));
    assert.equal(await keys.resolveApiKey(old.key, at(60_001)), null);
    assert.ok(await keys.resolveApiKey(rolled.key, at(60_001)));
    assert.equal((await keys.getApiKey(old.id, at(60_001)))?.state, 'revoked');
  });

  it('refuses to roll a revoked, expired or already-rolled key, and says which', async () => {
    const refused = (reason: RegExp) => (e: unknown) =>
      IdentityError.hasCode(e, 'invalid_state') && reason.test(e.message);
    const r = await keys.createApiKey('org_no', { name: 'r' });
    await keys.revokeApiKey(r.id, t0);
    await assert.rejects(keys.rollApiKey(r.id, {}, t0), refused(/revoked/));
    const x = await keys.createApiKey('org_no', { name: 'x', expiresAt: at(-1) });
    await assert.rejects(keys.rollApiKey(x.id, {}, t0), refused(/expired/));
    const twice = await keys.createApiKey('org_no', { name: 'twice' });
    const first = await keys.rollApiKey(twice.id, {}, t0);
    await assert.rejects(keys.rollApiKey(twice.id, {}, t0), refused(/already rolled/));
    assert.ok(await keys.rollApiKey(first.id, {}, t0), 'rolling the replacement is how to go again');
    await assert.rejects(keys.rollApiKey(twice.id, { overlapMs: 31 * 24 * HOUR }, t0), (e: unknown) =>
      IdentityError.hasCode(e, 'invalid_request'),
    );
    await assert.rejects(keys.rollApiKey('not-a-uuid'), (e: unknown) => IdentityError.hasCode(e, 'not_found'));
  });

  it('two rolls at once leave one replacement', async () => {
    const k = await keys.createApiKey('org_race', { name: 'race' });
    const results = await Promise.allSettled([keys.rollApiKey(k.id, {}, t0), keys.rollApiKey(k.id, {}, t0)]);
    assert.equal(results.filter((r) => r.status === 'fulfilled').length, 1);
    const rows = await h.db.query<{ n: string }>(
      'SELECT count(*)::text AS n FROM identity.api_keys WHERE rolled_from = $1',
      [k.id],
    );
    assert.equal(rows[0]?.n, '1');
  });

  it('keeps a lifetime: a key that expired after 90 days is replaced by one that does too', async () => {
    const k = await keys.createApiKey('org_life', { name: 'ttl', expiresAt: at(90 * 24 * HOUR) });
    const created = (await keys.getApiKey(k.id))?.createdAt as Date;
    const span = at(90 * 24 * HOUR).getTime() - created.getTime();
    const rolled = await keys.rollApiKey(k.id, {}, t0);
    assert.equal((await keys.getApiKey(rolled.id))?.expiresAt?.getTime(), t0.getTime() + span);
  });

  it('keeps each prefix to its own keys when several share the table and an owner', async () => {
    const chat = createApiKeys({ db: h.db, prefix: 'idrc' });
    const reg = createApiKeys({ db: h.db, prefix: 'idrr' });
    const c = await chat.createApiKey('ws_shared', { name: 'chat' });
    const r = await reg.createApiKey('ws_shared', { name: 'registry' });
    assert.deepEqual(
      (await chat.listApiKeys('ws_shared')).map((k) => k.id),
      [c.id],
      'one kind’s list never shows another’s',
    );
    assert.equal(await chat.getApiKey(r.id), null);
    await chat.revokeApiKey(r.id);
    assert.ok(await reg.resolveApiKey(r.key), 'a revoke through the wrong kind does nothing');
    await assert.rejects(chat.rollApiKey(r.id), (e: unknown) => IdentityError.hasCode(e, 'not_found'));
    assert.equal(await chat.revokeAllApiKeys('ws_shared'), 1, 'revoke-all stays within its kind');
    assert.equal(await chat.resolveApiKey(c.key), null);
    assert.ok(await reg.resolveApiKey(r.key), 'the registry token is untouched');
    await keys.revokeApiKey('not-a-uuid');
  });

  it('an operator revokes every live key an owner holds, and finds any key by id', async () => {
    const a = await keys.createApiKey('org_stop', { name: 'a' });
    const b = await keys.createApiKey('org_stop', { name: 'b' });
    const c = await keys.rollApiKey(b.id, { overlapMs: HOUR }, t0);
    await keys.createApiKey('org_other', { name: 'untouched' });
    assert.equal((await keys.getApiKey(c.id))?.ownerId, 'org_stop');
    assert.equal(await keys.getApiKey('nope'), null);
    assert.equal(await keys.revokeAllApiKeys('org_stop', at(1)), 3, 'a, the rolling b, and its replacement');
    for (const key of [a.key, c.key]) assert.equal(await keys.resolveApiKey(key, at(2)), null);
    assert.equal(await keys.revokeAllApiKeys('org_stop', at(3)), 0, 'a second press finds nothing left');
    assert.equal((await keys.listApiKeys('org_other')).filter((k) => k.state === 'active').length, 1);
  });
});
