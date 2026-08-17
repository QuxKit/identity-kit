// API keys authenticate as an owner, not as a user, and are rejected structurally
// before any database work. The tests cover the shape/checksum gate, the
// once-only reveal, resolution to the owner + scopes, expiry and revocation.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import { createApiKeys } from '../src/apikeys.ts';
import { type Harness, SKIP_REASON, setupDatabase } from './harness.ts';

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
    assert.equal(principal!.ownerId, 'org_42');
    assert.equal(principal!.apiKeyId, created.id);
    assert.deepEqual(principal!.scopes, ['read', 'write']);

    // the full key is not retrievable — a listing shows only the display prefix
    const listed = await keys.listApiKeys('org_42');
    assert.equal(listed.length, 1);
    assert.equal(listed[0]!.displayPrefix, created.displayPrefix);
    assert.equal((listed[0] as unknown as Record<string, unknown>).key, undefined);
  });

  it('refuses an expired key and a revoked key', async () => {
    const past = new Date(Date.now() - 1000);
    const expired = await keys.createApiKey('org_42', { name: 'old', expiresAt: past });
    assert.equal(await keys.resolveApiKey(expired.key), null, 'expired key does not resolve');

    const live = await keys.createApiKey('org_42', { name: 'to-revoke' });
    assert.ok(await keys.resolveApiKey(live.key));
    await keys.revokeApiKey(live.id);
    assert.equal(await keys.resolveApiKey(live.key), null, 'revoked key does not resolve');
  });

  it('does not resolve a structurally invalid key (no probe on the hot path)', async () => {
    assert.equal(await keys.resolveApiKey('idk_live_short'), null);
    assert.equal(await keys.resolveApiKey('garbage'), null);
  });
});
