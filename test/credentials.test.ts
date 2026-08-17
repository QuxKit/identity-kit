// The credential module without a database: hashing round-trips, the pepper
// binds the hash to the process, `needsRehash` drives upgrades, and the dummy
// path burns the same work while always failing.

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { createCredentials, IdentityError, PARAMS, passwordProblem } from '../src/index.ts';
import { testConfig } from './harness.ts';

describe('credentials', () => {
  const creds = createCredentials(testConfig);

  it('hashes and verifies; a wrong password or a wrong pepper fails', async () => {
    const stored = await creds.hashPassword('correct horse battery');
    assert.match(stored, /^\$argon2id\$v=19\$m=65536,t=3,p=1\$/);
    assert.equal(await creds.verifyPassword(stored, 'correct horse battery', 1), true);
    assert.equal(await creds.verifyPassword(stored, 'wrong', 1), false);
    const other = createCredentials({ ...testConfig, pepper: 'a different pepper' });
    assert.equal(
      await other.verifyPassword(stored, 'correct horse battery', 1),
      false,
      'the pepper is part of the hash',
    );
  });

  it('a malformed stored hash verifies as false, never throws', async () => {
    assert.equal(await creds.verifyPassword('not-a-hash', 'anything', 1), false);
  });

  it('pepper rotation: a stored version this process does not hold is a typed error, not a wrong password', async () => {
    const stored = await creds.hashPassword('correct horse battery');
    const v2 = createCredentials({ ...testConfig, pepperVersion: 2 });
    await assert.rejects(
      () => v2.verifyPassword(stored, 'correct horse battery', 1),
      (e: unknown) => IdentityError.hasCode(e, 'pepper_version') && e.failure.stored === 1 && e.failure.current === 2,
    );
    assert.equal(v2.needsRehash(stored, 1), true, 'an old pepper version always needs a rehash');
    assert.equal(v2.needsRehash(await v2.hashPassword('x'.repeat(8)), 2), false);
    // holding the retired pepper makes the old hash verify again
    const ring = createCredentials({
      ...testConfig,
      pepper: 'new-pepper',
      pepperVersion: 2,
      previousPeppers: { 1: testConfig.pepper },
    });
    assert.equal(await ring.verifyPassword(stored, 'correct horse battery', 1), true);
    assert.equal(await ring.verifyPassword(stored, 'wrong', 1), false);
  });

  it('needsRehash: below-cost parameters, a different parallelism, or garbage', () => {
    const cheap = '$argon2id$v=19$m=4096,t=1,p=1$c2FsdA$aGFzaA';
    assert.equal(creds.needsRehash(cheap, 1), true, 'lower memory/time cost');
    const parallel = `$argon2id$v=19$m=${PARAMS.memoryCost},t=${PARAMS.timeCost},p=2$c2FsdA$aGFzaA`;
    assert.equal(creds.needsRehash(parallel, 1), true, 'p must match exactly');
    const stronger = `$argon2id$v=19$m=${PARAMS.memoryCost * 2},t=${PARAMS.timeCost + 1},p=1$c2FsdA$aGFzaA`;
    assert.equal(creds.needsRehash(stronger, 1), false, 'a stronger hash is left alone');
    assert.equal(creds.needsRehash('garbage', 1), true);
  });

  it('verifyAgainstDummy always returns false', async () => {
    assert.equal(await creds.verifyAgainstDummy('anything'), false);
    assert.equal(await creds.verifyAgainstDummy('dummy'), false);
  });

  it('passwordProblem: NIST length floor and ceiling, no composition rules', () => {
    assert.match(passwordProblem('short') ?? '', /at least 8/);
    assert.match(passwordProblem('x'.repeat(1025)) ?? '', /at most 1024/);
    assert.equal(passwordProblem('all lower case and spaces'), null);
  });
});
