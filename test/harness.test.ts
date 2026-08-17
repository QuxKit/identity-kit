// The harness itself: importable without a database, and honest about what the
// default `test` script runs. Both checks need no Postgres, so they run — and
// can fail — everywhere.

import assert from 'node:assert/strict';
import { readdirSync } from 'node:fs';
import { describe, it } from 'node:test';
import { fileURLToPath } from 'node:url';

import * as harness from './harness.ts';

describe('test harness', () => {
  it('imports and exposes the pieces the suites rely on', () => {
    assert.equal(typeof harness.setupDatabase, 'function');
    assert.equal(typeof harness.one, 'function');
    assert.equal(typeof harness.tokenFrom, 'function');
    assert.equal(typeof harness.testConfig.pepper, 'string');
    assert.match(harness.TEST_DATABASE_URL, /^postgres(ql)?:\/\//);
    assert.match(harness.SKIP_REASON, /identity_kit_test|IDENTITY_KIT_TEST_DATABASE_URL/);
  });

  it('one() returns the first row and throws legibly on none', () => {
    assert.equal(harness.one([1, 2]), 1);
    assert.throws(() => harness.one([], 'user row'), /expected a user row/);
  });

  it('tokenFrom() pulls a URL-encoded token out of a mail body', () => {
    assert.equal(harness.tokenFrom('go to https://app.test/verify?token=a%2Bb%3D and done'), 'a+b=');
    assert.throws(() => harness.tokenFrom('no link here'), /no token/);
  });

  it('every test file lives where the default `test` glob will run it', () => {
    // The `test` script globs `test/*.test.ts` (flat, shell-expanded, so it works
    // in every CI shell). A test file nested deeper — or under src/ — would be
    // silently skipped; this is the check that keeps the glob honest.
    const root = fileURLToPath(new URL('..', import.meta.url));
    const nested = readdirSync(root, { recursive: true, encoding: 'utf8' })
      .filter((p) => p.endsWith('.test.ts') && !p.includes('node_modules'))
      .filter((p) => !/^test\/[^/]+\.test\.ts$/.test(p));
    assert.deepEqual(nested, [], `test files the default glob would miss: ${nested.join(', ')}`);
  });
});
