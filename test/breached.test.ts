// The breached-password screen. What matters: the password never leaves the
// process (only five hex characters of its SHA-1 do), a hit is refused
// everywhere a password is set, and the third party being down does not become
// an outage of signup, reset and change.

import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { after, describe, it } from 'node:test';

import { passwordBreached } from '../src/breached.ts';
import { passwordProblemAsync } from '../src/credentials.ts';
import { IdentityError } from '../src/errors.ts';
import { createIdentity } from '../src/index.ts';
import { type Harness, SKIP_REASON, setupDatabase, testConfig, tokenFrom } from './harness.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

const sha1 = (value: string) => createHash('sha1').update(value, 'utf8').digest('hex').toUpperCase();

/** A range API that answers from a set of known-breached passwords, padded the
 *  way the real one pads. Records every URL it was asked for. */
const fakeRange = (breached: Record<string, number>, opts: { fail?: boolean; status?: number } = {}) => {
  const calls: { url: string; headers?: Record<string, string> }[] = [];
  const fetchImpl = async (url: string, init?: { headers?: Record<string, string> }) => {
    calls.push({ url, headers: init?.headers });
    if (opts.fail) throw new Error('network down');
    if (opts.status && opts.status !== 200) {
      return { ok: false, status: opts.status, text: async () => 'nope' };
    }
    const prefix = url.slice(url.lastIndexOf('/') + 1);
    const lines: string[] = [];
    for (const [password, count] of Object.entries(breached)) {
      const digest = sha1(password);
      if (digest.startsWith(prefix)) lines.push(`${digest.slice(5)}:${count}`);
    }
    // padding: decoys with a zero count, as the API sends when add-padding is on
    lines.push(`${'0'.repeat(35)}:0`, `${'F'.repeat(35)}:0`);
    return { ok: true, status: 200, text: async () => `${lines.join('\r\n')}\r\n` };
  };
  return { fetchImpl, calls };
};

describe('breached passwords (no database)', () => {
  it('sends only the first five hex characters of the SHA-1, and matches the suffix locally', async () => {
    const { fetchImpl, calls } = fakeRange({ 'hunter2 forever': 4321 });
    const check = passwordBreached(fetchImpl);
    assert.equal(await check('hunter2 forever'), 4321);
    assert.equal(calls.length, 1);
    const url = calls[0]?.url as string;
    const prefix = sha1('hunter2 forever').slice(0, 5);
    assert.equal(url, `https://api.pwnedpasswords.com/range/${prefix}`);
    assert.doesNotMatch(url, /hunter2/, 'the password itself never appears in the request');
    assert.equal(url.slice(url.lastIndexOf('/') + 1).length, 5, 'five characters, not the whole digest');
    assert.equal(calls[0]?.headers?.['add-padding'], 'true');
    assert.equal(await check('a password nobody has used'), 0);
  });

  it('ignores padding decoys, tolerates CRLF and junk lines, and honours a custom endpoint', async () => {
    const digest = sha1('padded-case');
    const fetchImpl = async () => ({
      ok: true,
      status: 200,
      text: async () => ['not-a-line', `${'A'.repeat(35)}:0`, `${digest.slice(5).toLowerCase()}: 17 `, ''].join('\r\n'),
    });
    const check = passwordBreached(fetchImpl, { endpoint: 'https://mirror.internal/range/', padding: false });
    assert.equal(await check('padded-case'), 17, 'case-insensitive suffix match, whitespace trimmed');
    const seen: string[] = [];
    const recording = async (url: string, init?: { headers?: Record<string, string> }) => {
      seen.push(url);
      assert.equal(init?.headers?.['add-padding'], undefined, 'padding off means no header');
      return { ok: true, status: 200, text: async () => '' };
    };
    await passwordBreached(recording, { endpoint: 'https://mirror.internal/range/', padding: false })('x');
    assert.equal(seen[0], `https://mirror.internal/range/${sha1('x').slice(0, 5)}`);
  });

  it('fails open when the API is down or errors — unless strict', async () => {
    const down = fakeRange({}, { fail: true });
    assert.equal(await passwordBreached(down.fetchImpl)('anything'), 0, 'unreachable is not "breached"');
    const bad = fakeRange({}, { status: 503 });
    assert.equal(await passwordBreached(bad.fetchImpl)('anything'), 0);
    await assert.rejects(() => passwordBreached(down.fetchImpl, { strict: true })('anything'), /network down/);
    await assert.rejects(() => passwordBreached(bad.fetchImpl, { strict: true })('anything'), /503/);
  });

  it('abandons a slow API by its timeout, and fails open when it does', async () => {
    const hang: Parameters<typeof passwordBreached>[0] = (_url, init) =>
      new Promise((_resolve, reject) => {
        init?.signal?.addEventListener('abort', () => reject(new Error('aborted')));
      });
    assert.equal(await passwordBreached(hang, { timeoutMs: 20 })('slow'), 0);
    await assert.rejects(() => passwordBreached(hang, { timeoutMs: 20, strict: true })('slow'), /aborted/);
  });

  it('passwordProblemAsync layers the screen on top of the length floor', async () => {
    const { fetchImpl } = fakeRange({ 'breached but long enough': 9 });
    const config = { ...testConfig, breachedPasswords: passwordBreached(fetchImpl) };
    assert.match((await passwordProblemAsync(config, 'short')) ?? '', /at least 8/);
    assert.match((await passwordProblemAsync(config, 'breached but long enough')) ?? '', /data breach/);
    assert.equal(await passwordProblemAsync(config, 'a fresh unbroken passphrase'), null);
    // no screen wired: only the local rules, and nothing is fetched at all
    const spy = fakeRange({ 'breached but long enough': 9 });
    assert.equal(await passwordProblemAsync(testConfig, 'breached but long enough'), null);
    assert.equal(spy.calls.length, 0, 'an unconfigured screen makes no request');
  });
});

describe('breached passwords — through the flows', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const { fetchImpl, calls } = fakeRange({ 'correct horse battery staple': 5_000_000 });
  const config = { ...testConfig, breachedPasswords: passwordBreached(fetchImpl) };
  const id = createIdentity({ db: h.db, config, mail: h.mail, rateLimiter: null });

  it('refuses a breached password at signup, reset and change; accepts a fresh one', async () => {
    await assert.rejects(
      () => id.signup({ email: 'hibp@example.com', password: 'correct horse battery staple' }),
      (e: unknown) => IdentityError.hasCode(e, 'weak_password') && /data breach/.test(e.failure.reason),
    );
    assert.ok(calls.length > 0, 'the screen was consulted');

    h.mail.clear();
    await id.signup({ email: 'hibp@example.com', password: 'an unbreached passphrase' });
    await id.verifyEmail(tokenFrom(h.mail.first('hibp@example.com').body));
    h.mail.clear();

    // reset: the weak_password result, not a throw
    await id.requestPasswordReset('hibp@example.com');
    const token = tokenFrom(h.mail.first('hibp@example.com').body);
    const reset = await id.resetPassword(token, 'correct horse battery staple');
    assert.equal(reset.kind, 'weak_password');
    if (reset.kind === 'weak_password') assert.match(reset.message, /data breach/);

    // change
    const login = await id.login({ email: 'hibp@example.com', password: 'an unbreached passphrase' });
    assert.equal(login.kind, 'session');
    const userId = (
      await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE email = $1', ['hibp@example.com'])
    )[0]?.id as string;
    await assert.rejects(
      () => id.changePassword(userId, 'an unbreached passphrase', 'correct horse battery staple'),
      (e: unknown) => IdentityError.hasCode(e, 'weak_password') && /data breach/.test(e.failure.reason),
    );
    await id.changePassword(userId, 'an unbreached passphrase', 'another fine passphrase');
  });

  it('a breached password already in use still logs in — screening gates setting, not authenticating', async () => {
    // Someone whose stored password later appears in a breach must still be able
    // to sign in; otherwise the screen locks people out of the account they need
    // to get into in order to fix it.
    const bare = createIdentity({ db: h.db, config: testConfig, mail: h.mail, rateLimiter: null });
    h.mail.clear();
    await bare.signup({ email: 'hibp2@example.com', password: 'correct horse battery staple' });
    await bare.verifyEmail(tokenFrom(h.mail.first('hibp2@example.com').body));
    const r = await id.login({ email: 'hibp2@example.com', password: 'correct horse battery staple' });
    assert.equal(r.kind, 'session', 'the screen is not consulted on login');
  });
});
