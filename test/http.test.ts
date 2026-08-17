// The routes builder: every endpoint through the neutral request shape, the
// cookie and error mapping, CSRF double-submit, and the three adapters driven
// by fake (and, for node:http, real) requests.

import assert from 'node:assert/strict';
import { createServer } from 'node:http';
import { after, describe, it } from 'node:test';
import { Secret, TOTP } from 'otpauth';

import { createApiKeys } from '../src/apikeys.ts';
import { IdentityError } from '../src/errors.ts';
import {
  cookies,
  createCsrf,
  errorResponse,
  expressHandler,
  type HttpRequest,
  type HttpResponse,
  honoHandler,
  nodeListener,
  routes,
} from '../src/http.ts';
import { createIdentity, createMemoryRateLimiter } from '../src/index.ts';
import { createMagic } from '../src/magic.ts';
import { createMfa } from '../src/mfa.ts';
import { createPasskeys } from '../src/passkeys.ts';
import { type Harness, SKIP_REASON, setupDatabase, testConfig, testTotpKey, tokenFrom } from './harness.ts';
import { SoftAuthenticator } from './soft-authenticator.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

const RP = { id: 'app.test', name: 'Test', origin: 'https://app.test' };
const T0 = new Date('2026-08-15T12:00:00Z');

/** Pull `name=value` out of a Set-Cookie header value. */
const cookieValue = (res: HttpResponse, name: string): string | undefined => {
  const sc = res.headers['set-cookie'];
  const list = Array.isArray(sc) ? sc : sc ? [sc] : [];
  for (const c of list) {
    const m = new RegExp(`^${name.replace(/[-[\]/{}()*+?.\\^$|]/g, '\\$&')}=([^;]*)`).exec(c);
    if (m) return m[1];
  }
  return undefined;
};

describe('identity-kit/http — csrf + helpers (no database)', () => {
  it('csrf: issue + verify by header or body, constant-time; the cookie follows cookieSecure', () => {
    const csrf = createCsrf(testConfig);
    assert.equal(csrf.cookieName(), '__Host-csrf');
    const { token, cookie } = csrf.issue();
    assert.match(cookie, /^__Host-csrf=.+; SameSite=Strict; Path=\/; Max-Age=43200; Secure$/);
    const req = (h: Record<string, string>, body?: unknown): HttpRequest => ({
      method: 'POST',
      path: '/x',
      headers: h,
      body,
    });
    assert.equal(csrf.verify(req({ cookie: `__Host-csrf=${token}`, 'x-csrf-token': token })), true);
    assert.equal(csrf.verify(req({ cookie: `__Host-csrf=${token}` }, { _csrf: token })), true);
    assert.equal(csrf.verify(req({ cookie: `__Host-csrf=${token}`, 'x-csrf-token': `${token}x` })), false);
    assert.equal(csrf.verify(req({ 'x-csrf-token': token })), false);
    assert.equal(csrf.verify(req({ cookie: `__Host-csrf=${token}` })), false);
    assert.equal(createCsrf({ ...testConfig, cookieSecure: false }).cookieName(), 'csrf');
    assert.doesNotMatch(createCsrf({ ...testConfig, cookieSecure: false }).issue().cookie, /Secure/);
  });

  it('cookies() parses the header, first value wins, junk ignored', () => {
    const c = cookies({ method: 'GET', path: '/', headers: { cookie: 'a=1; b=2 ; a=3; junk; =x' } });
    assert.deepEqual(c, { a: '1', b: '2' });
    assert.deepEqual(cookies({ method: 'GET', path: '/', headers: {} }), {});
  });

  it('errorResponse maps codes and hides the limiter key; non-IdentityErrors propagate', () => {
    const r = errorResponse(new IdentityError({ code: 'rate_limited', retryAfterMs: 1500, key: 'login:a@b|1.2.3.4' }));
    assert.equal(r.status, 429);
    assert.equal(r.headers['retry-after'], '2');
    assert.deepEqual(r.body, { error: 'rate_limited', code: 'rate_limited', retryAfterMs: 1500 });
    assert.equal(errorResponse(new IdentityError({ code: 'reauth_required' })).status, 401);
    assert.equal(errorResponse(new IdentityError({ code: 'no_id_token' })).status, 400);
    assert.throws(() => errorResponse(new TypeError('boom')), TypeError);
  });
});

describe('identity-kit/http — routes', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const rotating = { ...testConfig, rotateSessions: true };
  const identity = createIdentity({ db: h.db, config: rotating, mail: h.mail, rateLimiter: null });
  const mfa = createMfa({
    db: h.db,
    config: rotating,
    mail: h.mail,
    totp: { key: testTotpKey, keyVersion: 1, issuer: 'test' },
    rateLimiter: null,
  });
  const identityMfa = createIdentity({
    db: h.db,
    config: rotating,
    mail: h.mail,
    rateLimiter: null,
    secondFactor: mfa.secondFactor,
  });
  const apiKeys = createApiKeys({ db: h.db, prefix: 'rt' });
  const magic = createMagic({ db: h.db, config: rotating, mail: h.mail, rateLimiter: null });
  const passkeys = createPasskeys({ db: h.db, config: rotating, mail: h.mail, rp: RP, rateLimiter: null });
  let now = T0;
  const r = routes({
    identity: identityMfa,
    config: rotating,
    mfa,
    apiKeys,
    magic,
    passkeys,
    basePath: '/auth',
    clock: () => now,
  });

  const call = (
    method: string,
    path: string,
    body?: unknown,
    headers: Record<string, string> = {},
    ip = '203.0.113.1',
  ) => r.handle({ method, path: `/auth${path}`, headers: { 'user-agent': 'routes-test', ...headers }, body, ip });
  const must = async (...args: Parameters<typeof call>): Promise<HttpResponse> => {
    const out = await call(...args);
    assert.ok(out, `expected a response for ${args[0]} ${args[1]}`);
    return out;
  };
  const cookieHeader = (token: string) => ({ cookie: `${identity.cookieName()}=${token}` });

  it('lists its paths and falls through on anything else; wrong method is 405', async () => {
    assert.ok(r.paths.includes('/auth/login'));
    assert.ok(r.paths.includes('/auth/passkeys/:id'));
    assert.equal(await r.handle({ method: 'GET', path: '/nope', headers: {} }), null);
    assert.equal(await r.handle({ method: 'GET', path: '/auth/nope', headers: {} }), null);
    assert.equal(await r.handle({ method: 'GET', path: '/authx/login', headers: {} }), null);
    assert.equal((await must('GET', '/login')).status, 405);
    assert.equal((await must('POST', '/apikeys/abc/def')).status, 405);
  });

  it('rejects a non-object or malformed JSON body, and missing fields, with 400', async () => {
    assert.equal((await must('POST', '/login', '{not json')).status, 400);
    assert.equal((await must('POST', '/login', [1, 2])).status, 400);
    const missing = await must('POST', '/login', { email: 'a@b.c' });
    assert.equal(missing.status, 400);
    assert.deepEqual(missing.body, { error: 'invalid_body', missing: 'password' });
  });

  it('signup → verify → login sets the session cookie; session, logout clear it', async () => {
    h.mail.clear();
    const s = await must('POST', '/signup', {
      email: 'rt-a@example.com',
      password: 'correct horse battery',
      name: 'A',
    });
    assert.equal(s.status, 202);
    const token = tokenFrom(h.mail.first('rt-a@example.com').body);
    assert.equal((await must('POST', '/verify', { token: 'bad' })).status, 400);
    assert.equal((await must('POST', '/verify', { token })).status, 200);
    assert.equal((await must('POST', '/verify/resend', { email: 'rt-a@example.com' })).status, 202);

    const bad = await must('POST', '/login', { email: 'rt-a@example.com', password: 'wrong' });
    assert.equal(bad.status, 401);
    assert.deepEqual(bad.body, { kind: 'failed' });

    const ok = await must('POST', '/login', { email: 'rt-a@example.com', password: 'correct horse battery' });
    assert.equal(ok.status, 200);
    assert.equal(ok.headers['content-type'], 'application/json; charset=utf-8');
    const session = cookieValue(ok, '__Host-session');
    assert.ok(session);
    assert.match(String(ok.headers['set-cookie']), /HttpOnly; SameSite=Lax; Path=\/; Max-Age=\d+; Secure/);

    const me = await must('GET', '/session', undefined, cookieHeader(session));
    assert.equal(me.status, 200);
    assert.equal((me.body as { userId: string }).userId.length, 36);
    // bearer works too
    assert.equal((await must('GET', '/session', undefined, { authorization: `Bearer ${session}` })).status, 200);
    assert.equal((await must('GET', '/session', undefined, cookieHeader('nope'))).status, 401);
    assert.equal((await must('GET', '/session')).status, 401);

    const out = await must('POST', '/logout', undefined, cookieHeader(session));
    assert.equal(out.status, 204);
    assert.equal(out.body, null);
    assert.match(String(out.headers['set-cookie']), /__Host-session=; .*Max-Age=0/);
    assert.equal((await must('GET', '/session', undefined, cookieHeader(session))).status, 401);
    // logout without a session is still 204
    assert.equal((await must('POST', '/logout')).status, 204);
  });

  it('login backoff is 429 with Retry-After; a rotated session comes back as a new cookie', async () => {
    h.mail.clear();
    await must('POST', '/signup', { email: 'rt-b@example.com', password: 'correct horse battery' });
    await must('POST', '/verify', { token: tokenFrom(h.mail.first('rt-b@example.com').body) });
    for (let i = 0; i < 6; i += 1) await must('POST', '/login', { email: 'rt-b@example.com', password: 'wrong' });
    const back = await must('POST', '/login', { email: 'rt-b@example.com', password: 'wrong' });
    assert.equal(back.status, 429);
    assert.ok(Number(back.headers['retry-after']) >= 1);

    now = new Date(T0.getTime() + 20 * 60_000);
    const ok = await must('POST', '/login', { email: 'rt-b@example.com', password: 'correct horse battery' });
    const session = cookieValue(ok, '__Host-session') as string;
    // eight days later the sliding renewal rotates: the new cookie is set
    now = new Date(now.getTime() + 8 * 24 * 60 * 60_000);
    const me = await must('GET', '/session', undefined, cookieHeader(session));
    assert.equal(me.status, 200);
    const rotated = cookieValue(me, '__Host-session');
    assert.ok(rotated && rotated !== session);
    now = T0;
  });

  it('password reset request/confirm and change (rotates the kept session)', async () => {
    h.mail.clear();
    await must('POST', '/signup', { email: 'rt-c@example.com', password: 'correct horse battery' });
    await must('POST', '/verify', { token: tokenFrom(h.mail.first('rt-c@example.com').body) });
    h.mail.clear();
    assert.equal((await must('POST', '/password/reset/request', { email: 'rt-c@example.com' })).status, 202);
    const token = tokenFrom(h.mail.first('rt-c@example.com').body);
    const weak = await must('POST', '/password/reset/confirm', { token, password: 'short' });
    assert.equal(weak.status, 400);
    assert.equal((weak.body as { kind: string }).kind, 'weak_password');
    // burned by the weak attempt
    assert.deepEqual((await must('POST', '/password/reset/confirm', { token, password: 'a longer one now' })).body, {
      kind: 'invalid',
    });
    h.mail.clear();
    await must('POST', '/password/reset/request', { email: 'rt-c@example.com' });
    const token2 = tokenFrom(h.mail.first('rt-c@example.com').body);
    assert.deepEqual(
      (await must('POST', '/password/reset/confirm', { token: token2, password: 'reset passphrase' })).body,
      {
        kind: 'done',
      },
    );

    const login = await must('POST', '/login', { email: 'rt-c@example.com', password: 'reset passphrase' });
    const session = cookieValue(login, '__Host-session') as string;
    assert.equal((await must('POST', '/password/change', { current: 'x', next: 'y' })).status, 401);
    const wrong = await must(
      'POST',
      '/password/change',
      { current: 'nope nope', next: 'changed passphrase' },
      cookieHeader(session),
    );
    assert.equal(wrong.status, 403);
    assert.equal((wrong.body as { error: string }).error, 'bad_credentials');
    const changed = await must(
      'POST',
      '/password/change',
      { current: 'reset passphrase', next: 'changed passphrase' },
      cookieHeader(session),
    );
    assert.equal(changed.status, 200);
    const rotated = cookieValue(changed, '__Host-session');
    assert.ok(rotated && rotated !== session, 'kept session rotated');
    assert.equal((await must('GET', '/session', undefined, cookieHeader(rotated))).status, 200);
  });

  it('mfa: begin (session proof) → confirm → login is mfa_required → verify (totp and recovery) → remove', async () => {
    h.mail.clear();
    await must('POST', '/signup', { email: 'rt-d@example.com', password: 'correct horse battery' });
    await must('POST', '/verify', { token: tokenFrom(h.mail.first('rt-d@example.com').body) });
    const login = await must('POST', '/login', { email: 'rt-d@example.com', password: 'correct horse battery' });
    const session = cookieValue(login, '__Host-session') as string;

    assert.equal((await must('POST', '/mfa/begin')).status, 401);
    const begin = await must('POST', '/mfa/begin', {}, cookieHeader(session));
    assert.equal(begin.status, 200);
    const { secret } = begin.body as { secret: string };
    const code = (when: Date) =>
      new TOTP({ algorithm: 'SHA1', digits: 6, period: 30, secret: Secret.fromBase32(secret) }).generate({
        timestamp: when.getTime(),
      });
    assert.equal((await must('POST', '/mfa/confirm', { code: '000000' }, cookieHeader(session))).status, 400);
    const confirm = await must('POST', '/mfa/confirm', { code: code(now) }, cookieHeader(session));
    assert.equal(confirm.status, 200);
    const { recoveryCodes } = confirm.body as { recoveryCodes: string[] };
    assert.equal(recoveryCodes.length, 10);
    const rotated = cookieValue(confirm, '__Host-session');
    assert.ok(rotated && rotated !== session);

    now = new Date(T0.getTime() + 60_000);
    const l2 = await must('POST', '/login', { email: 'rt-d@example.com', password: 'correct horse battery' });
    assert.equal((l2.body as { kind: string }).kind, 'mfa_required');
    const { pendingToken } = l2.body as { pendingToken: string };
    assert.equal((await must('POST', '/mfa/verify', { pendingToken, code: '111111' })).status, 401);
    const v = await must('POST', '/mfa/verify', { pendingToken, code: code(now) });
    assert.equal(v.status, 200);
    assert.ok(cookieValue(v, '__Host-session'));

    now = new Date(T0.getTime() + 120_000);
    const l3 = await must('POST', '/login', { email: 'rt-d@example.com', password: 'correct horse battery' });
    const p3 = (l3.body as { pendingToken: string }).pendingToken;
    const rec = await must('POST', '/mfa/verify', {
      pendingToken: p3,
      code: recoveryCodes[0] as string,
      recovery: true,
    });
    assert.equal(rec.status, 200);
    const s3 = cookieValue(rec, '__Host-session') as string;
    // five bad guesses on a fresh pending → restart
    const l4 = await must('POST', '/login', { email: 'rt-d@example.com', password: 'correct horse battery' });
    const p4 = (l4.body as { pendingToken: string }).pendingToken;
    let last: HttpResponse | null = null;
    for (let i = 0; i < 5; i += 1) last = await must('POST', '/mfa/verify', { pendingToken: p4, code: '222222' });
    assert.deepEqual(last?.body, { kind: 'restart' }, 'the fifth wrong guess destroys the pending login');
    assert.deepEqual((await must('POST', '/mfa/verify', { pendingToken: p4, code: '222222' })).body, {
      kind: 'failed',
    });

    assert.equal((await must('POST', '/mfa/remove', { password: 'wrong' }, cookieHeader(s3))).status, 403);
    const removed = await must('POST', '/mfa/remove', { password: 'correct horse battery' }, cookieHeader(s3));
    assert.equal(removed.status, 200);
    assert.ok(cookieValue(removed, '__Host-session'));
    now = T0;
  });

  it('api keys: create, list, delete (owner-scoped)', async () => {
    h.mail.clear();
    await must('POST', '/signup', { email: 'rt-e@example.com', password: 'correct horse battery' });
    await must('POST', '/verify', { token: tokenFrom(h.mail.first('rt-e@example.com').body) });
    const session = cookieValue(
      await must('POST', '/login', { email: 'rt-e@example.com', password: 'correct horse battery' }),
      '__Host-session',
    ) as string;
    assert.equal((await must('POST', '/apikeys', { name: 'x' })).status, 401);
    const created = await must(
      'POST',
      '/apikeys',
      { name: 'CI', scopes: ['read', 7], environment: 'test', expiresAt: 'not-a-date' },
      cookieHeader(session),
    );
    assert.equal(created.status, 201);
    const { id, key } = created.body as { id: string; key: string };
    assert.match(key, /^rt_test_/);
    const list = await must('GET', '/apikeys', undefined, cookieHeader(session));
    assert.deepEqual(
      (list.body as { keys: { id: string; scopes: string[] }[] }).keys.map((k) => [k.id, k.scopes]),
      [[id, ['read']]],
    );
    // someone else's session cannot revoke it
    h.mail.clear();
    await must('POST', '/signup', { email: 'rt-f@example.com', password: 'correct horse battery' });
    await must('POST', '/verify', { token: tokenFrom(h.mail.first('rt-f@example.com').body) });
    const other = cookieValue(
      await must('POST', '/login', { email: 'rt-f@example.com', password: 'correct horse battery' }),
      '__Host-session',
    ) as string;
    assert.equal((await must('DELETE', `/apikeys/${id}`, undefined, cookieHeader(other))).status, 404);
    assert.equal((await must('DELETE', `/apikeys/${id}`, undefined, cookieHeader(session))).status, 204);
    assert.equal(await apiKeys.resolveApiKey(key), null);
  });

  it('magic: request + consume', async () => {
    h.mail.clear();
    await must('POST', '/signup', { email: 'rt-g@example.com', password: 'correct horse battery' });
    await must('POST', '/verify', { token: tokenFrom(h.mail.first('rt-g@example.com').body) });
    h.mail.clear();
    assert.equal((await must('POST', '/magic/request', { email: 'rt-g@example.com' })).status, 202);
    const token = tokenFrom(h.mail.first('rt-g@example.com').body);
    const ok = await must('POST', '/magic/consume', { token });
    assert.equal(ok.status, 200);
    assert.ok(cookieValue(ok, '__Host-session'));
    assert.deepEqual((await must('POST', '/magic/consume', { token })).body, { kind: 'failed' });
  });

  it('passkeys: register begin/finish, list, authenticate begin/finish, delete', async () => {
    h.mail.clear();
    await must('POST', '/signup', { email: 'rt-h@example.com', password: 'correct horse battery' });
    await must('POST', '/verify', { token: tokenFrom(h.mail.first('rt-h@example.com').body) });
    const session = cookieValue(
      await must('POST', '/login', { email: 'rt-h@example.com', password: 'correct horse battery' }),
      '__Host-session',
    ) as string;
    const auth = new SoftAuthenticator(RP.id, RP.origin);
    assert.equal((await must('POST', '/passkeys/register/begin')).status, 401);
    const begin = await must('POST', '/passkeys/register/begin', {}, cookieHeader(session));
    assert.equal(begin.status, 200);
    assert.equal((await must('POST', '/passkeys/register/finish', { nope: 1 }, cookieHeader(session))).status, 400);
    const finish = await must(
      'POST',
      '/passkeys/register/finish',
      { response: auth.create(begin.body as never), name: 'Laptop' },
      cookieHeader(session),
    );
    assert.equal(finish.status, 201);
    const { id } = finish.body as { id: string };
    const list = await must('GET', '/passkeys', undefined, cookieHeader(session));
    assert.equal((list.body as { passkeys: unknown[] }).passkeys.length, 1);

    const ab = await must('POST', '/passkeys/authenticate/begin', {});
    assert.equal(ab.status, 200);
    assert.equal((await must('POST', '/passkeys/authenticate/finish', {})).status, 400);
    const af = await must('POST', '/passkeys/authenticate/finish', { response: auth.get(ab.body as never) });
    assert.equal(af.status, 200);
    assert.ok(cookieValue(af, '__Host-session'));
    // a spent challenge is a typed 400
    const replay = await must('POST', '/passkeys/authenticate/finish', { response: auth.get(ab.body as never) });
    assert.equal(replay.status, 400);
    assert.equal((replay.body as { error: string }).error, 'invalid_challenge');

    assert.equal(
      (await must('DELETE', `/passkeys/${encodeURIComponent(id)}`, undefined, cookieHeader(session))).status,
      204,
    );
    assert.equal(
      (await must('DELETE', `/passkeys/${encodeURIComponent(id)}`, undefined, cookieHeader(session))).status,
      404,
    );
  });

  it('csrf: true refuses a non-GET without the double-submit token, accepts with it', async () => {
    const guarded = routes({ identity, config: rotating, csrf: true, clock: () => now });
    const denied = await guarded.handle({ method: 'POST', path: '/login', headers: {}, body: {} });
    assert.equal(denied?.status, 403);
    const issued = await guarded.handle({ method: 'GET', path: '/csrf', headers: {} });
    assert.equal(issued?.status, 200);
    assert.ok(issued);
    const token = (issued.body as { token: string }).token;
    const cookie = cookieValue(issued as HttpResponse, '__Host-csrf');
    assert.equal(cookie, token);
    const allowed = await guarded.handle({
      method: 'POST',
      path: '/login',
      headers: { cookie: `__Host-csrf=${token}`, 'x-csrf-token': token },
      body: { email: 'nobody@example.com', password: 'whatever!!' },
    });
    assert.equal(allowed?.status, 401, 'past CSRF, into the handler');
    assert.equal(guarded.csrf.cookieName(), '__Host-csrf');
  });

  it('typed errors become status codes: rate_limited 429 + Retry-After, weak_password 400', async () => {
    const limitedIdentity = createIdentity({
      db: h.db,
      config: testConfig,
      mail: h.mail,
      rateLimiter: createMemoryRateLimiter({ rules: { signup: { limit: 1, windowMs: 60_000 } } }),
    });
    const lr = routes({ identity: limitedIdentity, config: testConfig });
    const first = await lr.handle({
      method: 'POST',
      path: '/signup',
      headers: {},
      body: { email: 'rl@example.com', password: 'correct horse battery' },
    });
    assert.equal(first?.status, 202);
    const second = await lr.handle({
      method: 'POST',
      path: '/signup',
      headers: {},
      body: { email: 'rl@example.com', password: 'correct horse battery' },
    });
    assert.equal(second?.status, 429);
    assert.ok(second?.headers['retry-after']);
    assert.ok(second);
    assert.equal((second.body as { key?: string }).key, undefined, 'the limiter key never leaves the server');
    const weak = await lr.handle({
      method: 'POST',
      path: '/signup',
      headers: {},
      body: { email: 'w@example.com', password: 'x' },
    });
    assert.ok(weak);
    assert.equal(weak.status, 400);
    assert.equal((weak.body as { error: string }).error, 'weak_password');
    // routes without optional modules do not answer their paths
    assert.equal(await lr.handle({ method: 'POST', path: '/mfa/begin', headers: {}, body: {} }), null);
    assert.equal(await lr.handle({ method: 'POST', path: '/magic/request', headers: {}, body: {} }), null);
  });

  it('adapter: node:http — a real server, real requests, fall-through for other paths', async () => {
    const listener = nodeListener(r, { trustProxy: true });
    const server = createServer(async (req, res) => {
      if (await listener(req, res)) return;
      res.statusCode = 200;
      res.end('fallthrough');
    });
    await new Promise<void>((resolve) => server.listen(0, '127.0.0.1', resolve));
    const addr = server.address();
    assert.ok(addr && typeof addr === 'object');
    const url = `http://127.0.0.1:${addr.port}`;
    try {
      const other = await fetch(`${url}/somewhere-else`);
      assert.equal(await other.text(), 'fallthrough');
      const bad = await fetch(`${url}/auth/login`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', 'x-forwarded-for': '198.51.100.77, 10.0.0.1' },
        body: JSON.stringify({ email: 'nobody@example.com', password: 'whatever!!' }),
      });
      assert.equal(bad.status, 401);
      assert.deepEqual(await bad.json(), { kind: 'failed' });
      const me = await fetch(`${url}/auth/session`);
      assert.equal(me.status, 401);
      const csrfRes = await fetch(`${url}/auth/csrf`);
      assert.match(csrfRes.headers.get('set-cookie') ?? '', /__Host-csrf=/);
      const nobody = await fetch(`${url}/auth/logout`, { method: 'POST' });
      assert.equal(nobody.status, 204);
      const huge = await fetch(`${url}/auth/login`, { method: 'POST', body: 'x'.repeat(70 * 1024) }).catch(() => null);
      assert.equal(huge?.status, 413, 'an oversized body is refused, not buffered');
    } finally {
      await new Promise<void>((resolve) => server.close(() => resolve()));
    }
  });

  it('adapter: Express-shaped fake req/res, next() on fall-through and on a thrown non-IdentityError', async () => {
    const handler = expressHandler(r);
    const res = () => {
      const state = {
        status: 0,
        headers: {} as Record<string, string | string[]>,
        body: undefined as unknown,
        ended: false,
      };
      const self = {
        state,
        status(c: number) {
          state.status = c;
          return self;
        },
        set(k: string, v: string | string[]) {
          state.headers[k] = v;
          return self;
        },
        json(b: unknown) {
          state.body = b;
        },
        end() {
          state.ended = true;
        },
      };
      return self;
    };
    let nextCalled: unknown[] = [];
    const next = (e?: unknown) => nextCalled.push(e ?? 'next');
    const r1 = res();
    await handler(
      {
        method: 'POST',
        path: '/auth/login',
        headers: {},
        body: { email: 'nobody@example.com', password: 'whatever!!' },
        ip: '1.2.3.4',
      },
      r1,
      next,
    );
    assert.equal(r1.state.status, 401);
    assert.deepEqual(r1.state.body, { kind: 'failed' });
    assert.deepEqual(nextCalled, []);
    const r2 = res();
    await handler({ method: 'GET', path: '/elsewhere', headers: {} }, r2, next);
    assert.deepEqual(nextCalled, ['next']);
    const r3 = res();
    await handler({ method: 'POST', path: '/auth/logout', headers: {} }, r3, next);
    assert.equal(r3.state.status, 204);
    assert.equal(r3.state.ended, true);
    // a thrown non-IdentityError goes to next(err)
    nextCalled = [];
    const broken = routes({
      identity: { ...identity, login: async () => Promise.reject(new TypeError('db down')) },
      config: testConfig,
    });
    await expressHandler(broken)(
      { method: 'POST', path: '/login', headers: {}, body: { email: 'a@b.c', password: 'whatever!!' } },
      res(),
      next,
    );
    assert.ok(nextCalled[0] instanceof TypeError);
  });

  it('adapter: Hono-shaped fake context, headers appended, next() on fall-through', async () => {
    const handler = honoHandler(r);
    const ctx = (method: string, path: string, body?: unknown, headers: Record<string, string> = {}) => {
      const set: [string, string, boolean][] = [];
      const out = { status: 0, body: undefined as unknown };
      return {
        set,
        out,
        c: {
          req: {
            method,
            path,
            header: () => ({ 'User-Agent': 'hono-test', ...headers }),
            text: async () => (body === undefined ? '' : JSON.stringify(body)),
          },
          header(k: string, v: string, o?: { append?: boolean }) {
            set.push([k, v, o?.append === true]);
          },
          json(b: unknown, status = 200) {
            out.status = status;
            out.body = b;
            return 'json';
          },
          body(_: null, status = 200) {
            out.status = status;
            out.body = null;
            return 'empty';
          },
          ip: '9.9.9.9',
        },
      };
    };
    const a = ctx('POST', '/auth/login', { email: 'nobody@example.com', password: 'whatever!!' });
    assert.equal(await handler(a.c), 'json');
    assert.equal(a.out.status, 401);
    assert.ok(a.set.some(([k]) => k === 'content-type'));
    const b = ctx('POST', '/auth/logout');
    assert.equal(await handler(b.c), 'empty');
    assert.equal(b.out.status, 204);
    assert.deepEqual(
      b.set.map(([k, , append]) => [k, append]),
      [['set-cookie', true]],
    );
    let nexted = false;
    assert.equal(
      await handler(ctx('GET', '/other').c, async () => {
        nexted = true;
      }),
      undefined,
    );
    assert.equal(nexted, true);
    assert.equal(await handler(ctx('GET', '/other').c), undefined);
  });
});
