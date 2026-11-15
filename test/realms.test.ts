// Realms. One address, one account per realm, and nothing that authenticates in
// one realm accepted in another: not a session, a reset or verification link, a
// magic link, a social link or a passkey. A credential from the wrong realm is
// not found — and not burned, so presenting it there cannot sign its owner out.
// The default realm, '', behaves exactly as before.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import { IdentityError } from '../src/errors.ts';
import { createIdentity, createMemoryRateLimiter, realmOf, realmSubject } from '../src/index.ts';
import { createMagic } from '../src/magic.ts';
import { linkOrCreate } from '../src/oidc-link.ts';
import { createPasskeys } from '../src/passkeys.ts';
import { type Harness, one, SKIP_REASON, setupDatabase, testConfig, tokenFrom } from './harness.ts';
import { SoftAuthenticator } from './soft-authenticator.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

const T0 = new Date('2026-08-15T12:00:00Z');
const PASSWORD = 'correct horse battery';
const A = 'school:aaaa';
const B = 'school:bbbb';

describe('realm names', () => {
  it('accepts the default and well-formed names, and refuses anything else as invalid_config', () => {
    assert.equal(realmOf({}), '');
    assert.equal(realmOf({ realm: '' }), '');
    assert.equal(realmOf({ realm: 'school:3f2a-9c.x_y' }), 'school:3f2a-9c.x_y');
    for (const bad of ['School:A', ' school', 'a|b', 'a b', ':lead', 'x'.repeat(81)]) {
      assert.throws(
        () => realmOf({ realm: bad }),
        (e: unknown) => IdentityError.hasCode(e, 'invalid_config'),
        bad,
      );
    }
  });

  it('keys a default-realm address exactly as before, and a realm one so no default key can equal it', () => {
    assert.equal(realmSubject('', 'a@x.test'), 'a@x.test');
    assert.equal(realmSubject(A, 'a@x.test'), 'a@x.test/school:aaaa');
    // The part after the last '@' is a domain, which never holds '/'.
    assert.notEqual(realmSubject('', 'school:aaaa/a@x.test'), realmSubject(A, 'a@x.test'));
  });
});

describe('identity-kit realms', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const base = createIdentity({ db: h.db, config: testConfig, mail: h.mail, rateLimiter: null });
  const a = base.inRealm(A, { appUrl: 'https://a.school.test' });
  const b = base.inRealm(B, { appUrl: 'https://b.school.test' });

  const verified = async (id: typeof base, email: string): Promise<string> => {
    h.mail.clear();
    await id.signup({ email, password: PASSWORD });
    assert.equal(await id.verifyEmail(tokenFrom(h.mail.first(email).body)), true);
    h.mail.clear();
    const rows = await h.db.query<{ id: string }>('SELECT id FROM identity.users WHERE realm = $1 AND email = $2', [
      id.realm,
      email,
    ]);
    return one(rows).id;
  };
  const signIn = async (id: typeof base, email: string, password = PASSWORD) => {
    const r = await id.login({ email, password }, {}, T0);
    assert.equal(r.kind, 'session', `${email} signs in at ${id.realm || 'the default realm'}`);
    if (r.kind !== 'session') throw new Error('unreachable');
    return r;
  };

  it('binds the realm and keeps the default one', () => {
    assert.equal(base.realm, '');
    assert.equal(a.realm, A);
    assert.equal(a.inRealm(B).realm, B, 'a realm instance can bind another');
  });

  it('the same address is a separate account in each realm, each with its own password', async () => {
    const inBase = await verified(base, 'two@example.com');
    const inA = await verified(a, 'two@example.com');
    assert.notEqual(inBase, inA);

    h.mail.clear();
    await b.signup({ email: 'two@example.com', password: 'a different passphrase' });
    await b.verifyEmail(tokenFrom(h.mail.first('two@example.com').body));

    const who = async (id: typeof base) =>
      (await id.resolveSession((await signIn(id, 'two@example.com')).token, T0))?.userId;
    assert.equal(await who(base), inBase);
    assert.equal(await who(a), inA);
    // B's password is B's: A's does not open it, and B's does not open A.
    assert.equal((await b.login({ email: 'two@example.com', password: PASSWORD }, {}, T0)).kind, 'failed');
    assert.equal(
      (await a.login({ email: 'two@example.com', password: 'a different passphrase' }, {}, T0)).kind,
      'failed',
    );
    const realms = await h.db.query<{ realm: string }>(
      "SELECT realm FROM identity.users WHERE email = 'two@example.com' ORDER BY realm",
    );
    assert.deepEqual(
      realms.map((r) => r.realm),
      ['', A, B],
    );
  });

  it('a taken address is taken only in its own realm, and the database holds that too', async () => {
    await verified(a, 'taken@example.com');
    h.mail.clear();
    await a.signup({ email: 'taken@example.com', password: PASSWORD });
    assert.match(h.mail.first('taken@example.com').subject, /tried to create an account/i, 'A says it is taken');
    h.mail.clear();
    await b.signup({ email: 'taken@example.com', password: PASSWORD });
    assert.match(h.mail.first('taken@example.com').body, /token=/, 'B makes a new account');

    await assert.rejects(
      h.db.query("INSERT INTO identity.users (email, email_display, realm) VALUES ('taken@example.com', 'x', $1)", [A]),
      /users_realm_email_unique/,
    );
    await assert.rejects(
      h.db.query(
        "INSERT INTO identity.users (email, email_display, realm) VALUES ('bad@example.com', 'x', 'Bad|Realm')",
      ),
      /users_realm_format/,
    );
  });

  it('a session resolves only in its own realm, and presenting it elsewhere does not end it', async () => {
    const userId = await verified(a, 'sess@example.com');
    const s = await signIn(a, 'sess@example.com');
    assert.equal(await b.resolveSession(s.token, T0), null);
    assert.equal(await base.resolveSession(s.token, T0), null);
    assert.equal(await b.rotateSession(s.token, T0), null, 'nor can it be rotated there');
    assert.equal((await a.resolveSession(s.token, T0))?.userId, userId, 'still live where it belongs');
  });

  it('a verification link from another realm is not found, and still works at home', async () => {
    h.mail.clear();
    await a.signup({ email: 'verify@example.com', password: PASSWORD });
    const mail = h.mail.first('verify@example.com');
    assert.match(mail.body, /^https:\/\/a\.school\.test\/|https:\/\/a\.school\.test\//m, "A's own address");
    const token = tokenFrom(mail.body);
    assert.equal(await b.verifyEmail(token, T0), false);
    assert.equal(await base.verifyEmail(token, T0), false);
    assert.equal(await a.verifyEmail(token, T0), true, 'not burned by the attempts elsewhere');
  });

  it('a reset link from another realm is invalid there, and resets only at home', async () => {
    await verified(a, 'reset@example.com');
    await verified(b, 'reset@example.com');
    h.mail.clear();
    await a.requestPasswordReset('reset@example.com');
    const mail = h.mail.first('reset@example.com');
    assert.match(mail.body, /https:\/\/a\.school\.test\//);
    const token = tokenFrom(mail.body);
    assert.equal((await b.resetPassword(token, 'taken over in b', T0)).kind, 'invalid');
    assert.equal((await a.resetPassword(token, 'a fresh one for a', T0)).kind, 'done');
    assert.equal((await signIn(a, 'reset@example.com', 'a fresh one for a')).kind, 'session');
    assert.equal((await signIn(b, 'reset@example.com')).kind, 'session', "B's password is untouched");
  });

  it('magic links are asked for and spent per realm', async () => {
    const magicA = createMagic({ db: h.db, config: { ...testConfig, realm: A }, mail: h.mail, rateLimiter: null });
    const magicB = createMagic({ db: h.db, config: { ...testConfig, realm: B }, mail: h.mail, rateLimiter: null });
    const userId = await verified(a, 'magic@example.com');

    h.mail.clear();
    await magicB.request({ email: 'magic@example.com' }, T0);
    assert.doesNotMatch(h.mail.first('magic@example.com').body, /token=/, 'B has no such account');

    h.mail.clear();
    await magicA.request({ email: 'magic@example.com' }, T0);
    const token = tokenFrom(h.mail.first('magic@example.com').body);
    assert.deepEqual(await magicB.consume({ token }, {}, T0), { kind: 'invalid' });
    const r = await magicA.consume({ token }, {}, T0);
    assert.equal(r.kind, 'session');
    if (r.kind === 'session') assert.equal((await a.resolveSession(r.token, T0))?.userId, userId);
  });

  it('social links are per realm: one provider subject, one account at each school', async () => {
    const claims = { provider: 'google', subject: 'g-123', email: 'social@example.com', emailVerified: true };
    const inA = await linkOrCreate(h.db, claims, T0, { realm: A });
    const inB = await linkOrCreate(h.db, claims, T0, { realm: B });
    assert.equal(inA.kind, 'ok');
    assert.equal(inB.kind, 'ok');
    if (inA.kind !== 'ok' || inB.kind !== 'ok') return;
    assert.equal(inA.isNewUser, true);
    assert.equal(inB.isNewUser, true);
    assert.notEqual(inA.userId, inB.userId);

    const again = await a.linkOrCreate(claims, T0);
    assert.deepEqual(again, { kind: 'ok', userId: inA.userId, isNewUser: false }, 'the instance passes its realm');
    const rows = await h.db.query<{ realm: string }>(
      "SELECT realm FROM identity.oauth_identities WHERE subject = 'g-123' ORDER BY realm",
    );
    assert.deepEqual(
      rows.map((r) => r.realm),
      [A, B],
    );
  });

  it('a passkey registered in one realm does not sign in at another', async () => {
    const RP = { id: 'app.test', name: 'Test', origin: 'https://app.test' };
    const pkA = createPasskeys({
      db: h.db,
      config: { ...testConfig, realm: A },
      mail: h.mail,
      rp: RP,
      rateLimiter: null,
    });
    const pkB = createPasskeys({
      db: h.db,
      config: { ...testConfig, realm: B },
      mail: h.mail,
      rp: RP,
      rateLimiter: null,
    });
    const userId = await verified(a, 'passkey@example.com');
    const auth = new SoftAuthenticator(RP.id, RP.origin);
    await pkA.registerFinish(userId, auth.create(await pkA.registerBegin(userId, { password: PASSWORD }, T0)), {
      now: T0,
    });

    assert.equal(
      (await pkB.authenticateFinish(auth.get(await pkB.authenticateBegin({ now: T0 })), {}, T0)).kind,
      'failed',
    );
    const home = await pkA.authenticateFinish(auth.get(await pkA.authenticateBegin({ now: T0 })), {}, T0);
    assert.equal(home.kind, 'session');
  });

  it("rate limits are per realm: one realm's flood does not meter another's", async () => {
    const limiter = createMemoryRateLimiter({ rules: { login: { limit: 1, windowMs: 60_000 } }, clock: () => T0 });
    const limited = createIdentity({ db: h.db, config: testConfig, mail: h.mail, rateLimiter: limiter });
    const la = limited.inRealm(A);
    const lb = limited.inRealm(B);
    await la.login({ email: 'flood@example.com', password: 'x' }, { ipAddress: '192.0.2.1' }, T0);
    await assert.rejects(
      la.login({ email: 'flood@example.com', password: 'x' }, { ipAddress: '192.0.2.1' }, T0),
      (e: unknown) => IdentityError.hasCode(e, 'rate_limited'),
    );
    await lb.login({ email: 'flood@example.com', password: 'x' }, { ipAddress: '192.0.2.1' }, T0);
  });

  it('a default-realm instance never finds a realm account', async () => {
    await verified(b, 'only-b@example.com');
    assert.equal((await base.login({ email: 'only-b@example.com', password: PASSWORD }, {}, T0)).kind, 'failed');
    h.mail.clear();
    await base.requestPasswordReset('only-b@example.com');
    assert.doesNotMatch(h.mail.first('only-b@example.com').body, /token=/, 'unknown here: no reset link');
  });
});
