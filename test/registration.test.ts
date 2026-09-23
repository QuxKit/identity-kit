// Closing registration, on both doors into identity.users.
//
// The property worth guarding hardest is the one this feature could quietly
// break: signup is enumeration-safe, and a refusal that happened only for
// addresses without an account would turn the closed door into the oracle the
// rest of the module is built to avoid. So the refusal is asserted to be
// identical for a known and an unknown address — same error, same message, no
// user created either way.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import { IdentityError } from '../src/errors.ts';
import { createIdentity } from '../src/index.ts';
import { linkOrCreate } from '../src/oidc-link.ts';
import { registrationPolicy } from '../src/registration.ts';
import type { RegistrationAttempt, RegistrationSetting } from '../src/types.ts';
import { type Harness, one, SKIP_REASON, setupDatabase, testConfig } from './harness.ts';

// --- the policy resolver, which needs no database ---------------------------

describe('registrationPolicy', () => {
  const attempt: RegistrationAttempt = { email: 'ada@example.com', via: 'password' };

  it('treats an absent setting as open, so an untouched host is unaffected', async () => {
    assert.deepEqual(await registrationPolicy(undefined)(attempt), { allow: true });
    assert.deepEqual(await registrationPolicy('open')(attempt), { allow: true });
  });

  it('refuses when closed, with a reason meant for the person who tried', async () => {
    const decision = await registrationPolicy('closed')(attempt);
    assert.equal(decision.allow, false);
    assert.match(decision.allow === false ? decision.reason : '', /not being created/i);
  });

  it('hands the whole attempt to a function, so invite-only is expressible', async () => {
    const seen: RegistrationAttempt[] = [];
    const policy = registrationPolicy((a) => {
      seen.push(a);
      return a.invite === 'good' ? { allow: true } : { allow: false, reason: 'Invite only.' };
    });
    assert.deepEqual(await policy({ ...attempt, invite: 'good' }), { allow: true });
    assert.deepEqual(await policy({ ...attempt, invite: 'bad' }), { allow: false, reason: 'Invite only.' });
    assert.deepEqual(
      seen.map((a) => a.invite),
      ['good', 'bad'],
    );
    assert.equal(seen[0]?.via, 'password');
  });

  it('rejects a setting that is neither mode nor function, at the point of use', () => {
    assert.throws(() => registrationPolicy('sometimes' as unknown as RegistrationSetting), IdentityError);
  });
});

// --- both doors, against the database ---------------------------------------

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

describe('registration, closed', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const open = createIdentity({ db: h.db, config: testConfig, mail: h.mail, rateLimiter: null });
  const closed = createIdentity({
    db: h.db,
    config: { ...testConfig, registration: 'closed' },
    mail: h.mail,
    rateLimiter: null,
  });

  const userCount = async (email: string): Promise<number> => {
    const rows = await h.db.query<{ n: string }>('SELECT count(*)::text AS n FROM identity.users WHERE email = $1', [
      email.toLowerCase(),
    ]);
    return Number(one(rows).n);
  };

  const refusal = async (fn: () => Promise<unknown>): Promise<IdentityError> => {
    try {
      await fn();
    } catch (e) {
      assert.ok(IdentityError.is(e), 'expected an IdentityError');
      return e;
    }
    throw new assert.AssertionError({ message: 'expected a refusal, got none' });
  };

  it('refuses a password signup, and creates nothing', async () => {
    const email = `closed-${Date.now()}@example.com`;
    const e = await refusal(() => closed.signup({ email, password: 'correct horse battery' }));
    assert.equal(e.code, 'registration_closed');
    assert.equal(await userCount(email), 0);
  });

  it('refuses identically for a KNOWN and an unknown address — no enumeration oracle', async () => {
    const known = `known-${Date.now()}@example.com`;
    await open.signup({ email: known, password: 'correct horse battery' });
    assert.equal(await userCount(known), 1, 'fixture: the account exists');
    h.mail.clear();

    const unknown = `unknown-${Date.now()}@example.com`;
    const a = await refusal(() => closed.signup({ email: known, password: 'correct horse battery' }));
    const b = await refusal(() => closed.signup({ email: unknown, password: 'correct horse battery' }));

    assert.equal(a.code, b.code);
    assert.equal(a.message, b.message, 'the refusal must not differ by whether the address is taken');
    assert.equal(await userCount(unknown), 0);
    // And no mail on either branch: the open path emails both ways, so a
    // closed path that emailed only one would leak the same fact by inbox.
    assert.equal(h.mail.sent.length, 0, 'a closed door sends nothing');
  });

  it('lets an invite through, because the policy decides and this kit does not', async () => {
    const email = `invited-${Date.now()}@example.com`;
    const inviteOnly = createIdentity({
      db: h.db,
      config: {
        ...testConfig,
        registration: (a) => (a.invite === 'golden' ? { allow: true } : { allow: false, reason: 'Invite only.' }),
      },
      mail: h.mail,
      rateLimiter: null,
    });
    await refusal(() => inviteOnly.signup({ email, password: 'correct horse battery' }));
    assert.equal(await userCount(email), 0);

    await inviteOnly.signup({ email, password: 'correct horse battery', invite: 'golden' });
    assert.equal(await userCount(email), 1);
  });

  it('refuses the SOCIAL door too — the one that reads as logging in', async () => {
    const email = `social-${Date.now()}@example.com`;
    const claims = { provider: 'google', subject: `sub-${Date.now()}`, email, emailVerified: true };

    const refused = await linkOrCreate(h.db, claims, new Date(), { registration: 'closed' });
    assert.equal(refused.kind, 'registration_closed');
    assert.equal(await userCount(email), 0);

    // Through the instance, the policy comes from config and cannot be
    // forgotten — which is the point of the method existing.
    assert.equal((await closed.linkOrCreate(claims)).kind, 'registration_closed');
    assert.equal(await userCount(email), 0);

    // Open, the same claims create the account.
    const made = await open.linkOrCreate(claims);
    assert.equal(made.kind, 'ok');
    assert.equal(made.kind === 'ok' && made.isNewUser, true);
    assert.equal(await userCount(email), 1);
  });

  it('still signs an EXISTING social account in while closed — locked, not evicted', async () => {
    const email = `returning-${Date.now()}@example.com`;
    const claims = { provider: 'google', subject: `sub-r-${Date.now()}`, email, emailVerified: true };
    const first = await open.linkOrCreate(claims);
    assert.equal(first.kind, 'ok');

    const again = await closed.linkOrCreate(claims);
    assert.equal(again.kind, 'ok');
    assert.equal(again.kind === 'ok' && again.isNewUser, false);
    assert.equal(again.kind === 'ok' && again.userId, first.kind === 'ok' ? first.userId : '');
  });

  it('still lets an existing password account sign in while closed', async () => {
    const email = `signin-${Date.now()}@example.com`;
    const password = 'correct horse battery';
    await open.signup({ email, password });
    await h.db.query('UPDATE identity.users SET email_verified_at = now() WHERE email = $1', [email.toLowerCase()]);

    const r = await closed.login({ email, password });
    assert.equal(r.kind, 'session');
  });
});
