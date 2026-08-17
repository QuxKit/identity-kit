// A complete password login round-trip against a local Postgres, in one file.
//
// The mail transport is a console printer, so the verification link's token is
// read straight back off stdout — in a real host it goes to a relay.

import { createIdentity, type Message } from '@quxkit/identity-kit';
import { pgExecutor } from '@quxkit/identity-kit/pg';
import pg from 'pg';

const url = process.env.DATABASE_URL ?? 'postgres://localhost:5432/identity_kit_example';
const pool = new pg.Pool({ connectionString: url });

const outbox: Message[] = [];
const identity = createIdentity({
  db: pgExecutor(pool),
  mail: {
    async send(message) {
      outbox.push(message);
      console.log(`\n--- mail to ${message.to}: ${message.subject}\n${message.body}\n---`);
    },
  },
  config: {
    pepper: process.env.AUTH_PEPPER ?? 'example-pepper-change-me',
    pepperVersion: 1,
    appUrl: 'http://localhost:3000',
    cookieSecure: false, // plain-http dev origin; true in production
  },
});

const email = `alice+${Date.now()}@example.com`;
const password = 'correct horse battery staple';

await identity.signup({ email, password });
const verifyMail = outbox.find((m) => m.to === email);
const token = decodeURIComponent(/token=([^&\s]+)/.exec(verifyMail?.body ?? '')?.[1] ?? '');
console.log('verified:', await identity.verifyEmail(token));

const result = await identity.login({ email, password }, { userAgent: 'example/1.0' });
if (result.kind !== 'session') throw new Error(`login did not mint a session: ${result.kind}`);
console.log('Set-Cookie:', identity.sessionCookie(result.token, result.expiresAt));

const session = await identity.resolveSession(result.token);
console.log('resolved session for user', session?.userId);

await identity.revokeSession(session?.tokenHash ?? '');
console.log('after revoke:', await identity.resolveSession(result.token));

await pool.end();
