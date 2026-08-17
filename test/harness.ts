// The shipped pg adapter, a schema rebuild, and a mail collector.
//
// The tests run against a real Postgres, because the behaviour worth testing —
// the token burned in the same transaction as the write, the unique constraint
// on email, cascade on delete — is in the database, not the TypeScript.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import { pgExecutor } from '../src/pg.ts';
import type { IdentityConfig, MailSender, Message, SqlExecutor } from '../src/types.ts';

export const TEST_DATABASE_URL =
  process.env.IDENTITY_KIT_TEST_DATABASE_URL ?? 'postgres://localhost:5432/identity_kit_test';

/** The first row of a result, or a thrown assertion — for the queries whose
 *  contract is "exactly one row" (INSERT … RETURNING, a lookup by primary key). */
export function one<T>(rows: readonly T[], what = 'row'): T {
  const row = rows[0];
  if (row === undefined) throw new Error(`expected a ${what}, got none`);
  return row;
}

/** Pull the token out of a transactional mail body. */
export function tokenFrom(body: string): string {
  const match = /token=([^&\s]+)/.exec(body);
  if (!match?.[1]) throw new Error(`no token in mail body: ${body}`);
  return decodeURIComponent(match[1]);
}

/** Collects sent mail so a test can assert what was sent to whom. */
export class MailCollector implements MailSender {
  readonly sent: Message[] = [];
  async send(message: Message): Promise<void> {
    this.sent.push(message);
  }
  to(address: string): Message[] {
    return this.sent.filter((m) => m.to === address);
  }
  /** The first message sent to `address`, or a thrown assertion. */
  first(address: string): Message {
    return one(this.to(address), `mail to ${address}`);
  }
  clear(): void {
    this.sent.length = 0;
  }
}

export const testConfig: IdentityConfig = {
  pepper: 'test-pepper-not-a-real-secret',
  pepperVersion: 1,
  appUrl: 'https://app.test',
  cookieSecure: true,
};

/** 32 bytes as 64 hex chars — a throwaway AES key for the MFA tests. */
export const testTotpKey = '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff';

export interface Harness {
  db: SqlExecutor;
  mail: MailCollector;
  close(): Promise<void>;
}

/**
 * Connect, rebuild the schema, and hand back the harness — or null when there is
 * no database to talk to, so the suite skips with `SKIP_REASON`.
 *
 * Under `REQUIRE_DB=1` (CI) an unreachable database is a failure, not a skip: a
 * broken service container must not turn the whole suite green.
 */
export async function setupDatabase(): Promise<Harness | null> {
  const pool = new pg.Pool({ connectionString: TEST_DATABASE_URL, max: 4 });
  try {
    await pool.query('SELECT 1');
  } catch (error) {
    await pool.end().catch(() => {});
    if (process.env.REQUIRE_DB) {
      throw new Error(
        `REQUIRE_DB is set but the test database at ${TEST_DATABASE_URL} is unreachable: ${String(error)}`,
      );
    }
    return null;
  }
  await pool.query('DROP SCHEMA IF EXISTS identity CASCADE');
  for (const f of [
    '001_identity.sql',
    '002_mfa.sql',
    '003_apikeys.sql',
    '004_oidc.sql',
    '005_hardening.sql',
    '006_events.sql',
    '007_passkeys.sql',
    '008_magic.sql',
  ]) {
    await pool.query(await readFile(fileURLToPath(new URL(`../sql/${f}`, import.meta.url)), 'utf8'));
  }
  return { db: pgExecutor(pool), mail: new MailCollector(), close: () => pool.end() };
}

export const SKIP_REASON =
  `no database at ${TEST_DATABASE_URL} — set IDENTITY_KIT_TEST_DATABASE_URL or ` +
  'run `createdb identity_kit_test` to exercise the SQL paths';
