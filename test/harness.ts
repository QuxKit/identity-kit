// A pg.Pool adapter for SqlExecutor, a schema rebuild, and a mail collector.
//
// The tests run against a real Postgres, because the behaviour worth testing —
// the token burned in the same transaction as the write, the unique constraint
// on email, cascade on delete — is in the database, not the TypeScript.

import { readFile } from 'node:fs/promises';
import { fileURLToPath } from 'node:url';
import pg from 'pg';

import type { IdentityConfig, MailSender, Message, SqlExecutor } from '../src/types.ts';

export function fromPool(pool: pg.Pool): SqlExecutor {
  return {
    async query<T>(text: string, params?: readonly unknown[]): Promise<T[]> {
      const result = await pool.query(text, params as unknown[]);
      return result.rows as T[];
    },
    async transaction<T>(fn: (tx: SqlExecutor) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      const bound: SqlExecutor = {
        async query<R>(text: string, params?: readonly unknown[]): Promise<R[]> {
          const result = await client.query(text, params as unknown[]);
          return result.rows as R[];
        },
        transaction: (inner) => inner(bound),
      };
      try {
        await client.query('BEGIN');
        const out = await fn(bound);
        await client.query('COMMIT');
        return out;
      } catch (error) {
        await client.query('ROLLBACK');
        throw error;
      } finally {
        client.release();
      }
    },
  };
}

export const TEST_DATABASE_URL =
  process.env.IDENTITY_KIT_TEST_DATABASE_URL ?? 'postgres://localhost:5432/identity_kit_test';

/** Collects sent mail so a test can assert what was sent to whom. */
export class MailCollector implements MailSender {
  readonly sent: Message[] = [];
  async send(message: Message): Promise<void> {
    this.sent.push(message);
  }
  to(address: string): Message[] {
    return this.sent.filter((m) => m.to === address);
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

export async function setupDatabase(): Promise<Harness | null> {
  const pool = new pg.Pool({ connectionString: TEST_DATABASE_URL, max: 4 });
  try {
    await pool.query('SELECT 1');
  } catch {
    await pool.end().catch(() => {});
    return null;
  }
  await pool.query('DROP SCHEMA IF EXISTS identity CASCADE');
  for (const f of ['001_identity.sql', '002_mfa.sql', '003_apikeys.sql', '004_oidc.sql']) {
    await pool.query(await readFile(fileURLToPath(new URL(`../sql/${f}`, import.meta.url)), 'utf8'));
  }
  return { db: fromPool(pool), mail: new MailCollector(), close: () => pool.end() };
}

export const SKIP_REASON =
  `no database at ${TEST_DATABASE_URL} — set IDENTITY_KIT_TEST_DATABASE_URL or ` +
  'run `createdb identity_kit_test` to exercise the SQL paths';
