// The shipped pg adapter. The properties that matter: a transaction body runs on
// ONE connection (so ROLLBACK covers it), a throw rolls back, and a nested
// transaction is a savepoint that rolls back only its own work.

import assert from 'node:assert/strict';
import { after, describe, it } from 'node:test';

import { type Harness, one, SKIP_REASON, setupDatabase } from './harness.ts';

const harness = await setupDatabase();
after(async () => {
  await harness?.close();
});

describe('identity-kit/pg', { skip: harness === null ? SKIP_REASON : false }, () => {
  const h = harness as Harness;
  const db = h.db;

  const count = async (email: string): Promise<number> =>
    Number(
      one(await db.query<{ n: string }>('SELECT count(*)::text AS n FROM identity.users WHERE email = $1', [email])).n,
    );

  const insert = (tx: { query: typeof db.query }, email: string) =>
    tx.query('INSERT INTO identity.users (email, email_display) VALUES ($1, $1)', [email]);

  it('pins one connection for the transaction body', async () => {
    const pids = await db.transaction(async (tx) => {
      const a = one(await tx.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).pid;
      const b = one(await tx.query<{ pid: number }>('SELECT pg_backend_pid() AS pid')).pid;
      const inTx = one(await tx.query<{ n: number }>('SELECT txid_current() AS n')).n;
      return { a, b, inTx };
    });
    assert.equal(pids.a, pids.b, 'both statements ran on the same backend');
    assert.ok(pids.inTx, 'and inside a transaction');
  });

  it('commits on resolve and rolls everything back on throw', async () => {
    await db.transaction((tx) => insert(tx, 'pg-commit@example.com'));
    assert.equal(await count('pg-commit@example.com'), 1);

    await assert.rejects(
      db.transaction(async (tx) => {
        await insert(tx, 'pg-rollback@example.com');
        throw new Error('boom');
      }),
      /boom/,
    );
    assert.equal(await count('pg-rollback@example.com'), 0, 'the insert did not survive the throw');
  });

  it('a nested transaction is a savepoint: an inner failure keeps the outer work', async () => {
    await db.transaction(async (tx) => {
      await insert(tx, 'pg-outer@example.com');
      await assert.rejects(
        tx.transaction(async (inner) => {
          await insert(inner, 'pg-inner@example.com');
          throw new Error('inner boom');
        }),
        /inner boom/,
      );
      // still usable after the inner rollback — no "current transaction is aborted"
      await insert(tx, 'pg-after@example.com');
    });
    assert.equal(await count('pg-outer@example.com'), 1);
    assert.equal(await count('pg-after@example.com'), 1);
    assert.equal(await count('pg-inner@example.com'), 0, 'only the inner insert was rolled back');
  });
});
