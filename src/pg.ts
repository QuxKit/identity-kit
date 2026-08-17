// identity-kit/pg — the SqlExecutor over a node-postgres Pool.
//
// The one adapter most hosts would otherwise write themselves, shipped so the
// quickstart is `pgExecutor(pool)` and not fifteen lines of boilerplate. `pg` is
// an optional peer dependency: import this subpath only if you use it.
//
// `transaction` pins one connection for the whole body — the property the
// executor contract requires, because a body that runs on different pool
// connections is not a transaction at all. A nested `transaction` inside the
// body becomes a SAVEPOINT, so an inner failure rolls back only its own work.

import type { Pool, PoolClient } from 'pg';

import type { SqlExecutor } from './types.ts';

/** The subset of `pg.Pool` this adapter needs; a real Pool satisfies it. */
export type PgPoolLike = Pick<Pool, 'query' | 'connect'>;

const bound = (client: PoolClient, depth: number): SqlExecutor => ({
  async query<T>(text: string, params?: readonly unknown[]): Promise<T[]> {
    const result = await client.query(text, params as unknown[]);
    return result.rows as T[];
  },
  async transaction<T>(fn: (tx: SqlExecutor) => Promise<T>): Promise<T> {
    const name = `identity_kit_sp_${depth}`;
    await client.query(`SAVEPOINT ${name}`);
    try {
      const out = await fn(bound(client, depth + 1));
      await client.query(`RELEASE SAVEPOINT ${name}`);
      return out;
    } catch (error) {
      await client.query(`ROLLBACK TO SAVEPOINT ${name}`);
      throw error;
    }
  },
});

export function pgExecutor(pool: PgPoolLike): SqlExecutor {
  return {
    async query<T>(text: string, params?: readonly unknown[]): Promise<T[]> {
      const result = await pool.query(text, params as unknown[]);
      return result.rows as T[];
    },
    async transaction<T>(fn: (tx: SqlExecutor) => Promise<T>): Promise<T> {
      const client = await pool.connect();
      try {
        await client.query('BEGIN');
        const out = await fn(bound(client, 1));
        await client.query('COMMIT');
        return out;
      } catch (error) {
        await client.query('ROLLBACK').catch(() => {});
        throw error;
      } finally {
        client.release();
      }
    },
  };
}
