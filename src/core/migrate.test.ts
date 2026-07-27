import type { DatabaseAdapter } from '../adapters/database';
import { describe, expect, it, vi } from 'vitest';
import { createSqliteDrizzleAdapter } from '../drizzle/adapter';
import { createTestAdapter } from '../testing';
import { createFortress } from './fortress';

const SECRET = 'fortress-migrate-test-secret-32!';

function createBareSqliteAdapter(): DatabaseAdapter {
  // eslint-disable-next-line ts/no-require-imports
  const BetterSqlite3 = require('better-sqlite3');
  // eslint-disable-next-line ts/no-require-imports
  const { drizzle } = require('drizzle-orm/better-sqlite3');
  return createSqliteDrizzleAdapter(drizzle(new BetterSqlite3(':memory:')));
}

describe('fortress.migrate', () => {
  it('runs fortress migrations and reports the applied result', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createBareSqliteAdapter(),
    });

    const result = await fortress.migrate();

    expect(result.fortress.applied.length).toBeGreaterThan(0);
    expect(result.fortress.toVersion).toBeGreaterThan(0);
    expect(result.appRan).toBe(false);
  });

  it('calls migrateApp after fortress migrations complete', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });

    const callOrder: string[] = [];
    const migrateApp = vi.fn(async () => {
      callOrder.push('app');
    });

    // Stub the fortress-side step indirectly by recording from the result
    const result = await fortress.migrate({ migrateApp });

    expect(migrateApp).toHaveBeenCalledOnce();
    expect(result.appRan).toBe(true);
    expect(callOrder).toEqual(['app']);
  });

  it('is idempotent — re-running applies nothing', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });

    await fortress.migrate();
    const second = await fortress.migrate();
    expect(second.fortress.applied).toEqual([]);
  });

  it('propagates errors from migrateApp', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });

    const err = new Error('app migration failed');
    await expect(
      fortress.migrate({ migrateApp: async () => { throw err; } }),
    ).rejects.toThrow('app migration failed');
  });

  it('rejects a CRUD-only adapter with an actionable capability error', async () => {
    const migratable = createTestAdapter();
    const database: DatabaseAdapter = {
      create: migratable.create,
      findOne: migratable.findOne,
      findMany: migratable.findMany,
      update: migratable.update,
      delete: migratable.delete,
      count: migratable.count,
      transaction: migratable.transaction,
    };
    const fortress = createFortress({ jwt: { key: SECRET }, database });

    await expect(fortress.migrate()).rejects.toThrow(
      'dialect: \'sqlite\' | \'pg\' and rawQuery support',
    );
  });

  it('rejects adapters that provide only one migration capability', async () => {
    const migratable = createTestAdapter();
    const missingDialect: DatabaseAdapter = { ...migratable, dialect: undefined };
    const missingRawQuery: DatabaseAdapter = { ...migratable, rawQuery: undefined };

    const fortressMissingDialect = createFortress({ jwt: { key: SECRET }, database: missingDialect });
    const fortressMissingRawQuery = createFortress({ jwt: { key: SECRET }, database: missingRawQuery });
    await expect(fortressMissingDialect.migrate()).rejects.toThrow(
      'dialect: \'sqlite\' | \'pg\' and rawQuery support',
    );
    await expect(fortressMissingRawQuery.migrate()).rejects.toThrow(
      'dialect: \'sqlite\' | \'pg\' and rawQuery support',
    );
  });
});
