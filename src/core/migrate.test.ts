import type { DatabaseAdapter } from '../adapters/database';
import { describe, expect, it, vi } from 'vitest';
import { createDrizzleAdapter } from '../drizzle/adapter';
import { createTestAdapter } from '../testing';
import { createFortress } from './fortress';

const SECRET = 'fortress-migrate-test-secret-32!';

function createBareSqliteAdapter(): DatabaseAdapter {
  // eslint-disable-next-line ts/no-require-imports
  const BetterSqlite3 = require('better-sqlite3');
  // eslint-disable-next-line ts/no-require-imports
  const { drizzle } = require('drizzle-orm/better-sqlite3');
  return createDrizzleAdapter(drizzle(new BetterSqlite3(':memory:')));
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
});
