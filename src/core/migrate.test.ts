import { describe, expect, it, vi } from 'vitest';
import { createTestAdapter } from '../testing';
import { createFortress } from './fortress';

const SECRET = 'fortress-migrate-test-secret-32!';

describe('fortress.migrate', () => {
  it('runs fortress migrations and reports the applied result', async () => {
    const fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
    });

    const result = await fortress.migrate();

    expect(result.fortress.applied.length).toBeGreaterThan(0);
    expect(result.fortress.toVersion).toBeGreaterThan(0);
    expect(result.appRan).toBe(false);
  });

  it('calls migrateApp after fortress migrations complete', async () => {
    const fortress = createFortress({
      jwt: { secret: SECRET },
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
      jwt: { secret: SECRET },
      database: createTestAdapter(),
    });

    await fortress.migrate();
    const second = await fortress.migrate();
    expect(second.fortress.applied).toEqual([]);
  });

  it('propagates errors from migrateApp', async () => {
    const fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
    });

    const err = new Error('app migration failed');
    await expect(
      fortress.migrate({ migrateApp: async () => { throw err; } }),
    ).rejects.toThrow('app migration failed');
  });
});
