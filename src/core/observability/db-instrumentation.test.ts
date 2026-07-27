import type { DatabaseAdapter, MigratableDatabaseAdapter } from '../../adapters/database';
import { describe, expect, expectTypeOf, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { instrumentAdapter } from './db-instrumentation';
import { NO_OP_TELEMETRY } from './types';

describe('instrumentAdapter capabilities', () => {
  it('preserves migration capability and literal dialect through transactions', async () => {
    const wrapped = instrumentAdapter(createTestAdapter(), NO_OP_TELEMETRY);
    expectTypeOf(wrapped).toEqualTypeOf<MigratableDatabaseAdapter<'sqlite'>>();
    expect(wrapped.dialect).toBe('sqlite');

    await wrapped.transaction(async (tx) => {
      expectTypeOf(tx).toEqualTypeOf<MigratableDatabaseAdapter<'sqlite'>>();
      expect(tx.dialect).toBe('sqlite');
      await expect(tx.rawQuery('SELECT 1')).resolves.toEqual([{ 1: 1 }]);
    });
  });

  it('does not synthesize migration capability for CRUD-only adapters', () => {
    const migratable = createTestAdapter();
    const base: DatabaseAdapter = {
      create: migratable.create,
      findOne: migratable.findOne,
      findMany: migratable.findMany,
      update: migratable.update,
      delete: migratable.delete,
      count: migratable.count,
      transaction: migratable.transaction,
    };
    const wrapped = instrumentAdapter(base, NO_OP_TELEMETRY);

    expectTypeOf(wrapped).toEqualTypeOf<DatabaseAdapter>();
    expect(wrapped.rawQuery).toBeUndefined();
    expect(wrapped.dialect).toBeUndefined();
  });
});
