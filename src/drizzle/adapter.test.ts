import type { DatabaseAdapter } from '../adapters/database';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { FortressError } from '../core/errors';
import { createTestAdapter } from '../testing';
import { createPostgresDrizzleAdapter } from './adapter';

let db: DatabaseAdapter;

beforeEach(() => {
  db = createTestAdapter();
});

describe('dialect-specific Drizzle factories', () => {
  it('advertises SQLite for the test adapter', () => {
    expect(createTestAdapter().dialect).toBe('sqlite');
  });

  it('advertises PostgreSQL and uses its native transaction path', async () => {
    const run = vi.fn(() => {
      throw new Error('PostgreSQL must not use SQLite .run()');
    });
    const execute = vi.fn(async () => []);
    const drizzle = {
      insert: vi.fn(),
      select: vi.fn(),
      update: vi.fn(),
      delete: vi.fn(),
      run,
      execute,
      transaction: vi.fn(async (fn: (tx: typeof drizzle) => Promise<unknown>) => fn(drizzle)),
    };
    const adapter = createPostgresDrizzleAdapter(drizzle);

    expect(adapter.dialect).toBe('pg');
    await expect(adapter.transaction(async (tx) => {
      expect(tx.dialect).toBe('pg');
      await tx.rawQuery('SELECT 1');
      return 'ok';
    })).resolves.toBe('ok');
    expect(drizzle.transaction).toHaveBeenCalledOnce();
    expect(execute).toHaveBeenCalledOnce();
    expect(run).not.toHaveBeenCalled();
  });
});

describe('drizzle adapter: buildWhereCondition edge cases', () => {
  it('throws a model-aware BAD_REQUEST for unknown fields', async () => {
    await expect(
      db.findOne({
        model: 'user',
        where: [{ field: 'nonexistent_column', operator: '=', value: 'test' }],
      }),
    ).rejects.toMatchObject({
      code: 'BAD_REQUEST',
      statusCode: 400,
      message: 'Unknown field: nonexistent_column on model/table \'user\'',
      details: { model: 'user', field: 'nonexistent_column' },
    });
  });

  it('throws BAD_REQUEST for unsupported operator', async () => {
    await expect(
      db.findOne({
        model: 'user',
        where: [{ field: 'email', operator: 'regex' as any, value: '.*test.*' }],
      }),
    ).rejects.toThrow(FortressError);

    await expect(
      db.findOne({
        model: 'user',
        where: [{ field: 'email', operator: 'regex' as any, value: '.*test.*' }],
      }),
    ).rejects.toThrow('Unsupported operator');
  });

  it('supports like operator', async () => {
    await db.create({ model: 'user', data: { email: 'alice@test.com', name: 'Alice', passwordHash: 'h', isActive: true } });
    await db.create({ model: 'user', data: { email: 'bob@other.com', name: 'Bob', passwordHash: 'h', isActive: true } });

    const results = await db.findMany<{ email: string }>({
      model: 'user',
      where: [{ field: 'email', operator: 'like' as any, value: '%test%' }],
    });

    expect(results).toHaveLength(1);
    expect(results[0].email).toBe('alice@test.com');
  });

  it('aNDs multiple where conditions together', async () => {
    await db.create({ model: 'user', data: { email: 'alice@test.com', name: 'Alice', passwordHash: 'h', isActive: true } });
    await db.create({ model: 'user', data: { email: 'bob@test.com', name: 'Bob', passwordHash: 'h', isActive: true } });
    await db.create({ model: 'user', data: { email: 'alice@other.com', name: 'Alice', passwordHash: 'h', isActive: true } });

    // Both conditions must match — name = Alice AND email = alice@test.com
    const results = await db.findMany<{ email: string; name: string }>({
      model: 'user',
      where: [
        { field: 'name', operator: '=', value: 'Alice' },
        { field: 'email', operator: '=', value: 'alice@test.com' },
      ],
    });

    expect(results).toHaveLength(1);
    expect(results[0].email).toBe('alice@test.com');
  });

  it('maps snake_case field names to camelCase columns', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'snake@test.com', name: 'Snake', passwordHash: 'h', isActive: true },
    });

    await db.create({
      model: 'refresh_token',
      data: {
        userId: user.id,
        tokenHash: 'hash123',
        tokenFamily: 'fam1',
        isRevoked: false,
        expiresAt: new Date('2099-01-01T00:00:00.000Z'),
        userAgent: 'Mozilla/5.0',
      },
    });

    // Query using snake_case field name — adapter should map to camelCase column
    const found = await db.findOne<{ userAgent: string }>({
      model: 'refresh_token',
      where: [{ field: 'user_agent', operator: '=', value: 'Mozilla/5.0' }],
    });

    expect(found).not.toBeNull();
    expect(found!.userAgent).toBe('Mozilla/5.0');
  });
});

describe('drizzle adapter: date and value handling', () => {
  it('stores and retrieves Date objects correctly', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'date@test.com', name: 'Date', passwordHash: 'h', isActive: true },
    });
    const now = new Date('2025-06-15T12:00:00.000Z');

    await db.create({
      model: 'refresh_token',
      data: {
        userId: user.id,
        tokenHash: 'hash-date-test',
        tokenFamily: 'fam-date',
        isRevoked: false,
        expiresAt: now,
      },
    });

    const found = await db.findOne<{ expiresAt: Date }>({
      model: 'refresh_token',
      where: [{ field: 'token_hash', operator: '=', value: 'hash-date-test' }],
    });

    expect(found).not.toBeNull();
    expect(found!.expiresAt).toBeInstanceOf(Date);
    expect(found!.expiresAt.getTime()).toBe(now.getTime());
  });

  it('handles booleans correctly', async () => {
    const user = await db.create<{ id: string; isActive: boolean }>({
      model: 'user',
      data: { email: 'bool@test.com', name: 'Bool', passwordHash: 'h', isActive: false },
    });

    const found = await db.findOne<{ id: string; isActive: boolean }>({
      model: 'user',
      where: [{ field: 'id', operator: '=', value: user.id }],
    });

    expect(found).not.toBeNull();
    expect(found!.isActive).toBe(false);
  });

  it('passes null values through unchanged', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'null@test.com', name: 'Null', passwordHash: 'h', isActive: true },
    });

    await db.create({
      model: 'refresh_token',
      data: {
        userId: user.id,
        tokenHash: 'hash-null-test',
        tokenFamily: 'fam-null',
        isRevoked: false,
        expiresAt: new Date('2099-01-01T00:00:00.000Z'),
        ipAddress: null,
      },
    });

    const found = await db.findOne<{ ipAddress: string | null }>({
      model: 'refresh_token',
      where: [{ field: 'token_hash', operator: '=', value: 'hash-null-test' }],
    });

    expect(found).not.toBeNull();
    expect(found!.ipAddress).toBeNull();
  });

  it('converts undefined values to null', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'undef@test.com', name: 'Undef', passwordHash: 'h', isActive: true },
    });

    await db.create({
      model: 'refresh_token',
      data: {
        userId: user.id,
        tokenHash: 'hash-undef-test',
        tokenFamily: 'fam-undef',
        isRevoked: false,
        expiresAt: new Date('2099-01-01T00:00:00.000Z'),
        deviceName: undefined,
      },
    });

    const found = await db.findOne<{ deviceName: string | null }>({
      model: 'refresh_token',
      where: [{ field: 'token_hash', operator: '=', value: 'hash-undef-test' }],
    });

    expect(found).not.toBeNull();
    expect(found!.deviceName).toBeNull();
  });
});

describe('drizzle adapter: unknown model', () => {
  it('throws BAD_REQUEST for unknown model name', async () => {
    await expect(
      db.findOne({
        model: 'nonexistent_model',
        where: [{ field: 'id', operator: '=', value: 1 }],
      }),
    ).rejects.toThrow(FortressError);

    await expect(
      db.findOne({
        model: 'nonexistent_model',
        where: [{ field: 'id', operator: '=', value: 1 }],
      }),
    ).rejects.toThrow('Unknown model');
  });
});

describe('drizzle adapter: count', () => {
  it('returns correct count with where clause', async () => {
    await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
    await db.create({ model: 'user', data: { email: 'b@test.com', name: 'A', passwordHash: 'h', isActive: true } });
    await db.create({ model: 'user', data: { email: 'c@test.com', name: 'C', passwordHash: 'h', isActive: true } });

    const count = await db.count({
      model: 'user',
      where: [{ field: 'name', operator: '=', value: 'A' }],
    });

    expect(count).toBe(2);
  });

  it('returns 0 for empty table', async () => {
    const count = await db.count({ model: 'user' });
    expect(count).toBe(0);
  });
});

describe('drizzle adapter: transaction', () => {
  it('rolls back all operations on error', async () => {
    await expect(
      db.transaction(async (tx) => {
        await tx.create({ model: 'user', data: { email: 'tx1@test.com', name: 'TX1', passwordHash: 'h', isActive: true } });
        await tx.create({ model: 'user', data: { email: 'tx2@test.com', name: 'TX2', passwordHash: 'h', isActive: true } });
        // Force an error — both creates above should be rolled back
        throw new Error('rollback test');
      }),
    ).rejects.toThrow('rollback test');

    // Both records should be gone due to rollback
    const count = await db.count({ model: 'user' });
    expect(count).toBe(0);
  });

  it('commits all operations on success', async () => {
    await db.transaction(async (tx) => {
      await tx.create({ model: 'user', data: { email: 'commit1@test.com', name: 'C1', passwordHash: 'h', isActive: true } });
      await tx.create({ model: 'user', data: { email: 'commit2@test.com', name: 'C2', passwordHash: 'h', isActive: true } });
    });

    const count = await db.count({ model: 'user' });
    expect(count).toBe(2);
  });
});

describe('drizzle adapter: update returns null on no match', () => {
  it('returns null when where clause matches no rows', async () => {
    const result = await db.update({
      model: 'user',
      where: [{ field: 'id', operator: '=', value: 99999 }],
      data: { name: 'Ghost' },
    });

    expect(result).toBeNull();
  });

  it('applies update to every matching row while returning one row', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'update-many@test.com', name: 'Many', passwordHash: 'h', isActive: true },
    });
    await db.create({
      model: 'refresh_token',
      data: { userId: user.id, tokenHash: 'many-1', tokenFamily: 'fam-many', isRevoked: false, expiresAt: new Date('2099-01-01T00:00:00Z') },
    });
    await db.create({
      model: 'refresh_token',
      data: { userId: user.id, tokenHash: 'many-2', tokenFamily: 'fam-many', isRevoked: false, expiresAt: new Date('2099-01-01T00:00:00Z') },
    });

    const result = await db.update({
      model: 'refresh_token',
      where: [{ field: 'tokenFamily', operator: '=', value: 'fam-many' }],
      data: { isRevoked: true },
    });

    expect(result).not.toBeNull();
    const remainingActive = await db.count({
      model: 'refresh_token',
      where: [
        { field: 'tokenFamily', operator: '=', value: 'fam-many' },
        { field: 'isRevoked', operator: '=', value: false },
      ],
    });
    expect(remainingActive).toBe(0);
  });

  it('returns the updated record when a row matches', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'update@test.com', name: 'Before', passwordHash: 'h', isActive: true },
    });

    const updated = await db.update<{ id: string; name: string }>({
      model: 'user',
      where: [{ field: 'id', operator: '=', value: user.id }],
      data: { name: 'After' },
    });

    expect(updated).not.toBeNull();
    expect(updated!.name).toBe('After');
    expect(updated!.id).toBe(user.id);
  });
});

// C3 regression: two concurrent transactions on SQLite must not collide.
// Pre-fix, an awaited callback could let a second BEGIN issue against the
// same connection ("cannot start a transaction within a transaction") and
// a COMMIT from one path would close the other. The fix serialises
// transactions through an async chain and uses BEGIN IMMEDIATE to take
// the write lock up front.
describe('drizzle adapter: concurrent transactions (C3)', () => {
  it('does not error "transaction within a transaction" under concurrency', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'cas@test.com', name: 'CAS', passwordHash: 'h', isActive: true },
    });

    const txOne = db.transaction(async (tx) => {
      const row = await tx.findOne<{ id: string; name: string }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
      });
      // Yield so the second tx has a chance to start while we're "inside"
      // this one. With the old `BEGIN`/shared-adapter pattern this is where
      // the failure mode would surface.
      await new Promise(r => setTimeout(r, 0));
      await tx.update({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
        data: { name: `${row!.name}-A` },
      });
    });
    const txTwo = db.transaction(async (tx) => {
      const row = await tx.findOne<{ id: string; name: string }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
      });
      await tx.update({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
        data: { name: `${row!.name}-B` },
      });
    });

    await Promise.all([txOne, txTwo]);

    const final = await db.findOne<{ name: string }>({
      model: 'user',
      where: [{ field: 'id', operator: '=', value: user.id }],
    });
    // Both transactions ran serially, so the final name reflects both
    // updates layered on top of each other. The exact ordering is
    // implementation-defined (whichever tx the chain scheduled first wins).
    expect(final!.name === 'CAS-A-B' || final!.name === 'CAS-B-A').toBe(true);
  });

  it('rejects nested SQLite transactions with a clear error instead of deadlocking', async () => {
    await expect(
      db.transaction(async (tx) => {
        await tx.transaction(async () => 'nested');
      }),
    ).rejects.toThrow('Nested transactions are not supported by the SQLite Drizzle adapter');
  });

  it('compare-and-set update is atomic across concurrent transactions', async () => {
    // This is the pattern OAuth code exchange + refresh rotation rely on:
    // exactly one of N concurrent transactions can flip a NULL claim flag.
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'claim@test.com', name: 'C', passwordHash: 'h', isActive: true },
    });
    await db.create({
      model: 'refresh_token',
      data: {
        userId: user.id,
        tokenHash: 'h-claim',
        tokenFamily: 'f',
        isRevoked: false,
        expiresAt: new Date('2099-01-01T00:00:00Z'),
      },
    });

    async function tryClaim(): Promise<boolean> {
      return db.transaction(async (tx) => {
        const claimed = await tx.update<{ id: string }>({
          model: 'refresh_token',
          where: [
            { field: 'tokenHash', operator: '=', value: 'h-claim' },
            { field: 'isRevoked', operator: '=', value: false },
          ],
          data: { isRevoked: true },
        });
        return claimed !== null;
      });
    }

    const results = await Promise.all([tryClaim(), tryClaim(), tryClaim()]);
    const wins = results.filter(Boolean).length;
    expect(wins).toBe(1);
  });
});
