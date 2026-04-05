import type { DatabaseAdapter } from '../adapters/database';
import { beforeEach, describe, expect, it } from 'vitest';
import { FortressError } from '../core/errors';
import { createTestAdapter } from '../testing';

let db: DatabaseAdapter;

beforeEach(() => {
  db = createTestAdapter();
});

describe('drizzle adapter: buildWhereCondition edge cases', () => {
  it('throws BAD_REQUEST for unknown field', async () => {
    await expect(
      db.findOne({
        model: 'user',
        where: [{ field: 'nonexistent_column', operator: '=', value: 'test' }],
      }),
    ).rejects.toThrow(FortressError);

    await expect(
      db.findOne({
        model: 'user',
        where: [{ field: 'nonexistent_column', operator: '=', value: 'test' }],
      }),
    ).rejects.toThrow('Unknown field');
  });

  it('throws BAD_REQUEST for unsupported operator', async () => {
    await expect(
      db.findOne({
        model: 'user',
        where: [{ field: 'email', operator: 'like' as any, value: '%test%' }],
      }),
    ).rejects.toThrow(FortressError);

    await expect(
      db.findOne({
        model: 'user',
        where: [{ field: 'email', operator: 'like' as any, value: '%test%' }],
      }),
    ).rejects.toThrow('Unsupported operator');
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
    const user = await db.create<{ id: number }>({
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
        expiresAt: '2099-01-01T00:00:00.000Z',
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

describe('drizzle adapter: sanitizeForSqlite', () => {
  it('converts Date objects to ISO strings on create', async () => {
    const user = await db.create<{ id: number }>({
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

    const found = await db.findOne<{ expiresAt: string }>({
      model: 'refresh_token',
      where: [{ field: 'token_hash', operator: '=', value: 'hash-date-test' }],
    });

    expect(found).not.toBeNull();
    expect(found!.expiresAt).toBe('2025-06-15T12:00:00.000Z');
  });

  it('converts booleans to 0/1 on create', async () => {
    const user = await db.create<{ id: number; isActive: boolean | number }>({
      model: 'user',
      data: { email: 'bool@test.com', name: 'Bool', passwordHash: 'h', isActive: false },
    });

    // In SQLite, booleans are stored as 0/1
    const found = await db.findOne<{ id: number; isActive: boolean | number }>({
      model: 'user',
      where: [{ field: 'id', operator: '=', value: user.id }],
    });

    expect(found).not.toBeNull();
    // The value should be falsy (either 0 or false depending on Drizzle mode)
    expect(found!.isActive).toBeFalsy();
  });

  it('passes null values through unchanged', async () => {
    const user = await db.create<{ id: number }>({
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
        expiresAt: '2099-01-01T00:00:00.000Z',
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
    const user = await db.create<{ id: number }>({
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
        expiresAt: '2099-01-01T00:00:00.000Z',
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

  it('returns the updated record when a row matches', async () => {
    const user = await db.create<{ id: number }>({
      model: 'user',
      data: { email: 'update@test.com', name: 'Before', passwordHash: 'h', isActive: true },
    });

    const updated = await db.update<{ id: number; name: string }>({
      model: 'user',
      where: [{ field: 'id', operator: '=', value: user.id }],
      data: { name: 'After' },
    });

    expect(updated).not.toBeNull();
    expect(updated!.name).toBe('After');
    expect(updated!.id).toBe(user.id);
  });
});
