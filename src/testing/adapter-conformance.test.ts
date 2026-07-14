import type { DatabaseAdapter } from '../adapters/database';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from './index';

function assertStringId(record: { id: unknown }): asserts record is { id: string } {
  if (typeof record.id !== 'string')
    throw new TypeError(`DatabaseAdapter.create() returned a non-string id (${typeof record.id})`);
}

/**
 * Adapter conformance test suite.
 * Run this against any DatabaseAdapter implementation to verify the contract.
 *
 * Usage for custom adapters:
 *   runAdapterTests(() => createMyAdapter());
 */
export function runAdapterTests(createAdapter: () => DatabaseAdapter): void {
  let db: DatabaseAdapter;

  beforeEach(() => {
    db = createAdapter();
  });

  describe('create', () => {
    it('creates a record and returns it with an id', async () => {
      const user = await db.create<{ id: string; email: string; name: string }>({
        model: 'user',
        data: { email: 'alice@test.com', name: 'Alice', passwordHash: 'hash', isActive: true },
      });

      expect(user.id).toBeDefined();
      assertStringId(user);
      expect(user.email).toBe('alice@test.com');
      expect(user.name).toBe('Alice');
    });
  });

  describe('findOne', () => {
    it('returns a matching record', async () => {
      await db.create({ model: 'user', data: { email: 'alice@test.com', name: 'Alice', passwordHash: 'hash', isActive: true } });

      const found = await db.findOne<{ email: string }>({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'alice@test.com' }],
      });

      expect(found).not.toBeNull();
      expect(found!.email).toBe('alice@test.com');
    });

    it('returns null when no match', async () => {
      const found = await db.findOne({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'nobody@test.com' }],
      });

      expect(found).toBeNull();
    });
  });

  describe('findMany', () => {
    it('returns all matching records', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });

      const users = await db.findMany<{ email: string }>({ model: 'user' });
      expect(users).toHaveLength(2);
    });

    it('returns empty array when no matches', async () => {
      const users = await db.findMany({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'nobody@test.com' }],
      });

      expect(users).toEqual([]);
    });

    it('respects limit', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'c@test.com', name: 'C', passwordHash: 'h', isActive: true } });

      const users = await db.findMany({ model: 'user', limit: 2 });
      expect(users).toHaveLength(2);
    });

    it('supports offset', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'c@test.com', name: 'C', passwordHash: 'h', isActive: true } });

      const users = await db.findMany({ model: 'user', limit: 10, offset: 2 });
      expect(users).toHaveLength(1);
    });
  });

  describe('update', () => {
    it('updates matching records and returns the updated row', async () => {
      const user = await db.create<{ id: string }>({
        model: 'user',
        data: { email: 'alice@test.com', name: 'Alice', passwordHash: 'hash', isActive: true },
      });

      const updated = await db.update<{ id: string; name: string }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
        data: { name: 'Alice Updated' },
      });
      expect(updated).toMatchObject({ id: user.id, name: 'Alice Updated' });

      const found = await db.findOne<{ name: string }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
      });

      expect(found!.name).toBe('Alice Updated');
    });

    it('returns null when no row matches', async () => {
      await expect(db.update({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'missing@test.com' }],
        data: { name: 'Nobody' },
      })).resolves.toBeNull();
    });

    it('updates every matching row while returning one updated row', async () => {
      await db.create({ model: 'user', data: { email: 'multi-a@test.com', name: 'A', passwordHash: 'shared', isActive: true } });
      await db.create({ model: 'user', data: { email: 'multi-b@test.com', name: 'B', passwordHash: 'shared', isActive: true } });
      const updated = await db.update<{ isActive: boolean }>({
        model: 'user',
        where: [{ field: 'passwordHash', operator: '=', value: 'shared' }],
        data: { isActive: false },
      });
      expect(updated?.isActive).toBe(false);
      expect(await db.count({
        model: 'user',
        where: [{ field: 'isActive', operator: '=', value: false }],
      })).toBe(2);
    });

    it('round-trips boolean values on create, update, and read', async () => {
      const user = await db.create<{ id: string; isActive: boolean }>({
        model: 'user',
        data: { email: 'boolean@test.com', name: 'Boolean', passwordHash: 'h', isActive: false },
      });
      expect(user.isActive).toBe(false);
      const updated = await db.update<{ isActive: boolean }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
        data: { isActive: true },
      });
      expect(updated?.isActive).toBe(true);
      await expect(db.findOne<{ isActive: boolean }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
      })).resolves.toMatchObject({ isActive: true });
    });
  });

  describe('delete', () => {
    it('removes matching records', async () => {
      const user = await db.create<{ id: string }>({
        model: 'user',
        data: { email: 'alice@test.com', name: 'Alice', passwordHash: 'hash', isActive: true },
      });

      await db.delete({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
      });

      const found = await db.findOne({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
      });

      expect(found).toBeNull();
    });

    it('removes every matching row', async () => {
      await db.create({ model: 'user', data: { email: 'delete-a@test.com', name: 'A', passwordHash: 'delete-shared', isActive: true } });
      await db.create({ model: 'user', data: { email: 'delete-b@test.com', name: 'B', passwordHash: 'delete-shared', isActive: true } });
      await db.delete({
        model: 'user',
        where: [{ field: 'passwordHash', operator: '=', value: 'delete-shared' }],
      });
      expect(await db.count({ model: 'user' })).toBe(0);
    });

    it('is a no-op when no match', async () => {
      // Should not throw
      await db.delete({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: 99999 }],
      });
    });
  });

  describe('count', () => {
    it('counts all records', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });

      const count = await db.count({ model: 'user' });
      expect(count).toBe(2);
    });

    it('counts with filter', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });

      const count = await db.count({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'a@test.com' }],
      });
      expect(count).toBe(1);
    });

    it('returns 0 for no matches', async () => {
      const count = await db.count({ model: 'user' });
      expect(count).toBe(0);
    });
  });

  describe('rawQuery placeholder contract', () => {
    it('accepts canonical ? placeholders on every dialect', async () => {
      if (!db.rawQuery)
        return;
      const rows = await db.rawQuery<{ value: number | string }>('SELECT ? AS value', [42]);
      expect(Number(rows[0]?.value)).toBe(42);
    });
  });

  describe('transaction', () => {
    it('commits on success', async () => {
      await db.transaction(async (tx) => {
        await tx.create({ model: 'user', data: { email: 'tx@test.com', name: 'TX', passwordHash: 'h', isActive: true } });
      });

      const found = await db.findOne<{ email: string }>({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'tx@test.com' }],
      });

      expect(found).not.toBeNull();
    });

    it('rolls back on error', async () => {
      await expect(
        db.transaction(async (tx) => {
          await tx.create({ model: 'user', data: { email: 'rollback@test.com', name: 'RB', passwordHash: 'h', isActive: true } });
          throw new Error('forced rollback');
        }),
      ).rejects.toThrow('forced rollback');

      const found = await db.findOne({
        model: 'user',
        where: [{ field: 'email', operator: '=', value: 'rollback@test.com' }],
      });

      expect(found).toBeNull();
    });
  });

  describe('operators', () => {
    it('supports != operator', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });

      const users = await db.findMany<{ email: string }>({
        model: 'user',
        where: [{ field: 'email', operator: '!=', value: 'a@test.com' }],
      });

      expect(users).toHaveLength(1);
      expect(users[0].email).toBe('b@test.com');
    });

    it('supports in operator', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'b@test.com', name: 'B', passwordHash: 'h', isActive: true } });
      await db.create({ model: 'user', data: { email: 'c@test.com', name: 'C', passwordHash: 'h', isActive: true } });

      const users = await db.findMany<{ email: string }>({
        model: 'user',
        where: [{ field: 'email', operator: 'in', value: ['a@test.com', 'c@test.com'] }],
      });

      expect(users).toHaveLength(2);
    });

    it('supports gt, lt, gte, and lte operators', async () => {
      const dates = [
        new Date('2020-01-01T00:00:00.000Z'),
        new Date('2021-01-01T00:00:00.000Z'),
        new Date('2022-01-01T00:00:00.000Z'),
      ];
      for (const [index, createdAt] of dates.entries()) {
        await db.create({
          model: 'user',
          data: { email: `date-${index}@test.com`, name: String(index), passwordHash: 'h', isActive: true, createdAt, updatedAt: createdAt },
        });
      }
      const cases = [
        ['gt', dates[1], 1],
        ['lt', dates[1], 1],
        ['gte', dates[1], 2],
        ['lte', dates[1], 2],
      ] as const;
      for (const [operator, value, expected] of cases) {
        const rows = await db.findMany({
          model: 'user',
          where: [{ field: 'createdAt', operator, value }],
        });
        expect(rows, operator).toHaveLength(expected);
      }
    });

    it('supports isNull independently of the supplied value', async () => {
      await db.create({ model: 'user', data: { email: 'null@test.com', name: 'Null', passwordHash: null, isActive: true } });
      await db.create({ model: 'user', data: { email: 'not-null@test.com', name: 'Not null', passwordHash: 'h', isActive: true } });
      const rows = await db.findMany<{ email: string }>({
        model: 'user',
        where: [{ field: 'passwordHash', operator: 'isNull', value: false }],
      });
      expect(rows.map(row => row.email)).toEqual(['null@test.com']);
    });

    it('throws for an unknown operator', async () => {
      await expect(db.findMany({
        model: 'user',
        where: [{ field: 'email', operator: 'definitely-unsupported', value: 'x' }],
      })).rejects.toThrow();
    });
  });

  describe('sortBy', () => {
    it('sorts ascending and descending by the requested field', async () => {
      for (const name of ['Charlie', 'Alice', 'Bob']) {
        await db.create({
          model: 'user',
          data: { email: `${name.toLowerCase()}@test.com`, name, passwordHash: 'h', isActive: true },
        });
      }
      const ascending = await db.findMany<{ name: string }>({
        model: 'user',
        sortBy: { field: 'name', direction: 'asc' },
      });
      const descending = await db.findMany<{ name: string }>({
        model: 'user',
        sortBy: { field: 'name', direction: 'desc' },
      });
      expect(ascending.map(row => row.name)).toEqual(['Alice', 'Bob', 'Charlie']);
      expect(descending.map(row => row.name)).toEqual(['Charlie', 'Bob', 'Alice']);
    });
  });

  describe('empty where clause is rejected on mutations', () => {
    // A frozen contract guarantee: update/delete/findOne with an empty where
    // must throw rather than silently match every row (a full-table wipe
    // footgun). Unfiltered reads (findMany/count) remain legal.
    it('update throws on an empty where', async () => {
      await expect(
        db.update({ model: 'user', where: [], data: { name: 'x' } }),
      ).rejects.toThrow();
    });

    it('delete throws on an empty where', async () => {
      await expect(
        db.delete({ model: 'user', where: [] }),
      ).rejects.toThrow();
    });

    it('findOne throws on an empty where', async () => {
      await expect(
        db.findOne({ model: 'user', where: [] }),
      ).rejects.toThrow();
    });

    it('findMany still allows an unfiltered read', async () => {
      await db.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      const users = await db.findMany({ model: 'user', where: [] });
      expect(users).toHaveLength(1);
    });
  });

  describe('constraint violations map to typed errors', () => {
    it('maps a unique violation to a 409 CONFLICT', async () => {
      await db.create({ model: 'user', data: { email: 'dupe@test.com', name: 'A', passwordHash: 'h', isActive: true } });
      await expect(
        db.create({ model: 'user', data: { email: 'dupe@test.com', name: 'B', passwordHash: 'h', isActive: true } }),
      ).rejects.toMatchObject({ code: 'CONFLICT', statusCode: 409 });
    });
  });
}

describe('conformance regression guards', () => {
  it('rejects a deliberately broken numeric-id adapter result', () => {
    expect(() => assertStringId({ id: 123 })).toThrow(/non-string id \(number\)/);
  });
});

// Run conformance tests against the built-in test adapter
describe('adapter conformance: createTestAdapter', () => {
  runAdapterTests(createTestAdapter);
});
