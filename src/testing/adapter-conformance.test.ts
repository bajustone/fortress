import type { DatabaseAdapter } from '../adapters/database';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from './index';

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
      const user = await db.create<{ id: number; email: string; name: string }>({
        model: 'user',
        data: { email: 'alice@test.com', name: 'Alice', passwordHash: 'hash', isActive: true },
      });

      expect(user.id).toBeDefined();
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
    it('updates matching records', async () => {
      const user = await db.create<{ id: number }>({
        model: 'user',
        data: { email: 'alice@test.com', name: 'Alice', passwordHash: 'hash', isActive: true },
      });

      await db.update({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
        data: { name: 'Alice Updated' },
      });

      const found = await db.findOne<{ name: string }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
      });

      expect(found!.name).toBe('Alice Updated');
    });
  });

  describe('delete', () => {
    it('removes matching records', async () => {
      const user = await db.create<{ id: number }>({
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
  });
}

// Run conformance tests against the built-in test adapter
describe('adapter conformance: createTestAdapter', () => {
  runAdapterTests(createTestAdapter);
});
