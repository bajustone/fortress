import type { Fortress } from '../fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

const SECRET = 'auth-admin-test-secret-32chars!!';

describe('auth admin: user management', () => {
  let fortress: Fortress;

  beforeEach(() => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
  });

  async function createUsers(count: number): Promise<void> {
    for (let i = 1; i <= count; i++) {
      await fortress.auth.createUser({
        email: `user${i}@test.com`,
        name: `User ${i}`,
        password: 'Password123456!',
      });
    }
  }

  // ── listUsers ────────────────────────────────────────────────

  describe('listUsers', () => {
    it('returns paginated users with total count', async () => {
      await createUsers(5);

      const result = await fortress.auth.listUsers({ limit: 3, offset: 0 });

      expect(result.users).toHaveLength(3);
      expect(result.total).toBe(5);
    });

    it('returns second page', async () => {
      await createUsers(5);

      const result = await fortress.auth.listUsers({ limit: 3, offset: 3 });

      expect(result.users).toHaveLength(2);
      expect(result.total).toBe(5);
    });

    it('returns empty when no users', async () => {
      const result = await fortress.auth.listUsers({});

      expect(result.users).toEqual([]);
      expect(result.total).toBe(0);
    });

    it('strips passwordHash from results', async () => {
      await createUsers(1);

      const result = await fortress.auth.listUsers({});

      expect(result.users[0]).not.toHaveProperty('passwordHash');
      expect(result.users[0].email).toBe('user1@test.com');
    });

    it('searches by email', async () => {
      await createUsers(3);

      const result = await fortress.auth.listUsers({ search: 'user2' });

      expect(result.users).toHaveLength(1);
      expect(result.users[0].email).toBe('user2@test.com');
      expect(result.total).toBe(1);
    });

    it('returns all when search matches nothing', async () => {
      await createUsers(2);

      const result = await fortress.auth.listUsers({ search: 'nonexistent' });

      expect(result.users).toHaveLength(0);
      expect(result.total).toBe(0);
    });
  });

  // ── getUserById ──────────────────────────────────────────────

  describe('getUserById', () => {
    it('returns user without passwordHash', async () => {
      await createUsers(1);

      const listResult = await fortress.auth.listUsers({});
      const user = await fortress.auth.getUserById(listResult.users[0].id);

      expect(user.email).toBe('user1@test.com');
      expect(user.name).toBe('User 1');
      expect(user).not.toHaveProperty('passwordHash');
    });

    it('throws NOT_FOUND for missing user', async () => {
      await expect(fortress.auth.getUserById('99999')).rejects.toThrow('User not found');
    });
  });

  // ── updateUser ───────────────────────────────────────────────

  describe('updateUser', () => {
    it('updates user name', async () => {
      await createUsers(1);
      const { users } = await fortress.auth.listUsers({});
      const userId = users[0].id;

      const updated = await fortress.auth.updateUser(userId, { name: 'Updated Name' });

      expect(updated.name).toBe('Updated Name');
      expect(updated.email).toBe('user1@test.com');
      expect(updated).not.toHaveProperty('passwordHash');
    });

    it('updates user email and login identifier', async () => {
      await createUsers(1);
      const { users } = await fortress.auth.listUsers({});
      const userId = users[0].id;

      const updated = await fortress.auth.updateUser(userId, { email: 'new@test.com' });

      expect(updated.email).toBe('new@test.com');

      // Verify login identifier was updated too
      const identifiers = await fortress.auth.getLoginIdentifiers(userId);
      expect(identifiers.some(i => i.value === 'new@test.com')).toBe(true);
    });

    it('revokes active refresh tokens when password changes', async () => {
      await createUsers(1);
      const login = await fortress.auth.login('user1@test.com', 'Password123456!');
      if (login.status !== 'success')
        throw new Error('expected login success');

      await fortress.auth.updateUser(login.user.id, { password: 'NewPassword123456!' });

      await expect(fortress.auth.refresh(login.refreshToken)).rejects.toThrow();
    });

    it('updates isActive', async () => {
      await createUsers(1);
      const { users } = await fortress.auth.listUsers({});
      const userId = users[0].id;

      const updated = await fortress.auth.updateUser(userId, { isActive: false });

      expect(updated.isActive).toBeFalsy();
    });

    it('throws CONFLICT for duplicate email', async () => {
      await createUsers(2);
      const { users } = await fortress.auth.listUsers({});

      await expect(
        fortress.auth.updateUser(users[0].id, { email: 'user2@test.com' }),
      ).rejects.toThrow('A user with this email already exists');
    });

    it('throws NOT_FOUND for missing user', async () => {
      await expect(
        fortress.auth.updateUser('99999', { name: 'Test' }),
      ).rejects.toThrow('User not found');
    });
  });

  // ── deleteUser ───────────────────────────────────────────────

  describe('deleteUser', () => {
    it('deletes user', async () => {
      await createUsers(1);
      const { users } = await fortress.auth.listUsers({});
      const userId = users[0].id;

      await fortress.auth.deleteUser(userId);

      const result = await fortress.auth.listUsers({});
      expect(result.total).toBe(0);
    });

    it('throws NOT_FOUND for missing user', async () => {
      await expect(fortress.auth.deleteUser('99999')).rejects.toThrow('User not found');
    });
  });
});
