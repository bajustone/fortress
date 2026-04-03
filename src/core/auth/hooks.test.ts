import type { Fortress } from '../fortress';

import { describe, expect, it, vi } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

let fortress: Fortress;
const SECRET = 'hooks-test-secret-at-least-32chars!!';

async function seedUser(): Promise<{ id: number }> {
  return fortress.auth.createUser({
    email: 'hook-user@example.com',
    name: 'Hook User',
    password: 'password-123',
  });
}

describe('plugin hooks', () => {
  describe('beforeLogout', () => {
    it('is called before logout', async () => {
      const beforeLogout = vi.fn(async () => {});

      fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [{ name: 'test', hooks: { beforeLogout } }],
      });

      await seedUser();
      const { refreshToken } = await fortress.auth.login('hook-user@example.com', 'password-123');
      await fortress.auth.logout(refreshToken!);

      expect(beforeLogout).toHaveBeenCalledOnce();
      expect(beforeLogout).toHaveBeenCalledWith(expect.objectContaining({
        token: refreshToken,
      }));
    });
  });

  describe('afterRegister', () => {
    it('is called after user creation', async () => {
      const afterRegister = vi.fn(async () => {});

      fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [{ name: 'test', hooks: { afterRegister } }],
      });

      await fortress.auth.createUser({
        email: 'new-user@example.com',
        name: 'New User',
        password: 'password-123',
      });

      expect(afterRegister).toHaveBeenCalledOnce();
      expect(afterRegister).toHaveBeenCalledWith(
        expect.objectContaining({ responseHeaders: expect.any(Headers) }),
        expect.objectContaining({ email: 'new-user@example.com' }),
      );
    });

    it('receives the created user', async () => {
      let receivedUser: unknown = null;
      const afterRegister = vi.fn(async (_ctx: unknown, user: unknown) => {
        receivedUser = user;
      });

      fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [{ name: 'test', hooks: { afterRegister } }],
      });

      await fortress.auth.createUser({
        email: 'check-user@example.com',
        name: 'Check User',
        password: 'password-123',
      });

      expect(receivedUser).toMatchObject({ email: 'check-user@example.com', name: 'Check User' });
    });
  });

  describe('beforeTokenRefresh', () => {
    it('is called before token refresh', async () => {
      const beforeTokenRefresh = vi.fn(async () => {});

      fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [{ name: 'test', hooks: { beforeTokenRefresh } }],
      });

      await seedUser();
      const { refreshToken } = await fortress.auth.login('hook-user@example.com', 'password-123');
      await fortress.auth.refresh(refreshToken!);

      expect(beforeTokenRefresh).toHaveBeenCalledOnce();
      expect(beforeTokenRefresh).toHaveBeenCalledWith(expect.objectContaining({
        token: refreshToken,
      }));
    });

    it('can block refresh with HookResult', async () => {
      fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [{
          name: 'blocker',
          hooks: {
            async beforeTokenRefresh() {
              return { stop: true, response: { blocked: true } };
            },
          },
        }],
      });

      await seedUser();
      const { refreshToken } = await fortress.auth.login('hook-user@example.com', 'password-123');
      const result = await fortress.auth.refresh(refreshToken!);

      expect((result as any).blocked).toBe(true);
    });
  });

  describe('afterTokenRefresh', () => {
    it('is called after token refresh and can modify result', async () => {
      fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [{
          name: 'test',
          hooks: {
            async afterTokenRefresh(_ctx, result) {
              return { ...result, accessToken: `modified-${result.accessToken}` };
            },
          },
        }],
      });

      await seedUser();
      const { refreshToken } = await fortress.auth.login('hook-user@example.com', 'password-123');
      const result = await fortress.auth.refresh(refreshToken!);

      expect(result.accessToken).toMatch(/^modified-/);
    });
  });

  describe('hook execution order', () => {
    it('runs hooks in plugin registration order', async () => {
      const order: string[] = [];

      fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [
          {
            name: 'first',
            hooks: {
              async afterLogin(_ctx, result) {
                order.push('first');
                return result;
              },
            },
          },
          {
            name: 'second',
            hooks: {
              async afterLogin(_ctx, result) {
                order.push('second');
                return result;
              },
            },
          },
        ],
      });

      await seedUser();
      await fortress.auth.login('hook-user@example.com', 'password-123');

      expect(order).toEqual(['first', 'second']);
    });
  });

  describe('plugin validation', () => {
    it('throws on duplicate plugin names', () => {
      expect(() => createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [
          { name: 'duplicate' },
          { name: 'duplicate' },
        ],
      })).toThrow('Duplicate plugin name');
    });
  });
});
