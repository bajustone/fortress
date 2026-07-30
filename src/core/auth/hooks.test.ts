import type { Fortress } from '../fortress';
import { describe, expect, it, vi } from 'vitest';

import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';
import { assertSuccess } from '../types';

let fortress: Fortress;
const SECRET = 'hooks-test-secret-at-least-32chars!!';

async function seedUser(): Promise<{ id: string }> {
  return fortress.auth.createUser({
    email: 'hook-user@example.com',
    name: 'Hook User',
    password: 'password-123456',
  });
}

describe('plugin hooks', () => {
  describe('beforeRegister', () => {
    it('re-normalizes email after a hook mutates registration data', async () => {
      const beforeRegister = vi.fn(async (ctx: { data: { email: string } }) => {
        ctx.data.email = 'E\u0301.HOOK@EXAMPLE.COM';
      });
      fortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [{ name: 'test', hooks: { beforeRegister } }],
      });

      const user = await fortress.auth.createUser({
        email: 'original@example.com',
        name: 'Hook User',
        password: 'password-123456',
      });
      expect(user.email).toBe('é.hook@example.com');
      expect(requireAt(await fortress.auth.getLoginIdentifiers(user.id), 0, 'email login identifier').value).toBe('é.hook@example.com');
    });
  });

  describe('beforeLogout', () => {
    it('is called before logout', async () => {
      const beforeLogout = vi.fn(async () => {});

      fortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [{ name: 'test', hooks: { beforeLogout } }],
      });

      await seedUser();
      const login = await fortress.auth.login('hook-user@example.com', 'password-123456');
      assertSuccess(login);
      await fortress.auth.logout(login.refreshToken as string);

      expect(beforeLogout).toHaveBeenCalledOnce();
      expect(beforeLogout).toHaveBeenCalledWith(expect.objectContaining({
        token: login.refreshToken,
      }));
    });
  });

  describe('afterRegister', () => {
    it('is called after user creation', async () => {
      const afterRegister = vi.fn(async () => {});

      fortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [{ name: 'test', hooks: { afterRegister } }],
      });

      await fortress.auth.createUser({
        email: 'new-user@example.com',
        name: 'New User',
        password: 'password-123456',
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
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [{ name: 'test', hooks: { afterRegister } }],
      });

      await fortress.auth.createUser({
        email: 'check-user@example.com',
        name: 'Check User',
        password: 'password-123456',
      });

      expect(receivedUser).toMatchObject({ email: 'check-user@example.com', name: 'Check User' });
    });
  });

  describe('beforeTokenRefresh', () => {
    it('is called before token refresh', async () => {
      const beforeTokenRefresh = vi.fn(async () => {});

      fortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [{ name: 'test', hooks: { beforeTokenRefresh } }],
      });

      await seedUser();
      const login = await fortress.auth.login('hook-user@example.com', 'password-123456');
      assertSuccess(login);
      await fortress.auth.refresh(login.refreshToken as string);

      expect(beforeTokenRefresh).toHaveBeenCalledOnce();
      expect(beforeTokenRefresh).toHaveBeenCalledWith(expect.objectContaining({
        token: login.refreshToken,
      }));
    });

    it('can block refresh with HookResult', async () => {
      fortress = createFortress({
        jwt: { key: SECRET },
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
      const login = await fortress.auth.login('hook-user@example.com', 'password-123456');
      assertSuccess(login);
      const result = await fortress.auth.refresh(login.refreshToken as string);

      expect((result as any).blocked).toBe(true);
    });
  });

  describe('afterTokenRefresh', () => {
    it('is called after token refresh and can modify result', async () => {
      fortress = createFortress({
        jwt: { key: SECRET },
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
      const login = await fortress.auth.login('hook-user@example.com', 'password-123456');
      assertSuccess(login);
      const result = await fortress.auth.refresh(login.refreshToken as string);

      expect(result.accessToken).toMatch(/^modified-/);
    });
  });

  describe('onLoginFailure isolation', () => {
    it('preserves the auth error and continues after a hook throws', async () => {
      const secondHook = vi.fn(async () => {});
      fortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [
          {
            name: 'broken',
            hooks: {
              async onLoginFailure() {
                throw new Error('hook bug');
              },
            },
          },
          { name: 'observer', hooks: { onLoginFailure: secondHook } },
        ],
      });
      await seedUser();

      await expect(
        fortress.auth.login('hook-user@example.com', 'wrong-password'),
      ).rejects.toThrow('Invalid credentials');
      expect(secondHook).toHaveBeenCalledOnce();
    });
  });

  describe('hook execution order', () => {
    it('runs hooks in plugin registration order', async () => {
      const order: string[] = [];

      fortress = createFortress({
        jwt: { key: SECRET },
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
      await fortress.auth.login('hook-user@example.com', 'password-123456');

      expect(order).toEqual(['first', 'second']);
    });
  });

  describe('plugin validation', () => {
    it('throws on duplicate plugin names', () => {
      expect(() => createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [
          { name: 'duplicate' },
          { name: 'duplicate' },
        ],
      })).toThrow('Duplicate plugin name');
    });
  });
});
function requireAt<T>(values: readonly T[], index: number, description: string): T {
  const value = values[index];
  if (value === undefined)
    throw new Error(`Expected ${description}`);
  return value;
}
