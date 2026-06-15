import { afterEach, describe, expect, it, vi } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';
import { clearHibpCache, isPasswordBreached, validatePassword } from './password-policy';

describe('password-policy', () => {
  afterEach(() => {
    clearHibpCache();
    vi.restoreAllMocks();
  });

  describe('validatePassword', () => {
    it('accepts a valid password with default config', async () => {
      await expect(validatePassword('secureP@ss123')).resolves.toBeUndefined();
    });

    it('rejects passwords shorter than minLength', async () => {
      await expect(validatePassword('short', { minLength: 8 })).rejects.toThrow(
        'Password must be at least 8 characters',
      );
    });

    it('rejects passwords longer than maxLength', async () => {
      const longPassword = 'a'.repeat(200);
      await expect(validatePassword(longPassword, { maxLength: 128 })).rejects.toThrow(
        'Password must be at most 128 characters',
      );
    });

    it('accepts password at exact minLength boundary', async () => {
      await expect(validatePassword('12345678', { minLength: 8 })).resolves.toBeUndefined();
    });

    it('accepts password at exact maxLength boundary', async () => {
      const exactMax = 'a'.repeat(128);
      await expect(validatePassword(exactMax, { maxLength: 128 })).resolves.toBeUndefined();
    });

    it('uses default min 8 and max 128 when not configured', async () => {
      await expect(validatePassword('1234567')).rejects.toThrow('at least 8');
      await expect(validatePassword('a'.repeat(129))).rejects.toThrow('at most 128');
    });

    it('respects custom minLength and maxLength', async () => {
      await expect(validatePassword('abc', { minLength: 3, maxLength: 10 })).resolves.toBeUndefined();
      await expect(validatePassword('ab', { minLength: 3 })).rejects.toThrow('at least 3');
    });

    it('applies NFKC before length checks', async () => {
      await expect(validatePassword('ﬃ', { minLength: 3, maxLength: 3 })).resolves.toBeUndefined();
    });
  });

  describe('isPasswordBreached (HIBP)', () => {
    it('detects a breached password', async () => {
      // "password" is SHA-1: 5BAA61E4C9B93F3F0682250B6CF8331B7EE68FD8
      // prefix: 5BAA6, suffix: 1E4C9B93F3F0682250B6CF8331B7EE68FD8
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response('1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493\r\nABCDEF1234567890ABCDEF1234567890ABC:5', {
          status: 200,
        }),
      );

      const result = await isPasswordBreached('password');
      expect(result).toBe(true);
    });

    it('returns false for a clean password', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response('0000000000000000000000000000000000000:1\r\nFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF:2', {
          status: 200,
        }),
      );

      const result = await isPasswordBreached('my-unique-fortress-password-xyz');
      expect(result).toBe(false);
    });

    it('fails open on network error', async () => {
      vi.spyOn(globalThis, 'fetch').mockRejectedValueOnce(new Error('Network error'));

      const result = await isPasswordBreached('password');
      expect(result).toBe(false);
    });

    it('fails open on non-200 API response', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response('Service Unavailable', { status: 503 }),
      );

      const result = await isPasswordBreached('password');
      expect(result).toBe(false);
    });

    it('uses cached HIBP response within TTL', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch').mockResolvedValue(
        new Response('1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493', { status: 200 }),
      );

      await isPasswordBreached('password');
      await isPasswordBreached('password');

      expect(fetchSpy).toHaveBeenCalledTimes(1);
    });
  });

  describe('validatePassword with breach checking', () => {
    it('rejects breached password when checkBreached is enabled', async () => {
      vi.spyOn(globalThis, 'fetch').mockResolvedValueOnce(
        new Response('1E4C9B93F3F0682250B6CF8331B7EE68FD8:3861493', { status: 200 }),
      );

      await expect(
        validatePassword('password', { checkBreached: true }),
      ).rejects.toThrow('data breach');
    });

    it('does not check breaches when checkBreached is false', async () => {
      const fetchSpy = vi.spyOn(globalThis, 'fetch');

      await expect(
        validatePassword('password', { checkBreached: false }),
      ).resolves.toBeUndefined();

      expect(fetchSpy).not.toHaveBeenCalled();
    });
  });

  describe('integration with createUser', () => {
    it('rejects short passwords during user creation', async () => {
      const fortress = createFortress({
        jwt: { key: 'test-secret-at-least-32-characters!!' },
        database: createTestAdapter(),
        passwordPolicy: { minLength: 10 },
      });

      await expect(
        fortress.auth.createUser({ email: 'a@b.com', name: 'Test', password: 'short' }),
      ).rejects.toThrow('at least 10');
    });

    it('allows valid passwords during user creation', async () => {
      const fortress = createFortress({
        jwt: { key: 'test-secret-at-least-32-characters!!' },
        database: createTestAdapter(),
        passwordPolicy: { minLength: 6 },
      });

      const user = await fortress.auth.createUser({
        email: 'a@b.com',
        name: 'Test',
        password: 'validpass',
      });

      expect(user.email).toBe('a@b.com');
    });

    it('allows passwordless user creation (no validation)', async () => {
      const fortress = createFortress({
        jwt: { key: 'test-secret-at-least-32-characters!!' },
        database: createTestAdapter(),
        passwordPolicy: { minLength: 10 },
      });

      const user = await fortress.auth.createUser({ email: 'a@b.com', name: 'Test' });
      expect(user.email).toBe('a@b.com');
    });

    it('normalizes passwords consistently across create, update, and login', async () => {
      const passwordHasher = {
        hash: async (password: string) => `hash:${password}`,
        verify: async (hash: string, password: string) => hash === `hash:${password}`,
      };
      const fortress = createFortress({
        jwt: { key: 'test-secret-at-least-32-characters!!' },
        database: createTestAdapter(),
        passwordHasher,
      });

      const user = await fortress.auth.createUser({
        email: 'nfkc@test.com',
        name: 'NFKC',
        password: 'Ｐａｓｓｗｏｒｄ１２３！',
      });
      await expect(fortress.auth.login('nfkc@test.com', 'Password123!')).resolves.toMatchObject({
        status: 'success',
      });

      await fortress.auth.updateUser(user.id, { password: 'ＮｅｗＰａｓｓｗｏｒｄ１２３！' });
      await expect(fortress.auth.login('nfkc@test.com', 'NewPassword123!')).resolves.toMatchObject({
        status: 'success',
      });
    });
  });
});
