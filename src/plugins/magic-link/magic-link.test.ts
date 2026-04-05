import type { Fortress } from '../../core/fortress';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { magicLink } from './index';

const SECRET = 'magic-link-test-secret-32chars!!';

describe('magic-link plugin', () => {
  let fortress: Fortress;
  let capturedToken: string | null;
  let capturedEmail: string | null;
  const onSend = vi.fn(async (email: string, token: string) => {
    capturedEmail = email;
    capturedToken = token;
  });

  beforeEach(() => {
    capturedToken = null;
    capturedEmail = null;
    onSend.mockClear();

    fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
      plugins: [magicLink({ onSendMagicLink: onSend })],
    });
  });

  describe('sendMagicLink', () => {
    it('creates a token record and calls onSendMagicLink', async () => {
      const send = fortress.plugins['magic-link'].sendMagicLink as (email: string) => Promise<{ sent: true }>;
      const result = await send('alice@example.com');

      expect(result).toEqual({ sent: true });
      expect(onSend).toHaveBeenCalledOnce();
      expect(capturedEmail).toBe('alice@example.com');
      expect(capturedToken).toBeTruthy();
    });
  });

  describe('verifyMagicLink', () => {
    it('returns user info and access token for existing user', async () => {
      // Pre-create the user
      await fortress.auth.createUser({
        email: 'bob@example.com',
        name: 'Bob',
        password: 'password-123',
      });

      const send = fortress.plugins['magic-link'].sendMagicLink as (email: string) => Promise<{ sent: true }>;
      await send('bob@example.com');

      const verify = fortress.plugins['magic-link'].verifyMagicLink as (token: string) => Promise<{ userId: number; email: string; accessToken: string }>;
      const result = await verify(capturedToken!);

      expect(result.email).toBe('bob@example.com');
      expect(result.userId).toBeDefined();
      expect(result.accessToken).toBeTruthy();
    });

    it('auto-creates user for unknown email (JIT provisioning)', async () => {
      const send = fortress.plugins['magic-link'].sendMagicLink as (email: string) => Promise<{ sent: true }>;
      await send('newuser@example.com');

      const verify = fortress.plugins['magic-link'].verifyMagicLink as (token: string) => Promise<{ userId: number; email: string; accessToken: string }>;
      const result = await verify(capturedToken!);

      expect(result.email).toBe('newuser@example.com');
      expect(result.userId).toBeDefined();
      expect(result.accessToken).toBeTruthy();

      // Confirm the user was actually created
      const user = await fortress.auth.me(result.userId);
      expect(user.email).toBe('newuser@example.com');
      expect(user.name).toBe('newuser');
    });

    it('rejects expired tokens', async () => {
      const expiredFortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [magicLink({ tokenExpirySeconds: -1, onSendMagicLink: onSend })],
      });

      const send = expiredFortress.plugins['magic-link'].sendMagicLink as (email: string) => Promise<{ sent: true }>;
      await send('expired@example.com');

      const verify = expiredFortress.plugins['magic-link'].verifyMagicLink as (token: string) => Promise<unknown>;
      await expect(verify(capturedToken!)).rejects.toThrow('Magic link token expired');
    });

    it('rejects already-used tokens', async () => {
      const send = fortress.plugins['magic-link'].sendMagicLink as (email: string) => Promise<{ sent: true }>;
      await send('carol@example.com');

      const verify = fortress.plugins['magic-link'].verifyMagicLink as (token: string) => Promise<unknown>;
      await verify(capturedToken!);

      await expect(verify(capturedToken!)).rejects.toThrow('Magic link token already used');
    });

    it('rejects invalid tokens', async () => {
      const verify = fortress.plugins['magic-link'].verifyMagicLink as (token: string) => Promise<unknown>;
      await expect(verify('bogus-token')).rejects.toThrow('Invalid magic link token');
    });
  });
});
