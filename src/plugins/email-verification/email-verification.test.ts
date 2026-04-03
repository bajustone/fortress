import type { Fortress } from '../../core/fortress';
import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { emailVerification } from './index';

const SECRET = 'email-verify-test-secret-32chars!';

describe('email-verification plugin', () => {
  let fortress: Fortress;
  let capturedToken: string | null;
  let capturedEmail: string | null;
  const onSend = vi.fn(async (email: string, token: string, _userId: number) => {
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
      plugins: [emailVerification({ onSendVerification: onSend })],
    });
  });

  describe('afterRegister hook', () => {
    it('calls onSendVerification when user is created', async () => {
      await fortress.auth.createUser({
        email: 'alice@example.com',
        name: 'Alice',
        password: 'password-123',
      });

      expect(onSend).toHaveBeenCalledOnce();
      expect(capturedEmail).toBe('alice@example.com');
      expect(capturedToken).toBeTruthy();
    });
  });

  describe('verify method', () => {
    it('verifies a valid token', async () => {
      await fortress.auth.createUser({
        email: 'alice@example.com',
        name: 'Alice',
        password: 'password-123',
      });

      const result = await (fortress.plugins['email-verification'].verify as (token: string) => Promise<{ userId: number; email: string }>)(capturedToken!);

      expect(result.email).toBe('alice@example.com');
      expect(result.userId).toBeDefined();
    });

    it('rejects already-used token', async () => {
      await fortress.auth.createUser({
        email: 'bob@example.com',
        name: 'Bob',
        password: 'password-123',
      });

      const verify = fortress.plugins['email-verification'].verify as (token: string) => Promise<unknown>;
      await verify(capturedToken!);

      await expect(verify(capturedToken!)).rejects.toThrow('Token already used');
    });

    it('rejects invalid token', async () => {
      const verify = fortress.plugins['email-verification'].verify as (token: string) => Promise<unknown>;
      await expect(verify('bogus-token')).rejects.toThrow('Invalid verification token');
    });

    it('rejects expired token', async () => {
      // Create with negative expiry to guarantee token is already expired
      const shortFortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [emailVerification({ tokenExpirySeconds: -1, onSendVerification: onSend })],
      });

      await shortFortress.auth.createUser({
        email: 'carol@example.com',
        name: 'Carol',
        password: 'password-123',
      });

      const verify = shortFortress.plugins['email-verification'].verify as (token: string) => Promise<unknown>;
      await expect(verify(capturedToken!)).rejects.toThrow('Verification token expired');
    });
  });

  describe('beforeLogin hook', () => {
    it('blocks unverified user login', async () => {
      await fortress.auth.createUser({
        email: 'dave@example.com',
        name: 'Dave',
        password: 'password-123',
      });

      // Login should be blocked (email not verified)
      const result = await fortress.auth.login('dave@example.com', 'password-123');
      // beforeLogin returns a stop response, which becomes the auth response
      expect((result as unknown as { error: string }).error).toBe('EMAIL_NOT_VERIFIED');
    });

    it('allows verified user login', async () => {
      await fortress.auth.createUser({
        email: 'eve@example.com',
        name: 'Eve',
        password: 'password-123',
      });

      // Verify email first
      const verify = fortress.plugins['email-verification'].verify as (token: string) => Promise<unknown>;
      await verify(capturedToken!);

      // Login should succeed
      const result = await fortress.auth.login('eve@example.com', 'password-123');
      expect(result.accessToken).toBeTruthy();
      expect(result.user.email).toBe('eve@example.com');
    });
  });

  describe('sendVerification method', () => {
    it('generates a new token for existing user', async () => {
      const user = await fortress.auth.createUser({
        email: 'frank@example.com',
        name: 'Frank',
        password: 'password-123',
      });

      onSend.mockClear();
      const sendVerification = fortress.plugins['email-verification'].sendVerification as (userId: number) => Promise<{ token: string }>;
      const result = await sendVerification(user.id);

      expect(result.token).toBeTruthy();
      expect(onSend).toHaveBeenCalledOnce();
    });
  });

  describe('requireVerification: false', () => {
    it('allows login without verification', async () => {
      const noRequireFortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [emailVerification({ requireVerification: false })],
      });

      await noRequireFortress.auth.createUser({
        email: 'grace@example.com',
        name: 'Grace',
        password: 'password-123',
      });

      const result = await noRequireFortress.auth.login('grace@example.com', 'password-123');
      expect(result.accessToken).toBeTruthy();
    });
  });
});
