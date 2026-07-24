import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { magicLink } from './index';

const SECRET = 'magic-link-test-secret-32chars!!';

describe('magic-link plugin', () => {
  let capturedToken: string | null;
  let capturedEmail: string | null;
  const onSend = vi.fn(async (email: string, token: string) => {
    capturedEmail = email;
    capturedToken = token;
  });

  function makeFortress() {
    return createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [magicLink({ onSendMagicLink: onSend })],
    });
  }

  let fortress: ReturnType<typeof makeFortress>;

  beforeEach(() => {
    capturedToken = null;
    capturedEmail = null;
    onSend.mockClear();

    fortress = makeFortress();
  });

  describe('sendMagicLink', () => {
    it('creates a token record and calls onSendMagicLink', async () => {
      const send = fortress.plugins['magic-link'].sendMagicLink;
      const result = await send('alice@example.com');

      expect(result).toEqual({ sent: true });
      expect(onSend).toHaveBeenCalledOnce();
      expect(capturedEmail).toBe('alice@example.com');
      expect(capturedToken).toBeTruthy();
    });
  });

  describe('verify', () => {
    it('returns user info and access token for existing user', async () => {
      // Pre-create the user
      await fortress.auth.createUser({
        email: 'bob@example.com',
        name: 'Bob',
        password: 'password-123456',
      });

      const send = fortress.plugins['magic-link'].sendMagicLink;
      await send('bob@example.com');

      const verify = fortress.plugins['magic-link'].verify;
      const result = await verify(capturedToken!);

      expect(result.user.email).toBe('bob@example.com');
      expect(result.user.id).toBeDefined();
      expect(result.status === 'success' ? result.accessToken : null).toBeTruthy();
    });

    it('verifies through the core HTTP endpoint and attaches auth cookies', async () => {
      const send = fortress.plugins['magic-link'].sendMagicLink;
      await send('bob@example.com');

      const response = await fortress.handleRequest(new Request('http://localhost/auth/magic-link/verify', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ token: capturedToken }),
      }));
      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toMatchObject({
        status: 'success',
        method: 'magic-link',
        user: { email: 'bob@example.com' },
      });
      expect(response.headers.getSetCookie().length).toBeGreaterThan(0);
    });

    it('runs configured post-auth gates before issuing tokens', async () => {
      const database = createTestAdapter();
      const gated = createFortress({
        jwt: { key: SECRET },
        database,
        plugins: [
          magicLink({ onSendMagicLink: onSend }),
          {
            name: 'factor',
            hooks: {
              postAuthGate: {
                reason: 'two-factor',
                evaluate: async () => ({ pluginData: { requires2FA: true } }),
                verify: async () => {},
              },
            },
          },
        ],
      });
      const send = gated.plugins['magic-link'].sendMagicLink;
      const verify = gated.plugins['magic-link'].verify;
      await send('gated@example.com');

      const result = await verify(capturedToken!);
      expect(result.status).toBe('pending');
      expect(result.status === 'pending' ? result.pending?.reason : undefined).toBe('two-factor');
      expect(await database.count({ model: 'refresh_token' })).toBe(0);
    });

    it('auto-creates user for unknown email (JIT provisioning)', async () => {
      const send = fortress.plugins['magic-link'].sendMagicLink;
      await send('newuser@example.com');

      const verify = fortress.plugins['magic-link'].verify;
      const result = await verify(capturedToken!);

      expect(result.user.email).toBe('newuser@example.com');
      expect(result.user.id).toBeDefined();
      expect(result.status === 'success' ? result.accessToken : null).toBeTruthy();

      // Confirm the user was actually created
      const user = await fortress.auth.me(result.user.id);
      expect(user.email).toBe('newuser@example.com');
      expect(user.name).toBe('newuser');
    });

    it('rejects expired tokens', async () => {
      const expiredFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [magicLink({ tokenExpirySeconds: -1, onSendMagicLink: onSend })],
      });

      const send = expiredFortress.plugins['magic-link'].sendMagicLink;
      await send('expired@example.com');

      const verify = expiredFortress.plugins['magic-link'].verify;
      await expect(verify(capturedToken!)).rejects.toThrow('Invalid or expired magic link token');
    });

    it('rejects already-used tokens', async () => {
      const send = fortress.plugins['magic-link'].sendMagicLink;
      await send('carol@example.com');

      const verify = fortress.plugins['magic-link'].verify;
      await verify(capturedToken!);

      await expect(verify(capturedToken!)).rejects.toThrow('Invalid or expired magic link token');
    });

    it('rejects invalid tokens', async () => {
      const verify = fortress.plugins['magic-link'].verify;
      await expect(verify('bogus-token')).rejects.toThrow('Invalid or expired magic link token');
    });
  });
});
