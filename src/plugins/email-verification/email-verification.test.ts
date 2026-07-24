import { beforeEach, describe, expect, it, vi } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { emailVerification } from './index';

const SECRET = 'email-verify-test-secret-32chars!';

describe('email-verification plugin', () => {
  let capturedToken: string | null;
  let capturedEmail: string | null;
  const onSend = vi.fn(async (email: string, token: string, _userId: string) => {
    capturedEmail = email;
    capturedToken = token;
  });

  function makeFortress() {
    return createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [emailVerification({ onSendVerification: onSend })],
    });
  }

  let fortress: ReturnType<typeof makeFortress>;

  beforeEach(() => {
    capturedToken = null;
    capturedEmail = null;
    onSend.mockClear();

    fortress = makeFortress();
  });

  describe('afterRegister hook', () => {
    it('calls onSendVerification when user is created', async () => {
      await fortress.auth.createUser({
        email: 'alice@example.com',
        name: 'Alice',
        password: 'password-123456',
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
        password: 'password-123456',
      });

      const result = await fortress.plugins['email-verification'].verify(capturedToken!);

      expect(result.email).toBe('alice@example.com');
      expect(result.userId).toBeDefined();
    });

    it('rejects already-used token', async () => {
      await fortress.auth.createUser({
        email: 'bob@example.com',
        name: 'Bob',
        password: 'password-123456',
      });

      const verify = fortress.plugins['email-verification'].verify;
      await verify(capturedToken!);

      await expect(verify(capturedToken!)).rejects.toThrow('Invalid or expired verification token');
    });

    it('rejects invalid token', async () => {
      const verify = fortress.plugins['email-verification'].verify;
      await expect(verify('bogus-token')).rejects.toThrow('Invalid or expired verification token');
    });

    it('rejects expired token', async () => {
      // Create with negative expiry to guarantee token is already expired
      const shortFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [emailVerification({ tokenExpirySeconds: -1, onSendVerification: onSend })],
      });

      await shortFortress.auth.createUser({
        email: 'carol@example.com',
        name: 'Carol',
        password: 'password-123456',
      });

      const verify = shortFortress.plugins['email-verification'].verify;
      await expect(verify(capturedToken!)).rejects.toThrow('Invalid or expired verification token');
    });
  });

  describe('post-auth gate', () => {
    it('holds unverified login and completes after token verification', async () => {
      await fortress.auth.createUser({
        email: 'dave@example.com',
        name: 'Dave',
        password: 'password-123456',
      });

      const result = await fortress.auth.login('dave@example.com', 'password-123456');
      expect(result.status).toBe('pending');
      expect(result.pluginData?.requiresEmailVerification).toBe(true);
      expect(await fortress.config.database.count({ model: 'refresh_token' })).toBe(0);
      if (result.status !== 'pending' || !result.pending)
        throw new Error('Expected email-verification continuation');

      const complete = fortress.plugins['email-verification'].completeVerification;
      await expect(complete(result.pending.continuationToken, capturedToken!)).resolves.toMatchObject({
        status: 'success',
      });
    });

    it('allows verified user login', async () => {
      await fortress.auth.createUser({
        email: 'eve@example.com',
        name: 'Eve',
        password: 'password-123456',
      });

      // Verify email first
      const verify = fortress.plugins['email-verification'].verify;
      await verify(capturedToken!);

      // Login should succeed
      const result = await fortress.auth.login('eve@example.com', 'password-123456');
      if (result.status !== 'success')
        throw new Error('Expected successful login');
      expect(result.accessToken).toBeTruthy();
      expect(result.user.email).toBe('eve@example.com');
    });
  });

  describe('sendVerification method', () => {
    it('generates a new token for existing user', async () => {
      const user = await fortress.auth.createUser({
        email: 'frank@example.com',
        name: 'Frank',
        password: 'password-123456',
      });

      onSend.mockClear();
      const sendVerification = fortress.plugins['email-verification'].sendVerification;
      const result = await sendVerification(user.id);

      expect(result).toEqual({ sent: true });
      expect(onSend).toHaveBeenCalledOnce();
    });

    it('adopts a changed email only after its token is verified', async () => {
      const user = await fortress.auth.createUser({
        email: 'old@example.com',
        name: 'Changed',
        password: 'password-123456',
      });
      onSend.mockClear();
      const methods = fortress.plugins['email-verification'];
      await methods.sendVerification(user.id, 'new@example.com');
      const token = onSend.mock.calls[0]![1];

      const findUser = () => fortress.config.database.findOne<{ email: string; emailVerified: boolean }>({
        model: 'user',
        where: [{ field: 'id', operator: '=', value: user.id }],
      });
      expect((await findUser())?.email).toBe('old@example.com');
      await methods.verify(token);
      expect(await findUser()).toMatchObject({
        email: 'new@example.com',
        emailVerified: true,
      });
    });
  });

  describe('requireVerification: false', () => {
    it('allows login without verification', async () => {
      const noRequireFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [emailVerification({ requireVerification: false })],
      });

      await noRequireFortress.auth.createUser({
        email: 'grace@example.com',
        name: 'Grace',
        password: 'password-123456',
      });

      const result = await noRequireFortress.auth.login('grace@example.com', 'password-123456');
      if (result.status !== 'success')
        throw new Error('Expected successful login');
      expect(result.accessToken).toBeTruthy();
    });
  });
});
