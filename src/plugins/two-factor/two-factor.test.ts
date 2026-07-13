import type { Fortress } from '../../core/fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { generateTOTP, twoFactor } from './index';

const SECRET = 'two-factor-test-secret-at-least32';

interface TwoFactorMethods {
  enable: (userId: string) => Promise<{ secret: string; otpauthUrl: string; backupCodes: string[] }>;
  confirmSetup: (userId: string, code: string, meta?: { userAgent?: string }) => Promise<{ verified: true }>;
  verify: (continuationToken: string, code: string, meta?: { userAgent?: string }) => Promise<unknown>;
  disable: (userId: string) => Promise<void>;
}

describe('two-factor plugin', () => {
  let fortress: Fortress<any>;
  let methods: TwoFactorMethods;
  let userId: string;

  beforeEach(async () => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [twoFactor({ totp: { issuer: 'TestApp' }, backupCodes: { count: 5 } })],
    });

    methods = fortress.plugins['two-factor'] as unknown as TwoFactorMethods;

    const user = await fortress.auth.createUser({
      email: 'alice@example.com',
      name: 'Alice',
      password: 'password-123',
    });
    userId = user.id;
  });

  describe('enable', () => {
    it('returns secret, otpauth URL, and backup codes', async () => {
      const setup = await methods.enable(userId);

      expect(setup.secret).toBeTruthy();
      expect(setup.otpauthUrl).toContain('otpauth://totp/');
      expect(setup.otpauthUrl).toContain('TestApp');
      expect(setup.backupCodes).toHaveLength(5);
    });

    it('rejects if already enabled', async () => {
      const setup = await methods.enable(userId);
      // Verify to enable
      const code = await generateTOTP(setup.secret, 30, 6);
      await methods.confirmSetup(userId, code);

      await expect(methods.enable(userId)).rejects.toThrow('already enabled');
    });
  });

  describe('verify', () => {
    it('verifies a valid TOTP code', async () => {
      const setup = await methods.enable(userId);
      const code = await generateTOTP(setup.secret, 30, 6);

      const result = await methods.confirmSetup(userId, code);
      expect(result.verified).toBe(true);
    });

    it('rejects replay of a captured TOTP code', async () => {
      const setup = await methods.enable(userId);
      const code = await generateTOTP(setup.secret, 30, 6);

      await expect(methods.confirmSetup(userId, code)).resolves.toEqual({ verified: true });
      await expect(methods.confirmSetup(userId, code)).rejects.toThrow('already been used');
    });

    it('rejects invalid TOTP code', async () => {
      await methods.enable(userId);
      await expect(methods.confirmSetup(userId, '000000')).rejects.toThrow('Invalid two-factor code');
    });

    it('accepts a backup code', async () => {
      const setup = await methods.enable(userId);
      const backupCode = setup.backupCodes[0];

      const result = await methods.confirmSetup(userId, backupCode);
      expect(result.verified).toBe(true);
    });

    it('rejects already-used backup code', async () => {
      const setup = await methods.enable(userId);
      const backupCode = setup.backupCodes[0];

      await methods.confirmSetup(userId, backupCode);
      await expect(methods.confirmSetup(userId, backupCode)).rejects.toThrow('Invalid two-factor code');
    });

    it('rejects when 2FA not set up', async () => {
      await expect(methods.confirmSetup(userId, '123456')).rejects.toThrow('not set up');
    });
  });

  describe('disable', () => {
    it('removes all 2FA data', async () => {
      const setup = await methods.enable(userId);
      const code = await generateTOTP(setup.secret, 30, 6);
      await methods.confirmSetup(userId, code);

      await methods.disable(userId);

      // Can enable again
      const newSetup = await methods.enable(userId);
      expect(newSetup.secret).toBeTruthy();
    });
  });

  describe('post-auth gate', () => {
    it('holds token issuance and completes with a full auth result', async () => {
      const setup = await methods.enable(userId);
      // Enable by verifying first
      const code = await generateTOTP(setup.secret, 30, 6);
      await methods.confirmSetup(userId, code);

      // Login should be intercepted
      const result = await fortress.auth.login('alice@example.com', 'password-123');
      expect(result.accessToken).toBeNull();
      expect(result.refreshToken).toBeNull();
      expect(result.pluginData?.requires2FA).toBe(true);
      expect(await fortress.config.database.count({ model: 'refresh_token' })).toBe(0);
      if (result.status !== 'pending' || !result.pending)
        throw new Error('Expected a two-factor continuation');

      const completed = await methods.verify(result.pending.continuationToken, setup.backupCodes[0]);
      expect(completed).toMatchObject({ status: 'success', method: 'two-factor' });
      expect(await fortress.config.database.count({ model: 'refresh_token' })).toBe(1);
    });

    it('allows normal login when 2FA not enabled', async () => {
      const result = await fortress.auth.login('alice@example.com', 'password-123');
      expect(result.accessToken).toBeTruthy();
      expect(result.refreshToken).toBeTruthy();
    });

    it('skips 2FA for trusted device', async () => {
      const setup = await methods.enable(userId);
      const code = await generateTOTP(setup.secret, 30, 6);
      const userAgent = 'TestBrowser/1.0';

      // First verify with device info to trust it
      await methods.confirmSetup(userId, code, { userAgent });

      // Login with same userAgent should bypass 2FA
      const result = await fortress.auth.login('alice@example.com', 'password-123', { userAgent });
      expect(result.accessToken).toBeTruthy();
    });
  });
});
