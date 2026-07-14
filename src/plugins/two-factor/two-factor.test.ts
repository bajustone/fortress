import type { Fortress } from '../../core/fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { accountLockout } from '../account-lockout';
import { generateTOTP, twoFactor } from './index';

const SECRET = 'two-factor-test-secret-at-least32';
const TOTP_ENCRYPTION_KEY = 't'.repeat(32);

interface TwoFactorMethods {
  enable: (userId: string) => Promise<{ secret: string; otpauthUrl: string; backupCodes: string[] }>;
  confirmSetup: (userId: string, code: string, meta?: { userAgent?: string; trustedDeviceToken?: string; rememberDevice?: boolean }) => Promise<{ verified: true; trustedDeviceToken?: string }>;
  verify: (continuationToken: string, code: string, meta?: { userAgent?: string; trustedDeviceToken?: string; rememberDevice?: boolean }) => Promise<unknown>;
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
      plugins: [twoFactor({ secretEncryptionKey: TOTP_ENCRYPTION_KEY, totp: { issuer: 'TestApp' }, backupCodes: { count: 5 } })],
    });

    methods = fortress.plugins['two-factor'] as unknown as TwoFactorMethods;

    const user = await fortress.auth.createUser({
      email: 'alice@example.com',
      name: 'Alice',
      password: 'password-123456',
    });
    userId = user.id;
  });

  describe('configuration', () => {
    it('requires an exact 32-byte encryption key', () => {
      expect(() => twoFactor(undefined as any)).toThrow('requires secretEncryptionKey');
      expect(() => twoFactor({ secretEncryptionKey: 'too-short' })).toThrow('exactly 32 bytes');
    });
  });

  describe('enable', () => {
    it('returns secret, otpauth URL, and backup codes', async () => {
      const setup = await methods.enable(userId);

      expect(setup.secret).toBeTruthy();
      expect(setup.otpauthUrl).toContain('otpauth://totp/');
      expect(setup.otpauthUrl).toContain('TestApp');
      expect(setup.backupCodes).toHaveLength(5);
      expect(setup.backupCodes.every(code => /^[0-9a-f]{32}$/.test(code))).toBe(true);
      const stored = await fortress.config.database.findOne<{ secret: string }>({
        model: 'two_factor_secret',
        where: [{ field: 'userId', operator: '=', value: userId }],
      });
      expect(stored?.secret).toMatch(/^v1\./);
      expect(stored?.secret).not.toContain(setup.secret);
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
      const result = await fortress.auth.login('alice@example.com', 'password-123456');
      expect('accessToken' in result).toBe(false);
      expect('refreshToken' in result).toBe(false);
      expect(result.pluginData?.requires2FA).toBe(true);
      expect(await fortress.config.database.count({ model: 'refresh_token' })).toBe(0);
      if (result.status !== 'pending' || !result.pending)
        throw new Error('Expected a two-factor continuation');

      const completed = await methods.verify(result.pending.continuationToken, setup.backupCodes[0]);
      expect(completed).toMatchObject({ status: 'success', method: 'two-factor' });
      expect(await fortress.config.database.count({ model: 'refresh_token' })).toBe(1);
    });

    it('allows normal login when 2FA not enabled', async () => {
      const result = await fortress.auth.login('alice@example.com', 'password-123456');
      if (result.status !== 'success')
        throw new Error('Expected successful login');
      expect(result.accessToken).toBeTruthy();
      expect(result.refreshToken).toBeTruthy();
    });

    it('requires explicit opt-in and uses a server-issued trusted-device secret', async () => {
      const setup = await methods.enable(userId);
      const code = await generateTOTP(setup.secret, 30, 6);

      const enrolled = await methods.confirmSetup(userId, code, { rememberDevice: true });
      expect(enrolled.trustedDeviceToken).toMatch(/^[\w-]{40,}$/);
      expect(await fortress.config.database.count({ model: 'trusted_device' })).toBe(1);
      const stored = await fortress.config.database.findOne<{ deviceHash: string }>({
        model: 'trusted_device',
        where: [{ field: 'userId', operator: '=', value: userId }],
      });
      expect(stored?.deviceHash).not.toBe(enrolled.trustedDeviceToken);

      const result = await fortress.auth.login('alice@example.com', 'password-123456', {
        trustedDeviceToken: enrolled.trustedDeviceToken,
      });
      expect(result.status).toBe('success');
    });

    it('does not trust User-Agent without opt-in', async () => {
      const setup = await methods.enable(userId);
      const code = await generateTOTP(setup.secret, 30, 6);
      await methods.confirmSetup(userId, code, { userAgent: 'TestBrowser/1.0' });
      const result = await fortress.auth.login('alice@example.com', 'password-123456', { userAgent: 'TestBrowser/1.0' });
      expect(result.status).toBe('pending');
    });
  });
});

describe('two-factor + account-lockout integration', () => {
  interface LockoutMethods {
    getLockoutStatus: (identifier: string) => Promise<{ failedAttempts: number; isLocked: boolean }>;
  }

  it('feeds failed 2FA verifications into account lockout and locks the account', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [
        // cooldown 0 so the brute-force is not artificially throttled between attempts
        twoFactor({ secretEncryptionKey: TOTP_ENCRYPTION_KEY, failedAttemptCooldownSeconds: 0 }),
        accountLockout({ maxFailedAttempts: 3 }),
      ],
    });
    const twoFactorMethods = fortress.plugins['two-factor'] as unknown as TwoFactorMethods;
    const lockoutMethods = fortress.plugins['account-lockout'] as unknown as LockoutMethods;

    const user = await fortress.auth.createUser({
      email: 'lockme@example.com',
      name: 'Lock Me',
      password: 'password-123456',
    });
    const setup = await twoFactorMethods.enable(user.id);
    await twoFactorMethods.confirmSetup(user.id, await generateTOTP(setup.secret, 30, 6));

    // Three wrong second-factor attempts, each on a fresh pending login so the
    // per-continuation cap is never the thing that stops the attacker.
    for (let i = 0; i < 3; i++) {
      const pending = await fortress.auth.login('lockme@example.com', 'password-123456');
      if (pending.status !== 'pending')
        throw new Error('expected a pending 2FA challenge');
      await expect(
        fortress.auth.completePendingAuth(pending.pending.continuationToken, '000000'),
      ).rejects.toThrow();
    }

    const status = await lockoutMethods.getLockoutStatus('lockme@example.com');
    expect(status.failedAttempts).toBeGreaterThanOrEqual(3);
    expect(status.isLocked).toBe(true);

    // The locked account is now rejected before it can even reach the 2FA step.
    await expect(
      fortress.auth.login('lockme@example.com', 'password-123456'),
    ).rejects.toThrow(/locked/i);
  });
});
