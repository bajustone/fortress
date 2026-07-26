import type { Fortress } from '../../core/fortress';
import type { LockoutStatus } from './index';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { assertSuccess } from '../../core/types';
import { createTestAdapter } from '../../testing';
import { accountLockout } from './index';

const SECRET = 'lockout-test-secret-at-least-32!!';

interface LockoutMethods {
  getLockoutStatus: (identifier: string) => Promise<LockoutStatus>;
  resetLockout: (identifier: string) => Promise<void>;
}

describe('account-lockout plugin', () => {
  let fortress: Fortress;
  let methods: LockoutMethods;
  const email = 'alice@example.com';

  beforeEach(async () => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [accountLockout({
        maxFailedAttempts: 3,
        lockoutDurationSeconds: 60,
        escalation: true,
        maxLockoutSeconds: 300,
      })],
    });

    methods = fortress.resolvePlugin(
      'account-lockout',
      (value): value is LockoutMethods => typeof value === 'object'
        && value !== null
        && typeof Reflect.get(value, 'getLockoutStatus') === 'function'
        && typeof Reflect.get(value, 'resetLockout') === 'function',
    );

    await fortress.auth.createUser({
      email,
      name: 'Alice',
      password: 'correct-password',
    });
  });

  /** Simulate a failed login attempt by calling the onLoginFailure hook directly. */
  async function simulateLoginFailure(identifier: string): Promise<void> {
    const plugin = fortress.config.plugins!.find(p => p.name === 'account-lockout')!;
    await plugin.hooks!.onLoginFailure!({
      db: fortress.config.database,
      config: fortress.config,
      identifier,
      error: new Error('Invalid credentials'),
    });
  }

  describe('allows login within failure limit', () => {
    it('does not lock account before maxFailedAttempts', async () => {
      await simulateLoginFailure(email);
      await simulateLoginFailure(email);

      // 2 failures, max is 3 — should not be locked
      const status = await methods.getLockoutStatus(email);
      expect(status.failedAttempts).toBe(2);
      expect(status.isLocked).toBe(false);

      // Login should still succeed
      const result = await fortress.auth.login(email, 'correct-password');
      assertSuccess(result);
      expect(result.accessToken).toBeTruthy();
    });
  });

  describe('locks account after maxFailedAttempts', () => {
    it('sets lockedUntil when threshold is reached', async () => {
      await simulateLoginFailure(email);
      await simulateLoginFailure(email);
      await simulateLoginFailure(email);

      const status = await methods.getLockoutStatus(email);
      expect(status.failedAttempts).toBe(3);
      expect(status.isLocked).toBe(true);
      expect(status.lockedUntil).toBeTruthy();
      expect(status.lockoutCount).toBe(1);
    });
  });

  describe('locked account rejects login attempts', () => {
    it('throws unauthorized for locked account on beforeLogin', async () => {
      await simulateLoginFailure(email);
      await simulateLoginFailure(email);
      await simulateLoginFailure(email);

      await expect(
        fortress.auth.login(email, 'correct-password'),
      ).rejects.toThrow('Account temporarily locked. Try again later.');
    });
  });

  describe('lockout expires after duration', () => {
    it('allows login after lockout duration passes', async () => {
      // Use a very short lockout for this test
      const shortFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [accountLockout({
          maxFailedAttempts: 2,
          lockoutDurationSeconds: -1, // already expired
          escalation: false,
        })],
      });

      await shortFortress.auth.createUser({
        email: 'bob@example.com',
        name: 'Bob',
        password: 'correct-password',
      });

      const shortPlugin = shortFortress.config.plugins!.find(p => p.name === 'account-lockout')!;

      // Trigger lockout
      await shortPlugin.hooks!.onLoginFailure!({
        db: shortFortress.config.database,
        config: shortFortress.config,
        identifier: 'bob@example.com',
        error: new Error('Invalid credentials'),
      });
      await shortPlugin.hooks!.onLoginFailure!({
        db: shortFortress.config.database,
        config: shortFortress.config,
        identifier: 'bob@example.com',
        error: new Error('Invalid credentials'),
      });

      // Lockout is set but with negative duration, so lockedUntil is in the past
      const result = await shortFortress.auth.login('bob@example.com', 'correct-password');
      assertSuccess(result);
      expect(result.accessToken).toBeTruthy();
    });
  });

  describe('window-expiry reset, re-lock guard & identifier normalization (#34/#35/M1)', () => {
    /** A fortress whose lockout window is already in the past (-1s) the moment it's set. */
    function expiredLockoutFortress(): { f: Fortress; plugin: NonNullable<Fortress['config']['plugins']>[number]; m: LockoutMethods } {
      const f = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [accountLockout({ maxFailedAttempts: 2, lockoutDurationSeconds: -1, escalation: false })],
      });
      const plugin = f.config.plugins!.find(p => p.name === 'account-lockout')!;
      const m = f.plugins['account-lockout'] as unknown as LockoutMethods;
      return { f, plugin, m };
    }

    it('resets failedAttempts to zero when a login arrives after the window expired', async () => {
      const { f, plugin, m } = expiredLockoutFortress();
      await f.auth.createUser({ email: 'dave@example.com', name: 'Dave', password: 'correct-password' });
      const fail = () => plugin.hooks!.onLoginFailure!({ db: f.config.database, config: f.config, identifier: 'dave@example.com', error: new Error('Invalid credentials') });

      await fail();
      await fail(); // reaches the threshold, but lockedUntil is already in the past

      let status = await m.getLockoutStatus('dave@example.com');
      expect(status.failedAttempts).toBe(2);
      expect(status.isLocked).toBe(false); // window already expired

      // A login attempt runs beforeLogin, which clears the stale counter.
      await plugin.hooks!.beforeLogin!({ db: f.config.database, config: f.config, email: 'dave@example.com' });

      status = await m.getLockoutStatus('dave@example.com');
      expect(status.failedAttempts).toBe(0);
      expect(status.lockedUntil).toBeNull();
      expect(status.lastFailedAt).toBeNull();
    });

    it('cannot be re-locked by a single failure after the window expired (no self-DoS)', async () => {
      const { f, plugin, m } = expiredLockoutFortress();
      await f.auth.createUser({ email: 'erin@example.com', name: 'Erin', password: 'correct-password' });
      const fail = () => plugin.hooks!.onLoginFailure!({ db: f.config.database, config: f.config, identifier: 'erin@example.com', error: new Error('Invalid credentials') });

      await fail();
      await fail(); // threshold reached, immediately expired
      expect((await m.getLockoutStatus('erin@example.com')).failedAttempts).toBe(2);

      // One more failure after expiry must reset-then-increment to 1, NOT stack to 3 and re-lock.
      await fail();
      const status = await m.getLockoutStatus('erin@example.com');
      expect(status.failedAttempts).toBe(1);
      expect(status.isLocked).toBe(false);
    });

    it('keys lockout state by normalized identifier (case / whitespace / NFC)', async () => {
      // Three surface forms of the same identifier all accumulate against one
      // normalized row (the default fortress: max 3) and reach the threshold.
      await simulateLoginFailure('ALICE@example.com');
      await simulateLoginFailure('  alice@example.com  ');
      await simulateLoginFailure('Alice@Example.com');

      const status = await methods.getLockoutStatus('alice@example.com');
      expect(status.failedAttempts).toBe(3);
      expect(status.isLocked).toBe(true);
    });
  });

  describe('successful login resets failure counter', () => {
    it('clears failedAttempts on successful login via afterLogin hook', async () => {
      await simulateLoginFailure(email);
      await simulateLoginFailure(email);

      let status = await methods.getLockoutStatus(email);
      expect(status.failedAttempts).toBe(2);

      // Successful login
      await fortress.auth.login(email, 'correct-password');

      status = await methods.getLockoutStatus(email);
      expect(status.failedAttempts).toBe(0);
      expect(status.isLocked).toBe(false);
    });
  });

  describe('escalation doubles lockout duration on repeated lockouts', () => {
    it('increases lockoutCount and duration with each lockout', async () => {
      // First lockout: 3 failures
      await simulateLoginFailure(email);
      await simulateLoginFailure(email);
      await simulateLoginFailure(email);

      let status = await methods.getLockoutStatus(email);
      expect(status.lockoutCount).toBe(1);
      expect(status.lockedUntil).toBeTruthy();

      // Admin reset to allow further testing
      await methods.resetLockout(email);

      // Second lockout: 3 failures again
      await simulateLoginFailure(email);
      await simulateLoginFailure(email);
      await simulateLoginFailure(email);

      status = await methods.getLockoutStatus(email);
      // resetLockout clears lockoutCount, so this is a fresh lockout
      expect(status.lockoutCount).toBe(1);

      // Now test escalation without resetting lockoutCount.
      // We need to simulate repeated lockouts without full reset.
      // The onLoginFailure hook increments lockoutCount each time it locks.
      // To test escalation, we manually set things up:
      // After first lockout, lockoutCount = 1. Let lockout expire, then fail again.
      // For this test, we use a fortress with short lockout.
      const escFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [accountLockout({
          maxFailedAttempts: 1,
          lockoutDurationSeconds: 60,
          escalation: true,
          maxLockoutSeconds: 300,
        })],
      });

      await escFortress.auth.createUser({
        email: 'carol@example.com',
        name: 'Carol',
        password: 'correct-password',
      });

      const escPlugin = escFortress.config.plugins!.find(p => p.name === 'account-lockout')!;
      const escMethods = escFortress.plugins['account-lockout'] as unknown as LockoutMethods;

      // First lockout (lockoutCount goes 0 -> 1, duration = 60 * 2^0 = 60s)
      await escPlugin.hooks!.onLoginFailure!({
        db: escFortress.config.database,
        config: escFortress.config,
        identifier: 'carol@example.com',
        error: new Error('Invalid credentials'),
      });

      let escStatus = await escMethods.getLockoutStatus('carol@example.com');
      expect(escStatus.lockoutCount).toBe(1);
      const firstDuration = new Date(escStatus.lockedUntil!).getTime()
        - new Date(escStatus.lastFailedAt!).getTime();

      // Manually reset only failedAttempts and lockedUntil (not lockoutCount)
      // to simulate an expired lockout. We do this through the DB directly.
      await escFortress.config.database.update({
        model: 'account_lockout',
        where: [{ field: 'identifier', operator: '=', value: 'carol@example.com' }],
        data: { failedAttempts: 0, lockedUntil: null },
      });

      // Second lockout (lockoutCount goes 1 -> 2, duration = 60 * 2^1 = 120s)
      await escPlugin.hooks!.onLoginFailure!({
        db: escFortress.config.database,
        config: escFortress.config,
        identifier: 'carol@example.com',
        error: new Error('Invalid credentials'),
      });

      escStatus = await escMethods.getLockoutStatus('carol@example.com');
      expect(escStatus.lockoutCount).toBe(2);
      const secondDuration = new Date(escStatus.lockedUntil!).getTime()
        - new Date(escStatus.lastFailedAt!).getTime();

      // Second lockout should be roughly double the first
      expect(secondDuration).toBeGreaterThan(firstDuration);
      expect(Math.round(secondDuration / firstDuration)).toBe(2);
    });
  });

  describe('getLockoutStatus', () => {
    it('returns clean status for unknown identifier', async () => {
      const status = await methods.getLockoutStatus('unknown@example.com');
      expect(status.failedAttempts).toBe(0);
      expect(status.lockoutCount).toBe(0);
      expect(status.lockedUntil).toBeNull();
      expect(status.lastFailedAt).toBeNull();
      expect(status.isLocked).toBe(false);
    });

    it('returns current status for tracked identifier', async () => {
      await simulateLoginFailure(email);

      const status = await methods.getLockoutStatus(email);
      expect(status.identifier).toBe(email);
      expect(status.failedAttempts).toBe(1);
      expect(status.lastFailedAt).toBeTruthy();
      expect(status.isLocked).toBe(false);
    });
  });

  describe('resetLockout', () => {
    it('clears all lockout data for an identifier', async () => {
      // Lock the account
      await simulateLoginFailure(email);
      await simulateLoginFailure(email);
      await simulateLoginFailure(email);

      let status = await methods.getLockoutStatus(email);
      expect(status.isLocked).toBe(true);
      expect(status.lockoutCount).toBe(1);

      // Admin reset
      await methods.resetLockout(email);

      status = await methods.getLockoutStatus(email);
      expect(status.failedAttempts).toBe(0);
      expect(status.lockoutCount).toBe(0);
      expect(status.lockedUntil).toBeNull();
      expect(status.lastFailedAt).toBeNull();
      expect(status.isLocked).toBe(false);
    });

    it('is a no-op for unknown identifier', async () => {
      // Should not throw
      await methods.resetLockout('nonexistent@example.com');
    });
  });

  describe('lockout for non-existent accounts', () => {
    it('tracks lockouts for identifiers without user accounts', async () => {
      await simulateLoginFailure('phantom@example.com');
      await simulateLoginFailure('phantom@example.com');
      await simulateLoginFailure('phantom@example.com');

      const status = await methods.getLockoutStatus('phantom@example.com');
      expect(status.isLocked).toBe(true);
      expect(status.failedAttempts).toBe(3);
    });
  });
});
