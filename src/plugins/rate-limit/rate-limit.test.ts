import type { Fortress } from '../../core/fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { rateLimit } from './index';
import { createMemoryStore } from './memory-store';

const SECRET = 'rate-limit-test-secret-32-chars!!!';

describe('rate-limit plugin', () => {
  describe('login rate limiting', () => {
    let fortress: Fortress;

    beforeEach(async () => {
      fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [
          rateLimit({
            login: { maxPerIp: 3, maxPerAccount: 2, windowSeconds: 60 },
          }),
        ],
      });

      await fortress.auth.createUser({
        email: 'test@example.com',
        name: 'Test',
        password: 'valid-password-123',
      });
    });

    it('allows requests within limits', async () => {
      // 2 attempts within both limits (per-IP: 3, per-account: 2)
      for (let i = 0; i < 2; i++) {
        try {
          await fortress.auth.login('test@example.com', 'wrong-password', { ipAddress: '1.2.3.4' });
        }
        catch (e: any) {
          // Unauthorized is expected for wrong password, RATE_LIMITED is not expected yet
          expect(e.code).toBe('UNAUTHORIZED');
        }
      }
    });

    it('blocks requests exceeding per-IP limit', async () => {
      const meta = { ipAddress: '1.2.3.4' };

      // Exhaust per-IP limit (3 attempts)
      for (let i = 0; i < 3; i++) {
        try {
          await fortress.auth.login('test@example.com', 'wrong', meta);
        }
        catch { /* ignore auth errors */ }
      }

      // 4th attempt should be rate limited
      try {
        await fortress.auth.login('test@example.com', 'wrong', meta);
        expect.fail('Should have thrown');
      }
      catch (e: any) {
        expect(e.code).toBe('RATE_LIMITED');
        expect(e.statusCode).toBe(429);
        expect(e.retryAfter).toBeGreaterThan(0);
      }
    });

    it('blocks requests exceeding per-account limit', async () => {
      // Use different IPs but same account
      for (let i = 0; i < 2; i++) {
        try {
          await fortress.auth.login('test@example.com', 'wrong', { ipAddress: `10.0.0.${i}` });
        }
        catch { /* ignore auth errors */ }
      }

      // 3rd attempt on same account (different IP) should be rate limited
      try {
        await fortress.auth.login('test@example.com', 'wrong', { ipAddress: '10.0.0.99' });
        expect.fail('Should have thrown');
      }
      catch (e: any) {
        expect(e.code).toBe('RATE_LIMITED');
      }
    });

    it('allows different accounts under per-IP limit', async () => {
      await fortress.auth.createUser({
        email: 'other@example.com',
        name: 'Other',
        password: 'valid-password-123',
      });

      const meta = { ipAddress: '5.5.5.5' };

      // 1 attempt on each account = 2 IP hits, both under per-account limit
      try {
        await fortress.auth.login('test@example.com', 'wrong', meta);
      }
      catch { /* expected */ }

      try {
        await fortress.auth.login('other@example.com', 'wrong', meta);
      }
      catch (e: any) {
        // Should be UNAUTHORIZED (wrong password), not RATE_LIMITED
        expect(e.code).toBe('UNAUTHORIZED');
      }
    });

    it('successful login still counts against rate limit', async () => {
      const meta = { ipAddress: '7.7.7.7' };

      // 2 successful logins (at the per-account limit)
      for (let i = 0; i < 2; i++) {
        await fortress.auth.login('test@example.com', 'valid-password-123', meta);
      }

      // 3rd attempt should be rate limited even though credentials are valid
      try {
        await fortress.auth.login('test@example.com', 'valid-password-123', meta);
        expect.fail('Should have thrown');
      }
      catch (e: any) {
        expect(e.code).toBe('RATE_LIMITED');
      }
    });
  });

  describe('registration rate limiting', () => {
    let fortress: Fortress;

    beforeEach(() => {
      fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [
          rateLimit({
            register: { maxPerIp: 2, windowSeconds: 60 },
          }),
        ],
      });
    });

    it('allows registrations within limit', async () => {
      await fortress.auth.createUser({
        email: 'user1@example.com',
        name: 'User 1',
        password: 'password-123',
      });

      await fortress.auth.createUser({
        email: 'user2@example.com',
        name: 'User 2',
        password: 'password-123',
      });
    });

    it('blocks registrations exceeding per-IP limit', async () => {
      // Note: createUser doesn't pass meta by default, so IP is 'unknown'
      // We can't easily pass meta to createUser, so all registrations share the same 'unknown' IP key
      await fortress.auth.createUser({
        email: 'u1@test.com',
        name: 'U1',
        password: 'password-123',
      });

      await fortress.auth.createUser({
        email: 'u2@test.com',
        name: 'U2',
        password: 'password-123',
      });

      // 3rd registration should be rate limited
      try {
        await fortress.auth.createUser({
          email: 'u3@test.com',
          name: 'U3',
          password: 'password-123',
        });
        expect.fail('Should have thrown');
      }
      catch (e: any) {
        expect(e.code).toBe('RATE_LIMITED');
        expect(e.retryAfter).toBeGreaterThan(0);
      }
    });
  });

  describe('iPv6 normalization', () => {
    let fortress: Fortress;

    beforeEach(async () => {
      fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [
          rateLimit({
            login: { maxPerIp: 2, windowSeconds: 60 },
          }),
        ],
      });

      await fortress.auth.createUser({
        email: 'test@example.com',
        name: 'Test',
        password: 'valid-password-123',
      });
    });

    it('normalizes IPv6 addresses to /64 prefix', async () => {
      // These two IPv6 addresses share the same /64 prefix
      const ip1 = '2001:0db8:85a3:0000:0000:8a2e:0370:7334';
      const ip2 = '2001:0db8:85a3:0000:1111:2222:3333:4444';

      try {
        await fortress.auth.login('test@example.com', 'wrong', { ipAddress: ip1 });
      }
      catch { /* expected */ }

      try {
        await fortress.auth.login('test@example.com', 'wrong', { ipAddress: ip2 });
      }
      catch { /* expected */ }

      // 3rd attempt from same /64 should be rate limited
      try {
        await fortress.auth.login('test@example.com', 'wrong', { ipAddress: ip1 });
        expect.fail('Should have thrown');
      }
      catch (e: any) {
        expect(e.code).toBe('RATE_LIMITED');
      }
    });
  });

  describe('memory store', () => {
    it('tracks request counts per key', async () => {
      const store = createMemoryStore();

      const r1 = await store.increment('key1', 60_000);
      expect(r1.count).toBe(1);

      const r2 = await store.increment('key1', 60_000);
      expect(r2.count).toBe(2);

      // Different key should be independent
      const r3 = await store.increment('key2', 60_000);
      expect(r3.count).toBe(1);
    });

    it('returns null for unknown keys', async () => {
      const store = createMemoryStore();
      const result = await store.get('nonexistent');
      expect(result).toBeNull();
    });

    it('returns resetAt time', async () => {
      const store = createMemoryStore();
      const before = Date.now();
      const result = await store.increment('key', 60_000);
      expect(result.resetAt).toBeGreaterThanOrEqual(before + 60_000);
    });
  });

  describe('custom store', () => {
    it('uses provided custom store', async () => {
      const calls: string[] = [];
      const customStore = {
        async increment(key: string, _windowMs: number) {
          calls.push(key);
          return { count: 1, resetAt: Date.now() + 60_000 };
        },
        async get() {
          return null;
        },
      };

      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [rateLimit({ store: customStore })],
      });

      await fortress.auth.createUser({
        email: 'test@example.com',
        name: 'Test',
        password: 'valid-password-123',
      });

      await fortress.auth.login('test@example.com', 'valid-password-123');

      // Should have called increment for IP and account keys
      expect(calls.some(k => k.startsWith('login:ip:'))).toBe(true);
      expect(calls.some(k => k.startsWith('login:account:'))).toBe(true);
    });
  });
});
