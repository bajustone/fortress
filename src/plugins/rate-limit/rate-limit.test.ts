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
        plugins: [rateLimit({
          login: { maxPerIp: 10, maxPerAccount: 5, windowSeconds: 60 },
          store: customStore,
        })],
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

  describe('refresh rate limiting', () => {
    it('blocks excessive refresh attempts from the same IP', async () => {
      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [
          rateLimit({
            refresh: { maxPerIp: 2, windowSeconds: 60 },
          }),
        ],
      });

      await fortress.auth.createUser({
        email: 'r@example.com',
        name: 'R',
        password: 'valid-password-123',
      });
      const meta = { ipAddress: '9.9.9.9' };
      const { refreshToken } = await fortress.auth.login('r@example.com', 'valid-password-123', meta);
      if (!refreshToken)
        throw new Error('expected refreshToken');

      // Two refreshes within limit
      let current = refreshToken;
      for (let i = 0; i < 2; i++) {
        const next = await fortress.auth.refresh(current, meta);
        current = next.refreshToken;
      }

      // Third is blocked
      try {
        await fortress.auth.refresh(current, meta);
        expect.fail('Should have thrown');
      }
      catch (e: any) {
        expect(e.code).toBe('RATE_LIMITED');
        expect(e.retryAfter).toBeGreaterThan(0);
      }
    });
  });

  describe('programmatic check() surface', () => {
    it('rejects when rule exceeded and prefixes keys by rule name', async () => {
      const calls: string[] = [];
      const customStore = {
        async increment(key: string, _windowMs: number) {
          calls.push(key);
          return { count: calls.filter(c => c === key).length, resetAt: Date.now() + 60_000 };
        },
        async get() {
          return null;
        },
      };

      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [
          rateLimit({
            rules: {
              api: { maxPerIp: 2, windowSeconds: 60 },
            },
            store: customStore,
          }),
        ],
      });

      const methods = fortress.plugins['rate-limit'] as unknown as {
        check: (r: string, k: { ip?: string; userId?: number }) => Promise<void>;
        listRules: () => string[];
      };

      expect(methods.listRules()).toContain('api');

      await methods.check('api', { ip: '1.2.3.4' });
      await methods.check('api', { ip: '1.2.3.4' });

      await expect(methods.check('api', { ip: '1.2.3.4' })).rejects.toMatchObject({
        code: 'RATE_LIMITED',
      });

      expect(calls.every(k => k.startsWith('api:ip:'))).toBe(true);
    });

    it('keys independently by user vs ip', async () => {
      const calls: string[] = [];
      const customStore = {
        async increment(key: string, _windowMs: number) {
          calls.push(key);
          return { count: calls.filter(c => c === key).length, resetAt: Date.now() + 60_000 };
        },
        async get() {
          return null;
        },
      };

      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [
          rateLimit({
            rules: {
              mixed: { maxPerIp: 10, maxPerUser: 10, windowSeconds: 60 },
            },
            store: customStore,
          }),
        ],
      });

      const methods = fortress.plugins['rate-limit'] as unknown as {
        check: (r: string, k: { ip?: string; userId?: number }) => Promise<void>;
      };

      await methods.check('mixed', { ip: '1.2.3.4', userId: 42 });
      expect(calls).toContain('mixed:ip:1.2.3.4');
      expect(calls).toContain('mixed:user:42');
    });

    it('throws when referencing an unknown rule', async () => {
      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [rateLimit({ rules: { api: { maxPerIp: 5, windowSeconds: 60 } } })],
      });
      const methods = fortress.plugins['rate-limit'] as unknown as {
        check: (r: string, k: { ip?: string }) => Promise<void>;
      };
      await expect(methods.check('missing', { ip: '1.1.1.1' })).rejects.toThrow(/unknown rule/);
    });
  });

  describe('middleware registration', () => {
    it('registers middleware for oauthToken and apiKeyIssue when configured', () => {
      const plugin = rateLimit({
        oauthToken: { maxPerIp: 100, windowSeconds: 60 },
        apiKeyIssue: { maxPerIp: 10, windowSeconds: 3600 },
      });
      const paths = (plugin.middleware ?? []).map(m => ({ path: m.path, pos: m.position }));
      expect(paths).toContainEqual({ path: '/oauth/token', pos: 'before-auth' });
      expect(paths).toContainEqual({ path: '/api-key/keys', pos: 'after-auth' });
    });

    it('registers middleware for user-defined paths', () => {
      const plugin = rateLimit({
        rules: { strict: { maxPerIp: 5, windowSeconds: 60 } },
        paths: [
          { match: '/webhooks/*', methods: ['POST'], rule: 'strict' },
          { match: '/public/*', position: 'before-auth', rule: { maxPerIp: 100, windowSeconds: 60 } },
        ],
      });
      expect(plugin.middleware).toHaveLength(2);
      expect(plugin.middleware?.[0].path).toBe('/webhooks/*');
      expect(plugin.middleware?.[1].path).toBe('/public/*');
    });

    it('emits no middleware when only hook-based configs are present', () => {
      const plugin = rateLimit({
        login: { maxPerIp: 5, windowSeconds: 60 },
        register: { maxPerIp: 5, windowSeconds: 60 },
      });
      expect(plugin.middleware).toBeUndefined();
    });
  });

  describe('end-to-end via fortress.handleRequest', () => {
    it('oauthToken middleware rate-limits POST /oauth/token through handleRequest', async () => {
      // Configure a tight limit and drive requests through handleRequest.
      // We intentionally don't mount the oauth plugin — the before-auth
      // middleware runs ahead of route matching, so rate-limiting fires
      // before the 404. That confirms end-to-end wiring without dragging
      // in the oauth dependency graph.
      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [rateLimit({ oauthToken: { maxPerIp: 2, windowSeconds: 60 } })],
      });

      const makeRequest = (): Request =>
        new Request('http://localhost/oauth/token', {
          method: 'POST',
          headers: {
            'content-type': 'application/x-www-form-urlencoded',
            'x-forwarded-for': '9.9.9.9',
          },
          body: 'grant_type=client_credentials',
        });

      // Two within limit — not blocked by rate-limit (they'll 404 because
      // oauth isn't mounted; either way NOT 429).
      const r1 = await fortress.handleRequest(makeRequest());
      const r2 = await fortress.handleRequest(makeRequest());
      expect(r1.status).not.toBe(429);
      expect(r2.status).not.toBe(429);

      // Third hits the rate limiter.
      const r3 = await fortress.handleRequest(makeRequest());
      expect(r3.status).toBe(429);
      expect(r3.headers.get('Retry-After')).toBeTruthy();
    });

    it('paths binding enforces method filter (GET passes, POST is limited)', async () => {
      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [
          rateLimit({
            rules: { mutations: { maxPerIp: 1, windowSeconds: 60 } },
            paths: [{ match: '/things/*', methods: ['POST'], rule: 'mutations' }],
          }),
        ],
      });

      // GET is never rate-limited (method filter excludes it). Both GETs
      // return 404 from handleRequest because /things is not a fortress route,
      // but neither is a 429.
      const g1 = await fortress.handleRequest(new Request('http://localhost/things/a', {
        headers: { 'x-forwarded-for': '1.1.1.1' },
      }));
      const g2 = await fortress.handleRequest(new Request('http://localhost/things/b', {
        headers: { 'x-forwarded-for': '1.1.1.1' },
      }));
      expect(g1.status).not.toBe(429);
      expect(g2.status).not.toBe(429);

      // First POST passes the rate-limit check, second is blocked with 429.
      const p1 = await fortress.handleRequest(new Request('http://localhost/things/a', {
        method: 'POST',
        headers: { 'x-forwarded-for': '1.1.1.1' },
      }));
      const p2 = await fortress.handleRequest(new Request('http://localhost/things/b', {
        method: 'POST',
        headers: { 'x-forwarded-for': '1.1.1.1' },
      }));
      expect(p1.status).not.toBe(429);
      expect(p2.status).toBe(429);
    });

    it('method filter is case-insensitive', async () => {
      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [
          rateLimit({
            rules: { r: { maxPerIp: 1, windowSeconds: 60 } },
            // Lowercase on purpose — the plugin should uppercase before matching.
            paths: [{ match: '/x/*', methods: ['post'], rule: 'r' }],
          }),
        ],
      });

      const hit = async (): Promise<number> => (await fortress.handleRequest(new Request('http://localhost/x/a', {
        method: 'POST',
        headers: { 'x-forwarded-for': '2.2.2.2' },
      }))).status;

      expect(await hit()).not.toBe(429);
      expect(await hit()).toBe(429);
    });

    it('cross-rule isolation: exceeding one rule does not affect another', async () => {
      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [
          rateLimit({
            rules: {
              a: { maxPerIp: 1, windowSeconds: 60 },
              b: { maxPerIp: 1, windowSeconds: 60 },
            },
          }),
        ],
      });
      const methods = fortress.plugins['rate-limit'] as unknown as {
        check: (r: string, k: { ip: string }) => Promise<void>;
      };

      await methods.check('a', { ip: '3.3.3.3' });
      await expect(methods.check('a', { ip: '3.3.3.3' })).rejects.toMatchObject({ code: 'RATE_LIMITED' });

      // Rule 'b' is still fresh even though 'a' is exhausted.
      await methods.check('b', { ip: '3.3.3.3' });
    });
  });

  describe('gate-block defaults (login/register always-on)', () => {
    it('login is rate-limited with defaults even when the config block is omitted', async () => {
      // Registering the plugin with NO login config must still enforce the
      // default per-IP login limit (10 / 15min). Guards against the 0.0.37
      // silent-upgrade regression where opt-in meant "missing block = no limit."
      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [rateLimit({})],
      });

      await fortress.auth.createUser({
        email: 'default@example.com',
        name: 'Default',
        password: 'valid-password-123',
      });

      const meta = { ipAddress: '8.8.8.8' };
      // Burn through the per-IP default of 10.
      for (let i = 0; i < 10; i++) {
        try {
          await fortress.auth.login('default@example.com', 'wrong', meta);
        }
        catch { /* UNAUTHORIZED — expected */ }
      }

      // 11th attempt hits the rate-limit default.
      try {
        await fortress.auth.login('default@example.com', 'wrong', meta);
        expect.fail('Should have thrown RATE_LIMITED');
      }
      catch (e: any) {
        expect(e.code).toBe('RATE_LIMITED');
      }
    });

    it('login: { disabled: true } fully turns the hook off', async () => {
      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [rateLimit({ login: { disabled: true } })],
      });

      await fortress.auth.createUser({
        email: 'off@example.com',
        name: 'Off',
        password: 'valid-password-123',
      });

      // Past the default per-IP limit of 10 — no RATE_LIMITED should fire.
      // Password hashing dominates the clock here, so keep the loop small.
      const meta = { ipAddress: '4.4.4.4' };
      for (let i = 0; i < 15; i++) {
        try {
          await fortress.auth.login('off@example.com', 'wrong', meta);
        }
        catch (e: any) {
          // The only error we should see is UNAUTHORIZED for wrong password.
          expect(e.code).toBe('UNAUTHORIZED');
        }
      }
    }, 20000);

    it('register is rate-limited with defaults when the config block is omitted', async () => {
      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [rateLimit({})],
      });

      // Default `register.maxPerIp` is 3 per hour. createUser doesn't pass
      // meta so all hits share the 'unknown' IP key — fine for the test.
      await fortress.auth.createUser({ email: 'a@t.com', name: 'A', password: 'password-123' });
      await fortress.auth.createUser({ email: 'b@t.com', name: 'B', password: 'password-123' });
      await fortress.auth.createUser({ email: 'c@t.com', name: 'C', password: 'password-123' });

      try {
        await fortress.auth.createUser({ email: 'd@t.com', name: 'D', password: 'password-123' });
        expect.fail('Should have thrown RATE_LIMITED');
      }
      catch (e: any) {
        expect(e.code).toBe('RATE_LIMITED');
      }
    });

    it('register: { disabled: true } fully turns the hook off', async () => {
      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [rateLimit({ register: { disabled: true } })],
      });

      // Well past the default register limit — should all succeed.
      for (let i = 0; i < 10; i++) {
        await fortress.auth.createUser({
          email: `reg-off-${i}@t.com`,
          name: `U${i}`,
          password: 'password-123',
        });
      }
    });
  });
});
