import type { Fortress } from '../../core/fortress';
import type { AuditLogEntry, AuditLogQueryOptions } from './index';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { auditLog } from './index';

const SECRET = 'audit-log-test-secret-32chars!!x';

describe('audit-log plugin', () => {
  let fortress: Fortress<any>;
  let getAuditLog: (options?: AuditLogQueryOptions) => Promise<AuditLogEntry[]>;

  beforeEach(() => {
    fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
      plugins: [auditLog()],
    });
    getAuditLog = fortress.plugins['audit-log'].getAuditLog as typeof getAuditLog;
  });

  describe('afterLogin hook', () => {
    it('logs LOGIN_SUCCESS after successful login', async () => {
      await fortress.auth.createUser({
        email: 'alice@example.com',
        name: 'Alice',
        password: 'password-123',
      });

      await fortress.auth.login('alice@example.com', 'password-123');

      const entries = await getAuditLog();
      const loginEntry = entries.find(e => e.eventType === 'LOGIN_SUCCESS');

      expect(loginEntry).toBeDefined();
      expect(loginEntry!.actorType).toBe('user');
      expect(loginEntry!.outcome).toBe('success');
    });
  });

  describe('onLoginFailure hook', () => {
    it('logs LOGIN_FAILURE after failed login', async () => {
      await fortress.auth.createUser({
        email: 'bob@example.com',
        name: 'Bob',
        password: 'password-123',
      });

      await expect(
        fortress.auth.login('bob@example.com', 'wrong-password'),
      ).rejects.toThrow();

      const entries = await getAuditLog();
      const failureEntry = entries.find(e => e.eventType === 'LOGIN_FAILURE');

      expect(failureEntry).toBeDefined();
      expect(failureEntry!.actorId).toBeNull();
      expect(failureEntry!.actorType).toBe('anonymous');
      expect(failureEntry!.outcome).toBe('failure');

      const metadata = JSON.parse(failureEntry!.metadata!);
      expect(metadata.identifier).toBe('bob@example.com');
    });
  });

  describe('afterRegister hook', () => {
    it('logs REGISTER after user creation', async () => {
      const user = await fortress.auth.createUser({
        email: 'carol@example.com',
        name: 'Carol',
        password: 'password-123',
      });

      const entries = await getAuditLog();
      const registerEntry = entries.find(e => e.eventType === 'REGISTER');

      expect(registerEntry).toBeDefined();
      expect(registerEntry!.actorId).toBe(user.id);
      expect(registerEntry!.actorType).toBe('user');
      expect(registerEntry!.targetId).toBe(user.id);
      expect(registerEntry!.targetType).toBe('user');
      expect(registerEntry!.outcome).toBe('success');
    });
  });

  describe('beforeLogout hook', () => {
    it('logs LOGOUT after logout', async () => {
      await fortress.auth.createUser({
        email: 'dave@example.com',
        name: 'Dave',
        password: 'password-123',
      });

      const loginResult = await fortress.auth.login('dave@example.com', 'password-123');
      await fortress.auth.logout(loginResult.refreshToken!);

      const entries = await getAuditLog();
      const logoutEntry = entries.find(e => e.eventType === 'LOGOUT');

      expect(logoutEntry).toBeDefined();
      expect(logoutEntry!.eventType).toBe('LOGOUT');
      expect(logoutEntry!.outcome).toBe('success');
    });
  });

  describe('afterTokenRefresh hook', () => {
    it('logs TOKEN_REFRESH after token refresh', async () => {
      await fortress.auth.createUser({
        email: 'eve@example.com',
        name: 'Eve',
        password: 'password-123',
      });

      const loginResult = await fortress.auth.login('eve@example.com', 'password-123');
      await fortress.auth.refresh(loginResult.refreshToken!);

      const entries = await getAuditLog();
      const refreshEntry = entries.find(e => e.eventType === 'TOKEN_REFRESH');

      expect(refreshEntry).toBeDefined();
      expect(refreshEntry!.eventType).toBe('TOKEN_REFRESH');
      expect(refreshEntry!.outcome).toBe('success');
    });
  });

  describe('getAuditLog method', () => {
    it('returns entries filtered by userId', async () => {
      const alice = await fortress.auth.createUser({
        email: 'alice2@example.com',
        name: 'Alice',
        password: 'password-123',
      });

      await fortress.auth.createUser({
        email: 'bob2@example.com',
        name: 'Bob',
        password: 'password-123',
      });

      // Both users get REGISTER entries, filter by Alice's id
      const entries = await getAuditLog({ userId: alice.id });

      expect(entries.length).toBeGreaterThan(0);
      for (const entry of entries) {
        expect(entry.actorId).toBe(alice.id);
      }
    });

    it('returns entries filtered by eventType', async () => {
      await fortress.auth.createUser({
        email: 'frank@example.com',
        name: 'Frank',
        password: 'password-123',
      });

      await fortress.auth.login('frank@example.com', 'password-123');

      const entries = await getAuditLog({ eventType: 'LOGIN_SUCCESS' });

      expect(entries.length).toBeGreaterThan(0);
      for (const entry of entries) {
        expect(entry.eventType).toBe('LOGIN_SUCCESS');
      }
    });
  });

  describe('hash chain', () => {
    it('creates previousHash entries when enabled', async () => {
      const chainFortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [auditLog({ hashChain: true })],
      });

      const chainGetAuditLog = chainFortress.plugins['audit-log'].getAuditLog as typeof getAuditLog;

      await chainFortress.auth.createUser({
        email: 'grace@example.com',
        name: 'Grace',
        password: 'password-123',
      });

      await chainFortress.auth.login('grace@example.com', 'password-123');

      const entries = await chainGetAuditLog();

      // First entry should have no previousHash
      const sortedEntries = [...entries].sort((a, b) => a.id - b.id);
      expect(sortedEntries[0].previousHash).toBeNull();

      // Second entry should have a previousHash linking to the first
      expect(sortedEntries[1].previousHash).toBeTruthy();
      expect(typeof sortedEntries[1].previousHash).toBe('string');
      expect(sortedEntries[1].previousHash!.length).toBe(64); // SHA-256 hex is 64 chars
    });
  });

  describe('event filtering', () => {
    it('only logs configured event types when events array is provided', async () => {
      const filteredFortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [auditLog({ events: ['LOGIN_SUCCESS'] })],
      });

      const filteredGetAuditLog = filteredFortress.plugins['audit-log'].getAuditLog as typeof getAuditLog;

      await filteredFortress.auth.createUser({
        email: 'heidi@example.com',
        name: 'Heidi',
        password: 'password-123',
      });

      await filteredFortress.auth.login('heidi@example.com', 'password-123');

      const entries = await filteredGetAuditLog();

      // Should only have LOGIN_SUCCESS, not REGISTER
      expect(entries.length).toBe(1);
      expect(entries[0].eventType).toBe('LOGIN_SUCCESS');
    });
  });
});
