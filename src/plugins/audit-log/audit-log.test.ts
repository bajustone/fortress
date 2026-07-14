import type { Fortress } from '../../core/fortress';
import type { AuditLogEntry, AuditLogMethods, AuditLogQueryOptions, ChainVerificationResult } from './index';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { assertSuccess } from '../../core/types';
import { createTestAdapter } from '../../testing';
import { auditLog } from './index';

const SECRET = 'audit-log-test-secret-32chars!!x';
const SHA256_HEX_RE = /^[a-f0-9]{64}$/;

describe('audit-log plugin', () => {
  let fortress: Fortress<any>;
  let getAuditLog: (options?: AuditLogQueryOptions) => Promise<AuditLogEntry[]>;

  beforeEach(() => {
    fortress = createFortress({
      jwt: { key: SECRET },
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
        password: 'password-123456',
      });

      await fortress.auth.login('alice@example.com', 'password-123456');

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
        password: 'password-123456',
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
        password: 'password-123456',
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
        password: 'password-123456',
      });

      const loginResult = await fortress.auth.login('dave@example.com', 'password-123456');
      assertSuccess(loginResult);
      await fortress.auth.logout(loginResult.refreshToken as string);

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
        password: 'password-123456',
      });

      const loginResult = await fortress.auth.login('eve@example.com', 'password-123456');
      assertSuccess(loginResult);
      await fortress.auth.refresh(loginResult.refreshToken as string);

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
        password: 'password-123456',
      });

      await fortress.auth.createUser({
        email: 'bob2@example.com',
        name: 'Bob',
        password: 'password-123456',
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
        password: 'password-123456',
      });

      await fortress.auth.login('frank@example.com', 'password-123456');

      const entries = await getAuditLog({ eventType: 'LOGIN_SUCCESS' });

      expect(entries.length).toBeGreaterThan(0);
      for (const entry of entries) {
        expect(entry.eventType).toBe('LOGIN_SUCCESS');
      }
    });
  });

  describe('hash chain', () => {
    it('declares string identifiers consistently with the public entry type', () => {
      const model = auditLog().models?.find(candidate => candidate.name === 'audit_log');
      expect(model?.fields.id.type).toBe('string');
      expect(model?.fields.actorId.type).toBe('string');
      expect(model?.fields.targetId.type).toBe('string');
    });

    it('creates previousHash entries when enabled', async () => {
      const chainFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [auditLog({ hashChain: true })],
      });

      const chainGetAuditLog = chainFortress.plugins['audit-log'].getAuditLog as typeof getAuditLog;

      await chainFortress.auth.createUser({
        email: 'grace@example.com',
        name: 'Grace',
        password: 'password-123456',
      });

      await chainFortress.auth.login('grace@example.com', 'password-123456');

      const entries = await chainGetAuditLog();

      // First entry should have no previousHash
      const sortedEntries = [...entries].sort((a, b) => a.id.localeCompare(b.id));
      expect(sortedEntries[0].previousHash).toBeNull();

      // Second entry should have a previousHash linking to the first
      expect(sortedEntries[1].previousHash).toBeTruthy();
      expect(typeof sortedEntries[1].previousHash).toBe('string');
      expect(sortedEntries[1].previousHash!.length).toBe(64); // SHA-256 hex is 64 chars
    });

    it('serializes concurrent writes into one unbranched chain', async () => {
      const chainFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [auditLog({ hashChain: true })],
      });
      const methods = chainFortress.plugins['audit-log'] as AuditLogMethods;

      await Promise.all(Array.from({ length: 20 }, (_, index) => methods.logCustomEvent({
        eventType: 'ROLE_CREATED',
        targetId: String(index),
        metadata: { index },
      })));

      const entries = await methods.getAuditLog();
      expect(entries).toHaveLength(20);
      expect(entries.filter(entry => entry.previousHash == null)).toHaveLength(1);
      expect(new Set(entries.flatMap(entry => entry.previousHash ?? [])).size).toBe(19);
      const anchor = await chainFortress.config.database.findOne<{ entryCount: number; lastHash: string }>({
        model: 'audit_chain_state',
        where: [{ field: 'id', operator: '=', value: '1' }],
      });
      expect(anchor).toMatchObject({ entryCount: 20 });
      expect(anchor?.lastHash).toMatch(SHA256_HEX_RE);
      await expect(methods.verifyChain()).resolves.toMatchObject({ valid: true, totalEntries: 20 });
    });

    it('verifies from the same locked snapshot while appends are in flight', async () => {
      const chainFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [auditLog({ hashChain: true })],
      });
      const methods = chainFortress.plugins['audit-log'] as AuditLogMethods;
      const operations: Array<Promise<ChainVerificationResult | void>> = [];
      for (let index = 0; index < 12; index++) {
        operations.push(methods.logCustomEvent({ eventType: 'ROLE_CREATED', targetId: String(index) }));
        operations.push(methods.verifyChain());
      }

      const results = await Promise.all(operations);
      const verifications = results.filter((result): result is ChainVerificationResult => result != null);
      expect(verifications).toHaveLength(12);
      expect(verifications.every(result => result.valid)).toBe(true);
      await expect(methods.verifyChain()).resolves.toMatchObject({ valid: true, totalEntries: 12 });
    });

    it('detects tampering in fields omitted by the old digest and refuses to append', async () => {
      const db = createTestAdapter();
      const chainFortress = createFortress({
        jwt: { key: SECRET },
        database: db,
        plugins: [auditLog({ hashChain: true })],
      });
      const methods = chainFortress.plugins['audit-log'] as AuditLogMethods;
      await methods.logCustomEvent({ eventType: 'ROLE_CREATED', metadata: { state: 'original' } });
      await methods.logCustomEvent({ eventType: 'ROLE_UPDATED', metadata: { state: 'second' } });
      const root = (await methods.getAuditLog()).find(entry => entry.previousHash == null)!;

      await db.rawQuery!(
        'UPDATE fortress_audit_log SET metadata = ? WHERE id = ?',
        [JSON.stringify({ state: 'tampered' }), root.id],
      );

      await expect(methods.verifyChain()).resolves.toMatchObject({ valid: false, totalEntries: 2 });
      await expect(
        methods.logCustomEvent({ eventType: 'ROLE_DELETED' }),
      ).rejects.toThrow('Cannot append to an invalid audit hash chain');
      expect(await db.count({ model: 'audit_log' })).toBe(2);
    });

    it('detects deletion of the terminal entry through the persisted anchor', async () => {
      const db = createTestAdapter();
      const chainFortress = createFortress({
        jwt: { key: SECRET },
        database: db,
        plugins: [auditLog({ hashChain: true })],
      });
      const methods = chainFortress.plugins['audit-log'] as AuditLogMethods;
      for (let index = 0; index < 3; index++)
        await methods.logCustomEvent({ eventType: 'ROLE_CREATED', targetId: String(index) });
      const entries = await methods.getAuditLog();
      const tail = entries.reduce((latest, entry) => Number(entry.id) > Number(latest.id) ? entry : latest);

      await db.delete({
        model: 'audit_log',
        where: [{ field: 'id', operator: '=', value: tail.id }],
      });

      const verification = await methods.verifyChain();
      expect(verification).toMatchObject({ valid: false, totalEntries: 2 });
      expect(verification.brokenLinks.some(link => link.expected === 'anchor entry count 3')).toBe(true);
      await expect(
        methods.logCustomEvent({ eventType: 'ROLE_DELETED' }),
      ).rejects.toThrow('Cannot append to an invalid audit hash chain');
      expect(await db.count({ model: 'audit_log' })).toBe(2);
    });

    it('does not treat deletion of both the chain and anchor as fresh bootstrap', async () => {
      const db = createTestAdapter();
      const chainFortress = createFortress({
        jwt: { key: SECRET },
        database: db,
        plugins: [auditLog({ hashChain: true })],
      });
      const methods = chainFortress.plugins['audit-log'] as AuditLogMethods;
      await methods.logCustomEvent({ eventType: 'ROLE_CREATED' });
      await methods.logCustomEvent({ eventType: 'ROLE_UPDATED' });
      await db.rawQuery!('DELETE FROM fortress_audit_log');
      await db.rawQuery!('DELETE FROM fortress_audit_chain_state');

      const verification = await methods.verifyChain();
      expect(verification).toMatchObject({ valid: false, totalEntries: 0 });
      expect(verification.brokenLinks).toContainEqual({
        entryId: 'anchor',
        expected: 'persistent zero-entry audit-chain anchor',
        actual: null,
      });
      await expect(
        methods.logCustomEvent({ eventType: 'ROLE_DELETED' }),
      ).rejects.toThrow('Cannot append to an invalid audit hash chain');
      expect(await db.count({ model: 'audit_log' })).toBe(0);
    });
  });

  describe('logCustomEvent method', () => {
    it('logs a custom event', async () => {
      const logCustomEvent = fortress.plugins['audit-log'].logCustomEvent as (event: any) => Promise<void>;

      await logCustomEvent({
        eventType: 'ROLE_CREATED',
        actorId: '1',
        actorType: 'user',
        targetId: '10',
        targetType: 'role',
        outcome: 'success',
        metadata: { name: 'admin' },
      });

      const entries = await getAuditLog();
      const entry = entries.find(e => e.eventType === 'ROLE_CREATED');

      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe('1');
      expect(entry!.targetId).toBe('10');
      expect(entry!.targetType).toBe('role');
      expect(JSON.parse(entry!.metadata!)).toEqual({ name: 'admin' });
    });

    it('defaults actorType to system when not provided', async () => {
      const logCustomEvent = fortress.plugins['audit-log'].logCustomEvent as (event: any) => Promise<void>;

      await logCustomEvent({ eventType: 'PERMISSION_CHANGED' });

      const entries = await getAuditLog();
      const entry = entries.find(e => e.eventType === 'PERMISSION_CHANGED');
      expect(entry!.actorType).toBe('system');
    });
  });

  describe('verifyChain method', () => {
    it('reports valid chain when hash chain is enabled', async () => {
      const chainFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [auditLog({ hashChain: true })],
      });

      const verifyChain = chainFortress.plugins['audit-log'].verifyChain as () => Promise<ChainVerificationResult>;
      const logCustomEvent = chainFortress.plugins['audit-log'].logCustomEvent as (event: any) => Promise<void>;

      await chainFortress.auth.createUser({ email: 'a@b.com', name: 'A', password: 'password-123456' });
      await chainFortress.auth.login('a@b.com', 'password-123456');
      await logCustomEvent({ eventType: 'ROLE_CREATED', actorId: '1' });

      const result = await verifyChain();
      expect(result.valid).toBe(true);
      expect(result.totalEntries).toBe(3);
      expect(result.brokenLinks).toHaveLength(0);
    });

    it('reports empty chain as valid', async () => {
      const verifyChain = fortress.plugins['audit-log'].verifyChain as () => Promise<ChainVerificationResult>;
      const result = await verifyChain();
      expect(result.valid).toBe(true);
      expect(result.totalEntries).toBe(0);
    });
  });

  describe('iAM event integration', () => {
    it('logs ROLE_CREATED when a role is created', async () => {
      const auditFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [auditLog()],
      });

      const auditGetLog = auditFortress.plugins['audit-log'].getAuditLog as typeof getAuditLog;

      await auditFortress.iam.createRole('editor', [
        { resource: 'post', action: 'read' },
      ]);

      const entries = await auditGetLog();
      const entry = entries.find(e => e.eventType === 'ROLE_CREATED');
      expect(entry).toBeDefined();
      expect(entry!.targetType).toBe('role');
    });

    it('logs ROLE_BOUND when a role is bound to a user', async () => {
      const auditFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [auditLog()],
      });

      const auditGetLog = auditFortress.plugins['audit-log'].getAuditLog as typeof getAuditLog;

      const user = await auditFortress.auth.createUser({ email: 'x@y.com', name: 'X', password: 'password-123456' });
      const role = await auditFortress.iam.createRole('viewer', [{ resource: 'post', action: 'read' }]);
      await auditFortress.iam.bindRoleToUser(user.id, role.id);

      const entries = await auditGetLog();
      const entry = entries.find(e => e.eventType === 'ROLE_BOUND');
      expect(entry).toBeDefined();
      expect(entry!.actorId).toBe(user.id);
      expect(entry!.targetId).toBe(role.id);
    });

    it('logs GROUP_CREATED when a group is created', async () => {
      const auditFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [auditLog()],
      });

      const auditGetLog = auditFortress.plugins['audit-log'].getAuditLog as typeof getAuditLog;

      await auditFortress.iam.createGroup('editors', 'Content editors');

      const entries = await auditGetLog();
      const entry = entries.find(e => e.eventType === 'GROUP_CREATED');
      expect(entry).toBeDefined();
      expect(entry!.targetType).toBe('group');
    });
  });

  describe('exportEntries method', () => {
    it('exports entries as JSON by default', async () => {
      const methods = fortress.plugins['audit-log'] as AuditLogMethods;

      await fortress.auth.createUser({ email: 'export@example.com', name: 'Export', password: 'password-123456' });
      await fortress.auth.login('export@example.com', 'password-123456');

      const json = await methods.exportEntries();
      const parsed = JSON.parse(json) as { eventType: string }[];
      expect(parsed.length).toBeGreaterThanOrEqual(1);
      expect(parsed.some(entry => entry.eventType === 'LOGIN_SUCCESS')).toBe(true);
    });

    it('exports entries as CSV with a stable header row', async () => {
      const methods = fortress.plugins['audit-log'] as AuditLogMethods;

      await fortress.auth.createUser({ email: 'csv@example.com', name: 'Csv', password: 'password-123456' });
      await fortress.auth.login('csv@example.com', 'password-123456');

      const csv = await methods.exportEntries('csv');
      const lines = csv.split('\n');
      expect(lines[0]).toBe('id,timestamp,eventType,actorId,actorType,targetId,targetType,ipAddress,userAgent,outcome,metadata,previousHash,createdAt');
      expect(lines.length).toBeGreaterThanOrEqual(2);
      expect(csv).toContain('LOGIN_SUCCESS');
    });

    it('escapes CSV cells containing commas and quotes (RFC 4180)', async () => {
      const methods = fortress.plugins['audit-log'] as AuditLogMethods;

      await methods.logCustomEvent({
        eventType: 'ROLE_CREATED',
        metadata: { note: 'a, b "quoted"' },
      });

      const csv = await methods.exportEntries('csv');
      // The metadata JSON contains a comma and quotes, so the cell must be
      // wrapped and its embedded quotes doubled.
      expect(csv).toContain('""note""');
    });

    it('neutralizes spreadsheet formula prefixes in CSV cells', async () => {
      const methods = fortress.plugins['audit-log'] as AuditLogMethods;
      const dangerous = ['=cmd', '+cmd', '-cmd', '@cmd', '\tcmd', '\rcmd'];
      await Promise.all(dangerous.map(actorType => methods.logCustomEvent({
        eventType: 'ROLE_CREATED',
        actorType,
      })));

      const csv = await methods.exportEntries('csv');
      for (const value of dangerous)
        expect(csv).toContain(`'${value}`);
    });

    it('honours query filters when exporting', async () => {
      const methods = fortress.plugins['audit-log'] as AuditLogMethods;

      await fortress.auth.createUser({ email: 'filter@example.com', name: 'Filter', password: 'password-123456' });
      await fortress.auth.login('filter@example.com', 'password-123456');

      const json = await methods.exportEntries('json', { eventType: 'REGISTER' });
      const parsed = JSON.parse(json) as { eventType: string }[];
      expect(parsed.length).toBeGreaterThanOrEqual(1);
      expect(parsed.every(entry => entry.eventType === 'REGISTER')).toBe(true);
    });
  });

  describe('event filtering', () => {
    it('only logs configured event types when events array is provided', async () => {
      const filteredFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [auditLog({ events: ['LOGIN_SUCCESS'] })],
      });

      const filteredGetAuditLog = filteredFortress.plugins['audit-log'].getAuditLog as typeof getAuditLog;

      await filteredFortress.auth.createUser({
        email: 'heidi@example.com',
        name: 'Heidi',
        password: 'password-123456',
      });

      await filteredFortress.auth.login('heidi@example.com', 'password-123456');

      const entries = await filteredGetAuditLog();

      // Should only have LOGIN_SUCCESS, not REGISTER
      expect(entries.length).toBe(1);
      expect(entries[0].eventType).toBe('LOGIN_SUCCESS');
    });
  });
});
