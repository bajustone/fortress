import type { Fortress } from '../../core/fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { tenancy } from './index';

const SECRET = 'tenancy-test-secret-at-least-32!!';

interface TenancyMethods {
  createTenant: (input: { name: string; taxId: string; description?: string }) => Promise<{ id: number; name: string; taxId: string }>;
  deleteTenant: (input: { id: number | string }) => Promise<{ ok: true }>;
  addUserToTenant: (userId: number, tenantId: number) => Promise<void>;
  getUserTenants: (userId: number) => Promise<{ id: number; name: string; taxId: string }[]>;
  getMyTenants: (input: { userId?: number }, routeCtx?: { userId?: number }) => Promise<{ id: number; name: string; taxId: string }[]>;
  switchTenant: (input: { taxId: string; userId?: number }, routeCtx?: { userId?: number }) => Promise<{ ok: true }>;
}

describe('tenancy plugin', () => {
  let fortress: Fortress<any>;
  let methods: TenancyMethods;
  let userId: number;

  beforeEach(async () => {
    fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
      plugins: [tenancy()],
    });

    methods = fortress.plugins.tenancy as unknown as TenancyMethods;

    const user = await fortress.auth.createUser({
      email: 'alice@example.com',
      name: 'Alice',
      password: 'password-123',
    });
    userId = user.id;
  });

  describe('createTenant', () => {
    it('creates a tenant', async () => {
      const tenant = await methods.createTenant({ name: 'Acme Corp', taxId: 'acme-001' });

      expect(tenant.id).toBeDefined();
      expect(tenant.name).toBe('Acme Corp');
      expect(tenant.taxId).toBe('acme-001');
    });

    it('rejects duplicate taxId', async () => {
      await methods.createTenant({ name: 'Acme', taxId: 'acme-001' });

      await expect(
        methods.createTenant({ name: 'Acme 2', taxId: 'acme-001' }),
      ).rejects.toThrow('already exists');
    });
  });

  describe('addUserToTenant', () => {
    it('adds user to tenant', async () => {
      const tenant = await methods.createTenant({ name: 'Acme', taxId: 'acme-001' });
      await methods.addUserToTenant(userId, tenant.id);

      const tenants = await methods.getUserTenants(userId);
      expect(tenants).toHaveLength(1);
      expect(tenants[0].taxId).toBe('acme-001');
    });

    it('is idempotent', async () => {
      const tenant = await methods.createTenant({ name: 'Acme', taxId: 'acme-001' });
      await methods.addUserToTenant(userId, tenant.id);
      await methods.addUserToTenant(userId, tenant.id); // No error

      const tenants = await methods.getUserTenants(userId);
      expect(tenants).toHaveLength(1);
    });
  });

  describe('getUserTenants', () => {
    it('returns multiple tenants', async () => {
      const t1 = await methods.createTenant({ name: 'Acme', taxId: 'acme-001' });
      const t2 = await methods.createTenant({ name: 'Beta', taxId: 'beta-001' });

      await methods.addUserToTenant(userId, t1.id);
      await methods.addUserToTenant(userId, t2.id);

      const tenants = await methods.getUserTenants(userId);
      expect(tenants).toHaveLength(2);
    });

    it('returns empty for user with no tenants', async () => {
      const tenants = await methods.getUserTenants(userId);
      expect(tenants).toEqual([]);
    });
  });

  describe('switchTenant', () => {
    it('switches default tenant', async () => {
      const t1 = await methods.createTenant({ name: 'Acme', taxId: 'acme-001' });
      const t2 = await methods.createTenant({ name: 'Beta', taxId: 'beta-001' });

      await methods.addUserToTenant(userId, t1.id);
      await methods.addUserToTenant(userId, t2.id);

      await methods.switchTenant({ taxId: 'beta-001', userId });

      // Verify via enrichTokenClaims
      const plugin = fortress.config.plugins![0];
      const claims = await plugin.enrichTokenClaims!(userId, {
        db: fortress.config.database,
        config: fortress.config,
      });

      expect(claims.tenantCode).toBe('beta-001');
    });

    it('rejects switching to non-member tenant', async () => {
      await methods.createTenant({ name: 'Acme', taxId: 'acme-001' });

      await expect(
        methods.switchTenant({ taxId: 'acme-001', userId }),
      ).rejects.toThrow('does not belong');
    });

    it('rejects non-existent tenant', async () => {
      await expect(
        methods.switchTenant({ taxId: 'nonexistent', userId }),
      ).rejects.toThrow('not found');
    });

    it('derives the caller from routeCtx, not the body', async () => {
      const t1 = await methods.createTenant({ name: 'Acme', taxId: 'acme-001' });
      const t2 = await methods.createTenant({ name: 'Beta', taxId: 'beta-001' });
      await methods.addUserToTenant(userId, t1.id);
      await methods.addUserToTenant(userId, t2.id);

      // userId in body is ignored when a routeCtx is present.
      await methods.switchTenant({ taxId: 'beta-001', userId: 999_999 }, { userId });

      const tenants = await methods.getMyTenants({}, { userId });
      expect(tenants.map(t => t.taxId).sort()).toEqual(['acme-001', 'beta-001']);
    });

    it('requires an authenticated caller via routeCtx', async () => {
      await expect(
        methods.switchTenant({ taxId: 'acme-001' }, {}),
      ).rejects.toThrow('Not authenticated');
    });
  });

  describe('deleteTenant', () => {
    it('removes the tenant and its memberships', async () => {
      const tenant = await methods.createTenant({ name: 'Acme', taxId: 'acme-001' });
      await methods.addUserToTenant(userId, tenant.id);

      const result = await methods.deleteTenant({ id: tenant.id });
      expect(result).toEqual({ ok: true });

      const tenants = await methods.getUserTenants(userId);
      expect(tenants).toEqual([]);
    });

    it('rejects an unknown tenant', async () => {
      await expect(methods.deleteTenant({ id: 999_999 })).rejects.toThrow('not found');
    });
  });

  describe('wrapAdapter', () => {
    it('is a pass-through on non-pg adapters even with a tenant claim', () => {
      const plugin = fortress.config.plugins![0];
      const base = fortress.config.database;
      const wrapped = plugin.wrapAdapter!(base, { tenantId: 1 });
      // SQLite test adapter: no schema switching, returns the adapter unchanged.
      expect(wrapped).toBe(base);
    });

    it('is a pass-through when no tenant claim is present', () => {
      const plugin = fortress.config.plugins![0];
      const base = fortress.config.database;
      expect(plugin.wrapAdapter!(base, {})).toBe(base);
    });
  });

  describe('enrichTokenClaims', () => {
    it('adds tenantId and tenantCode to JWT claims', async () => {
      const tenant = await methods.createTenant({ name: 'Acme', taxId: 'acme-001' });
      await methods.addUserToTenant(userId, tenant.id);

      const plugin = fortress.config.plugins![0];
      const claims = await plugin.enrichTokenClaims!(userId, {
        db: fortress.config.database,
        config: fortress.config,
      });

      expect(claims.tenantId).toBe(tenant.id);
      expect(claims.tenantCode).toBe('acme-001');
    });

    it('returns empty claims when user has no tenant', async () => {
      const plugin = fortress.config.plugins![0];
      const claims = await plugin.enrichTokenClaims!(userId, {
        db: fortress.config.database,
        config: fortress.config,
      });

      expect(claims).toEqual({});
    });
  });
});
