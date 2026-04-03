import type { Fortress } from '../../core/fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { tenancy } from './index';

const SECRET = 'tenancy-test-secret-at-least-32!!';

interface TenancyMethods {
  createTenant: (data: { name: string; taxId: string; description?: string }) => Promise<{ id: number; name: string; taxId: string }>;
  addUserToTenant: (userId: number, tenantId: number) => Promise<void>;
  getUserTenants: (userId: number) => Promise<{ id: number; name: string; taxId: string }[]>;
  switchTenant: (userId: number, taxId: string) => Promise<void>;
}

describe('tenancy plugin', () => {
  let fortress: Fortress;
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

      await methods.switchTenant(userId, 'beta-001');

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
        methods.switchTenant(userId, 'acme-001'),
      ).rejects.toThrow('does not belong');
    });

    it('rejects non-existent tenant', async () => {
      await expect(
        methods.switchTenant(userId, 'nonexistent'),
      ).rejects.toThrow('not found');
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
