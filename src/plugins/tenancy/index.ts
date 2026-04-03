import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressPlugin, PluginContext } from '../../core/plugin';
import { Errors } from '../../core/errors';

export interface TenancyConfig {
  /** Header name to read tenant code from (default: 'X-Tenant-Code') */
  headerName?: string;
  /** Schema prefix for tenant schemas (default: 'tenant_') */
  schemaPrefix?: string;
}

interface TenantRecord {
  id: number;
  name: string;
  taxId: string;
  description: string | null;
  createdAt: string;
  updatedAt: string;
}

interface TenantUserRecord {
  tenantId: number;
  userId: number;
  isDefault: boolean;
}

export function tenancy(config: TenancyConfig = {}): FortressPlugin {
  const schemaPrefix = config.schemaPrefix ?? 'tenant_';

  return {
    name: 'tenancy',

    models: [
      {
        name: 'tenant',
        fields: {
          id: { type: 'number', required: true },
          name: { type: 'string', required: true },
          taxId: { type: 'string', required: true, unique: true },
          description: { type: 'string' },
          createdAt: { type: 'date', required: true },
          updatedAt: { type: 'date', required: true },
        },
      },
      {
        name: 'tenant_user',
        fields: {
          tenantId: { type: 'number', required: true, references: { model: 'tenant', field: 'id' } },
          userId: { type: 'number', required: true, references: { model: 'user', field: 'id' } },
          isDefault: { type: 'boolean', required: true },
        },
      },
    ],

    async enrichTokenClaims(userId: number, ctx: PluginContext): Promise<Record<string, unknown>> {
      // Find user's default tenant
      const membership = await ctx.db.findOne<TenantUserRecord>({
        model: 'tenant_user',
        where: [
          { field: 'userId', operator: '=', value: userId },
          { field: 'isDefault', operator: '=', value: true },
        ],
      });

      if (!membership)
        return {};

      const tenant = await ctx.db.findOne<TenantRecord>({
        model: 'tenant',
        where: [{ field: 'id', operator: '=', value: membership.tenantId }],
      });

      if (!tenant)
        return {};

      return {
        tenantId: tenant.id,
        tenantCode: tenant.taxId,
      };
    },

    wrapAdapter(adapter: DatabaseAdapter, requestContext: Record<string, unknown>): DatabaseAdapter {
      const tenantCode = requestContext.tenantCode as string | undefined;
      if (!tenantCode)
        return adapter;

      const schemaName = `${schemaPrefix}${tenantCode}`;

      // Wrap adapter to execute SET LOCAL search_path before queries (PostgreSQL only)
      // For SQLite/MySQL, this is a no-op pass-through
      return {
        ...adapter,
        async create<T>(params: Parameters<DatabaseAdapter['create']>[0]): Promise<T> {
          if (adapter.rawQuery) {
            await adapter.rawQuery(`SET LOCAL search_path TO ${schemaName}, public`);
          }
          return adapter.create<T>(params);
        },
        async findOne<T>(params: Parameters<DatabaseAdapter['findOne']>[0]): Promise<T | null> {
          if (adapter.rawQuery) {
            await adapter.rawQuery(`SET LOCAL search_path TO ${schemaName}, public`);
          }
          return adapter.findOne<T>(params);
        },
        async findMany<T>(params: Parameters<DatabaseAdapter['findMany']>[0]): Promise<T[]> {
          if (adapter.rawQuery) {
            await adapter.rawQuery(`SET LOCAL search_path TO ${schemaName}, public`);
          }
          return adapter.findMany<T>(params);
        },
        async update<T>(params: Parameters<DatabaseAdapter['update']>[0]): Promise<T> {
          if (adapter.rawQuery) {
            await adapter.rawQuery(`SET LOCAL search_path TO ${schemaName}, public`);
          }
          return adapter.update<T>(params);
        },
        async delete(params: Parameters<DatabaseAdapter['delete']>[0]): Promise<void> {
          if (adapter.rawQuery) {
            await adapter.rawQuery(`SET LOCAL search_path TO ${schemaName}, public`);
          }
          return adapter.delete(params);
        },
        async count(params: Parameters<DatabaseAdapter['count']>[0]): Promise<number> {
          if (adapter.rawQuery) {
            await adapter.rawQuery(`SET LOCAL search_path TO ${schemaName}, public`);
          }
          return adapter.count(params);
        },
      };
    },

    methods: ctx => ({
      async createTenant(data: { name: string; taxId: string; description?: string }): Promise<TenantRecord> {
        const existing = await ctx.db.findOne<TenantRecord>({
          model: 'tenant',
          where: [{ field: 'taxId', operator: '=', value: data.taxId }],
        });

        if (existing)
          throw Errors.conflict(`Tenant with taxId '${data.taxId}' already exists`);

        const tenant = await ctx.db.create<TenantRecord>({
          model: 'tenant',
          data: {
            name: data.name,
            taxId: data.taxId,
            description: data.description ?? null,
          },
        });

        // Create tenant schema if rawQuery is available (PostgreSQL)
        if (ctx.db.rawQuery) {
          const schemaName = `${schemaPrefix}${data.taxId}`;
          await ctx.db.rawQuery(`CREATE SCHEMA IF NOT EXISTS ${schemaName}`);
        }

        return tenant;
      },

      async addUserToTenant(userId: number, tenantId: number): Promise<void> {
        // Check if user already belongs to this tenant
        const existing = await ctx.db.findOne<TenantUserRecord>({
          model: 'tenant_user',
          where: [
            { field: 'userId', operator: '=', value: userId },
            { field: 'tenantId', operator: '=', value: tenantId },
          ],
        });

        if (existing)
          return; // Already a member

        // Check if user has any tenants — if not, make this the default
        const memberships = await ctx.db.findMany<TenantUserRecord>({
          model: 'tenant_user',
          where: [{ field: 'userId', operator: '=', value: userId }],
        });

        await ctx.db.create({
          model: 'tenant_user',
          data: {
            tenantId,
            userId,
            isDefault: memberships.length === 0, // First tenant becomes default
          },
        });
      },

      async getUserTenants(userId: number): Promise<TenantRecord[]> {
        const memberships = await ctx.db.findMany<TenantUserRecord>({
          model: 'tenant_user',
          where: [{ field: 'userId', operator: '=', value: userId }],
        });

        if (memberships.length === 0)
          return [];

        const tenantIds = memberships.map(m => m.tenantId);
        return ctx.db.findMany<TenantRecord>({
          model: 'tenant',
          where: [{ field: 'id', operator: 'in', value: tenantIds }],
        });
      },

      async switchTenant(userId: number, taxId: string): Promise<void> {
        const tenant = await ctx.db.findOne<TenantRecord>({
          model: 'tenant',
          where: [{ field: 'taxId', operator: '=', value: taxId }],
        });

        if (!tenant)
          throw Errors.notFound(`Tenant '${taxId}' not found`);

        // Verify user belongs to this tenant
        const membership = await ctx.db.findOne<TenantUserRecord>({
          model: 'tenant_user',
          where: [
            { field: 'userId', operator: '=', value: userId },
            { field: 'tenantId', operator: '=', value: tenant.id },
          ],
        });

        if (!membership)
          throw Errors.forbidden('User does not belong to this tenant');

        // Unset current default
        const currentDefaults = await ctx.db.findMany<TenantUserRecord>({
          model: 'tenant_user',
          where: [
            { field: 'userId', operator: '=', value: userId },
            { field: 'isDefault', operator: '=', value: true },
          ],
        });

        for (const m of currentDefaults) {
          await ctx.db.update({
            model: 'tenant_user',
            where: [
              { field: 'userId', operator: '=', value: userId },
              { field: 'tenantId', operator: '=', value: m.tenantId },
            ],
            data: { isDefault: false },
          });
        }

        // Set new default
        await ctx.db.update({
          model: 'tenant_user',
          where: [
            { field: 'userId', operator: '=', value: userId },
            { field: 'tenantId', operator: '=', value: tenant.id },
          ],
          data: { isDefault: true },
        });
      },
    }),
  };
}
