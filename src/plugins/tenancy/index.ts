/**
 * Schema-per-tenant tenancy plugin for fortress (PostgreSQL only).
 *
 * Switches the active PostgreSQL `search_path` per request based on the
 * resolved tenant, providing strong data isolation between tenants without
 * touching application code. Requires a PostgreSQL-backed Drizzle adapter.
 *
 * The active tenant is read from the **verified** `tenantId` JWT claim (set by
 * {@link enrichTokenClaims} from the user's default `tenant_user` membership),
 * never from a client-supplied header — so a caller can only ever reach a
 * tenant they belong to. Switching tenants requires {@link switchTenant} plus a
 * token refresh.
 *
 * Isolation is enforced atomically: each database operation runs inside a
 * transaction that first pins `search_path` via a bound `set_config(..., true)`
 * call, so the schema selection and the query share one pooled connection and
 * the path cannot leak or be discarded.
 *
 * HTTP endpoints are opt-in: pass `tenancy({ routes: true })` to mount the
 * routes under `/tenancy/*`. The programmatic methods on
 * `fortress.plugins.tenancy` are always available regardless of the flag.
 *
 * @module
 */

import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressPlugin, PluginContext, PluginRouteContext } from '../../core/plugin';
import { Errors } from '../../core/errors';
import { arr, bool, endpoint, id, obj, ref, str } from '../../core/schema-builder';

/**
 * Callback invoked once, inside the creation transaction, after a tenant's
 * schema is created — the hook for per-tenant table DDL / migrations.
 */
export type OnSchemaCreated = (
  schemaName: string,
  rawQuery: <T>(sql: string, params?: unknown[]) => Promise<T[]>,
) => Promise<void>;

export interface TenancyConfig {
  /**
   * Schema prefix for tenant schemas (default: 'tenant_'). Must match
   * `^[a-z_][a-z0-9_]*$` — validated at factory time.
   */
  schemaPrefix?: string;
  /**
   * Mount HTTP routes under `/tenancy/*`. Default `false`. The programmatic
   * methods on `fortress.plugins.tenancy` are always available; this flag only
   * controls HTTP mounting.
   */
  routes?: boolean;
  /**
   * Run once inside the `createTenant` transaction, right after the tenant's
   * PostgreSQL schema is created. Use it to create the tenant's business
   * tables (or run a migration) against the new schema. The supplied
   * `rawQuery` is bound to the same connection/transaction as the schema
   * creation, so statements should reference the schema explicitly (e.g.
   * `CREATE TABLE "${schemaName}".widgets (...)`).
   */
  onSchemaCreated?: OnSchemaCreated;
  /**
   * When `true`, `deleteTenant` also issues `DROP SCHEMA IF EXISTS <schema>
   * CASCADE`, destroying all tenant data. Default `false` — destructive drops
   * must be opted into explicitly.
   */
  dropSchemaOnDelete?: boolean;
}

interface TenantRecord {
  id: string;
  name: string;
  taxId: string;
  description: string | null;
  createdAt: Date;
  updatedAt: Date;
}

interface TenantUserRecord {
  tenantId: string;
  userId: string;
  isDefault: boolean;
}

export interface TenancyMethods {
  createTenant: (
    input: { name: string; taxId: string; description?: string },
    routeCtx?: PluginRouteContext,
  ) => Promise<TenantRecord>;
  deleteTenant: (
    input: { id: string },
    routeCtx?: PluginRouteContext,
  ) => Promise<{ ok: true }>;
  addUserToTenant: (userId: string, tenantId: string) => Promise<void>;
  getUserTenants: (userId: string) => Promise<TenantRecord[]>;
  getMyTenants: (
    input: { userId?: string },
    routeCtx?: PluginRouteContext,
  ) => Promise<TenantRecord[]>;
  switchTenant: (
    input: { taxId: string; userId?: string },
    routeCtx?: PluginRouteContext,
  ) => Promise<{ ok: true }>;
}

const SAFE_SCHEMA_PREFIX = /^[a-z_][a-z0-9_]*$/;

/**
 * Subject-id strings that are safe to interpolate into a Postgres schema
 * name. The tenant claim is verified-JWT-supplied but is *user-controlled*
 * at sign-up time, so any character that isn't safe for an identifier must
 * be rejected before {@link tenantSchemaName} concatenates it.
 */
const SAFE_TENANT_ID = /^[\w-]+$/;

/**
 * Validate the configured schema prefix once, at factory time. The full
 * schema name is `${prefix}${numericId}`, so a safe prefix guarantees a safe
 * identifier — no per-value escaping is needed.
 */
function assertSafeSchemaPrefix(prefix: string): void {
  if (!SAFE_SCHEMA_PREFIX.test(prefix))
    throw Errors.badRequest(`Invalid tenancy schemaPrefix '${prefix}': must match ${SAFE_SCHEMA_PREFIX}`);
}

// ── Routes ──────────────────────────────────────────────────────────

const errorRef = ref('ErrorResponse');

const tenantResponse = obj({
  id: id('Tenant id'),
  name: str('Tenant name'),
  taxId: str('Unique tenant tax id / external code'),
  description: str('Optional description'),
  createdAt: str('ISO 8601 creation timestamp'),
  updatedAt: str('ISO 8601 update timestamp'),
}, 'id', 'name', 'taxId');

const tenancyRoutes = {
  createTenant: endpoint('POST', '/tenancy/tenants')
    .summary('Create a tenant')
    .description('Create a new tenant and its PostgreSQL schema. Requires the `fortress:manageTenants` permission.')
    .tags('Tenancy')
    .security('bearer')
    .permission('fortress', 'manageTenants')
    .body(obj({
      name: str('Human-readable tenant name'),
      taxId: str('Unique tenant tax id / external code'),
      description: str('Optional description'),
    }, 'name', 'taxId'))
    .response(201, 'Tenant created', tenantResponse)
    .response(401, 'Not authenticated', errorRef)
    .response(403, 'Insufficient permissions', errorRef)
    .response(409, 'taxId already exists', errorRef)
    .handler('createTenant')
    .build(),

  deleteTenant: endpoint('DELETE', '/tenancy/tenants/:id')
    .summary('Delete a tenant')
    .description('Remove a tenant, its memberships, and (when `dropSchemaOnDelete` is enabled) its schema. Requires the `fortress:manageTenants` permission.')
    .tags('Tenancy')
    .security('bearer')
    .permission('fortress', 'manageTenants')
    .params(obj({ id: str('Tenant id') }, 'id'))
    .response(200, 'Tenant deleted', obj({ ok: bool('Always true') }, 'ok'))
    .response(401, 'Not authenticated', errorRef)
    .response(403, 'Insufficient permissions', errorRef)
    .response(404, 'Tenant not found', errorRef)
    .handler('deleteTenant')
    .build(),

  getMyTenants: endpoint('GET', '/tenancy/tenants/mine')
    .summary('List the caller\'s tenants')
    .description('Return the tenants the authenticated caller belongs to.')
    .tags('Tenancy')
    .security('bearer')
    .response(200, 'Tenants', obj({ tenants: arr(tenantResponse, 'Tenants the caller belongs to') }, 'tenants'))
    .response(401, 'Not authenticated', errorRef)
    .handler('getMyTenants')
    .build(),

  switchTenant: endpoint('POST', '/tenancy/switch')
    .summary('Switch the caller\'s default tenant')
    .description('Set the authenticated caller\'s default tenant. The new tenant takes effect on the next token refresh.')
    .tags('Tenancy')
    .security('bearer')
    .body(obj({ taxId: str('Tax id of the tenant to switch to') }, 'taxId'))
    .response(200, 'Switched', obj({ ok: bool('Always true') }, 'ok'))
    .response(401, 'Not authenticated', errorRef)
    .response(403, 'Caller does not belong to this tenant', errorRef)
    .response(404, 'Tenant not found', errorRef)
    .handler('switchTenant')
    .build(),
} as const;

// ── Plugin Factory ──────────────────────────────────────────────────

/**
 * Tenancy plugin factory (PostgreSQL only). Returns a {@link FortressPlugin}
 * that switches the active PostgreSQL `search_path` per request based on the
 * verified `tenantId` JWT claim, providing schema-level isolation between
 * tenants. Pass `{ routes: true }` to mount the HTTP routes under `/tenancy/*`.
 */
export function tenancy(config: TenancyConfig = {}): FortressPlugin & { readonly name: 'tenancy' } {
  const schemaPrefix = config.schemaPrefix ?? 'tenant_';
  assertSafeSchemaPrefix(schemaPrefix);
  const mountRoutes = config.routes === true;

  /**
   * Schema name for a tenant. `id` is numeric, so the result is always a
   * valid, non-injectable identifier.
   */
  const tenantSchemaName = (id: string): string => `${schemaPrefix}${id}`;

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

    ...(mountRoutes ? { routes: tenancyRoutes } : {}),

    async enrichTokenClaims(userId: string, ctx: PluginContext): Promise<Record<string, unknown>> {
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
      const tenantId = requestContext.tenantId as string | undefined;
      // Fail closed: no verified tenant claim ⇒ no schema switch. Business
      // tables live only in tenant schemas, so they are simply not on the
      // search path — there is no silent fallback to another tenant's data.
      if (tenantId == null)
        return adapter;
      // Validate: alphanumeric + underscore + hyphen only. The id is
      // interpolated into a Postgres schema name (via tenantSchemaName), so
      // any character that isn't safe for an identifier MUST be rejected
      // here — there is no second sanitization step downstream.
      if (!SAFE_TENANT_ID.test(tenantId))
        throw Errors.forbidden('Invalid tenant claim');

      const isPg = adapter.dialect === 'pg' && !!adapter.rawQuery;
      // For SQLite/MySQL there is no schema-per-tenant model; pass through.
      if (!isPg)
        return adapter;

      const schemaName = tenantSchemaName(tenantId);

      // Pin search_path on the transaction's pinned connection. `$1` is a bound
      // parameter (never SQL), and `set_config(..., true)` is transaction-local,
      // so the path applies to exactly the operation that follows on the same
      // connection.
      const setPath = (tx: DatabaseAdapter): Promise<unknown> =>
        tx.rawQuery!(`SELECT set_config('search_path', $1, true)`, [`${schemaName}, public`]);

      return {
        ...adapter,
        async create<T>(params: Parameters<DatabaseAdapter['create']>[0]): Promise<T> {
          return adapter.transaction(async (tx) => {
            await setPath(tx);
            return tx.create<T>(params);
          });
        },
        async findOne<T>(params: Parameters<DatabaseAdapter['findOne']>[0]): Promise<T | null> {
          return adapter.transaction(async (tx) => {
            await setPath(tx);
            return tx.findOne<T>(params);
          });
        },
        async findMany<T>(params: Parameters<DatabaseAdapter['findMany']>[0]): Promise<T[]> {
          return adapter.transaction(async (tx) => {
            await setPath(tx);
            return tx.findMany<T>(params);
          });
        },
        async update<T>(params: Parameters<DatabaseAdapter['update']>[0]): Promise<T | null> {
          return adapter.transaction(async (tx) => {
            await setPath(tx);
            return tx.update<T>(params);
          });
        },
        async delete(params: Parameters<DatabaseAdapter['delete']>[0]): Promise<void> {
          return adapter.transaction(async (tx) => {
            await setPath(tx);
            return tx.delete(params);
          });
        },
        async count(params: Parameters<DatabaseAdapter['count']>[0]): Promise<number> {
          return adapter.transaction(async (tx) => {
            await setPath(tx);
            return tx.count(params);
          });
        },
        async transaction<T>(fn: (tx: DatabaseAdapter) => Promise<T>): Promise<T> {
          // Pin once for the whole transaction so every op inside the caller's
          // callback runs against the tenant schema.
          return adapter.transaction(async (tx) => {
            await setPath(tx);
            return fn(tx);
          });
        },
      };
    },

    methods: (ctx) => {
      const findTenantByTaxId = (taxId: string): Promise<TenantRecord | null> =>
        ctx.db.findOne<TenantRecord>({
          model: 'tenant',
          where: [{ field: 'taxId', operator: '=', value: taxId }],
        });

      const listUserTenants = async (userId: string): Promise<TenantRecord[]> => {
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
      };

      const requireUserId = (input: { userId?: string }, routeCtx?: PluginRouteContext): string => {
        const userId = routeCtx?.userId ?? input.userId;
        if (userId == null) {
          if (routeCtx)
            throw Errors.unauthorized('Not authenticated');
          throw Errors.badRequest('userId is required for programmatic calls');
        }
        return userId;
      };

      return {
        async createTenant(input: { name: string; taxId: string; description?: string }): Promise<TenantRecord> {
          const existing = await findTenantByTaxId(input.taxId);
          if (existing)
            throw Errors.conflict(`Tenant with taxId '${input.taxId}' already exists`);

          // Create the row and its schema atomically: PostgreSQL DDL is
          // transactional, so a failed schema/DDL step rolls the tenant row back.
          return ctx.db.transaction(async (tx) => {
            const tenant = await tx.create<TenantRecord>({
              model: 'tenant',
              data: {
                name: input.name,
                taxId: input.taxId,
                description: input.description ?? null,
              },
            });

            if (tx.dialect === 'pg' && tx.rawQuery) {
              const schemaName = tenantSchemaName(tenant.id); // numeric id ⇒ safe
              await tx.rawQuery(`CREATE SCHEMA IF NOT EXISTS ${schemaName}`);
              if (config.onSchemaCreated)
                await config.onSchemaCreated(schemaName, tx.rawQuery.bind(tx));
            }

            return tenant;
          });
        },

        async deleteTenant(input: { id: string }): Promise<{ ok: true }> {
          const id = String(input.id ?? '');
          if (!id)
            throw Errors.badRequest('id is required');

          const tenant = await ctx.db.findOne<TenantRecord>({
            model: 'tenant',
            where: [{ field: 'id', operator: '=', value: id }],
          });
          if (!tenant)
            throw Errors.notFound(`Tenant '${id}' not found`);

          await ctx.db.transaction(async (tx) => {
            await tx.delete({
              model: 'tenant_user',
              where: [{ field: 'tenantId', operator: '=', value: id }],
            });
            await tx.delete({
              model: 'tenant',
              where: [{ field: 'id', operator: '=', value: id }],
            });
            if (config.dropSchemaOnDelete && tx.dialect === 'pg' && tx.rawQuery) {
              const schemaName = tenantSchemaName(id); // numeric id ⇒ safe
              await tx.rawQuery(`DROP SCHEMA IF EXISTS ${schemaName} CASCADE`);
            }
          });

          return { ok: true };
        },

        async addUserToTenant(userId: string, tenantId: string): Promise<void> {
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

        async getUserTenants(userId: string): Promise<TenantRecord[]> {
          return listUserTenants(userId);
        },

        async getMyTenants(input: { userId?: string }, routeCtx?: PluginRouteContext): Promise<TenantRecord[]> {
          return listUserTenants(requireUserId(input, routeCtx));
        },

        async switchTenant(input: { taxId: string; userId?: string }, routeCtx?: PluginRouteContext): Promise<{ ok: true }> {
          const userId = requireUserId(input, routeCtx);

          const tenant = await findTenantByTaxId(input.taxId);
          if (!tenant)
            throw Errors.notFound(`Tenant '${input.taxId}' not found`);

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

          // Unset current default(s)
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

          return { ok: true };
        },
      };
    },
  };
}
