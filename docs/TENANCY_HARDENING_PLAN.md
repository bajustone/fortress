# Implementation Plan — Tenancy Plugin Hardening (for a local AI agent)

> **Audience:** an AI coding agent working on a fresh local checkout of the
> `fortress` repo (state: `main` @ v0.1.2). This plan was derived from a
> fully-implemented-and-verified change set (typecheck ✅, lint ✅, 995 unit
> tests ✅). Follow it top to bottom. Code blocks marked **FINAL FILE** are the
> complete file contents to write; blocks marked **EDIT** are surgical
> replacements (match the `old` text exactly, replace with `new`).

---

## 0. Goal & context

The `tenancy` plugin (schema-per-tenant Postgres isolation) is flagged
"experimental / unsafe to mount" (findings **C1, C2, H2, H3**). Close all four
and finish the plugin.

- **C1/C2 — SQL identifier injection.** `tenantCode`/`taxId` are interpolated raw
  into `SET LOCAL search_path TO ${schemaName}` and `CREATE SCHEMA ... ${schemaName}`.
  Also a functional bug: hyphenated tax IDs (`acme-001`) yield invalid unquoted
  identifiers.
- **H2 — fails open.** `SET LOCAL` is issued as a standalone `rawQuery`, then a
  *separate* CRUD call runs on a possibly-different pooled connection, so the path
  is discarded and queries silently hit `public`. `wrapAdapter` never overrides
  `transaction()`.
- **H3 — header trust.** The tenant comes from the raw `X-Tenant-Code` header with
  no membership check — any authenticated user can target any tenant's schema.

**Locked decisions:** (1) schema name = `${schemaPrefix}${tenant.id}` (numeric,
injection-proof); (2) tenant resolved from the verified `tenantId` JWT claim, drop
`X-Tenant-Code`; (3) opt-in HTTP routes behind `routes?: boolean` (default false);
(4) full hardening + tests + docs.

### ⚠️ Two non-obvious facts the agent MUST respect

1. **The tenant claim is nested.** `enrichTokenClaims` output is merged into
   `customClaims`, and `verifyToken` returns it under **`claims.customClaims.tenantId`**
   (NOT `claims.tenantId`). The framework adapters must read
   `claims?.customClaims?.tenantId`.
2. **Plugin route handlers have a fixed call shape.** The dispatcher invokes
   `methods[handler]({ ...body, ...pathParams }, routeCtx)`
   (`src/core/http/dispatch.ts:194`). Any method exposed as a route must take
   `(input, routeCtx?)`. This is why `switchTenant(userId, taxId)` (positional) is
   refactored to `switchTenant({ taxId, userId? }, routeCtx?)`.

### Supporting facts (already verified in the codebase)

- PG `transaction()` (`src/drizzle/adapter.ts:350`) builds a **connection-pinned**
  tx adapter via `buildAdapter(tx)` whose `rawQuery` is bound to that connection.
  So `set_config('search_path', $1, true)` + the CRUD op run atomically on one
  connection (the H2 fix) and `$1` is a bound param (removes injection).
- `requestContext.tenantCode` is consumed **only** by tenancy's `wrapAdapter`. IAM
  tenant scoping uses an explicit `body.tenantId`, NOT the header — so dropping the
  header does not break RBAC.
- `tenant` / `tenant_user` tables already exist in all schema sources
  (`src/drizzle/schema.ts`, `src/drizzle/pg/schema.ts`, `src/testing/index.ts`).
  **No table migration needed.**
- `endpoint()` builder lives in `src/core/schema-builder.ts`; `.permission(resource, action)`
  sets `meta.permission`, enforced by `enforceFortressPermission`
  (`src/core/http/fortress-rbac.ts`). Mirror `src/plugins/api-key/index.ts` for the
  opt-in route pattern (`...(mount ? { routes } : {})`).
- `DatabaseAdapter` interface: `src/adapters/database/index.ts` (create/findOne/
  findMany/update/delete/count/transaction + optional `rawQuery`, `dialect`).
- `jsr.json` already exports `./plugins/tenancy` — no change needed.

---

## 1. Setup

```bash
bun install
git checkout -b tenancy-hardening
```

---

## 2. `src/plugins/tenancy/index.ts` — **FINAL FILE** (replace entirely)

```ts
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
import { arr, bool, endpoint, int, obj, ref, str } from '../../core/schema-builder';

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
  id: number;
  name: string;
  taxId: string;
  description: string | null;
  createdAt: Date;
  updatedAt: Date;
}

interface TenantUserRecord {
  tenantId: number;
  userId: number;
  isDefault: boolean;
}

export interface TenancyMethods {
  createTenant: (
    input: { name: string; taxId: string; description?: string },
    routeCtx?: PluginRouteContext,
  ) => Promise<TenantRecord>;
  deleteTenant: (
    input: { id: number | string },
    routeCtx?: PluginRouteContext,
  ) => Promise<{ ok: true }>;
  addUserToTenant: (userId: number, tenantId: number) => Promise<void>;
  getUserTenants: (userId: number) => Promise<TenantRecord[]>;
  getMyTenants: (
    input: { userId?: number },
    routeCtx?: PluginRouteContext,
  ) => Promise<TenantRecord[]>;
  switchTenant: (
    input: { taxId: string; userId?: number },
    routeCtx?: PluginRouteContext,
  ) => Promise<{ ok: true }>;
}

const SAFE_SCHEMA_PREFIX = /^[a-z_][a-z0-9_]*$/;

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
  id: int('Tenant id'),
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

  /** Schema name for a tenant. `id` is numeric, so the result is always a
   *  valid, non-injectable identifier. */
  const tenantSchemaName = (id: number): string => `${schemaPrefix}${id}`;

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
      const tenantId = requestContext.tenantId as number | undefined;
      // Fail closed: no verified tenant claim ⇒ no schema switch. Business
      // tables live only in tenant schemas, so they are simply not on the
      // search path — there is no silent fallback to another tenant's data.
      if (tenantId == null)
        return adapter;

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

      const listUserTenants = async (userId: number): Promise<TenantRecord[]> => {
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

      const requireUserId = (input: { userId?: number }, routeCtx?: PluginRouteContext): number => {
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

        async deleteTenant(input: { id: number | string }): Promise<{ ok: true }> {
          const id = Number(input.id);
          if (!Number.isInteger(id))
            throw Errors.badRequest('id must be an integer');

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
          return listUserTenants(userId);
        },

        async getMyTenants(input: { userId?: number }, routeCtx?: PluginRouteContext): Promise<TenantRecord[]> {
          return listUserTenants(requireUserId(input, routeCtx));
        },

        async switchTenant(input: { taxId: string; userId?: number }, routeCtx?: PluginRouteContext): Promise<{ ok: true }> {
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
```

---

## 3. Framework adapters — H3 wiring (3 surgical EDITs)

At each site, `claims` is already destructured in scope. Replace the header read
with the verified claim.

### `src/hono/middleware/auth.ts`
**old**
```ts
    // Build request context from headers for plugin adapter wrappers
    const plugins = fortress.config.plugins ?? [];
    const requestContext: Record<string, unknown> = {
      tenantCode: c.req.header('X-Tenant-Code'),
      ipAddress:
        c.req.header('X-Forwarded-For') ?? c.req.header('X-Real-IP'),
      userAgent: c.req.header('User-Agent'),
    };
```
**new**
```ts
    // Build request context for plugin adapter wrappers. The tenant is taken
    // from the verified JWT claim (set by tenancy's enrichTokenClaims), never
    // a client header — so a caller can only reach a tenant they belong to.
    const plugins = fortress.config.plugins ?? [];
    const requestContext: Record<string, unknown> = {
      tenantId: claims?.customClaims?.tenantId,
      ipAddress:
        c.req.header('X-Forwarded-For') ?? c.req.header('X-Real-IP'),
      userAgent: c.req.header('User-Agent'),
    };
```

### `src/express/middleware.ts`
**old**
```ts
      const plugins = fortress.config.plugins ?? [];
      const requestContext: Record<string, unknown> = {
        tenantCode: req.headers['x-tenant-code'],
        ipAddress: req.headers['x-forwarded-for'] ?? req.headers['x-real-ip'],
        userAgent: req.headers['user-agent'],
      };
```
**new**
```ts
      const plugins = fortress.config.plugins ?? [];
      // Tenant comes from the verified JWT claim, never a client header.
      const requestContext: Record<string, unknown> = {
        tenantId: claims?.customClaims?.tenantId,
        ipAddress: req.headers['x-forwarded-for'] ?? req.headers['x-real-ip'],
        userAgent: req.headers['user-agent'],
      };
```

### `src/sveltekit/handle.ts`
**old**
```ts
  const plugins = fortress.config.plugins ?? [];
  const requestContext: Record<string, unknown> = {
    tenantCode: event.request.headers.get('x-tenant-code') ?? undefined,
    ipAddress:
      event.request.headers.get('x-forwarded-for')
      ?? event.request.headers.get('x-real-ip')
      ?? undefined,
    userAgent: event.request.headers.get('user-agent') ?? undefined,
  };
```
**new**
```ts
  const plugins = fortress.config.plugins ?? [];
  // Tenant comes from the verified JWT claim, never a client header.
  const requestContext: Record<string, unknown> = {
    tenantId: claims?.customClaims?.tenantId,
    ipAddress:
      event.request.headers.get('x-forwarded-for')
      ?? event.request.headers.get('x-real-ip')
      ?? undefined,
    userAgent: event.request.headers.get('user-agent') ?? undefined,
  };
```

> In `handle.ts`, `claims` is the `populateLocals` parameter typed
> `TokenClaims | undefined`; in the Hono/Express middleware it's destructured
> from `resolved` a few lines above. No new imports needed.

---

## 4. Unit test — `src/plugins/tenancy/tenancy.test.ts`

### EDIT A — replace the local `TenancyMethods` interface
**old**
```ts
interface TenancyMethods {
  createTenant: (data: { name: string; taxId: string; description?: string }) => Promise<{ id: number; name: string; taxId: string }>;
  addUserToTenant: (userId: number, tenantId: number) => Promise<void>;
  getUserTenants: (userId: number) => Promise<{ id: number; name: string; taxId: string }[]>;
  switchTenant: (userId: number, taxId: string) => Promise<void>;
}
```
**new**
```ts
interface TenancyMethods {
  createTenant: (input: { name: string; taxId: string; description?: string }) => Promise<{ id: number; name: string; taxId: string }>;
  deleteTenant: (input: { id: number | string }) => Promise<{ ok: true }>;
  addUserToTenant: (userId: number, tenantId: number) => Promise<void>;
  getUserTenants: (userId: number) => Promise<{ id: number; name: string; taxId: string }[]>;
  getMyTenants: (input: { userId?: number }, routeCtx?: { userId?: number }) => Promise<{ id: number; name: string; taxId: string }[]>;
  switchTenant: (input: { taxId: string; userId?: number }, routeCtx?: { userId?: number }) => Promise<{ ok: true }>;
}
```

### EDIT B — update the `switchTenant` describe block and add new blocks
Replace the existing `switchTenant` describe block body (the three `it(...)`
cases that call `switchTenant(userId, ...)`) so all calls use the object shape,
and append `derives the caller from routeCtx`, a `requires an authenticated
caller via routeCtx` case, plus new `deleteTenant` and `wrapAdapter` describe
blocks. Concretely:

- `methods.switchTenant(userId, 'beta-001')` → `methods.switchTenant({ taxId: 'beta-001', userId })`
- `methods.switchTenant(userId, 'acme-001')` → `methods.switchTenant({ taxId: 'acme-001', userId })`
- `methods.switchTenant(userId, 'nonexistent')` → `methods.switchTenant({ taxId: 'nonexistent', userId })`

Add these tests (inside `describe('tenancy plugin')`):

```ts
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
```

```ts
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
```

> Note: the `enrichTokenClaims` describe block is unchanged — its claim shape
> assertions (`claims.tenantId` / `claims.tenantCode`) are testing the hook's
> raw return value, which still returns `{ tenantId, tenantCode }`.

---

## 5. PG integration test — `src/drizzle/pg/pg.integration-test.ts`

The harness (`createPgAdapter()`, `pgClient`, testcontainers Postgres) and a
`describe('pg: tenancy plugin')` block already exist. Make these changes inside
that block:

### EDIT — fix the positional `switchTenant` call
**old**
```ts
    await fortress.plugins.tenancy.switchTenant(user.id, 't2');
```
**new**
```ts
    await fortress.plugins.tenancy.switchTenant({ taxId: 't2', userId: user.id });
```

### ADD — two tests before the block's closing `});`

```ts
  it('isolates tenant data via the transaction-pinned search_path (H2/H3)', async () => {
    // Each tenant gets an `items` table in its own schema via onSchemaCreated.
    const fortress = createFortress({
      jwt: { secret: SECRET },
      database: createPgAdapter(),
      plugins: [
        tenancy({
          onSchemaCreated: async (schemaName, rawQuery) => {
            await rawQuery(`CREATE TABLE IF NOT EXISTS ${schemaName}.items (id SERIAL PRIMARY KEY, name TEXT NOT NULL)`);
          },
        }),
      ],
    });

    const tenantPlugin = fortress.config.plugins![0];
    const base = fortress.config.database;

    const tA = await fortress.plugins.tenancy.createTenant({ name: 'A', taxId: 'iso-a' });
    const tB = await fortress.plugins.tenancy.createTenant({ name: 'B', taxId: 'iso-b' });

    const dbA = tenantPlugin.wrapAdapter!(base, { tenantId: tA.id });
    const dbB = tenantPlugin.wrapAdapter!(base, { tenantId: tB.id });

    // Writes route to each tenant's schema because the wrapped transaction pins
    // `search_path` on the same connection before the unqualified INSERT runs.
    await dbA.transaction(async tx => tx.rawQuery!(`INSERT INTO items (name) VALUES ('a-only')`));
    await dbB.transaction(async tx => tx.rawQuery!(`INSERT INTO items (name) VALUES ('b-only')`));

    const rowsA = await dbA.transaction(async tx => tx.rawQuery!<{ name: string }>(`SELECT name FROM items`));
    const rowsB = await dbB.transaction(async tx => tx.rawQuery!<{ name: string }>(`SELECT name FROM items`));

    // The load-bearing assertion: A cannot see B's rows and vice versa.
    expect(rowsA.map(r => r.name)).toEqual(['a-only']);
    expect(rowsB.map(r => r.name)).toEqual(['b-only']);

    // Fail closed: with no tenant claim, wrapAdapter is a pass-through. The
    // unqualified `items` table is not on the public search_path → it errors
    // rather than silently reading another tenant's schema.
    const dbNone = tenantPlugin.wrapAdapter!(base, {});
    expect(dbNone).toBe(base);
    await expect(
      dbNone.transaction(async tx => tx.rawQuery!(`SELECT name FROM items`)),
    ).rejects.toThrow();
  });

  it('drops the tenant schema on delete only when opted in', async () => {
    const fortress = createFortress({
      jwt: { secret: SECRET },
      database: createPgAdapter(),
      plugins: [
        tenancy({
          dropSchemaOnDelete: true,
          onSchemaCreated: async (schemaName, rawQuery) => {
            await rawQuery(`CREATE TABLE IF NOT EXISTS ${schemaName}.items (id SERIAL PRIMARY KEY)`);
          },
        }),
      ],
    });

    const tenant = await fortress.plugins.tenancy.createTenant({ name: 'Drop', taxId: 'drop-me' });
    const schemaName = `tenant_${tenant.id}`;

    const before = await pgClient.unsafe(
      `SELECT 1 FROM information_schema.schemata WHERE schema_name = '${schemaName}'`,
    );
    expect(before).toHaveLength(1);

    await fortress.plugins.tenancy.deleteTenant({ id: tenant.id });

    const after = await pgClient.unsafe(
      `SELECT 1 FROM information_schema.schemata WHERE schema_name = '${schemaName}'`,
    );
    expect(after).toHaveLength(0);
  });
```

> `tax_id` is `VARCHAR(100)` in the harness DDL — `iso-a` / `drop-me` fit.
> `SECRET`, `createPgAdapter`, `pgClient`, `tenancy`, `createFortress` are all
> already imported/defined in this file.

---

## 6. Examples — `examples/hono-app/index.ts`

**old**
```ts
app.post('/api/tenants/switch', async (c) => {
  const userId = getUserId(c);
  const { taxId } = await c.req.json();
  await fortress.plugins.tenancy.switchTenant(userId, taxId);
  return c.json({ data: { switched: true } });
});
```
**new**
```ts
app.post('/api/tenants/switch', async (c) => {
  const userId = getUserId(c);
  const { taxId } = await c.req.json();
  // userId is derived server-side from the verified token, never the body.
  await fortress.plugins.tenancy.switchTenant({ taxId, userId });
  return c.json({ data: { switched: true } });
});
```

> `examples/express-app/index.ts` only does `tenancy()` (no method calls) — no
> change. Examples are NOT in the `tsconfig.json` `include` (`src/**/*.ts` only),
> so they are not typechecked; the edit above must be correct by inspection.

---

## 7. Docs / changelog (prose — match the repo's existing tone)

These don't affect typecheck/tests but are part of the deliverable.

1. **`docs/plugins/tenancy.md`** — rewrite. Remove all `X-Tenant-Code` /
   `headerName` references. Document: numeric-id schemas (`tenant_<id>`), JWT-claim
   resolution, transaction-pinned isolation + fail-closed, the new config
   (`routes`, `onSchemaCreated`, `dropSchemaOnDelete`), the opt-in routes table
   (4 routes; admin routes need `fortress:manageTenants`, self-service derive the
   caller from the token), `deleteTenant`/`getMyTenants`, the updated method
   signatures, and the **JWT-staleness tradeoff** (a user removed from a tenant
   keeps access until token expiry/refresh). Update the "Service accounts and
   tenancy" section: service accounts have no `tenant_user` membership → no schema
   switch (fail closed); their tenant-scoped *permissions* still resolve via
   `role_binding.tenantId` with an explicit `tenantId` arg, unaffected by the
   dropped header.
2. **`SECURITY.md`** — replace the "Experimental plugins / tenancy is a skeleton"
   section with a "Tenancy isolation model" section describing: verified-claim
   resolution, numeric injection-safe schema names, atomic fail-closed isolation,
   and the JWT-staleness tradeoff.
3. **`README.md`** — in the `### Tenancy` section, drop the "Experimental / do not
   mount" callout; update the config snippet (remove `headerName`, add `routes`,
   `onSchemaCreated`, `dropSchemaOnDelete`) and the methods snippet
   (`switchTenant({ taxId, userId })`, add `deleteTenant`); add a one-line
   JWT-staleness note.
4. **`docs/architecture.md`** — in the tenancy plugin section (~line 1281): update
   the config block (numeric `tenant_<id>`, `routes`/`onSchemaCreated`/
   `dropSchemaOnDelete`), rewrite the `wrapAdapter` capability bullet (claim-sourced
   `tenantId`, transaction-pinned `set_config('search_path', $1, true)`, fail
   closed), and the methods line. Also line ~209: "schema-per-tenant via
   `SET LOCAL search_path`" → "via a transaction-pinned `search_path`".
5. **`CHANGELOG.md`** — under `## [Unreleased]`, add a `### Security` block
   summarising the C1/C2/H2/H3 fixes; an `### Added` entry for `deleteTenant` /
   `getMyTenants` / opt-in routes / `onSchemaCreated` / `dropSchemaOnDelete`; and a
   `### Changed` **BREAKING** entry: removed `headerName` + `X-Tenant-Code`; schemas
   renamed `tenant_<taxId>` → `tenant_<id>` (no in-place migration — rename manually);
   `switchTenant`/`getMyTenants` now `(input, routeCtx?)`.
6. **`jsr.json`** — confirm `"./plugins/tenancy": "./src/plugins/tenancy/index.ts"`
   is present (it already is). No change expected.

---

## 8. Verification

```bash
bun run typecheck         # expect: clean (tsc --noEmit)
bun run lint              # expect: clean (eslint .). If JSDoc multiline
                          #   warnings appear, run `bun run lint:fix`.
bun run test              # vitest run — expect full suite green (995+ tests)
# Optional, needs Docker (testcontainers spins up postgres:16-alpine):
bun run test:integration  # exercises the new cross-tenant isolation +
                          #   fail-closed + schema-drop tests
```

Expected end state (matches the reference implementation): **typecheck clean,
lint clean, 995 unit tests passing.** The integration test is typecheck-verified;
it requires Docker to run.

Manual OpenAPI smoke (optional): mount `tenancy({ routes: true })` alongside the
`openapi` plugin → `GET /openapi.json` includes the four `/tenancy/*` routes;
a non-admin caller is rejected (403) on `POST /tenancy/tenants`.

---

## 9. Gotchas checklist (do not skip)

- [ ] Adapters read `claims?.customClaims?.tenantId`, **not** `claims?.tenantId`.
- [ ] `wrapAdapter` returns the adapter **unchanged** when `tenantId == null` or
      dialect isn't pg (fail closed / no-op) — the unit tests assert identity
      (`toBe(base)`).
- [ ] `wrapAdapter` overrides **`transaction()` too**, not just CRUD methods.
- [ ] `setPath` uses a **bound param** (`$1`) and `true` (transaction-local) — never
      string-interpolate the schema into the `set_config` SQL.
- [ ] Schema names use the **numeric `tenant.id`**, never `taxId`.
- [ ] `createTenant` does row-insert + `CREATE SCHEMA` + `onSchemaCreated` in **one
      transaction**; pass `tx.rawQuery.bind(tx)` to the callback.
- [ ] Self-service route handlers derive `userId` from `routeCtx`, never the body.
- [ ] Route handlers are dispatched as `handler({ ...body, ...pathParams }, routeCtx)`
      — keep the `(input, routeCtx?)` signatures.
- [ ] `schemaPrefix` validated against `^[a-z_][a-z0-9_]*$` at factory time.

---

## 10. Commit

```bash
git add -A
git commit -m "Harden tenancy plugin: claim-based resolution, atomic schema isolation"
git push -u origin tenancy-hardening
```

Suggested commit body summary: closes C1/C2 (numeric-id schemas + bound
`set_config` param), H2 (transaction-pinned `search_path` + `transaction()`
override + fail-closed pass-through), H3 (verified-claim tenant resolution);
adds `deleteTenant`/`getMyTenants`/opt-in routes/`onSchemaCreated`/
`dropSchemaOnDelete`; breaking removal of `headerName`/`X-Tenant-Code` and
`tenant_<taxId>` → `tenant_<id>` rename.
```
```
