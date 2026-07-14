# Tenancy Plugin

## Overview

The `tenancy` plugin adds schema-per-tenant isolation for PostgreSQL. Each tenant gets its own schema named from its numeric database id (by default `tenant_<id>`), and request-scoped database operations run with that tenant schema on PostgreSQL's `search_path`.

Tenant selection is derived from the verified JWT claim produced by `enrichTokenClaims`: `claims.customClaims.tenantId`. It is never read from client-supplied tenant context. A caller can therefore only get a tenant claim after being a member of that tenant via `tenant_user`.

Isolation is transaction-pinned and fail-closed: each wrapped operation starts a transaction, calls `set_config('search_path', ?, true)` with a bound parameter on the pinned connection, then runs the operation. If there is no verified tenant claim, or the adapter is not PostgreSQL, the adapter is returned unchanged. Business tables should live only in tenant schemas, so missing tenant context fails by not finding those tables rather than silently reading another tenant.

This plugin is PostgreSQL-specific. For database-agnostic row-level isolation, see [Data Isolation](./data-isolation.md).

## Service accounts and tenancy

Service accounts have no `tenant_user` membership, so `enrichTokenClaims` does not add a tenant claim for them and the tenancy adapter wrapper does not switch schemas. That is intentional fail-closed behavior.

Tenant-scoped *permissions* for service accounts are unaffected. IAM still resolves grants through `role_binding.tenantId` when you pass an explicit `tenantId` to `fortress.iam.checkPermission(...)`; this is separate from schema switching and does not rely on any tenant header.

## Installation

```ts
import { createFortress } from '@bajustone/fortress';
import { tenancy } from '@bajustone/fortress/plugins/tenancy';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    tenancy({
      schemaPrefix: 'tenant_',
      routes: false,
      onSchemaCreated: async (schemaName, rawQuery) => {
        await rawQuery(`CREATE TABLE IF NOT EXISTS ${schemaName}.widgets (id SERIAL PRIMARY KEY)`);
      },
      dropSchemaOnDelete: false,
    }),
  ],
});
```

Programmatic methods are always available at `fortress.plugins.tenancy`. HTTP routes are mounted only when `routes: true`.

## Configuration

| Option | Type | Default | Description |
|---|---|---|---|
| `schemaPrefix` | `string` | `'tenant_'` | Prefix for tenant schemas. Must match `^[a-z_][a-z0-9_]*$`. Full schema name is `${schemaPrefix}${tenant.id}`. |
| `routes` | `boolean` | `false` | Mount opt-in HTTP routes under `/tenancy/*`. |
| `onSchemaCreated` | `(schemaName, rawQuery) => Promise<void>` | `undefined` | Runs inside the `createTenant` transaction after `CREATE SCHEMA`. Use for per-tenant DDL/migrations. |
| `dropSchemaOnDelete` | `boolean` | `false` | When `true`, `deleteTenant` drops the tenant schema with `CASCADE`. |

## HTTP Routes

Enable with `tenancy({ routes: true })`.

| Method | Path | Handler | Auth |
|---|---|---|---|
| `POST` | `/tenancy/tenants` | `createTenant` | Bearer + `fortress:manageTenants` |
| `DELETE` | `/tenancy/tenants/:id` | `deleteTenant` | Bearer + `fortress:manageTenants` |
| `GET` | `/tenancy/tenants/mine` | `getMyTenants` | Bearer; caller derived from token |
| `POST` | `/tenancy/switch` | `switchTenant` | Bearer; caller derived from token |

Self-service routes ignore any `userId` in the body when a route context is present.

## API Reference

| Method | Signature | Returns |
|---|---|---|
| `createTenant` | `({ name, taxId, description? })` | `Promise<TenantRecord>` |
| `deleteTenant` | `({ id })` | `Promise<{ ok: true }>` |
| `addUserToTenant` | `(userId, tenantId)` | `Promise<void>` |
| `getUserTenants` | `(userId)` | `Promise<TenantRecord[]>` |
| `getMyTenants` | `({ userId? }, routeCtx?)` | `Promise<{ tenants: TenantRecord[] }>` |
| `switchTenant` | `({ taxId, userId? }, routeCtx?)` | `Promise<{ ok: true }>` |

### createTenant

Creates the tenant row and, on PostgreSQL, schema `tenant_<id>` (or your configured prefix) in one transaction:

```ts
const tenant = await fortress.plugins.tenancy.createTenant({
  name: 'Acme Corp',
  taxId: 'acme-corp', // unique external code; not used in schema names
});
```

### deleteTenant

Removes tenant memberships and the tenant row. The schema is only dropped when `dropSchemaOnDelete: true`.

```ts
await fortress.plugins.tenancy.deleteTenant({ id: tenant.id });
```

### switchTenant

Sets the user's default tenant after verifying membership. The flip is serialized and performed as a two-phase update inside one transaction (clear, then set), while a partial unique index enforces at most one default membership per user. The new tenant takes effect on the next login/token refresh because tenant data is stored in JWT custom claims.

```ts
await fortress.plugins.tenancy.switchTenant({ taxId: 'acme-corp', userId });
```

## Migration notes for pre-hardening schemas

Older experimental builds derived schema names from tenant codes/tax IDs (for example `tenant_acme-001`) and trusted `X-Tenant-Code` as request context. Hardened Fortress no longer reads that header and no longer uses tax IDs in SQL identifiers.

For existing deployments:

1. For every row in `fortress_tenant`, compute the hardened schema name as `${schemaPrefix}${tenant.id}` (default: `tenant_<numeric id>`).
2. Rename each old tenant schema to the hardened name, or recreate it and copy data:
   ```sql
   ALTER SCHEMA old_schema_name RENAME TO tenant_123;
   ```
3. Ensure all tenant business tables live only in tenant schemas, not `public`, so missing tenant context fails closed.
4. Remove any app code that forwards or depends on `X-Tenant-Code`.
5. Have users log in or refresh tokens after `switchTenant`; the active tenant comes from `claims.customClaims.tenantId`.

No Fortress-owned table shape changes are required beyond the normal migration catalog/version checks.

## JWT staleness tradeoff

Tenant access is encoded in short-lived JWT access tokens. If a user is removed from a tenant, an already-issued token can retain its old `tenantId` claim until it expires or is refreshed. Keep access-token lifetimes short and force session/token revocation for immediate removal.
