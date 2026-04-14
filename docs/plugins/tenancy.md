# Tenancy Plugin

## Overview

The `tenancy` plugin adds schema-per-tenant isolation to Fortress for PostgreSQL. Each tenant gets its own database schema, providing strong data isolation at the database level. The plugin automatically enriches JWT claims with tenant information and wraps the database adapter to scope all queries to the correct schema.

This plugin is PostgreSQL-specific. For row-level isolation that works with any database, see the [Data Isolation](./data-isolation.md) plugin.

### Service accounts and tenancy

Service accounts are **not members of a tenant** in the membership sense — there is no `tenant_service_account` join table. Instead, service accounts are global identities that hold tenant-scoped grants via `role_binding.tenantId`, the same mechanism users use. A single service account can hold tenant-scoped or global bindings at the same time without any schema change.

The `tenancy` plugin's `enrichTokenClaims` hook reads `tenant_user` to find a user's default tenant; service accounts have no entry there, so the claim simply won't fire for them. Service-account-authenticated requests typically carry the tenant header (`X-Tenant-Code`) explicitly, and `fortress.iam.checkPermission({ type: 'SERVICE_ACCOUNT', id }, resource, action, { tenantId })` resolves the permission against bindings scoped to that tenant.

## Installation

Import the `tenancy` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { tenancy } from '@bajustone/fortress/plugins/tenancy';

const fortress = createFortress({
  jwt: { secret: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    tenancy({
      headerName: 'X-Tenant-Code',
      schemaPrefix: 'tenant_',
    }),
  ],
});
```

Once registered, methods are available at `fortress.plugins['tenancy']` with full type safety.

## Configuration

All fields on `TenancyConfig` are optional:

| Option | Type | Default | Description |
|---|---|---|---|
| `headerName` | `string` | `'X-Tenant-Code'` | HTTP header name used to identify the current tenant in requests. |
| `schemaPrefix` | `string` | `'tenant_'` | Prefix for PostgreSQL schema names. A tenant with `taxId` of `acme` gets schema `tenant_acme`. |

## How It Works

The plugin provides three integration points:

1. **`enrichTokenClaims`** -- When a user logs in, the plugin looks up their default tenant membership and adds `tenantId` and `tenantCode` to the JWT claims.

2. **`wrapAdapter`** -- On each request, the plugin wraps the database adapter. If a `tenantCode` is present in the request context, every database operation is preceded by `SET LOCAL search_path TO tenant_{code}, public`. This transparently scopes all SQL to the tenant's schema.

3. **`methods`** -- CRUD operations for managing tenants and user-tenant memberships.

## API Reference

| Method | Signature | Returns |
|---|---|---|
| `createTenant` | `(data: { name: string; taxId: string; description?: string })` | `Promise<TenantRecord>` |
| `addUserToTenant` | `(userId: number, tenantId: number)` | `Promise<void>` |
| `getUserTenants` | `(userId: number)` | `Promise<TenantRecord[]>` |
| `switchTenant` | `(userId: number, taxId: string)` | `Promise<void>` |

### createTenant

Creates a new tenant and its PostgreSQL schema:

```ts
const tenant = await fortress.plugins['tenancy'].createTenant({
  name: 'Acme Corp',
  taxId: 'acme-corp',          // unique identifier, used in schema name
  description: 'Enterprise customer',
});
// tenant.id, tenant.name, tenant.taxId, tenant.description, tenant.createdAt, tenant.updatedAt
```

If the database adapter supports `rawQuery`, a PostgreSQL schema `{schemaPrefix}{taxId}` is created via `CREATE SCHEMA IF NOT EXISTS`.

Throws `Conflict` if a tenant with the given `taxId` already exists.

### addUserToTenant

Adds a user to a tenant. The first tenant assigned to a user automatically becomes their default:

```ts
await fortress.plugins['tenancy'].addUserToTenant(userId, tenant.id);
```

If the user is already a member of the tenant, this is a no-op.

### getUserTenants

Returns all tenants a user belongs to:

```ts
const tenants = await fortress.plugins['tenancy'].getUserTenants(userId);
// Array of { id, name, taxId, description, createdAt, updatedAt }
```

### switchTenant

Changes the user's default tenant. The new default is used for JWT claims on the next token refresh:

```ts
await fortress.plugins['tenancy'].switchTenant(userId, 'acme-corp');
```

Throws:
- `NotFound` -- Tenant with the given `taxId` does not exist.
- `Forbidden` -- User does not belong to the specified tenant.

## JWT Claims

When a user has a default tenant, the following claims are added to their JWT:

```json
{
  "tenantId": 1,
  "tenantCode": "acme-corp"
}
```

## Example

```ts
import { createFortress } from '@bajustone/fortress';
import { tenancy } from '@bajustone/fortress/plugins/tenancy';

const fortress = createFortress({
  jwt: { secret: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    tenancy({ schemaPrefix: 'org_' }),
  ],
});

// Create tenants
const acme = await fortress.plugins['tenancy'].createTenant({
  name: 'Acme Corp',
  taxId: 'acme',
});

const globex = await fortress.plugins['tenancy'].createTenant({
  name: 'Globex',
  taxId: 'globex',
});

// Assign user to tenants
await fortress.plugins['tenancy'].addUserToTenant(userId, acme.id);
await fortress.plugins['tenancy'].addUserToTenant(userId, globex.id);

// List tenants
const tenants = await fortress.plugins['tenancy'].getUserTenants(userId);

// Switch default tenant
await fortress.plugins['tenancy'].switchTenant(userId, 'globex');
```
