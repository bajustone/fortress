# Data Isolation Plugin

## Overview

The `data-isolation` plugin adds row-level data isolation to Fortress. It works with any database by automatically injecting WHERE filters on reads and default values on creates based on configurable scopes.

Unlike the `tenancy` plugin (which uses PostgreSQL schema-per-tenant isolation), this plugin operates at the row level and supports any database backend.

Runtime note: scoped bypass helpers (`withoutScope()` and `unscoped()`) use
`node:async_hooks` / `AsyncLocalStorage` to keep bypass state local to the
current async request. Use this plugin in Node/Bun-compatible runtimes that
provide `node:async_hooks`; edge/browser-like runtimes may need a custom
request-context wrapper or should avoid those bypass helpers.

## Installation

Import the `dataIsolation` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { dataIsolation } from '@bajustone/fortress/plugins/data-isolation';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!!' },
  database: adapter,
  plugins: [
    dataIsolation({
      scopes: [
        {
          name: 'organization',
          field: 'orgId',
          models: ['post', 'comment'],
          resolveValue: async (userId, ctx) => {
            const user = await ctx.db.findOne({
              model: 'user',
              where: [{ field: 'id', operator: '=', value: userId }],
            });
            return user?.orgId;
          },
        },
      ],
    }),
  ],
});
```

Once registered, methods are available at `fortress.plugins['data-isolation']` with full type safety.

## Configuration

The `DataIsolationConfig` requires a `scopes` array:

| Option | Type | Required | Description |
|---|---|---|---|
| `scopes` | `DataIsolationScope[]` | Yes | Array of scope definitions that control row-level filtering. |
| `unresolvedScope` | `'deny' \| 'skip'` | No | Behavior for a nullish applicable scope. Defaults to secure `'deny'`. `'skip'` is unsafe legacy compatibility mode. |

Each `DataIsolationScope` has the following fields:

| Field | Type | Description |
|---|---|---|
| `name` | `string` | Scope name for identification and bypass control. |
| `field` | `string` | Column name that holds the scoping value in the target tables. |
| `models` | `string[]` | Which models (tables) this scope applies to. Use `['*']` for all models. |
| `resolveValue` | `(userId: string, ctx: PluginContext) => Promise<unknown>` | Async function that returns the current user's value for this scope. |

## How It Works

The plugin implements `scopeRules`, which the database adapter calls on every query:

- **Reads** (`findOne`, `findMany`, `count`) -- A WHERE filter is added: `WHERE {field} = {resolvedValue}`.
- **Creates** (`create`) -- The scoping field is set as a default value: `data.{field} = {resolvedValue}`.

If an applicable `resolveValue` returns `null` or `undefined`, the plugin fails closed by default with a `FORBIDDEN` error. Scope resolution happens before a scoped adapter is returned, so both reads and creates are denied rather than becoming unscoped or accepting caller-controlled scope fields.

For migration only, `unresolvedScope: 'skip'` restores the unsafe legacy behavior of omitting an unresolved filter. This can expose every row and permit cross-scope creates; do not use it as an authorization bypass. Use the explicit async-context-local `withoutScope()` or `unscoped()` helpers for reviewed administrative operations.

```ts
// Unsafe legacy compatibility only — remove after scope assignments are complete.
dataIsolation({
  unresolvedScope: 'skip',
  scopes: [/* ... */],
});
```

### Example behavior

With a scope `{ name: 'organization', field: 'orgId', models: ['post'] }` and a user whose `orgId` is `'acme'`:

```ts
// This query:
db.findMany({ model: 'post' });
// Becomes: SELECT * FROM post WHERE orgId = 'acme'

// This create:
db.create({ model: 'post', data: { title: 'Hello' } });
// Becomes: INSERT INTO post (title, orgId) VALUES ('Hello', 'acme')
```

## API Reference

| Method | Signature | Returns |
|---|---|---|
| `withoutScope` | `<T>(scopeName: string, fn: () => Promise<T>)` | `Promise<T>` |
| `unscoped` | `<T>(fn: () => Promise<T>)` | `Promise<T>` |

### withoutScope

Temporarily bypasses a specific named scope. Queries within the callback run without that scope's filter:

```ts
await fortress.plugins['data-isolation'].withoutScope('organization', async () => {
  // Queries here run without the 'organization' filter
  const allPosts = await db.findMany({ model: 'post' });
});
```

### unscoped

Temporarily bypasses all scopes. Use with caution -- no row-level isolation is applied within the callback:

```ts
await fortress.plugins['data-isolation'].unscoped(async () => {
  // No scoping at all
  const everything = await db.findMany({ model: 'post' });
});
```

## Using Scoped DB in Middleware

In Hono and Express, use the `getScopedDb` helper to get a database adapter with isolation applied:

```ts
app.get('/api/posts', async (c) => {
  const scopedDb = await getScopedDb(c, 'post');
  const posts = await scopedDb.findMany({ model: 'post' });
  // Only returns posts the current user has access to
});
```

## Example

```ts
import { createFortress } from '@bajustone/fortress';
import { dataIsolation } from '@bajustone/fortress/plugins/data-isolation';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!!' },
  database: adapter,
  plugins: [
    dataIsolation({
      scopes: [
        {
          name: 'organization',
          field: 'orgId',
          models: ['post', 'comment', 'invoice'],
          resolveValue: async (userId, ctx) => {
            const user = await ctx.db.findOne({
              model: 'user',
              where: [{ field: 'id', operator: '=', value: userId }],
            });
            return user?.orgId;
          },
        },
        {
          name: 'department',
          field: 'deptId',
          models: ['ticket'],
          resolveValue: async (userId, ctx) => {
            const user = await ctx.db.findOne({
              model: 'user',
              where: [{ field: 'id', operator: '=', value: userId }],
            });
            return user?.deptId;
          },
        },
      ],
    }),
  ],
});

// Admin operation that needs cross-org visibility:
await fortress.plugins['data-isolation'].withoutScope('organization', async () => {
  const allInvoices = await db.findMany({ model: 'invoice' });
});
```
