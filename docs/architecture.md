# Fortress Architecture

## Overview

Fortress is a framework-agnostic, adapter-based authentication and authorization library for TypeScript. The core provides auth (JWT, refresh tokens, password hashing) and IAM (groups, roles, permissions). Everything else — OAuth, tenancy, 2FA, email verification — is a plugin.

Published on JSR as `@bajustone/fortress`.

## Module Structure

```
src/
  index.ts                              # createFortress() factory, re-exports

  core/
    types.ts                            # All domain types and interfaces
    config.ts                           # FortressConfig type + defaults
    errors.ts                           # Unified error hierarchy
    plugin.ts                           # FortressPlugin interface, hook runner, plugin registry

    auth/
      jwt.ts                            # JWT sign/verify (jose)
      password.ts                       # PasswordHasher interface + default impl
      refresh-token.ts                  # Token generation, hashing, rotation logic
      auth-service.ts                   # Login, refresh, logout, me, createUser

    iam/
      permission-evaluator.ts           # Resource+action permission evaluation, conditions, deny
      iam-service.ts                    # Groups, roles, permissions CRUD
      resource-sync.ts                  # Load/export fortress.resources.json, DB sync

  adapters/
    database/
      index.ts                          # DatabaseAdapter interface (generic CRUD)
      types.ts                          # DB adapter types (transaction handle, etc.)

  testing/
    index.ts                            # createTestAdapter() — in-memory SQLite via bun:sqlite

  drizzle/
    index.ts                            # createDrizzleAdapter() export
    adapter.ts                          # DatabaseAdapter implementation (PostgreSQL, MySQL, SQLite)
    schema.ts                           # Reference Drizzle table definitions
    internal-adapter.ts                 # Entity-specific query layer on top of generic CRUD

  hono/
    index.ts                            # createHonoMiddleware() export
    middleware/
      auth.ts                           # Bearer token extraction + JWT verify
      rbac.ts                           # Resource+action permission check via route mapping
      error-handler.ts                  # FortressError → HTTP response
    helpers.ts                          # getUserId() context helpers

  plugins/
    tenancy/
      index.ts                          # tenancy() plugin factory
    oauth/
      index.ts                          # oauth() plugin factory
      pkce.ts                           # PKCE S256 challenge/verification
    two-factor/
      index.ts                          # twoFactor() plugin factory
    email-verification/
      index.ts                          # emailVerification() plugin factory
    api-key/
      index.ts                          # apiKey() plugin factory
    data-isolation/
      index.ts                          # dataIsolation() plugin factory
    social-login/
      index.ts                          # socialLogin() plugin factory
      providers/                        # Built-in provider configs
        microsoft.ts
        google.ts
        github.ts
        apple.ts
        discord.ts
        oidc.ts                         # Generic OIDC provider
```

## Key Design Decisions

### 1. Generic CRUD DatabaseAdapter (Lucia Lesson)

Lucia Auth was deprecated because its per-entity adapter interface was an unsustainable complexity tax. Better Auth survived by using a generic 5-method CRUD contract. We follow Better Auth's approach.

```typescript
interface DatabaseAdapter {
  create<T>(params: {
    model: string;
    data: Record<string, unknown>;
  }): Promise<T>;

  findOne<T>(params: {
    model: string;
    where: WhereClause[];
  }): Promise<T | null>;

  findMany<T>(params: {
    model: string;
    where?: WhereClause[];
    limit?: number;
    offset?: number;
    sortBy?: { field: string; direction: 'asc' | 'desc' };
  }): Promise<T[]>;

  update<T>(params: {
    model: string;
    where: WhereClause[];
    data: Record<string, unknown>;
  }): Promise<T>;

  delete(params: {
    model: string;
    where: WhereClause[];
  }): Promise<void>;

  count(params: {
    model: string;
    where?: WhereClause[];
  }): Promise<number>;

  transaction<T>(fn: (tx: DatabaseAdapter) => Promise<T>): Promise<T>;

  /** Optional: raw query for performance-critical multi-table operations (e.g., permission chain JOINs).
   *  Adapters that implement this get optimized IAM queries. Others fall back to multiple findMany calls. */
  rawQuery?<T>(sql: string, params?: unknown[]): Promise<T[]>;
}

interface WhereClause {
  field: string;
  operator: string;   // open string — core uses '=', '!=', 'in', 'gt', 'lt', 'gte', 'lte'
                      // adapters MAY support additional operators: 'like', 'isNull', 'between', etc.
  value: unknown;
}

// Built-in operators that all adapters MUST support:
type CoreOperator = '=' | '!=' | 'in' | 'gt' | 'lt' | 'gte' | 'lte';
```

**Why `operator` is an open `string`, not a closed union:**
New operators (`like`, `isNull`, `between`) can be added by plugins or consumers without breaking existing adapters. Adapters throw on unsupported operators at runtime. The `CoreOperator` type documents the required minimum.

**Why `rawQuery` exists:**
The IAM permission chain (user → group → role_binding → role_permission → permission) requires multi-table JOINs. With only `findMany`, this becomes 4 sequential queries. `rawQuery` lets the Drizzle adapter execute a single JOIN query. Adapters that don't implement it fall back to multiple `findMany` calls — slower but correct.

Entity-specific logic lives in an internal adapter layer that Fortress builds on top of this generic contract. Adapter authors implement 7 required methods (+1 optional), not 40+.

**Core models:** `user`, `refresh_token`, `group`, `group_user`, `role`, `role_binding`, `permission`, `role_permission`, `resource`

**Plugin models:** Plugins declare their own models (e.g., `oauth_client`, `two_factor_secret`) — handled by the same generic CRUD adapter with no adapter changes needed.

### 2. jose for JWT (not jsonwebtoken)

`jsonwebtoken` doesn't support ESM, doesn't work on edge runtimes, and has no native TypeScript types. `jose` uses the Web Crypto API, works everywhere (Bun, Deno, Cloudflare Workers, Node), is zero-dependency, and tree-shakeable.

```typescript
// src/core/auth/jwt.ts
import { SignJWT, jwtVerify } from 'jose';

async function signAccessToken(
  claims: TokenClaims,
  secret: Uint8Array,
  expiresInSeconds: number,
): Promise<string> {
  return new SignJWT({ ...claims })
    .setProtectedHeader({ alg: 'HS256' })
    .setIssuedAt()
    .setExpirationTime(`${expiresInSeconds}s`)
    .setIssuer(claims.iss)
    .setSubject(String(claims.sub))
    .sign(secret);
}

async function verifyAccessToken(
  token: string,
  secrets: Uint8Array[],  // try each secret in order (supports rotation)
): Promise<TokenClaims> {
  for (const secret of secrets) {
    try {
      const { payload } = await jwtVerify(token, secret);
      return payload as TokenClaims;
    } catch { continue; }
  }
  throw Errors.unauthorized('Invalid token');
}
```

**Secret rotation:** `jwt.secret` accepts `string | string[]`. When an array, the first secret is used for signing, all are tried for verification. This allows zero-downtime secret rotation:

```typescript
// 1. Add new secret, keep old one for verification:
jwt: { secret: ['new-secret', 'old-secret'] }
// Signs with 'new-secret', verifies against both

// 2. After all old tokens expire, remove old secret:
jwt: { secret: 'new-secret' }
```

### 3. Pluggable PasswordHasher (cross-runtime)

`@node-rs/argon2` uses native bindings that break on Deno Deploy and serverless. Password hashing is a pluggable interface with a WASM-based default.

```typescript
interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(hash: string, password: string): Promise<boolean>;
}
```

**Default:** WASM-based Argon2id (via `hash-wasm` or `@oslojs/crypto`)
**Optional swaps:** `@node-rs/argon2`, `Bun.password`, custom implementation

```typescript
const fortress = createFortress({
  // ...
  passwordHasher: customArgon2Hasher, // optional, defaults to WASM impl
});
```

### 4. No FrameworkAdapter Interface

Better Auth and Auth.js both use Web Standard `Request`/`Response` as the abstraction layer. Custom framework interfaces add dead weight. Each framework package (hono/, future express/) exports middleware factories specific to that framework.

### 5. Everything Beyond Core Auth + IAM Is a Plugin

OAuth, tenancy, 2FA, email verification — all are plugins. No special `modules` config, no `withX()` wrappers. This keeps the core small and makes extensibility uniform.

### 6. Composable Entry Points

Users who only need JWT or password hashing shouldn't pull in the full system. Following the `@oslojs/*` pattern (by Lucia's author), each piece is independently importable.

### 7. Database-Agnostic Core

Fortress core and the Drizzle adapter work with **any Drizzle-supported database**: PostgreSQL, MySQL, SQLite. The generic CRUD `DatabaseAdapter` uses standard SQL operations that are portable across databases.

| Database | Core Auth | IAM/RBAC | Data Isolation (row-level) | Tenancy (schema isolation) |
|----------|-----------|----------|---------------------------|---------------------------|
| PostgreSQL | Yes | Yes | Yes | Yes |
| MySQL | Yes | Yes | Yes | No |
| SQLite | Yes | Yes | Yes | No |
| bun:sqlite (in-memory) | Yes | Yes | Yes | No |

The **tenancy plugin** (schema-per-tenant via `SET LOCAL search_path`) is the only PostgreSQL-specific feature. It's opt-in — consumers on MySQL or SQLite use the **data isolation plugin** for row-level multi-tenancy instead.

**Dialect-specific schemas:** Fortress provides default table definitions per dialect:
- `@bajustone/fortress/drizzle` — SQLite schema (default, used for testing)
- `@bajustone/fortress/drizzle/pg` — PostgreSQL schema (`pgTable`, `serial`, `varchar`, `timestamp`)

**Configurable table mapping:** For existing projects with their own tables, the adapter accepts a table map that overrides defaults:

```typescript
// New project — use fortress default schema
const adapter = createDrizzleAdapter(db);

// Existing project — map to your own tables
import { users, refreshTokens } from './your-schema';

const adapter = createDrizzleAdapter(db, {
  tables: {
    user: users,                    // your Drizzle table definition
    refresh_token: refreshTokens,   // fortress maps model names to your tables
    login_identifier: loginKeys,    // bring your own login identifiers table
    // ... any table you want to override
  },
});
```

When `tables` is provided, fortress uses the consumer's table definitions instead of its own. Unmapped models fall back to the default fortress tables. This lets existing projects adopt fortress incrementally — override only the tables you already have, let fortress create the rest.

For **testing**, in-memory SQLite provides a zero-setup database:

```typescript
import { createTestAdapter } from '@bajustone/fortress/testing';
const adapter = createTestAdapter();  // in-memory SQLite, auto-creates tables
```

### 8. Transport-Agnostic Permissions (Resource + Action)

Permissions are modeled as `resource` + `action`, not `path` + `httpVerb`. This is the pattern used by GCP IAM (`storage.objects.get`), AWS IAM (`s3:GetObject`), and Kubernetes RBAC (`pods` + `get`). HTTP-to-resource mapping happens in the framework adapter layer, not the permission definition.

**Why not path + httpVerb:**
- Breaks for non-HTTP contexts (CLI, cron jobs, background workers, WebSocket, events)
- URL refactoring breaks all permission records in the database
- Multiple routes mapping to the same logical operation need duplicate permissions
- `SERVICE_ACCOUNT` principal type becomes unusable without HTTP context

### 8. Resource Definition File (`fortress.resources.json`)

Resources and their allowed actions are defined in a JSON file that serves as the source of truth, with bidirectional sync to the database.

```jsonc
// fortress.resources.json
{
  "resources": {
    "user": {
      "actions": ["create", "read", "update", "delete", "list", "ban"],
      "description": "User management"
    },
    "post": {
      "actions": ["create", "read", "update", "delete", "publish"],
      "description": "Blog posts"
    },
    "invoice": {
      "actions": ["create", "read", "void", "export"],
      "description": "Financial invoices"
    }
  }
}
```

**Sync commands:**
```bash
# JSON → DB: seed/update resources on deploy
bun run fortress sync:push

# DB → JSON: export after runtime changes via admin UI
bun run fortress sync:pull
```

**Benefits:**
- **Version controlled** — changes tracked in git, reviewed in PRs
- **Deploy-time seeding** — CI/CD runs `sync:push` after migrations
- **Runtime flexible** — admin UI creates new resources, `sync:pull` captures them back
- **Environment consistent** — same file deploys to staging and production
- **Validation** — `checkPermission()` can validate against known resources/actions
- **No OpenAPI coupling** — replaces the fragile `setup-resources <openapi-url>` pattern

**Optional type generation:**
```bash
# Generate TypeScript types from the resource file
bun run fortress sync:types
```

```typescript
// Generated: fortress.resources.d.ts
type FortressResource = 'user' | 'post' | 'invoice';
type FortressAction<R extends FortressResource> =
  R extends 'user' ? 'create' | 'read' | 'update' | 'delete' | 'list' | 'ban' :
  R extends 'post' ? 'create' | 'read' | 'update' | 'delete' | 'publish' :
  R extends 'invoice' ? 'create' | 'read' | 'void' | 'export' :
  never;
```

This gives compile-time safety without requiring resources to be defined in code.

---

## IAM Permission Model

### Permission Structure

```typescript
interface Permission {
  id: number;
  resource: string;     // "user", "post", "invoice"
  action: string;       // "create", "read", "update", "delete"
  effect: 'ALLOW' | 'DENY';  // default: 'ALLOW'
  conditions?: PermissionCondition[];
}

interface PermissionCondition {
  field: string;        // "resource.ownerId", "request.ip", "user.department"
  operator: 'eq' | 'neq' | 'in' | 'startsWith';
  value: string | string[];  // supports context variables like "${user.id}"
}
```

### Permission Chain (Simplified)

The `principal` table is dropped. Role bindings reference subjects directly via `subjectType` + `subjectId`, matching the Kubernetes RBAC pattern.

```
User ──┐
       ├── RoleBinding ── Role ── RolePermission ── Permission
Group ─┘
  (via group_user)
```

**Before:** User → Group → Principal → RoleBinding → Role → Permission (5 hops)
**After:** User → (direct or via Group) → RoleBinding → Role → Permission (3 hops)

```typescript
interface RoleBinding {
  id: number;
  roleId: number;
  subjectType: 'USER' | 'GROUP' | 'SERVICE_ACCOUNT';
  subjectId: number;
}
```

### Core DB Models (updated)

| Model | Fields | Notes |
|-------|--------|-------|
| `user` | id, email, name, passwordHash, isActive, timestamps | Core identity. Password on user row (not in junction table). |
| `login_identifier` | id, userId, type, value | Multiple login methods per user (email, phone, username). Value is globally unique. |
| `refresh_token` | id, userId, tokenHash, tokenFamily, isRevoked, expiresAt, ipAddress, userAgent | Token rotation |
| `group` | id, name, description | User grouping |
| `group_user` | groupId, userId | M2M junction |
| `resource` | name (PK), description | Resource type registry |
| `permission` | id, resource, action, effect, conditions (JSON), description | Transport-agnostic |
| `role` | id, name, description | Collection of permissions |
| `role_permission` | roleId, permissionId | M2M junction |
| `role_binding` | id, roleId, subjectType, subjectId | Direct subject reference |

### Multi-Key Login

Users can login with email, phone number, or username — all sharing the same password.

```typescript
// login_identifier model
{
  id: number;
  userId: number;           // FK to user
  type: 'email' | 'phone' | 'username';
  value: string;            // globally unique — the actual login identifier
}
```

**Login flow:**
```
1. login('alice@example.com', password)
2. Find login_identifier where value = 'alice@example.com'
3. Get user by identifier.userId
4. Verify user.passwordHash against password
5. Issue tokens
```

**Why not a junction table (loyalbook's approach):**
Loyalbook uses `user_keys → userKeysPasswords → keyPasswords` (3 tables, many-to-many). This implies users could have different passwords for different login methods — but that feature is never used. One password per user on the `user` row + a flat `login_identifier` table achieves the same result with one JOIN instead of three, no orphaned records, and no dead fields.

**Identifier management:**
```typescript
fortress.auth.addLoginIdentifier(userId, 'phone', '+250788123456');
fortress.auth.addLoginIdentifier(userId, 'username', 'alice');
fortress.auth.removeLoginIdentifier(userId, 'phone', '+250788123456');
fortress.auth.getLoginIdentifiers(userId);
// → [{ type: 'email', value: 'alice@example.com' }, { type: 'phone', value: '+250788123456' }]
```

When a user is created with `createUser({ email, name, password })`, a `login_identifier` of type `email` is automatically created.

### Permission Evaluation

```typescript
// Evaluation modes (configurable)
type EvaluationMode = 'allow-only' | 'deny-overrides';

// 'allow-only': if any ALLOW matches → allow, otherwise deny
// 'deny-overrides' (AWS-style):
//   1. Collect all matching permissions
//   2. If any DENY matches → deny (overrides everything)
//   3. If any ALLOW matches → allow
//   4. Otherwise → deny (implicit)
```

### Programmatic Permission Check

```typescript
// Core API — transport-agnostic, works everywhere
fortress.iam.checkPermission(
  userId: number,
  resource: string,
  action: string,
  context?: PermissionContext,
): Promise<boolean>;

interface PermissionContext {
  resource?: Record<string, unknown>;  // resource instance attributes
  request?: Record<string, unknown>;   // request metadata
  user?: Record<string, unknown>;      // extra user attributes
}
```

**Usage in different contexts:**

```typescript
// HTTP route handler
const allowed = await fortress.iam.checkPermission(userId, 'post', 'update', {
  resource: { ownerId: post.authorId },
});

// Cron job
await fortress.iam.checkPermission(serviceAccountId, 'report', 'generate');

// WebSocket handler
await fortress.iam.checkPermission(userId, 'dashboard', 'subscribe');

// CLI command
await fortress.iam.checkPermission(adminId, 'user', 'ban');
```

### Condition Evaluation

Conditions enable fine-grained access control like "users can only edit their own posts":

```typescript
// Role "author" has this permission:
{
  resource: 'post',
  action: 'update',
  effect: 'ALLOW',
  conditions: [
    { field: 'resource.ownerId', operator: 'eq', value: '${user.id}' }
  ]
}

// At check time, the condition is evaluated:
fortress.iam.checkPermission(userId, 'post', 'update', {
  resource: { ownerId: 42 },  // post's actual owner
});
// → userId === 42 ? ALLOW : DENY
```

`${user.id}` is resolved from the authenticated user context. Other supported variables:
- `${user.id}` — authenticated user's ID
- `${user.groups}` — user's group names
- `${request.ip}` — request IP (if provided in context)

### Hono RBAC Middleware: HTTP-to-Resource Mapping

The Hono adapter maps HTTP requests to resource+action checks. The permission model stays transport-agnostic; the mapping is framework-specific.

```typescript
import { createHonoMiddleware } from '@bajustone/fortress/hono';

const { authMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, {
  // Declarative route-to-resource mapping
  routeMap: {
    'POST /api/users': { resource: 'user', action: 'create' },
    'GET /api/users': { resource: 'user', action: 'list' },
    'GET /api/users/:id': { resource: 'user', action: 'read' },
    'PUT /api/users/:id': { resource: 'user', action: 'update' },
    'DELETE /api/users/:id': { resource: 'user', action: 'delete' },
    'POST /api/posts': { resource: 'post', action: 'create' },
    'POST /api/posts/:id/publish': { resource: 'post', action: 'publish' },
  },

  // Or a function for dynamic mapping
  mapRequest: (method, path) => {
    // Custom logic to derive resource+action from HTTP request
    return { resource: 'user', action: 'read' };
  },

  // Paths that skip permission checks entirely
  skipPaths: ['/health', '/docs', '/auth/*'],
});
```

The `rbacMiddleware` uses the route map to translate `POST /api/users` into `checkPermission(userId, 'user', 'create')`. The permission table never stores HTTP paths.

---

## Plugin System

### Plugin Interface

```typescript
interface FortressPlugin {
  /** Unique plugin identifier */
  name: string;

  /** DB models this plugin needs (generic CRUD handles them) */
  models?: ModelDefinition[];

  /** Hooks into auth lifecycle (executed in plugin registration order) */
  hooks?: PluginHooks;

  /** Extra methods exposed on fortress.plugins.<name> */
  methods?: (ctx: PluginContext) => Record<string, Function>;

  /** HTTP routes this plugin adds (e.g., OAuth endpoints) */
  routes?: RouteDefinition[];

  /** Middleware to inject into the request pipeline */
  middleware?: MiddlewareDefinition[];

  /** Wrap the DatabaseAdapter per-request (e.g., tenancy schema scoping) */
  wrapAdapter?: (
    adapter: DatabaseAdapter,
    requestContext: Record<string, unknown>,
  ) => DatabaseAdapter;

  /** Extend JWT token claims (e.g., tenancy adds tenantId/tenantCode) */
  enrichTokenClaims?: (
    userId: number,
    ctx: PluginContext,
  ) => Promise<Record<string, unknown>>;

  /** Scope data access by user context (row-level data isolation).
   *  Returns filters for reads (findOne/findMany/count/delete) AND
   *  default values to auto-inject on creates. */
  scopeRules?: (
    userId: number,
    model: string,
    ctx: PluginContext,
  ) => Promise<ScopeRule | null>;
}

/** Scope rules for a model — applied to both reads and writes */
interface ScopeRule {
  /** WHERE clauses auto-injected on findOne, findMany, count, update, delete */
  filters: WhereClause[];
  /** Default values auto-injected on create (e.g., { siteId: 3, organizationId: 7 }) */
  defaults: Record<string, unknown>;
}
```

### Hook Types

```typescript
interface PluginHooks {
  // "before" hooks — can inspect/modify input or short-circuit with HookResult
  beforeLogin?: (ctx: HookContext & { email: string }) => Promise<HookResult | void>;
  beforeRegister?: (ctx: HookContext & { data: CreateUserInput }) => Promise<HookResult | void>;
  beforeTokenRefresh?: (ctx: HookContext & { token: string }) => Promise<HookResult | void>;
  beforeLogout?: (ctx: HookContext & { token: string }) => Promise<void>;

  // "after" hooks — can modify result and set response headers (cookies, etc.)
  afterLogin?: (ctx: AfterHookContext, result: AuthResponse) => Promise<AuthResponse>;
  afterRegister?: (ctx: AfterHookContext, user: FortressUser) => Promise<void>;
  afterTokenRefresh?: (ctx: AfterHookContext, result: AuthTokenPair) => Promise<AuthTokenPair>;
}

/** Base context for all hooks */
interface HookContext {
  db: DatabaseAdapter;
  config: FortressConfig;
  meta?: RequestMeta;
}

/** Extended context for "after" hooks — includes response header access */
interface AfterHookContext extends HookContext {
  /** Set response headers (e.g., Set-Cookie for sessions plugin).
   *  Web Standard Headers API — supports append() for multi-value headers (Set-Cookie),
   *  case-insensitive names, and works across Bun, Deno, and Node 18+.
   *  Framework adapter (Hono, Express) forwards these to the HTTP response. */
  responseHeaders: Headers;
}

/** Returning HookResult from a "before" hook short-circuits the flow */
interface HookResult {
  stop: true;
  response: Record<string, unknown>;
}
```

### Supporting Types

```typescript
interface ModelDefinition {
  name: string;
  fields: Record<string, FieldDefinition>;
}

interface FieldDefinition {
  type: 'string' | 'number' | 'boolean' | 'date';
  required?: boolean;
  unique?: boolean;
  references?: { model: string; field: string };
}

interface PluginContext {
  db: DatabaseAdapter;
  config: FortressConfig;
  auth: Fortress['auth'];
}

interface RouteDefinition {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  handler: string;  // method name from methods
}

interface MiddlewareDefinition {
  path: string;                        // path pattern (e.g., '/api/*')
  position: 'before-auth' | 'after-auth' | 'after-rbac';
  handler: (ctx: PluginContext, request: unknown, next: () => Promise<void>) => Promise<void>;
}
```

### Plugin Capability Matrix

| Capability | Use Case | Example |
|-----------|----------|---------|
| `models` | Declare new DB tables | 2FA needs `two_factor_secret`, `backup_code` |
| `hooks` | Intercept/modify auth lifecycle | 2FA intercepts login, email verification blocks unverified users |
| `methods` | Expose new operations | `fortress.plugins['two-factor'].enable(userId)` |
| `routes` | Add HTTP endpoints | OAuth adds `/oauth/authorize`, `/oauth/token` |
| `middleware` | Inject per-request logic | Tenancy sets DB schema search_path |
| `wrapAdapter` | Modify DB behavior per-request | Tenancy scopes all queries to tenant schema |
| `enrichTokenClaims` | Add custom JWT claims | Tenancy adds `tenantId`, `tenantCode` to tokens |
| `scopeRules` | Auto-inject WHERE clauses on reads + default values on creates | Data isolation scopes queries and auto-sets scope fields on inserts |

### Plugin Composition Rules

**`wrapAdapter` chaining:** When multiple plugins define `wrapAdapter`, they chain in registration order. Each wrapper receives the result of the previous:

```typescript
plugins: [
  tenancy({ ... }),        // wrapAdapter #1: sets search_path
  dataIsolation({ ... }),  // wrapAdapter #2: injects WHERE clauses
]

// Execution: dataIsolation wraps tenancy's wrapped adapter
// adapter → tenancy.wrapAdapter(adapter) → dataIsolation.wrapAdapter(wrappedAdapter)
```

**`enrichTokenClaims` merging:** Claims from all plugins are shallow-merged into `customClaims`. If two plugins set the same key, the later plugin wins (registration order). Fortress logs a warning on key conflicts in development mode.

**`scopeRules` stacking:** All applicable scope filters from all plugins are AND'd together on every query. A plugin returning `null` means "no filter from me" (not "bypass all").

### Why This Works with Generic CRUD

Plugins declare new models (`oauth_client`, `two_factor_secret`, `trusted_device`) and query them through the same `create`/`findOne`/`update`/`delete` contract. No adapter changes needed. A per-entity adapter (like Lucia's) would require adapter authors to update their code for every new plugin — which is exactly what killed Lucia.

---

## Official Plugins

### Tenancy Plugin

Schema-per-tenant isolation for **PostgreSQL only**. Uses the deepest plugin capabilities: `wrapAdapter` (scopes queries to tenant schema via `SET LOCAL search_path`), `middleware` (reads `X-Tenant-Code` header), and `enrichTokenClaims` (adds tenant info to JWT).

> **Note:** This plugin requires PostgreSQL — it uses schema-level isolation (`SET LOCAL search_path`), which is a PostgreSQL-specific feature. For database-agnostic multi-tenancy, use the **Data Isolation plugin** with row-level filtering (`WHERE tenant_id = ?`) instead — it works on any database (PostgreSQL, MySQL, SQLite).

```typescript
import { tenancy } from '@bajustone/fortress/plugins/tenancy';

const fortress = createFortress({
  // ...
  plugins: [
    tenancy({
      headerName: 'X-Tenant-Code',   // default
      schemaPrefix: 'tenant_',       // default
    }),
  ],
});

// Plugin methods
await fortress.plugins.tenancy.createTenant({ name: 'Acme', taxId: 'acme-001' });
await fortress.plugins.tenancy.addUserToTenant(userId, tenantId);
await fortress.plugins.tenancy.getUserTenants(userId);
await fortress.plugins.tenancy.switchTenant(userId, 'acme-001');
```

**Models:** `tenant`, `tenant_user`

**Hooks:**
- `enrichTokenClaims` — adds `tenantId`, `tenantCode` to JWT
- `afterLogin` — resolves user's default tenant, includes in response
- `afterRegister` — optionally assigns user to a default tenant

**Middleware:**
- Reads `X-Tenant-Code` header, validates user belongs to tenant, sets tenant context

**wrapAdapter:**
- Returns a wrapped `DatabaseAdapter` that executes queries within tenant schema (`SET LOCAL search_path TO tenant_{taxId}, public`)

### OAuth Plugin

OAuth 2.0 authorization server with PKCE. Uses `routes` to add OAuth endpoints and `methods` for client management.

```typescript
import { oauth } from '@bajustone/fortress/plugins/oauth';

const fortress = createFortress({
  // ...
  plugins: [
    oauth({
      authCodeExpirySeconds: 600,   // default: 10 min
    }),
  ],
});

// Plugin methods
await fortress.plugins.oauth.createClient({ name: 'My App', redirectUris: [...], grantTypes: ['authorization_code'] });
await fortress.plugins.oauth.revokeToken(token);
```

**Models:** `oauth_client`, `oauth_authorization_code`, `oauth_access_token`, `oauth_pending_flow`

**Routes:**
- `GET /oauth/authorize` — authorization endpoint (handles both authenticated and unauthenticated users)
- `POST /oauth/token` — token exchange (auth code + PKCE, client credentials)
- `POST /oauth/revoke` — token revocation (RFC 7009)
- `GET /oauth/userinfo` — OpenID Connect userinfo

**Login continuation (identity broker support):**

When Fortress acts as an OIDC provider to external apps (e.g., Moodle) and delegates authentication to upstream providers (e.g., Microsoft via social login plugin), the `/oauth/authorize` endpoint must handle unauthenticated users:

```
1. Moodle redirects user to: GET /oauth/authorize?client_id=moodle-lms&redirect_uri=...&code_challenge=...
2. User is NOT authenticated → Fortress stores the OAuth params in a short-lived pending flow:
   → oauth_pending_flow { id, clientId, redirectUri, scope, state, codeChallenge, expiresAt }
3. Fortress redirects to login page: /auth/login?continue=<pending_flow_id>
4. User authenticates (via Microsoft social login, password, or any method)
5. After successful auth, Fortress checks for pending flow via the `continue` param
6. Fortress resumes /oauth/authorize with the now-authenticated user:
   → Generates authorization code
   → Redirects back to Moodle with the code
```

This is the standard identity broker pattern used by Keycloak, Auth0, and Okta. The `oauth_pending_flow` record is short-lived (default: 10 minutes) and single-use.

```typescript
oauth({
  authCodeExpirySeconds: 600,
  pendingFlowExpirySeconds: 600,      // default: 10 min
  loginUrl: '/auth/login',            // where to redirect unauthenticated users
})
```

**Identity broker example (Moodle → Fortress → Microsoft):**

```typescript
// Fortress configured as both provider and consumer:
plugins: [
  // Consumer: authenticate users via Microsoft
  socialLogin({
    providers: [{ name: 'microsoft', clientId: '...', clientSecret: '...', tenant: '...' }],
    autoRegister: true,
  }),

  // Provider: Moodle connects to Fortress as its IdP
  oauth({ loginUrl: '/auth/login' }),
]

// Register Moodle as an OAuth client:
await fortress.plugins.oauth.createClient({
  name: 'RTB Moodle LMS',
  clientId: 'moodle-lms',
  clientSecret: 'generated-secret',
  redirectUris: ['https://lms.rtb.co.rw/auth/oidc/callback'],
  grantTypes: ['authorization_code'],
});

// Moodle configuration:
// Authorization URL: https://tdmp.rtb.co.rw/oauth/authorize
// Token URL:         https://tdmp.rtb.co.rw/oauth/token
// UserInfo URL:      https://tdmp.rtb.co.rw/oauth/userinfo
```

### Two-Factor Authentication Plugin

TOTP, backup codes, and trusted devices.

```typescript
import { twoFactor } from '@bajustone/fortress/plugins/two-factor';

const fortress = createFortress({
  // ...
  plugins: [
    twoFactor({
      totp: { issuer: 'MyApp', period: 30, digits: 6 },
      backupCodes: { count: 10 },
      trustedDeviceDays: 30,
      sendOTP: async (user, code) => { await sendSMS(user.phone, code); },
    }),
  ],
});

// Plugin methods
const setup = await fortress.plugins['two-factor'].enable(userId);
// → { secret, qrCodeUrl, backupCodes }

await fortress.plugins['two-factor'].verify(userId, code, meta);
// → { accessToken, refreshToken } (issues real tokens after 2FA)

await fortress.plugins['two-factor'].disable(userId);
```

**Models:** `two_factor_secret`, `backup_code`, `trusted_device`

**Hooks:**
- `afterLogin` — if 2FA enabled for user, returns `{ requires2FA: true }` instead of tokens. Consumer must then call `verify()` with the TOTP code to get real tokens.

### Email Verification Plugin

Token-based email verification with optional login blocking.

```typescript
import { emailVerification } from '@bajustone/fortress/plugins/email-verification';

const fortress = createFortress({
  // ...
  plugins: [
    emailVerification({
      tokenExpirySeconds: 3600,
      requireBeforeLogin: true,
      sendEmail: async (user, token, verifyUrl) => {
        await mailer.send(user.email, `Verify: ${verifyUrl}`);
      },
    }),
  ],
});

// Plugin methods
await fortress.plugins['email-verification'].sendVerification(userId);
await fortress.plugins['email-verification'].verify(token);
```

**Models:** `email_verification_token`

**Hooks:**
- `beforeLogin` — if `requireBeforeLogin: true`, checks `user.emailVerified` and blocks unverified users
- `afterRegister` — auto-sends verification email on registration

### API Key Plugin

Long-lived API keys for service accounts, POS devices, CI/CD pipelines, and M2M communication. Keys authenticate via the same `Authorization: Bearer` header but are resolved to a SERVICE_ACCOUNT subject for permission evaluation.

```typescript
import { apiKey } from '@bajustone/fortress/plugins/api-key';

const fortress = createFortress({
  // ...
  plugins: [
    apiKey({
      prefix: 'fortress',                // key prefix: fortress_sk_live_...
      hashAlgorithm: 'sha256',           // default
      maxKeysPerAccount: 5,              // default
    }),
  ],
});

// Create a service account for a POS device
const device = await fortress.auth.createUser({
  name: 'POS Terminal - Main Counter',
  email: 'pos-001@devices.internal',
});
await fortress.iam.bindRole('SERVICE_ACCOUNT', device.id, posDeviceRoleId);

// Issue an API key for the device
const result = await fortress.plugins['api-key'].create(device.id, {
  name: 'POS-001 Production Key',
  expiresAt: null,              // no expiry (revocable)
  scopes: ['sale:*', 'shift:*', 'stock:read', 'cash_deposit:create'],  // optional scope restriction
});
// → { key: 'fortress_sk_live_a1b2c3d4e5...', keyId: 'key_abc123' }
// ⚠️ key is shown ONCE — only the SHA256 hash is stored

// List keys for an account (shows metadata, not the key itself)
await fortress.plugins['api-key'].list(device.id);
// → [{ id: 'key_abc123', name: 'POS-001 Production Key', lastUsedAt, createdAt, expiresAt }]

// Revoke a key
await fortress.plugins['api-key'].revoke('key_abc123');

// Rotate: revoke old + issue new in one call
await fortress.plugins['api-key'].rotate('key_abc123', { name: 'POS-001 Rotated Key' });
// → { key: 'fortress_sk_live_f6g7h8i9...', keyId: 'key_def456' }
```

**Models:**

| Model | Fields | Notes |
|-------|--------|-------|
| `api_key` | id, userId, keyHash (SHA256), keyPrefix (first 8 chars), name, scopes (JSON), expiresAt, lastUsedAt, lastUsedIp, isRevoked, createdAt | Hash-only storage, same pattern as refresh tokens |

**Key format:** `{prefix}_sk_{environment}_{random}`
- `fortress_sk_live_a1b2c3d4e5f6...` — production key
- `fortress_sk_test_a1b2c3d4e5f6...` — test key
- Prefix enables quick identification and key scanning (e.g., git secret detection)

**Middleware:**
- Extends the auth middleware to recognize API keys alongside JWTs
- If the Bearer token matches the key prefix pattern, resolve via key hash lookup instead of JWT verification
- Sets `subjectType: 'SERVICE_ACCOUNT'` in the request context
- Updates `lastUsedAt` and `lastUsedIp` on each use

**Scope restriction:**
- Keys can optionally be scoped to a subset of the account's permissions
- Format: `resource:action` or `resource:*` (all actions on a resource)
- If scopes are set, permission checks are intersected: the account must have the permission AND the key must include the scope
- If no scopes set, the key inherits all of the account's permissions

```typescript
// Device account has role with: sale:create, sale:void, sale:read, shift:open, shift:close, stock:read
// Key is scoped to: ['sale:create', 'sale:read', 'stock:read']

// ✅ Allowed (account has it AND key scope includes it)
await fortress.iam.checkPermission(deviceId, 'sale', 'create');

// ❌ Denied (account has it BUT key scope doesn't include sale:void)
await fortress.iam.checkPermission(deviceId, 'sale', 'void');
```

This is the same pattern used by GitHub (fine-grained PATs), Stripe (restricted keys), and AWS (scoped credentials).

**Security:**
- Key is returned once at creation, never stored or retrievable
- Only SHA256 hash stored in DB (same pattern as refresh tokens)
- `keyPrefix` (first 8 chars) stored for identification without exposing the full key
- Rate limiting recommended on key validation endpoint (via consumer or future rate-limit plugin)
- Key rotation without downtime via `rotate()` method

### Data Isolation Plugin

General-purpose row-level data isolation primitive. Automatically injects WHERE clauses into queries based on the authenticated user's context. Supports multi-tenancy (shared DB), multi-site, department scoping, or any "users should only see rows that belong to their context" pattern.

```typescript
import { dataIsolation } from '@bajustone/fortress/plugins/data-isolation';

const fortress = createFortress({
  // ...
  plugins: [
    dataIsolation({
      scopes: [
        {
          name: 'organization',
          field: 'organizationId',            // column name in scoped tables
          models: ['invoice', 'product', 'customer', 'report'],
          resolveValue: async (userId, ctx) => {
            // Look up the user's org from the DB or JWT claims
            const membership = await ctx.db.findOne({
              model: 'org_member',
              where: [{ field: 'userId', operator: '=', value: userId }],
            });
            return membership?.organizationId;
          },
        },
        {
          name: 'site',
          field: 'siteId',
          models: ['sale', 'inventory', 'shift', 'cash_deposit'],
          resolveValue: async (userId, ctx) => {
            const assignment = await ctx.db.findOne({
              model: 'user_site_assignment',
              where: [{ field: 'userId', operator: '=', value: userId }],
            });
            return assignment?.siteId;
          },
        },
      ],
    }),
  ],
});
```

**How it works:**

When the DatabaseAdapter processes a query, plugins with `scopeRules` are invoked. The data isolation plugin checks if the queried model is in any scope's `models` list, and if so, injects WHERE clauses on reads and default values on creates:

```typescript
// READS — developer writes:
await db.findMany({ model: 'sale', where: [{ field: 'date', operator: '=', value: '2026-04-03' }] });

// Data isolation plugin automatically injects WHERE clauses:
// → findMany({ model: 'sale', where: [
//     { field: 'date', operator: '=', value: '2026-04-03' },
//     { field: 'siteId', operator: '=', value: 3 },          ← injected
//     { field: 'organizationId', operator: '=', value: 7 },  ← injected
//   ]})

// WRITES — developer writes:
await db.create({ model: 'sale', data: { amount: 5000, date: '2026-04-03' } });

// Data isolation plugin automatically injects scope defaults:
// → create({ model: 'sale', data: {
//     amount: 5000, date: '2026-04-03',
//     siteId: 3,                                              ← injected
//     organizationId: 7,                                      ← injected
//   }})

// Impossible to accidentally read another site's or org's data
```

**Multiple scopes stack.** A model can belong to multiple scopes (e.g., `sale` is scoped by both `organizationId` and `siteId`). All applicable filters are AND'd together.

**Scope configuration:**

```typescript
interface DataIsolationScope {
  /** Scope name for identification and bypass control */
  name: string;

  /** Column name that holds the scoping value in the target tables */
  field: string;

  /** Which models (tables) this scope applies to */
  models: string[];

  /** Resolve the current user's value for this scope */
  resolveValue: (userId: number, ctx: PluginContext) => Promise<unknown>;

  /** Optional: cache the resolved value per request (default: true) */
  cachePerRequest?: boolean;
}
```

**Bypass for admin/cross-scope queries:**

Some operations legitimately need to cross scope boundaries (admin dashboards, analytics, migrations). The plugin provides a controlled bypass:

```typescript
// Admin generating a cross-site report:
await fortress.plugins['data-isolation'].withoutScope('site', async () => {
  // Queries in this callback skip the 'site' scope filter
  const allSales = await db.findMany({ model: 'sale', where: [...] });
  return generateReport(allSales);
});

// Or bypass all scopes:
await fortress.plugins['data-isolation'].unscoped(async () => {
  // No scope filters applied — use with caution
});
```

Bypass requires the caller to have explicit permission (e.g., `data-isolation:bypass` action in the IAM system).

**Models:** `user_scope_assignment` (optional — maps users to their scope values if not stored elsewhere)

| Model | Fields | Notes |
|-------|--------|-------|
| `user_scope_assignment` | userId, scopeName, scopeValue, createdAt | Optional. Only needed if scope values aren't derivable from existing tables |

**Hooks:**
- `enrichTokenClaims` — optionally embeds scope values in JWT for fast access without DB lookup

**scopeRules implementation:**

```typescript
// The plugin implements the scopeRules capability:
scopeRules: async (userId, model, ctx) => {
  const filters: WhereClause[] = [];
  const defaults: Record<string, unknown> = {};

  for (const scope of config.scopes) {
    if (!scope.models.includes(model)) continue;

    const value = await scope.resolveValue(userId, ctx);
    if (value === undefined || value === null) continue;

    // For reads: WHERE siteId = 3
    filters.push({ field: scope.field, operator: '=', value });

    // For writes: auto-set siteId = 3 on create
    defaults[scope.field] = value;
  }

  return filters.length > 0 ? { filters, defaults } : null;
}
```

This means developers **cannot accidentally create a sale in the wrong site** — the scope value is injected automatically, just like reads are filtered automatically.

**Multi-tenancy strategies comparison:**

| Strategy | Plugin | Isolation | Cross-tenant queries | DB complexity | Best for |
|----------|--------|-----------|---------------------|---------------|----------|
| Schema-per-tenant | `tenancy` | Schema-level (`SET search_path`) | Requires explicit schema switching | High (N schemas, N migrations) | **PostgreSQL only.** Regulatory compliance, fully independent data |
| Row-level (shared DB) | `data-isolation` | Row-level (`WHERE org_id = ?`) | Possible via `unscoped()` bypass | Low (one schema, one migration) | **Any database.** Most SaaS apps, simpler ops |
| Hybrid | Both | Schema for tenants, rows for sites within tenant | Controlled bypass at each level | Medium | **PostgreSQL only.** Multi-site tenants (loyalbook) |

**Real-world examples:**

```typescript
// 1. Simple SaaS multi-tenancy (shared DB, no schema isolation)
dataIsolation({
  scopes: [
    { name: 'tenant', field: 'tenantId', models: ['*'], resolveValue: async (userId, ctx) => getUserTenantId(userId, ctx) },
  ],
})

// 2. Multi-site within a tenant (loyalbook)
dataIsolation({
  scopes: [
    { name: 'site', field: 'siteId', models: ['sale', 'inventory', 'shift', 'cash_deposit'], resolveValue: async (userId, ctx) => getUserSiteId(userId, ctx) },
  ],
})

// 3. Department-scoped data
dataIsolation({
  scopes: [
    { name: 'department', field: 'departmentId', models: ['budget', 'expense', 'timesheet'], resolveValue: async (userId, ctx) => getUserDepartment(userId, ctx) },
  ],
})

// 4. Region-based data residency
dataIsolation({
  scopes: [
    { name: 'region', field: 'regionCode', models: ['customer', 'order', 'payment'], resolveValue: async (userId, ctx) => getUserRegion(userId, ctx) },
  ],
})
```

### Social Login Plugin

OAuth/OIDC consumer for authenticating users via external identity providers (Microsoft, Google, GitHub, etc.). While the OAuth plugin makes Fortress an OAuth *server*, this plugin makes Fortress an OAuth/OIDC *consumer* — it delegates authentication to external providers.

```typescript
import { socialLogin } from '@bajustone/fortress/plugins/social-login';

const fortress = createFortress({
  // ...
  plugins: [
    socialLogin({
      providers: [
        {
          name: 'microsoft',
          clientId: env.MS_CLIENT_ID,
          clientSecret: env.MS_CLIENT_SECRET,
          tenant: env.MS_TENANT_ID,          // or 'common' for multi-tenant
          allowedDomains: ['rtb.co.rw'],     // restrict to specific email domains
          scopes: ['openid', 'profile', 'email', 'User.Read'],
        },
        {
          name: 'google',
          clientId: env.GOOGLE_CLIENT_ID,
          clientSecret: env.GOOGLE_CLIENT_SECRET,
        },
      ],
      autoRegister: true,       // auto-create user on first social login
      linkAccounts: true,       // link social identity to existing user by email

      // Map provider profile fields to Fortress user fields
      mapProfile: (provider, profile) => ({
        email: profile.email,
        name: profile.displayName ?? profile.name,
      }),

      // Called on first-ever login for a social user
      onFirstLogin: async (user, provider, profile) => {
        await fortress.iam.bindRole('USER', user.id, defaultEmployeeRoleId);
      },
    }),
  ],
});
```

**Authentication flow:**

```
1. User clicks "Sign in with Microsoft"
2. App redirects to:    GET /auth/social/microsoft
3. Plugin redirects to Microsoft OIDC (authorization code + PKCE)
4. User authenticates at Microsoft
5. Microsoft redirects to: GET /auth/social/microsoft/callback?code=...&state=...
6. Plugin exchanges code for MS tokens (ID token + access token)
7. Plugin reads user profile (from ID token claims or provider API)
8. Lookup user by provider account ID or email:
   a. User exists → login, issue Fortress tokens
   b. User doesn't exist + autoRegister → create user, link social account, issue tokens
   c. User doesn't exist + !autoRegister → reject with UnauthorizedError
```

**Models:**

| Model | Fields | Notes |
|-------|--------|-------|
| `social_account` | id, userId, provider, providerAccountId, email, accessTokenEncrypted, refreshTokenEncrypted, tokenExpiresAt, profile (JSON), createdAt, updatedAt | Links external identity to Fortress user. Provider tokens encrypted at rest. |

**Configuration types:**

```typescript
interface SocialLoginConfig {
  providers: ProviderConfig[];
  autoRegister?: boolean;               // default: true
  linkAccounts?: boolean;               // default: true
  mapProfile?: (provider: string, profile: ProviderProfile) => Partial<CreateUserInput>;
  onFirstLogin?: (user: FortressUser, provider: string, profile: ProviderProfile) => Promise<void>;
}

interface ProviderConfig {
  name: string;                         // 'microsoft', 'google', 'github', etc.
  clientId: string;
  clientSecret: string;
  scopes?: string[];                    // defaults per provider
  // Provider-specific options:
  tenant?: string;                      // Microsoft: tenant ID, 'common', 'organizations'
  allowedDomains?: string[];            // restrict to email domains (e.g., ['rtb.co.rw'])
}

interface ProviderProfile {
  id: string;                           // provider's user ID
  email: string;
  name?: string;
  displayName?: string;
  avatar?: string;
  raw: Record<string, unknown>;         // full provider response
}
```

**Routes:**
- `GET /auth/social/:provider` — initiate OAuth flow (generates state + PKCE, redirects to provider)
- `GET /auth/social/:provider/callback` — handle callback (exchange code, verify state, login/register)

**Hooks:**
- `afterLogin` — for social login sessions, skips password verification (social-only users have no password)
- `afterRegister` — links social account to new user, calls `onFirstLogin` callback
- `enrichTokenClaims` — optionally adds `provider` and `providerAccountId` to JWT

**Key behaviors:**

| Scenario | Behavior |
|----------|----------|
| First login, user doesn't exist | Auto-creates user if `autoRegister: true`, rejects otherwise |
| First login, user exists by email | Links social account to existing user if `linkAccounts: true` |
| Subsequent login | Matches by `providerAccountId`, updates profile/tokens |
| Social-only user (no password) | `passwordHash` is nullable — user can only login via provider |
| User has both password + social | Either login method works independently |
| Provider token refresh | Stored encrypted, refreshed transparently when expired |
| Email domain restriction | `allowedDomains` checked before registration — rejects non-matching domains |
| Multiple providers per user | User can link multiple social accounts (MS + Google) |

**Built-in providers** (pre-configured OIDC discovery URLs, scopes, profile mapping):
- Microsoft Entra ID (Azure AD)
- Google
- GitHub
- Apple
- Discord

**Generic OIDC provider** (for any standards-compliant provider):

```typescript
{
  name: 'corporate-sso',
  clientId: env.SSO_CLIENT_ID,
  clientSecret: env.SSO_CLIENT_SECRET,
  issuer: 'https://sso.company.com',    // OIDC discovery via .well-known
}
```

**Security:**
- PKCE (S256) used for all OAuth flows — no implicit grants
- `state` parameter with CSRF protection
- Provider access/refresh tokens encrypted before storage (AES-256-GCM)
- `allowedDomains` prevents registration from unauthorized email domains
- ID token signature verified against provider's JWKS

---

## Fortress Instance

```typescript
interface Fortress<TPlugins extends FortressPlugin[] = FortressPlugin[]> {
  auth: {
    login(identifier: string, password: string, meta?: RequestMeta): Promise<AuthResponse>;
    refresh(refreshToken: string, meta?: RequestMeta): Promise<AuthTokenPair>;
    logout(refreshToken: string): Promise<void>;
    me(userId: number): Promise<FortressUser>;
    createUser(data: CreateUserInput): Promise<FortressUser>;
    verifyToken(token: string): Promise<TokenClaims>;
    signToken(claims: TokenClaims): Promise<string>;
    addLoginIdentifier(userId: number, type: 'email' | 'phone' | 'username', value: string): Promise<void>;
    removeLoginIdentifier(userId: number, type: string, value: string): Promise<void>;
    getLoginIdentifiers(userId: number): Promise<LoginIdentifier[]>;
  };
  iam: {
    checkPermission(userId: number, resource: string, action: string, context?: PermissionContext): Promise<boolean>;
    getUserPermissions(userId: number): Promise<Permission[]>;
    createRole(name: string, permissions: PermissionInput[]): Promise<Role>;
    bindRole(subjectType: SubjectType, subjectId: number, roleId: number): Promise<void>;
    bindRoleToUser(userId: number, roleId: number): Promise<void>;
    bindRoleToGroup(groupId: number, roleId: number): Promise<void>;
    unbindRole(subjectType: SubjectType, subjectId: number, roleId: number): Promise<void>;
    createGroup(name: string, description?: string): Promise<Group>;
    addUserToGroup(groupId: number, userId: number): Promise<void>;
    removeUserFromGroup(groupId: number, userId: number): Promise<void>;
    syncResources(direction: 'push' | 'pull', filePath?: string): Promise<void>;
  };
  plugins: InferPlugins<TPlugins>;
  config: Readonly<FortressConfig>;
}
```

**Type-safe plugin access:**

Plugins are typed via inference from the `plugins` array — no `Record<string, Record<string, Function>>`. Each plugin factory declares its method types, and `createFortress` infers them:

```typescript
// Plugin factories declare their return types:
function twoFactor(config: TwoFactorConfig): FortressPlugin & {
  _methods: {
    enable(userId: number): Promise<TwoFactorSetup>;
    verify(userId: number, code: string, meta?: RequestMeta): Promise<AuthTokenPair>;
    disable(userId: number): Promise<void>;
  };
};

function tenancy(config: TenancyConfig): FortressPlugin & {
  _methods: {
    createTenant(data: CreateTenantInput): Promise<Tenant>;
    addUserToTenant(userId: number, tenantId: number): Promise<void>;
    getUserTenants(userId: number): Promise<Tenant[]>;
    switchTenant(userId: number, taxId: string): Promise<void>;
  };
};

// InferPlugins extracts _methods from each plugin and maps by plugin name:
type InferPlugins<T extends FortressPlugin[]> = {
  [P in T[number] as P['name']]: P extends { _methods: infer M } ? M : Record<string, Function>;
};

// Result — full autocomplete and type checking:
const fortress = createFortress({
  database: createDrizzleAdapter(db),
  jwt: { secret: env.JWT_SECRET },
  plugins: [
    twoFactor({ totp: { issuer: 'MyApp' } }),
    tenancy({ schemaPrefix: 'tenant_' }),
  ],
});

fortress.plugins['two-factor'].enable(userId);      // ✅ typed: Promise<TwoFactorSetup>
fortress.plugins['two-factor'].verify(userId, code); // ✅ typed: Promise<AuthTokenPair>
fortress.plugins.tenancy.createTenant({ ... });      // ✅ typed: Promise<Tenant>
fortress.plugins.tenancy.foo();                      // ❌ TypeScript error: 'foo' does not exist
fortress.plugins['nonexistent'].bar();               // ❌ TypeScript error
```

## Configuration

```typescript
interface FortressConfig {
  jwt: {
    secret: string | string[];             // string[] for rotation: first signs, all verify
    issuer?: string;                       // default: 'fortress'
    accessTokenExpirySeconds?: number;     // default: 900
    refreshTokenExpirySeconds?: number;    // default: 604800
  };
  rbac?: {
    evaluationMode?: 'allow-only' | 'deny-overrides';  // default: 'allow-only'
    resourceFile?: string;                              // default: './fortress.resources.json'
  };
  database: DatabaseAdapter;
  passwordHasher?: PasswordHasher;         // default: WASM Argon2id
  plugins?: FortressPlugin[];              // optional plugins
}
```

**Minimal setup — only `secret` and `database` are required:**

```typescript
const fortress = createFortress({
  jwt: { secret: env.JWT_SECRET },
  database: createDrizzleAdapter(db),
});
```

## Domain Types

```typescript
// --- Identity ---
interface FortressUser {
  id: number;
  email: string;
  name: string;
  isActive: boolean;
  createdAt: Date;
  updatedAt: Date;
}

// --- Auth ---
interface TokenClaims {
  sub: number;
  name: string;
  groups: string[];
  iss: string;
  iat: number;
  exp: number;
  customClaims?: Record<string, unknown>;  // plugin-injected claims (tenantId, etc.)
}

interface AuthTokenPair {
  accessToken: string;
  refreshToken: string;
}

interface AuthResponse {
  user: FortressUser;
  accessToken: string | null;     // null when 2FA required
  refreshToken: string | null;    // null when 2FA required
  pluginData?: Record<string, unknown>;  // plugin-specific extras (requires2FA, etc.)
}

interface RequestMeta {
  ipAddress?: string;
  userAgent?: string;
}

interface LoginIdentifier {
  id: number;
  userId: number;
  type: 'email' | 'phone' | 'username';
  value: string;
}

// --- IAM ---
interface PermissionInput {
  resource: string;
  action: string;
  effect?: 'ALLOW' | 'DENY';     // default: 'ALLOW'
  conditions?: PermissionCondition[];
}

// --- IAM ---
type SubjectType = 'USER' | 'GROUP' | 'SERVICE_ACCOUNT';

interface Permission {
  id: number;
  resource: string;
  action: string;
  effect: 'ALLOW' | 'DENY';
  conditions?: PermissionCondition[];
  description?: string;
}

interface PermissionCondition {
  field: string;
  operator: 'eq' | 'neq' | 'in' | 'startsWith';
  value: string | string[];
}

interface PermissionContext {
  resource?: Record<string, unknown>;
  request?: Record<string, unknown>;
  user?: Record<string, unknown>;
}

interface Role {
  id: number;
  name: string;
  description?: string;
}

interface RoleBinding {
  id: number;
  roleId: number;
  subjectType: SubjectType;
  subjectId: number;
}

interface Group {
  id: number;
  name: string;
  description?: string;
}
```

## Error Hierarchy

Single `FortressError` class discriminated by `code` — no subclass hierarchy. Factory functions are the public API.

```typescript
type FortressErrorCode =
  | 'UNAUTHORIZED'
  | 'TOKEN_REUSE'
  | 'FORBIDDEN'
  | 'BAD_REQUEST'
  | 'NOT_FOUND'
  | 'RATE_LIMITED'
  | 'DATABASE_ERROR';

class FortressError extends Error {
  readonly code: FortressErrorCode;
  readonly statusCode: number;
  readonly retryAfter?: number;

  constructor(
    code: FortressErrorCode,
    message: string,
    statusCode: number,
    options?: { cause?: unknown; retryAfter?: number },
  ) {
    super(message, { cause: options?.cause });
    this.code = code;
    this.statusCode = statusCode;
    this.retryAfter = options?.retryAfter;
  }

  toJSON(): { code: FortressErrorCode; message: string; statusCode: number } {
    return { code: this.code, message: this.message, statusCode: this.statusCode };
  }
}

// Factory functions (preferred public API):
const Errors = {
  unauthorized: (message = 'Unauthorized') =>
    new FortressError('UNAUTHORIZED', message, 401),
  tokenReuse: () =>
    new FortressError('TOKEN_REUSE', 'Token reuse detected', 401),
  forbidden: (message = 'Forbidden') =>
    new FortressError('FORBIDDEN', message, 403),
  badRequest: (message = 'Bad request') =>
    new FortressError('BAD_REQUEST', message, 400),
  notFound: (message = 'Not found') =>
    new FortressError('NOT_FOUND', message, 404),
  rateLimited: (retryAfter: number) =>
    new FortressError('RATE_LIMITED', 'Too many requests', 429, { retryAfter }),
  database: (message = 'Database error', cause?: unknown) =>
    new FortressError('DATABASE_ERROR', message, 500, { cause }),
} as const;
```

**Why this design:**
- **One class, no inheritance** — `instanceof FortressError` works reliably across package boundaries (subclass `instanceof` breaks with duplicate dependency versions)
- **Factory functions** — tree-shakeable, clean API (`throw Errors.forbidden()`)
- **Discriminated by `code`** — exhaustive `switch(error.code)` works in TypeScript
- **Throwable** — real `Error` with stack traces and `cause` chaining
- **Serializable** — `toJSON()` built in for logging and API responses

**Usage:**

```typescript
// Throwing errors:
throw Errors.unauthorized('Invalid token');
throw Errors.rateLimited(60);
throw Errors.database('Connection failed', originalError);

// Handling errors (exhaustive switch):
if (error instanceof FortressError) {
  switch (error.code) {
    case 'UNAUTHORIZED':   // 401
    case 'TOKEN_REUSE':    // 401 — consumer can force-logout all devices
    case 'FORBIDDEN':      // 403
    case 'BAD_REQUEST':    // 400
    case 'NOT_FOUND':      // 404
    case 'RATE_LIMITED':   // 429 — set Retry-After header from error.retryAfter
    case 'DATABASE_ERROR': // 500 — log error.cause
  }
}
```

The Hono error handler maps `FortressError` to HTTP responses, adding `Retry-After` header for `RATE_LIMITED`.

## JSR Entry Points

```jsonc
{
  "exports": {
    ".": "./src/index.ts",
    "./crypto": "./src/core/auth/password.ts",
    "./jwt": "./src/core/auth/jwt.ts",
    "./testing": "./src/testing/index.ts",
    "./drizzle": "./src/drizzle/index.ts",
    "./hono": "./src/hono/index.ts",
    "./plugins/tenancy": "./src/plugins/tenancy/index.ts",
    "./plugins/oauth": "./src/plugins/oauth/index.ts",
    "./plugins/two-factor": "./src/plugins/two-factor/index.ts",
    "./plugins/email-verification": "./src/plugins/email-verification/index.ts",
    "./plugins/api-key": "./src/plugins/api-key/index.ts",
    "./plugins/data-isolation": "./src/plugins/data-isolation/index.ts",
    "./plugins/social-login": "./src/plugins/social-login/index.ts"
  }
}
```

| Import | Contains |
|--------|----------|
| `@bajustone/fortress` | `createFortress()`, types, errors, `DatabaseAdapter` interface, `FortressPlugin` interface |
| `@bajustone/fortress/crypto` | `PasswordHasher` interface, default WASM hasher |
| `@bajustone/fortress/jwt` | `signToken()`, `verifyToken()` standalone utilities |
| `@bajustone/fortress/testing` | `createTestAdapter()` — in-memory SQLite via bun:sqlite + Drizzle |
| `@bajustone/fortress/drizzle` | `createDrizzleAdapter()`, reference schema tables (PostgreSQL, MySQL, SQLite) |
| `@bajustone/fortress/hono` | `createHonoMiddleware()`, context helpers |
| `@bajustone/fortress/plugins/tenancy` | `tenancy()` plugin factory |
| `@bajustone/fortress/plugins/oauth` | `oauth()` plugin factory |
| `@bajustone/fortress/plugins/two-factor` | `twoFactor()` plugin factory |
| `@bajustone/fortress/plugins/email-verification` | `emailVerification()` plugin factory |
| `@bajustone/fortress/plugins/api-key` | `apiKey()` plugin factory |
| `@bajustone/fortress/plugins/data-isolation` | `dataIsolation()` plugin factory |
| `@bajustone/fortress/plugins/social-login` | `socialLogin()` plugin factory, built-in providers |

## Consumer Usage

### Full setup with plugins

```typescript
import { createFortress } from '@bajustone/fortress';
import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';
import { createHonoMiddleware } from '@bajustone/fortress/hono';
import { tenancy } from '@bajustone/fortress/plugins/tenancy';
import { oauth } from '@bajustone/fortress/plugins/oauth';
import { twoFactor } from '@bajustone/fortress/plugins/two-factor';
import { emailVerification } from '@bajustone/fortress/plugins/email-verification';

const fortress = createFortress({
  jwt: { secret: env.JWT_SECRET, issuer: 'my-app' },
  database: createDrizzleAdapter(db),
  rbac: { evaluationMode: 'deny-overrides' },
  plugins: [
    tenancy({ headerName: 'X-Tenant-Code', schemaPrefix: 'tenant_' }),
    oauth({ authCodeExpirySeconds: 600 }),
    twoFactor({
      totp: { issuer: 'MyApp' },
      sendOTP: async (user, code) => { /* ... */ },
    }),
    emailVerification({
      requireBeforeLogin: true,
      sendEmail: async (user, token, url) => { /* ... */ },
    }),
  ],
});

const { authMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, {
  routeMap: {
    'POST /api/users': { resource: 'user', action: 'create' },
    'GET /api/users': { resource: 'user', action: 'list' },
    'GET /api/users/:id': { resource: 'user', action: 'read' },
    'PUT /api/users/:id': { resource: 'user', action: 'update' },
    'DELETE /api/users/:id': { resource: 'user', action: 'delete' },
    'POST /api/posts': { resource: 'post', action: 'create' },
    'POST /api/posts/:id/publish': { resource: 'post', action: 'publish' },
  },
  skipPaths: ['/health', '/docs', '/auth/*'],
});

app.use('*', errorHandler);
app.use('/api/*', authMiddleware);
app.use('/api/*', rbacMiddleware);

app.post('/auth/login', async (c) => {
  const { identifier, password } = await c.req.json();
  const result = await fortress.auth.login(identifier, password);

  if (result.accessToken === null) {
    // 2FA required — plugin set pluginData.requires2FA
    return c.json({ data: result });
  }
  return c.json({ data: result });
});

// Fine-grained check in route handler
app.put('/api/posts/:id', async (c) => {
  const post = await getPost(c.req.param('id'));
  const allowed = await fortress.iam.checkPermission(userId, 'post', 'update', {
    resource: { ownerId: post.authorId },
  });
  if (!allowed) throw Errors.forbidden();
  // ...
});

// Type-safe plugin access — full autocomplete
const setup = await fortress.plugins['two-factor'].enable(userId);
// setup is typed as TwoFactorSetup: { secret, qrCodeUrl, backupCodes }

await fortress.plugins.tenancy.createTenant({ name: 'Acme', taxId: 'acme-001' });
// fully typed — TypeScript knows tenancy plugin methods

// Convenience methods for common operations
await fortress.iam.bindRoleToUser(userId, editorRoleId);
await fortress.iam.bindRoleToGroup(groupId, viewerRoleId);
```

### Minimal setup (no plugins)

```typescript
import { createFortress } from '@bajustone/fortress';
import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';

// Only secret and database are required — everything else has sensible defaults
const fortress = createFortress({
  jwt: { secret: env.JWT_SECRET },
  database: createDrizzleAdapter(db),
});
```

### Just JWT utilities

```typescript
import { signToken, verifyToken } from '@bajustone/fortress/jwt';

const token = await signToken(claims, secret, 900);
const decoded = await verifyToken(token, secret);
```

### Resource sync workflow

```bash
# 1. Define resources in fortress.resources.json
# 2. Seed DB on deploy
bun run fortress sync:push

# 3. Admin adds new resource via UI at runtime
# 4. Export changes back to file
bun run fortress sync:pull

# 5. Optionally generate TypeScript types
bun run fortress sync:types

# 6. Commit updated file + types
git add fortress.resources.json fortress.resources.d.ts
git commit -m "feat: add invoice resource"
```

## Implementation Sequence

### Phase 1a: Foundation
1. `core/types.ts` — all domain types (Permission, Role, RoleBinding with subjectType)
2. `core/config.ts` — configuration with defaults (evaluationMode, resourceFile)
3. `core/errors.ts` — error hierarchy
4. `adapters/database/index.ts` — generic CRUD DatabaseAdapter interface

### Phase 1b: Core Auth
5. `core/auth/password.ts` — PasswordHasher interface + WASM default
6. `core/auth/jwt.ts` — JWT sign/verify with jose
7. `core/auth/refresh-token.ts` — token generation, hashing, rotation
8. `core/auth/auth-service.ts` — login, refresh, logout orchestration

### Phase 1c: IAM
9. `core/iam/permission-evaluator.ts` — resource+action evaluation, conditions, deny-overrides
10. `core/iam/iam-service.ts` — group/role/permission CRUD, checkPermission
11. `core/iam/resource-sync.ts` — load/export fortress.resources.json, DB sync

### Phase 1d: Plugin System
12. `core/plugin.ts` — FortressPlugin interface, hook runner, plugin registry

### Phase 1e: Drizzle Adapter
13. `drizzle/schema.ts` — reference schema for core models (updated: no principal table, permission has resource+action+effect+conditions)
14. `drizzle/internal-adapter.ts` — entity-specific queries on top of generic CRUD
15. `drizzle/adapter.ts` — generic CRUD implementation for Drizzle (PostgreSQL, MySQL, SQLite)

### Phase 1f: Hono Adapter
16. `hono/middleware/*.ts` — auth, rbac with routeMap, error-handler, plugin mounting
17. `hono/helpers.ts` — context helpers

### Phase 1g: Wiring
18. `src/index.ts` — createFortress() factory with plugin processing

### Phase 2a: Tenancy Plugin
19. `plugins/tenancy/index.ts` — tenant CRUD, schema isolation, middleware, adapter wrapping

### Phase 2b: OAuth Plugin
20. `plugins/oauth/index.ts` — auth code + PKCE, client credentials, revoke, userinfo
21. `plugins/oauth/pkce.ts` — S256 challenge/verify

### Phase 2c: Two-Factor Plugin
22. `plugins/two-factor/index.ts` — TOTP, backup codes, trusted devices

### Phase 2d: Email Verification Plugin
23. `plugins/email-verification/index.ts` — token generation, verification flow

### Phase 2e: API Key Plugin
24. `plugins/api-key/index.ts` — key generation, hash storage, scope restriction, rotation, auth middleware extension

### Phase 2f: Data Isolation Plugin
25. `plugins/data-isolation/index.ts` — scope config, scopeRules implementation (read filters + write defaults), bypass control, adapter wrapping

### Phase 2g: Social Login Plugin
26. `plugins/social-login/index.ts` — social login config, OAuth/OIDC consumer flow, account linking
27. `plugins/social-login/providers/*.ts` — built-in provider configs (Microsoft, Google, GitHub, Apple, Discord, generic OIDC)

## Hono Adapter and Plugin Integration

`createHonoMiddleware(fortress)` auto-discovers plugin routes, middleware, and mounts them:

```typescript
function createHonoMiddleware(fortress: Fortress, options?: HonoAdapterOptions) {
  const plugins = fortress.config.plugins ?? [];

  return {
    authMiddleware: createAuthMiddleware(fortress),
    rbacMiddleware: createRbacMiddleware(fortress, options?.routeMap, options?.skipPaths),
    errorHandler: createErrorHandler(),

    // Mounts all plugin routes and middleware onto a Hono app
    mountPlugins(app: HonoApp): void {
      for (const plugin of plugins) {
        if (plugin.middleware) {
          for (const mw of plugin.middleware) {
            app.use(mw.path, /* wrap mw.handler */);
          }
        }
        if (plugin.routes) {
          for (const route of plugin.routes) {
            const handler = fortress.plugins[plugin.name][route.handler];
            app[route.method.toLowerCase()](route.path, /* wrap handler */);
          }
        }
      }
    },
  };
}

interface HonoAdapterOptions {
  routeMap?: Record<string, { resource: string; action: string }>;
  mapRequest?: (method: string, path: string) => { resource: string; action: string } | null;
  skipPaths?: string[];
}
```

## JSR Publishing Notes

- All exported functions must have **explicit return type annotations** (JSR "slow types" requirement)
- Use `npm:` prefix for npm dependencies in import map
- Sub-path exports isolate optional deps (Drizzle, Hono) — consumers only install what they import
- Run `deno publish --dry-run` in CI to catch issues before merging
- Use Web Standard APIs (crypto.subtle, Request/Response) where possible for cross-runtime compat
- Test under both `bun test` and `deno test`
