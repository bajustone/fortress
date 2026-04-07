# Fortress

Framework-agnostic, adapter-based authentication and authorization for TypeScript.

Published on [JSR](https://jsr.io/@bajustone/fortress). Runs on Bun, Deno, Node.js, and edge runtimes.

## Features

- **JWT auth** with access/refresh token pairs via [jose](https://github.com/panva/jose) (Web Crypto API)
- **Password hashing** with Argon2id (WASM default, swappable for native)
- **Refresh token rotation** with family tracking and reuse detection
- **Password policy** with configurable rules and optional Have I Been Pwned breach checking
- **IAM** with resource+action permissions, conditions, deny rules, groups, and roles
- **Session management** with device tracking, revocation, and admin impersonation
- **Plugin system** with 15 plugins for admin CRUD, 2FA, OAuth, tenancy, audit logging, and more
- **Database-agnostic** via a generic CRUD adapter interface
- **Framework-agnostic** with first-class Hono and Express middleware

## Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Configuration](#configuration)
- [Core Auth API](#core-auth-api)
  - [Register](#register)
  - [Login](#login)
  - [Token Refresh](#token-refresh)
  - [Logout](#logout)
  - [Current User](#current-user)
  - [Token Operations](#token-operations)
  - [Session Management](#session-management)
  - [Impersonation](#impersonation)
  - [Login Identifiers](#login-identifiers)
- [Core IAM API](#core-iam-api)
  - [Permission Checks](#permission-checks)
  - [Roles](#roles)
  - [Groups](#groups)
  - [Direct Permissions](#direct-permissions)
  - [Conditions and Deny Rules](#conditions-and-deny-rules)
  - [Resource Sync](#resource-sync)
- [Schema Builder](#schema-builder)
  - [Standard Schema V1](#standard-schema-v1)
  - [Type Inference](#type-inference)
  - [Runtime Validation](#runtime-validation)
- [Framework Integration](#framework-integration)
  - [Hono](#hono)
  - [Express](#express)
  - [CSRF Protection](#csrf-protection)
  - [Security Headers](#security-headers)
  - [Plugin Routes](#plugin-routes)
- [Database Adapters](#database-adapters)
  - [Drizzle Adapter](#drizzle-adapter)
  - [Custom Adapter](#custom-adapter)
- [Plugins](#plugins)
  - [Admin](#admin)
  - [Rate Limit](#rate-limit)
  - [Account Lockout](#account-lockout)
  - [Email Verification](#email-verification)
  - [Two-Factor Authentication](#two-factor-authentication)
  - [Magic Link](#magic-link)
  - [API Key](#api-key)
  - [Social Login](#social-login)
  - [Tenancy](#tenancy)
  - [Data Isolation](#data-isolation)
  - [Audit Log](#audit-log)
  - [Webhook](#webhook)
  - [OAuth Server](#oauth-server)
  - [WebAuthn](#webauthn)
  - [OpenAPI](#openapi)
- [Error Handling](#error-handling)
- [Testing](#testing)
- [Documentation](#documentation)
- [License](#license)

## Installation

```bash
# npm
npx jsr add @bajustone/fortress

# bun
bunx jsr add @bajustone/fortress

# deno
deno add jsr:@bajustone/fortress
```

Plugins, adapters, and middleware are sub-path exports -- you only install what you import:

```typescript
import { createFortress } from '@bajustone/fortress';
import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';
import { createHonoMiddleware } from '@bajustone/fortress/hono';
import { twoFactor } from '@bajustone/fortress/plugins/two-factor';
```

## Quick Start

```typescript
import { createFortress } from '@bajustone/fortress';
import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';
import { drizzle } from 'drizzle-orm/bun-sqlite';

const db = createDrizzleAdapter(drizzle('app.db'));

const fortress = createFortress({
  database: db,
  jwt: {
    secret: process.env.JWT_SECRET!, // min 32 bytes for HS256
    issuer: 'my-app',
  },
});

// Register
const user = await fortress.auth.createUser({
  email: 'alice@example.com',
  name: 'Alice',
  password: 'correct-horse-battery-staple',
});

// Login
const result = await fortress.auth.login('alice@example.com', 'correct-horse-battery-staple');
// result.accessToken, result.refreshToken, result.user

// Check permissions
const allowed = await fortress.iam.checkPermission(user.id, 'post', 'update');
```

## Configuration

The full `FortressConfig` interface:

```typescript
const fortress = createFortress({
  // Required
  database: adapter,
  jwt: {
    secret: 'min-32-bytes-long-secret-here!!!', // string or string[] for rotation
    issuer: 'fortress',                          // default: 'fortress'
    accessTokenExpirySeconds: 900,               // default: 900 (15 min)
    refreshTokenExpirySeconds: 604800,           // default: 604800 (7 days)
    validateRefreshFingerprint: false,            // default: false; true or 'warn'
  },

  // Optional
  rbac: {
    evaluationMode: 'allow-only',     // 'allow-only' (default) or 'deny-overrides'
    resourceFile: './fortress.resources.json',
    cache: {
      ttlSeconds: 30,                 // default: 30
      maxEntries: 1000,               // default: 1000
    },
  },

  passwordHasher: customHasher,       // default: WASM Argon2id
  passwordPolicy: {
    minLength: 8,                     // default: 8 (NIST 800-63B)
    maxLength: 128,                   // default: 128
    checkBreached: false,             // default: false (Have I Been Pwned k-anonymity)
    breachedCacheTtlMs: 86400000,     // default: 24h
  },

  plugins: [/* ... */],
});
```

### Secret Rotation

Pass an array of secrets for zero-downtime JWT key rotation. The first secret signs new tokens; all secrets are tried during verification:

```typescript
jwt: {
  secret: ['new-secret-min-32-bytes!!!!!!!!!', 'old-secret-min-32-bytes!!!!!!!!!'],
}
```

### Custom Password Hasher

```typescript
import { PasswordHasher } from '@bajustone/fortress';

const nativeArgon2: PasswordHasher = {
  hash: (password) => argon2.hash(password),
  verify: (hash, password) => argon2.verify(hash, password),
};

createFortress({ database: db, jwt: { secret }, passwordHasher: nativeArgon2 });
```

## Core Auth API

All methods are available on `fortress.auth`.

### Register

```typescript
const user = await fortress.auth.createUser({
  email: 'alice@example.com',
  name: 'Alice',
  password: 'correct-horse-battery-staple',
});
// Returns: { id, email, name, isActive, emailVerified, createdAt, updatedAt }
```

Password is validated against the configured policy before hashing with Argon2id.

### Login

```typescript
const result = await fortress.auth.login('alice@example.com', 'password', {
  ipAddress: '192.168.1.1',     // optional, stored on session
  userAgent: 'Mozilla/5.0...',  // optional, used for fingerprinting
  deviceName: 'Chrome on Mac',  // optional, stored on session
});

if (result.status === 'success') {
  // result.accessToken, result.refreshToken, result.user
}

if (result.status === 'pending') {
  // result.requires2FA -- two-factor verification needed
}
```

The identifier can be an email, phone number, or username -- Fortress checks login identifiers automatically. Timing-safe comparison prevents user enumeration.

### Token Refresh

```typescript
const tokens = await fortress.auth.refresh(refreshToken, {
  userAgent: 'Mozilla/5.0...',  // validated if fingerprinting is enabled
});
// Returns: { accessToken, refreshToken }
```

Refresh tokens are rotated on every use. The old token is revoked, and a new one is issued in the same token family. If a revoked token is reused (replay attack), the entire token family is invalidated.

### Logout

```typescript
await fortress.auth.logout(refreshToken);
```

### Current User

```typescript
const user = await fortress.auth.me(userId);
// Returns: { id, email, name, isActive, emailVerified, createdAt, updatedAt }
```

### Token Operations

```typescript
// Verify a JWT and extract claims
const claims = await fortress.auth.verifyToken(accessToken);
// Returns: { sub, name, groups, iss, iat, exp, act?, customClaims? }

// Sign a custom token
const token = await fortress.auth.signToken({
  sub: userId,
  name: 'Alice',
  groups: ['admin'],
});
```

### Session Management

```typescript
// List all active sessions for a user
const sessions = await fortress.auth.listSessions(userId);
// Returns: [{ id, ipAddress, userAgent, deviceName, lastActiveAt, createdAt }]

// Revoke a specific session
await fortress.auth.revokeSession(userId, tokenId);

// Revoke all sessions except the current one
await fortress.auth.revokeAllOtherSessions(userId, currentTokenId);
```

### Impersonation

Admin impersonation issues a short-lived access-only token with an RFC 8693 `act` claim. No refresh token is issued.

```typescript
const result = await fortress.auth.impersonate(adminUserId, targetUserId, {
  reason: 'Debugging user report #1234',
  expirySeconds: 300,  // default: short-lived
});
// result.accessToken contains { sub: targetUserId, act: { sub: adminUserId } }
```

### Login Identifiers

Users can have multiple login identifiers (email, phone, username) for flexible authentication:

```typescript
await fortress.auth.addLoginIdentifier(userId, 'phone', '+1234567890');
await fortress.auth.addLoginIdentifier(userId, 'username', 'alice');

const identifiers = await fortress.auth.getLoginIdentifiers(userId);

await fortress.auth.removeLoginIdentifier(userId, 'phone', '+1234567890');
```

After adding a phone or username identifier, users can log in with it:

```typescript
await fortress.auth.login('+1234567890', 'password');
await fortress.auth.login('alice', 'password');
```

## Core IAM API

Fortress implements hybrid RBAC + ABAC. Permissions are defined as `resource + action` pairs (not HTTP paths), so they work across HTTP, CLI, cron, WebSocket, and any other transport.

All methods are available on `fortress.iam`.

### Permission Checks

```typescript
const allowed = await fortress.iam.checkPermission(userId, 'post', 'update');
// Returns: boolean

// With context for condition evaluation
const allowed = await fortress.iam.checkPermission(userId, 'post', 'update', {
  resource: { ownerId: post.authorId },
  user: { id: userId, org: user.orgId },
  request: { ip: '192.168.1.1' },
});

// Get all permissions for a user
const perms = await fortress.iam.getUserPermissions(userId);
```

Permission results are cached (default: 30s TTL, 1000 entries). Clear manually if needed:

```typescript
fortress.iam.clearPermissionCache();
```

### Roles

```typescript
// Create a role with permissions
const editorRole = await fortress.iam.createRole(
  'editor',
  [
    { resource: 'post', action: 'create' },
    { resource: 'post', action: 'update' },
    { resource: 'post', action: 'read' },
    { resource: 'comment', action: '*' },  // wildcard: all actions on comments
  ],
  'Can manage posts and comments',
);

// Bind role to a user
await fortress.iam.bindRoleToUser(userId, editorRole.id);

// Bind role to a user in a specific tenant
await fortress.iam.bindRoleToUser(userId, editorRole.id, 'tenant-123');

// Unbind a role
await fortress.iam.unbindRole('USER', userId, editorRole.id);

// Delete a role
await fortress.iam.deleteRole(editorRole.id);
```

### Groups

```typescript
// Create a group
const team = await fortress.iam.createGroup('engineering', 'Engineering team');

// Add users to groups
await fortress.iam.addUserToGroup(team.id, userId);

// Bind a role to the group -- all members inherit the permissions
await fortress.iam.bindRoleToGroup(team.id, editorRole.id);

// Remove a user from the group
await fortress.iam.removeUserFromGroup(team.id, userId);
```

Group names are included in JWT claims (`groups` array), so they can be checked client-side without a round-trip.

### Direct Permissions

You can bind permissions directly to users or groups without creating a role:

```typescript
await fortress.iam.bindPermissionToUser(userId, {
  resource: 'analytics',
  action: 'view',
});

await fortress.iam.bindPermissionToGroup(groupId, {
  resource: 'report',
  action: 'export',
  effect: 'DENY',  // explicit deny
});

// Remove direct permissions
await fortress.iam.unbindPermissionFromUser(userId, permissionId);
await fortress.iam.unbindPermissionFromGroup(groupId, permissionId);
```

### Conditions and Deny Rules

Permissions support conditions for attribute-based access control:

```typescript
const ownerRole = await fortress.iam.createRole('owner', [
  {
    resource: 'post',
    action: 'update',
    effect: 'ALLOW',
    conditions: [
      {
        field: 'resource.ownerId',    // dotted path into context
        operator: 'eq',               // eq, neq, in, startsWith
        value: '${user.id}',          // template referencing context
      },
    ],
  },
]);
```

Conditions are evaluated against the `context` object passed to `checkPermission`. All conditions must match (AND logic).

#### Evaluation Modes

- **`allow-only`** (default): First matching ALLOW wins. No deny rules evaluated.
- **`deny-overrides`** (AWS-style): Any matching DENY blocks access, regardless of ALLOWs.

```typescript
createFortress({
  // ...
  rbac: { evaluationMode: 'deny-overrides' },
});
```

### Resource Sync

Sync resource definitions between a JSON file and the database:

```typescript
// Push from file to database
await fortress.iam.syncResources('push', './fortress.resources.json');

// Pull from database to file
await fortress.iam.syncResources('pull', './fortress.resources.json');
```

Resource file format:

```json
{
  "resources": {
    "post": {
      "actions": ["create", "read", "update", "delete"],
      "description": "Blog posts"
    },
    "comment": {
      "actions": ["create", "read", "delete"],
      "description": "Post comments"
    }
  }
}
```

## Schema Builder

Fortress includes a typed schema builder that produces `FortressSchema<T>` objects. Each schema is simultaneously:

- **JSON Schema** -- for OpenAPI 3.1 spec generation
- **Standard Schema V1** -- for runtime validation via `~standard.validate()`
- **TypeScript typed** -- for compile-time type inference via `Infer<T>`

```typescript
import { obj, str, int, bool, arr, enums, nullable, nullType, record, recordOf, ref } from '@bajustone/fortress';

// Primitives
str('description')           // FortressSchema<string>
int('description')           // FortressSchema<number>
num('description')           // FortressSchema<number>
bool('description')          // FortressSchema<boolean>
strFormat('email', 'desc')   // FortressSchema<string>
nullType()                   // FortressSchema<null>

// Objects — required fields listed as rest params
obj({ name: str(), age: int() }, 'name')
// FortressSchema<{ name: string; age?: number }>

// Combinators
arr(str())                   // FortressSchema<string[]>
enums('admin', 'user')       // FortressSchema<'admin' | 'user'>
nullable(str())              // FortressSchema<string | null>
record()                     // FortressSchema<Record<string, unknown>>
recordOf(str())              // FortressSchema<Record<string, string>>
ref('User')                  // $ref to component schema
oneOf(str(), int())          // FortressSchema<string | number>
```

### Standard Schema V1

Fortress schemas implement the [Standard Schema](https://standardschema.dev) spec. This means any tool that accepts Standard Schema (tRPC, Hono, Remix, etc.) works with fortress schemas out of the box.

```typescript
const schema = obj({ name: str(), email: str() }, 'name', 'email');

// Runtime validation
const result = schema['~standard'].validate({ name: 'Alice', email: 'a@b.com' });
// { value: { name: 'Alice', email: 'a@b.com' } }

const invalid = schema['~standard'].validate({ name: 123 });
// { issues: [{ message: 'Expected string, got number', path: [{ key: 'name' }] }] }
```

The `endpoint().body()`, `.query()`, and `.params()` methods also accept external Standard Schema from Zod, Valibot, or ArkType:

```typescript
import { z } from 'zod';
import { endpoint, obj, int } from '@bajustone/fortress';

// Mix fortress schemas and Zod in the same endpoint
endpoint('POST', '/users/:id')
  .params(obj({ id: int() }, 'id'))                              // fortress
  .body(z.object({ name: z.string().transform(s => s.trim()) })) // Zod
  .build();
```

### Type Inference

Extract TypeScript types from schemas using `Infer` or `StandardSchemaV1.InferOutput`:

```typescript
import { obj, str, enums, type Infer } from '@bajustone/fortress';

const createUserBody = obj(
  { name: str(), role: enums('admin', 'user') },
  'name', 'role',
);

type CreateUserBody = Infer<typeof createUserBody>;
// { name: string; role: 'admin' | 'user' }
```

### Runtime Validation

Use `createValidationMiddleware` to validate incoming requests against endpoint schemas. No external validator needed -- schemas validate themselves via Standard Schema.

```typescript
import { createValidationMiddleware } from '@bajustone/fortress/hono'; // or /express
import { endpoint, obj, str } from '@bajustone/fortress';

const endpoints = [
  endpoint('POST', '/users')
    .body(obj({ name: str(), email: str() }, 'name', 'email'))
    .handler('createUser')
    .build(),
];

app.use('/api/*', createValidationMiddleware(endpoints));
// Returns 422 with structured errors on validation failure
```

The `.permission()` method on endpoints declares IAM permissions for RBAC enforcement:

```typescript
endpoint('DELETE', '/iam/roles/:id')
  .permission('fortress', 'deleteRole')  // requires this IAM permission
  .handler('deleteRole')
  .build();
```

---

## Framework Integration

### Hono

```typescript
import { Hono } from 'hono';
import { createHonoMiddleware, getUserId, getClaims, mountPluginRoutes } from '@bajustone/fortress/hono';

const app = new Hono();

const { authMiddleware, rbacMiddleware, errorHandler, pluginMiddleware } = createHonoMiddleware(fortress, {
  // Map HTTP requests to resource+action permissions
  routeMap: {
    'GET /api/posts': { resource: 'post', action: 'list' },
    'POST /api/posts': { resource: 'post', action: 'create' },
    'PUT /api/posts/:id': { resource: 'post', action: 'update' },
    'DELETE /api/posts/:id': { resource: 'post', action: 'delete' },
  },
  skipPaths: ['/health', '/auth/*'],  // bypass RBAC for these paths
});

app.onError(errorHandler);
app.use('/api/*', pluginMiddleware.beforeAuth);  // rate-limit, etc.
app.use('/api/*', authMiddleware);
app.use('/api/*', pluginMiddleware.afterAuth);   // account lockout checks, etc.
app.use('/api/*', rbacMiddleware);
app.use('/api/*', pluginMiddleware.afterRbac);   // audit logging, etc.

app.get('/api/posts', (c) => {
  const userId = getUserId(c);
  const claims = getClaims(c);
  // ...
});
```

#### Dynamic Route Mapping

For complex routing, use `mapRequest` instead of `routeMap`:

```typescript
createHonoMiddleware(fortress, {
  mapRequest: (method, path) => {
    const match = path.match(/^\/api\/(\w+)/);
    if (match) {
      return { resource: match[1], action: method.toLowerCase() };
    }
    return null; // skip RBAC for this path
  },
});
```

#### Hono Helpers

```typescript
import { getUserId, getClaims, getDb, getScopedDb } from '@bajustone/fortress/hono';

app.get('/api/posts', async (c) => {
  const userId = getUserId(c);         // user ID from JWT
  const claims = getClaims(c);         // full JWT claims
  const db = getDb(c);                 // database adapter (tenant-aware if tenancy plugin active)
  const scopedDb = await getScopedDb(c, 'post'); // adapter with row-level isolation applied
});
```

#### Validated Request Helpers

Type-safe request extraction for Hono handlers. Zero runtime cost — fortress's `createValidationMiddleware` validates requests before handlers run. The schema parameter is used only for TypeScript type inference.

Works with any Standard Schema V1 library (Zod, Valibot, ArkType, or fortress's built-in schemas).

```typescript
import { vBody, vParam, vQuery, createValidationMiddleware } from '@bajustone/fortress/hono';
import { endpoint, obj, str } from '@bajustone/fortress';

// Define schemas once
const CreatePostBody = obj({ title: str(), content: str() }, 'title', 'content');
const IdParam = obj({ id: str('Post ID') }, 'id');
const SearchQuery = obj({ q: str('Search term'), page: str() }, 'q');

// Register validation middleware (validates against endpoint definitions)
app.use('/*', createValidationMiddleware(endpoints));

// Handlers get full type inference
app.post('/posts', async (c) => {
  const { title, content } = await vBody(c, CreatePostBody);  // typed
  const userId = getUserId(c);
  // ...
});

app.get('/posts/:id', (c) => {
  const { id } = vParam(c, IdParam);  // typed
  // ...
});

app.get('/search', (c) => {
  const { q, page } = vQuery(c, SearchQuery);  // typed
  // ...
});
```

### Express

```typescript
import express from 'express';
import { createExpressMiddleware, getUserId, getClaims } from '@bajustone/fortress/express';

const app = express();

const { authMiddleware, rbacMiddleware, errorHandler } = createExpressMiddleware(fortress, {
  routeMap: {
    'GET /api/posts': { resource: 'post', action: 'list' },
    'POST /api/posts': { resource: 'post', action: 'create' },
  },
  skipPaths: ['/health', '/auth/*'],
});

app.use('/api', authMiddleware);
app.use('/api', rbacMiddleware);

app.get('/api/posts', (req, res) => {
  const userId = getUserId(req);
  const claims = getClaims(req);
  // ...
});

app.use(errorHandler);
```

#### Express Helpers

```typescript
import { getUserId, getClaims, getDb, getScopedDb } from '@bajustone/fortress/express';

app.get('/api/posts', async (req, res) => {
  const userId = getUserId(req);
  const claims = getClaims(req);
  const db = getDb(req);
  const scopedDb = await getScopedDb(req, 'post');
});
```

### CSRF Protection

Hono-only. Uses the custom-header strategy -- browsers enforce CORS preflight on custom headers, preventing cross-site form submission:

```typescript
import { createCsrfMiddleware } from '@bajustone/fortress/hono';

app.use('/api/*', createCsrfMiddleware({
  headerName: 'X-Fortress-CSRF',      // default
  skipPaths: ['/api/webhooks/*'],
  safeMethods: ['GET', 'HEAD', 'OPTIONS'],  // default
}));
```

Clients must include the header on mutating requests:

```typescript
fetch('/api/posts', {
  method: 'POST',
  headers: { 'X-Fortress-CSRF': '1' },
});
```

### Security Headers

```typescript
import { createSecurityHeadersMiddleware } from '@bajustone/fortress/hono';

app.use(createSecurityHeadersMiddleware({
  hstsMaxAge: 31536000,
  frameOptions: 'DENY',
  noSniff: true,
  referrerPolicy: 'strict-origin-when-cross-origin',
}));
```

### Plugin Routes

Auto-mount HTTP routes defined by plugins (OAuth endpoints, WebAuthn, etc.):

```typescript
import { mountPluginRoutes } from '@bajustone/fortress/hono';

mountPluginRoutes(app, fortress, {
  prefix: '/auth',  // optional prefix for all plugin routes
});
// Mounts: POST /auth/oauth/token, POST /auth/oauth/introspect, etc.
```

## Database Adapters

### Drizzle Adapter

The Drizzle adapter supports PostgreSQL, MySQL, and SQLite.

#### SQLite

```typescript
import { drizzle } from 'drizzle-orm/bun-sqlite';
import { createDrizzleAdapter, fortressSchema } from '@bajustone/fortress/drizzle';

const drizzleDb = drizzle('app.db', { schema: fortressSchema });
const db = createDrizzleAdapter(drizzleDb); // dialect defaults to 'sqlite'
```

#### PostgreSQL

```typescript
import { drizzle } from 'drizzle-orm/node-postgres';
import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';
import { fortressPgSchema } from '@bajustone/fortress/drizzle/pg';

const drizzleDb = drizzle(connectionString, { schema: fortressPgSchema });
const db = createDrizzleAdapter(drizzleDb, { dialect: 'pg' });
```

#### MySQL

```typescript
import { drizzle } from 'drizzle-orm/mysql2';
import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';

const drizzleDb = drizzle(connection);
const db = createDrizzleAdapter(drizzleDb, { dialect: 'mysql' });
```

#### Custom Table Overrides

```typescript
const db = createDrizzleAdapter(drizzleDb, {
  dialect: 'pg',
  tables: {
    fortress_user: myCustomUsersTable,
  },
});
```

### Custom Adapter

Implement the `DatabaseAdapter` interface to use any database:

```typescript
import type { DatabaseAdapter, WhereClause } from '@bajustone/fortress';

const myAdapter: DatabaseAdapter = {
  async create({ model, data }) { /* insert and return record */ },
  async findOne({ model, where }) { /* return record or null */ },
  async findMany({ model, where, limit, offset, sortBy }) { /* return records */ },
  async update({ model, where, data }) { /* update and return record or null */ },
  async delete({ model, where }) { /* delete matching records */ },
  async count({ model, where }) { /* return count */ },
  async transaction(fn) { /* execute fn within a transaction */ },

  // Optional: raw SQL for multi-table queries (improves IAM performance)
  async rawQuery(sql, params) { /* return rows */ },
  dialect: 'pg',  // helps plugins generate correct SQL
};
```

The `WhereClause` interface:

```typescript
interface WhereClause {
  field: string;
  operator: '=' | '!=' | 'in' | 'gt' | 'lt' | 'gte' | 'lte' | (string & {});
  value: unknown;
}
```

## Plugins

Plugins are optional and tree-shakeable. Register them in the `plugins` array:

```typescript
import { createFortress } from '@bajustone/fortress';
import { rateLimit } from '@bajustone/fortress/plugins/rate-limit';
import { accountLockout } from '@bajustone/fortress/plugins/account-lockout';
import { twoFactor } from '@bajustone/fortress/plugins/two-factor';
import { auditLog } from '@bajustone/fortress/plugins/audit-log';

const fortress = createFortress({
  database: db,
  jwt: { secret },
  plugins: [
    rateLimit(),
    accountLockout(),
    twoFactor(),
    auditLog({ hashChain: true }),
  ],
});
```

Access plugin methods via `fortress.plugins`:

```typescript
fortress.plugins['two-factor'].enable(userId);
fortress.plugins['audit-log'].getAuditLog({ userId });
```

For type-safe access from external code:

```typescript
import { getPluginMethods } from '@bajustone/fortress';
import type { TwoFactorMethods } from '@bajustone/fortress';

const tf = getPluginMethods<TwoFactorMethods>(fortress, 'two-factor');
await tf.enable(userId);
```

> **Plugin order matters.** Hooks run in registration order. Gate plugins (rate-limit, account-lockout) should come first; observability plugins (audit-log, webhook) should come last.

| Plugin | Description |
|--------|-------------|
| [Admin](#admin) | Admin CRUD for users, roles, groups, permissions + bootstrap |
| [Rate Limit](#rate-limit) | Sliding window rate limiting with dual-key support |
| [Account Lockout](#account-lockout) | Progressive lockout with exponential backoff |
| [Email Verification](#email-verification) | Token-based email verification with login gating |
| [Two-Factor Authentication](#two-factor-authentication) | TOTP, backup codes, trusted devices |
| [Magic Link](#magic-link) | Passwordless authentication via one-time tokens |
| [API Key](#api-key) | Scoped API keys for service accounts and devices |
| [Social Login](#social-login) | OAuth/OIDC consumer (Google, GitHub, Microsoft, Apple, Discord) |
| [Tenancy](#tenancy) | Schema-per-tenant isolation (PostgreSQL) |
| [Data Isolation](#data-isolation) | Row-level data isolation (any database) |
| [Audit Log](#audit-log) | Append-only event logging with optional hash chain |
| [Webhook](#webhook) | Standard Webhooks spec with HMAC-SHA256 signing |
| [OAuth Server](#oauth-server) | OAuth 2.0 server with auth code + PKCE and client credentials |
| [WebAuthn](#webauthn) | WebAuthn/Passkey support (registration, passwordless auth, 2FA mode) |
| [OpenAPI](#openapi) | OpenAPI 3.1 spec generation + Scalar UI with unified spec support |

---

### Admin

Full IAM administration: users, roles, groups, permissions, role/permission bindings, and resource sync. Provides 35 endpoints + bootstrap for first admin setup. All endpoints are protected by `fortress:*` permissions and auto-mounted via `mountPluginRoutes`.

```typescript
import { admin } from '@bajustone/fortress/plugins/admin';

const fortress = createFortress({
  jwt: { secret: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    admin({ adminUserIds: [1] }), // superadmin bypass for user ID 1
  ],
});

// Bootstrap: assign all admin permissions to a user
await fortress.plugins.admin.bootstrap({ userId: 1 });

// User management
const { users, total } = await fortress.plugins.admin.listUsers({ limit: '20', search: 'alice' });
const user = await fortress.plugins.admin.getUserById({ id: '42' });
const newUser = await fortress.plugins.admin.createUser({ email: 'alice@co.com', name: 'Alice' });
await fortress.plugins.admin.updateUser({ id: '42', name: 'New Name', isActive: false });
await fortress.plugins.admin.deleteUser({ id: '42' });

// Role management
const roles = await fortress.plugins.admin.getRoles();
const role = await fortress.plugins.admin.getRole({ id: '1' });      // includes permissions
const newRole = await fortress.plugins.admin.createRole({ name: 'editor', permissions: [] });
await fortress.plugins.admin.bindRoleToUser({ id: '1', userId: 42 });
await fortress.plugins.admin.unbindRole({ id: '1', subjectType: 'USER', subjectId: 42 });

// Group management
const { groups } = await fortress.plugins.admin.listGroups({ limit: '20' });
const group = await fortress.plugins.admin.createGroup({ name: 'devs' });
await fortress.plugins.admin.addUserToGroup({ id: '5', userId: 42 });

// Permission checks
const { allowed } = await fortress.plugins.admin.checkPermission({
  userId: 42, resource: 'post', action: 'publish',
});
```

See [Admin plugin docs](docs/plugins/admin.md) for the full endpoint list and permissions reference.

---

### Rate Limit

Sliding-window rate limiting for login and registration. Tracks both IP and account to prevent distributed attacks while allowing legitimate use.

```typescript
import { rateLimit } from '@bajustone/fortress/plugins/rate-limit';

rateLimit({
  login: {
    maxPerIp: 10,           // default: 10 attempts per window
    maxPerAccount: 5,       // default: 5 attempts per window
    windowSeconds: 900,     // default: 900 (15 min)
  },
  register: {
    maxPerIp: 3,            // default: 3 registrations per window
    windowSeconds: 3600,    // default: 3600 (1 hour)
  },
  store: customStore,       // optional: custom RateLimitStore (default: in-memory)
})
```

This is a hook-only plugin -- it works automatically on login and registration with no methods to call. IPv6 addresses are normalized to /64 prefixes to prevent bypass via address rotation.

When rate-limited, a `FortressError` with code `RATE_LIMITED` and a `retryAfter` value (in seconds) is thrown.

---

### Account Lockout

Progressive lockout with exponential backoff after repeated failed login attempts.

```typescript
import { accountLockout } from '@bajustone/fortress/plugins/account-lockout';

accountLockout({
  maxFailedAttempts: 5,        // default: 5
  lockoutDurationSeconds: 900, // default: 900 (15 min)
  escalation: true,            // default: true (doubles duration on repeated lockouts)
  maxLockoutSeconds: 3600,     // default: 3600 (1 hour cap)
})
```

With escalation enabled, each successive lockout doubles the duration:
- 1st lockout: 15 min
- 2nd lockout: 30 min
- 3rd lockout: 60 min (capped)

**Methods:**

```typescript
// Check if an account is locked
const status = await fortress.plugins['account-lockout'].getLockoutStatus('alice@example.com');
// Returns: { isLocked, failedAttempts, lockedUntil, lockoutCount }

// Manually reset lockout (admin action)
await fortress.plugins['account-lockout'].resetLockout('alice@example.com');
```

---

### Email Verification

Token-based email verification with optional login gating. Automatically sends a verification token on registration.

```typescript
import { emailVerification } from '@bajustone/fortress/plugins/email-verification';

emailVerification({
  tokenExpirySeconds: 86400,      // default: 86400 (24 hours)
  requireVerification: true,       // default: true (block login for unverified users)
  onSendVerification: async (email, token, userId) => {
    // Send the verification email with token
    await sendEmail(email, `Verify: https://myapp.com/verify?token=${token}`);
  },
})
```

**Methods:**

```typescript
// Send (or resend) a verification email
await fortress.plugins['email-verification'].sendVerification(userId);
// Optionally specify a different email
await fortress.plugins['email-verification'].sendVerification(userId, 'newemail@example.com');

// Verify the token (from the email link)
await fortress.plugins['email-verification'].verify(rawToken);
// Marks user as email-verified and allows login
```

When `requireVerification` is `true`, unverified users receive an `UNAUTHORIZED` error on login.

---

### Two-Factor Authentication

TOTP (RFC 6238) with backup codes and trusted device support. Integrates into the login flow automatically.

```typescript
import { twoFactor } from '@bajustone/fortress/plugins/two-factor';

twoFactor({
  totp: {
    issuer: 'My App',      // default: 'Fortress'
    period: 30,             // default: 30 seconds
    digits: 6,              // default: 6
  },
  backupCodes: {
    count: 10,              // default: 10
  },
  trustedDeviceDays: 30,    // default: 30
})
```

**Methods:**

```typescript
// Step 1: Enable 2FA -- returns setup data for the authenticator app
const setup = await fortress.plugins['two-factor'].enable(userId);
// setup.otpauthUrl  -- QR code URL for authenticator apps
// setup.backupCodes -- one-time-use recovery codes

// Step 2: Verify -- activates 2FA on first successful verification
const result = await fortress.plugins['two-factor'].verify(userId, '123456', {
  userAgent: 'Mozilla/5.0...',  // optional: trust this device
});

// Disable 2FA (removes secret, backup codes, and trusted devices)
await fortress.plugins['two-factor'].disable(userId);
```

**Login flow with 2FA:**

```typescript
const result = await fortress.auth.login('alice@example.com', 'password');

if (result.status === 'pending' && result.requires2FA) {
  // Prompt user for TOTP code
  const code = await promptUser();

  const verification = await fortress.plugins['two-factor'].verify(result.userId, code, {
    userAgent: request.headers['user-agent'],
  });

  // Now re-login or use the tokens from the verification response
}
```

Trusted devices skip the 2FA prompt for the configured number of days.

---

### Magic Link

Passwordless authentication via one-time email tokens. Creates users automatically on first use (JIT provisioning).

```typescript
import { magicLink } from '@bajustone/fortress/plugins/magic-link';

magicLink({
  tokenExpirySeconds: 600,        // default: 600 (10 minutes)
  onSendMagicLink: async (email, token) => {
    await sendEmail(email, `Login: https://myapp.com/auth/magic?token=${token}`);
  },
})
```

**Methods:**

```typescript
// Send a magic link email
await fortress.plugins['magic-link'].sendMagicLink('alice@example.com');

// Verify the token (from the email link)
const result = await fortress.plugins['magic-link'].verifyMagicLink(rawToken);
// result.userId, result.email, result.accessToken
```

If no user exists with the given email, one is created automatically.

---

### API Key

Scoped API keys for service accounts, devices, and integrations. Keys are hashed before storage -- the raw key is only returned once at creation.

```typescript
import { apiKey } from '@bajustone/fortress/plugins/api-key';

apiKey({
  prefix: 'fortress',              // default: 'fortress' (key format: fortress_sk_<hex>)
  defaultExpirySeconds: null,       // default: null (never expires)
  maxKeysPerUser: 10,               // default: 10
})
```

**Methods:**

```typescript
// Create a key
const key = await fortress.plugins['api-key'].createKey(userId, {
  name: 'CI Pipeline',
  scopes: ['post:read', 'post:create'],
  expiresAt: new Date('2025-12-31'),  // optional
});
// key.rawKey -- ONLY returned at creation (e.g., "fortress_sk_a1b2c3...")

// List active keys (never includes raw key)
const keys = await fortress.plugins['api-key'].listKeys(userId);

// Revoke a key (soft delete)
await fortress.plugins['api-key'].revokeKey(userId, keyId);

// Rotate a key (revoke + create new with same scopes)
const newKey = await fortress.plugins['api-key'].rotateKey(userId, keyId);

// Resolve a key from a raw token (for middleware/auth)
const resolved = await fortress.plugins['api-key'].resolveKey('fortress_sk_a1b2c3...');
// resolved.userId, resolved.scopes -- or null if invalid/expired/revoked
```

---

### Social Login

OAuth/OIDC consumer for Google, GitHub, Microsoft, Apple, Discord, and custom OIDC providers. Supports automatic user registration, account linking, and PKCE.

```typescript
import { socialLogin } from '@bajustone/fortress/plugins/social-login';

socialLogin({
  providers: [
    {
      name: 'google',
      clientId: process.env.GOOGLE_CLIENT_ID!,
      clientSecret: process.env.GOOGLE_CLIENT_SECRET!,
    },
    {
      name: 'github',
      clientId: process.env.GITHUB_CLIENT_ID!,
      clientSecret: process.env.GITHUB_CLIENT_SECRET!,
    },
    {
      name: 'microsoft',
      clientId: process.env.MS_CLIENT_ID!,
      clientSecret: process.env.MS_CLIENT_SECRET!,
      tenant: 'common',  // Microsoft-specific
    },
    {
      // Custom OIDC provider
      name: 'corporate-sso',
      clientId: '...',
      clientSecret: '...',
      issuer: 'https://sso.corp.com',  // OIDC discovery
    },
  ],
  autoRegister: true,     // default: true (create user on first social login)
  linkAccounts: true,      // default: true (link by matching email)
  allowedDomains: ['company.com'],  // optional: restrict by email domain
  onFirstLogin: async (user, provider, profile) => {
    // Called when a user logs in via social for the first time
  },
})
```

**Methods:**

```typescript
// Step 1: Get the authorization URL (redirect the user here)
const { url, state, codeVerifier } = await fortress.plugins['social-login']
  .getAuthorizationUrl('google', 'https://myapp.com/auth/callback');
// Store state and codeVerifier in the session

// Step 2: Handle the callback (after user authorizes)
const result = await fortress.plugins['social-login']
  .handleCallback('google', code, 'https://myapp.com/auth/callback', codeVerifier);
// result.user, result.profile, result.isNewUser

// List linked social accounts
const accounts = await fortress.plugins['social-login'].getLinkedAccounts(userId);

// Unlink a social account
await fortress.plugins['social-login'].unlinkAccount(userId, 'google');

// List configured providers
const providers = fortress.plugins['social-login'].getProviders();
```

Built-in providers: **Google**, **GitHub**, **Microsoft** (with tenant support), **Apple**, **Discord**. Any OIDC-compliant provider can be added via the `issuer` field.

---

### Tenancy

Schema-per-tenant isolation for PostgreSQL. Each tenant gets its own database schema, providing strong data isolation at the database level.

```typescript
import { tenancy } from '@bajustone/fortress/plugins/tenancy';

tenancy({
  headerName: 'X-Tenant-Code',    // default: read tenant from this header
  schemaPrefix: 'tenant_',         // default: schema naming convention
})
```

**Methods:**

```typescript
// Create a new tenant (creates a PostgreSQL schema)
const tenant = await fortress.plugins['tenancy'].createTenant({
  name: 'Acme Corp',
  taxId: 'acme-corp',          // unique identifier, used in schema name
  description: 'Enterprise customer',
});

// Add a user to a tenant (first tenant becomes default)
await fortress.plugins['tenancy'].addUserToTenant(userId, tenant.id);

// List a user's tenants
const tenants = await fortress.plugins['tenancy'].getUserTenants(userId);

// Switch the user's default tenant
await fortress.plugins['tenancy'].switchTenant(userId, 'acme-corp');
```

The plugin automatically:
- Enriches JWT claims with `tenantId` and `tenantCode`
- Wraps the database adapter to inject `SET LOCAL search_path` on every query
- Scopes all data access to the tenant's schema transparently

---

### Data Isolation

Row-level data isolation that works with any database. Automatically injects WHERE filters on reads and default values on creates.

```typescript
import { dataIsolation } from '@bajustone/fortress/plugins/data-isolation';

dataIsolation({
  scopes: [
    {
      name: 'organization',
      field: 'orgId',                   // column to filter on
      models: ['post', 'comment'],      // tables to scope (or ['*'] for all)
      resolveValue: async (userId, ctx) => {
        // Return the current user's org ID
        const user = await ctx.db.findOne({ model: 'user', where: [{ field: 'id', operator: '=', value: userId }] });
        return user?.orgId;
      },
    },
  ],
})
```

With this configuration, when user 42 (orgId: 'acme') queries posts:
- `findMany({ model: 'post' })` automatically adds `WHERE orgId = 'acme'`
- `create({ model: 'post', data: {...} })` automatically sets `orgId = 'acme'`

**Methods:**

```typescript
// Temporarily bypass a specific scope (e.g., for admin operations)
await fortress.plugins['data-isolation'].withoutScope('organization', async () => {
  // Queries here run without the 'organization' filter
  const allPosts = await db.findMany({ model: 'post' });
});

// Bypass ALL scopes
await fortress.plugins['data-isolation'].unscoped(async () => {
  const everything = await db.findMany({ model: 'post' });
});
```

#### Using Scoped DB in Middleware

In Hono and Express, use the `getScopedDb` helper to get a database adapter with isolation applied:

```typescript
app.get('/api/posts', async (c) => {
  const scopedDb = await getScopedDb(c, 'post');
  const posts = await scopedDb.findMany({ model: 'post' });
  // Only returns posts the current user has access to
});
```

---

### Audit Log

Append-only event logging for authentication and IAM events. Supports optional hash chain for tamper detection.

```typescript
import { auditLog } from '@bajustone/fortress/plugins/audit-log';

auditLog({
  events: [                        // default: all events
    'LOGIN_SUCCESS',
    'LOGIN_FAILURE',
    'REGISTER',
    'ROLE_CREATED',
    'PERMISSION_CHANGED',
  ],
  hashChain: true,                 // default: false (enable SHA-256 chain)
})
```

Events are logged automatically via hooks. Available event types:

| Auth Events | IAM Events |
|------------|------------|
| `LOGIN_SUCCESS` | `ROLE_CREATED` |
| `LOGIN_FAILURE` | `ROLE_DELETED` |
| `LOGOUT` | `ROLE_BOUND` |
| `REGISTER` | `ROLE_UNBOUND` |
| `TOKEN_REFRESH` | `PERMISSION_CHANGED` |
| `TOKEN_REUSE` | `GROUP_CREATED` |
| | `GROUP_MEMBER_ADDED` |
| | `GROUP_MEMBER_REMOVED` |

**Methods:**

```typescript
// Query the audit log
const entries = await fortress.plugins['audit-log'].getAuditLog({
  userId: 42,
  eventType: 'LOGIN_SUCCESS',
  from: new Date('2025-01-01'),
  to: new Date('2025-12-31'),
  limit: 50,
  offset: 0,
});

// Log a custom event
await fortress.plugins['audit-log'].logCustomEvent({
  eventType: 'EXPORT_DATA',
  actorId: userId,
  actorType: 'USER',
  targetId: reportId,
  targetType: 'report',
  metadata: { format: 'csv' },
});

// Verify hash chain integrity (tamper detection)
const result = await fortress.plugins['audit-log'].verifyChain();
// result.valid, result.totalEntries, result.brokenLinks
```

When `hashChain` is enabled, each log entry stores a SHA-256 hash of the previous entry. `verifyChain()` walks the entire chain and reports any mismatches.

---

### Webhook

Delivers webhook events using the [Standard Webhooks](https://www.standardwebhooks.com) spec with HMAC-SHA256 signing and exponential retry backoff.

```typescript
import { webhook } from '@bajustone/fortress/plugins/webhook';

webhook({
  events: [                         // default: all events
    'LOGIN_SUCCESS',
    'REGISTER',
  ],
  maxRetries: 5,                    // default: 5
  deliver: async (url, payload, headers) => {
    // Optional: custom delivery function (default uses fetch)
    const res = await fetch(url, { method: 'POST', headers, body: JSON.stringify(payload) });
    return res.ok;
  },
})
```

Event types: `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`, `REGISTER`, `TOKEN_REFRESH`.

Retry intervals: 5s, 5min, 30min, 2h, 5h.

**Methods:**

```typescript
// Register a webhook endpoint
await fortress.plugins['webhook'].registerEndpoint(
  'https://myapp.com/webhooks',
  ['LOGIN_SUCCESS', 'REGISTER'],
  'whsec_my-webhook-secret',
);

// List registered endpoints
const endpoints = await fortress.plugins['webhook'].listEndpoints();

// Remove an endpoint
await fortress.plugins['webhook'].removeEndpoint(endpointId);

// Process pending retries (call periodically via cron)
await fortress.plugins['webhook'].processRetries();
```

Webhook payloads include Standard Webhooks headers:

```
webhook-id: msg_<unique-id>
webhook-timestamp: 1234567890
webhook-signature: v1,<base64-hmac-sha256>
```

---

### OAuth Server

Full OAuth 2.0 server (RFC 6749) with Authorization Code + PKCE, Client Credentials, token introspection (RFC 7662), revocation (RFC 7009), and OIDC discovery.

```typescript
import { oauth } from '@bajustone/fortress/plugins/oauth';

oauth({
  authCodeExpirySeconds: 600,        // default: 600 (10 min)
  pendingFlowExpirySeconds: 600,     // default: 600 (10 min)
  accessTokenExpirySeconds: 3600,    // default: 3600 (1 hour)
  issuerUrl: 'https://auth.myapp.com',
  scopePermissionMap: {
    'read:posts': { resource: 'post', action: 'read' },
    'write:posts': { resource: 'post', action: 'create' },
  },
})
```

**Client Management:**

```typescript
// Register an OAuth client
const client = await fortress.plugins['oauth'].createClient({
  name: 'Mobile App',
  redirectUris: ['myapp://callback'],
  grantTypes: ['authorization_code'],
});
// client.clientId, client.clientSecret (raw, only returned once)
```

**Authorization Code Flow:**

```typescript
// Step 1: Create an authorization code
const code = await fortress.plugins['oauth'].createAuthorizationCode({
  clientId: client.clientId,
  userId: userId,
  redirectUri: 'myapp://callback',
  scope: 'read:posts write:posts',
  codeChallenge: pkceChallenge,          // PKCE
  codeChallengeMethod: 'S256',
});

// Step 2: Exchange code for token
const tokens = await fortress.plugins['oauth'].exchangeCode({
  code: code,
  clientId: client.clientId,
  clientSecret: client.clientSecret,
  redirectUri: 'myapp://callback',
  codeVerifier: pkceVerifier,            // PKCE
});
// tokens.access_token, tokens.token_type, tokens.expires_in, tokens.scope
```

**Client Credentials Flow:**

```typescript
const tokens = await fortress.plugins['oauth'].clientCredentialsGrant({
  clientId: serviceClient.clientId,
  clientSecret: serviceClient.clientSecret,
  scope: 'read:posts',
});
```

**Token Operations:**

```typescript
// Introspect a token (RFC 7662)
const info = await fortress.plugins['oauth'].introspectToken(accessToken);
// info.active, info.client_id, info.scope, info.sub, info.exp

// Revoke a token (RFC 7009)
await fortress.plugins['oauth'].revokeToken(accessToken);

// Get user info (OIDC)
const userInfo = await fortress.plugins['oauth'].getUserInfo(accessToken);

// Map OAuth scopes to IAM permissions
const perms = await fortress.plugins['oauth'].resolveTokenPermissions(accessToken);
```

**HTTP Routes** (auto-mounted via `mountPluginRoutes`):

| Method | Path | Description |
|--------|------|-------------|
| POST | `/oauth/token` | Token endpoint (auth code + client credentials) |
| POST | `/oauth/introspect` | Token introspection (RFC 7662) |
| POST | `/oauth/revoke` | Token revocation (RFC 7009) |
| GET | `/oauth/userinfo` | OIDC UserInfo endpoint |
| GET | `/.well-known/openid-configuration` | OIDC Discovery document |

---

### WebAuthn

Passkey and WebAuthn support using [@simplewebauthn/server](https://simplewebauthn.dev/). Supports registration, passwordless authentication, and 2FA mode.

```typescript
import { webauthn } from '@bajustone/fortress/plugins/webauthn';

webauthn({
  rpName: 'My App',
  rpID: 'example.com',
  origin: 'https://example.com',
  supportPasswordless: true,         // default: true (returns JWT on auth)
  challengeTTLSeconds: 300,          // default: 300 (5 min)
})
```

**Methods:**

```typescript
// Registration: generate options for navigator.credentials.create()
const { options } = await fortress.plugins['webauthn'].generateRegistrationOptions({ userId });

// Verify registration response and store credential
const result = await fortress.plugins['webauthn'].verifyRegistration({
  userId,
  response: registrationResponseFromBrowser,
});

// Authentication: generate options for navigator.credentials.get()
const { options: authOpts } = await fortress.plugins['webauthn'].generateAuthenticationOptions({});

// Verify authentication and get tokens (passwordless mode)
const authResult = await fortress.plugins['webauthn'].verifyAuthentication({
  response: assertionFromBrowser,
});
// authResult.verified, authResult.userId, authResult.accessToken
```

When `supportPasswordless` is `false`, the plugin acts as a second factor via the `afterLogin` hook instead of issuing tokens directly.

See [WebAuthn plugin docs](docs/plugins/webauthn.md) for the full configuration and API reference.

---

### OpenAPI

Generates an OpenAPI 3.1 spec from all fortress endpoints (auth, IAM, plugins) and serves a Scalar interactive UI. Use `additionalEndpoints` with `convertRoutes` to merge your app's own routes into a single unified spec.

```typescript
import { openapi } from '@bajustone/fortress/plugins/openapi';
import { convertRoutes } from '@bajustone/fortress/hono'; // or /express
import { z } from 'zod'; // or Valibot, TypeBox, ArkType — bring your own

// Import your createRoute-defined routes
import { loginRoute, listUsersRoute } from './modules/auth/routes';
import { listSchoolsRoute } from './modules/sdms/routes';

openapi({
  title: 'My API',
  version: '1.0.0',
  description: 'Unified spec: fortress + app endpoints',
  // convertRoutes is schema-library agnostic — you provide the converter
  additionalEndpoints: convertRoutes(
    [loginRoute, listUsersRoute, listSchoolsRoute],
    { prefix: '/api/v1', schemaConverter: z.toJSONSchema },
  ),
})
```

This gives you:
- `GET /openapi.json` — unified OpenAPI 3.1 spec (fortress + your endpoints)
- `GET /openapi` — Scalar interactive UI

Config options:

| Option | Default | Description |
|--------|---------|-------------|
| `title` | `'Fortress Auth API'` | API title |
| `version` | `'1.0.0'` | API version |
| `description` | — | API description |
| `servers` | — | Server URL(s) for the spec |
| `specPath` | `'/openapi.json'` | Path to serve the JSON spec |
| `uiPath` | `'/openapi'` | Path to serve the Scalar UI |
| `disableUI` | `false` | Disable Scalar UI |
| `includeCoreAuth` | `true` | Include core auth endpoints |
| `includeCoreIam` | `true` | Include core IAM endpoints |
| `additionalEndpoints` | — | Extra `EndpointDefinition[]` to include |
| `additionalSchemas` | — | Extra component schemas to include |

---

## Error Handling

All Fortress errors are instances of `FortressError` with a typed error code and HTTP status:

```typescript
import { FortressError, Errors } from '@bajustone/fortress';

try {
  await fortress.auth.login('alice@example.com', 'wrong-password');
} catch (err) {
  if (err instanceof FortressError) {
    err.code;        // 'UNAUTHORIZED'
    err.statusCode;  // 401
    err.message;     // 'Invalid credentials'
    err.retryAfter;  // number (seconds) -- only for RATE_LIMITED
    err.details;     // unknown -- structured data for VALIDATION_ERROR
    err.toJSON();    // { code, message, statusCode, details? }
  }
}
```

**Error codes:**

| Code | Status | Description |
|------|--------|-------------|
| `UNAUTHORIZED` | 401 | Invalid credentials or token |
| `TOKEN_REUSE` | 401 | Refresh token replay detected |
| `FORBIDDEN` | 403 | Insufficient permissions |
| `BAD_REQUEST` | 400 | Invalid input |
| `NOT_FOUND` | 404 | Resource not found |
| `CONFLICT` | 409 | Duplicate resource (e.g., email already registered) |
| `RATE_LIMITED` | 429 | Too many requests (includes `retryAfter`) |
| `VALIDATION_ERROR` | 422 | Request validation failed (includes `details` with issues) |
| `DATABASE_ERROR` | 500 | Database operation failed |

**Error factory** for creating errors in custom code:

```typescript
import { Errors } from '@bajustone/fortress';

throw Errors.unauthorized('Custom message');
throw Errors.forbidden();
throw Errors.badRequest('Email is required');
throw Errors.notFound('User not found');
throw Errors.conflict('Email already registered');
throw Errors.rateLimited(60);  // retry after 60 seconds
throw Errors.database('Connection failed', originalError);
throw Errors.validationError([{ message: 'Name is required', path: [{ key: 'name' }] }]);
```

The `errorHandler` middleware (Hono and Express) automatically converts `FortressError` instances to HTTP responses with the correct status code and JSON body.

## Testing

Use the built-in test adapter for unit and integration tests. It creates an in-memory SQLite database with all Fortress tables pre-created.

```typescript
import { createTestAdapter } from '@bajustone/fortress/testing';
import { createFortress } from '@bajustone/fortress';
import { describe, it, expect } from 'vitest';

describe('auth', () => {
  const fortress = createFortress({
    database: createTestAdapter(),
    jwt: { secret: 'test-secret-min-32-bytes-long!!!' },
  });

  it('registers and logs in a user', async () => {
    const user = await fortress.auth.createUser({
      email: 'test@example.com',
      name: 'Test',
      password: 'password123456',
    });
    expect(user.email).toBe('test@example.com');

    const result = await fortress.auth.login('test@example.com', 'password123456');
    expect(result.status).toBe('success');
  });

  it('checks permissions', async () => {
    const role = await fortress.iam.createRole('viewer', [
      { resource: 'post', action: 'read' },
    ]);
    await fortress.iam.bindRoleToUser(1, role.id);

    const allowed = await fortress.iam.checkPermission(1, 'post', 'read');
    expect(allowed).toBe(true);

    const denied = await fortress.iam.checkPermission(1, 'post', 'delete');
    expect(denied).toBe(false);
  });
});
```

The test adapter auto-detects the runtime: Bun uses `bun:sqlite`, Node/Vitest uses `better-sqlite3`.

## Documentation

- [Architecture](docs/architecture.md) -- full technical design
- [Security](docs/security.md) -- JWT, password hashing, token storage, CSRF, audit logging
- Plugin guides: [Admin](docs/plugins/admin.md), [Rate Limit](docs/plugins/rate-limit.md), [Account Lockout](docs/plugins/account-lockout.md), [Email Verification](docs/plugins/email-verification.md), [Two-Factor](docs/plugins/two-factor.md), [Magic Link](docs/plugins/magic-link.md), [API Key](docs/plugins/api-key.md), [Social Login](docs/plugins/social-login.md), [Tenancy](docs/plugins/tenancy.md), [Data Isolation](docs/plugins/data-isolation.md), [Audit Log](docs/plugins/audit-log.md), [Webhook](docs/plugins/webhook.md), [OAuth](docs/plugins/oauth.md), [WebAuthn](docs/plugins/webauthn.md), [OpenAPI](docs/plugins/openapi.md)

## License

[MIT](LICENSE)
