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
- **Observability**: pluggable logger (pino/Fastify/console), auth+IAM+permission-check observers, opt-in OpenTelemetry adapter via `@bajustone/fortress/otel`
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
  - [Framework-agnostic core: `fortress.handleRequest`](#framework-agnostic-core-fortresshandlerequest)
  - [Hono](#hono)
  - [Express](#express)
  - [SvelteKit](#sveltekit)
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
    key: process.env.JWT_SECRET!, // min 32 bytes for HS256
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

### Typed in-process client (`fortress.call`)

Every endpoint you declare becomes callable with end-to-end types inferred
from the schemas. No hand-rolled fetchers, no casting, no manual types.

```typescript
// Input shape is inferred from the login endpoint's body schema.
// Response shape is inferred from the 200 response schema.
const { accessToken, user } = await fortress.call.login({
  identifier: 'alice@example.com',
  password: 'correct-horse-battery-staple',
});

// Params endpoints work the same — path :id is substituted automatically.
await fortress.call.revokeSession(
  { id: 42 },
  { headers: { authorization: `Bearer ${accessToken}` } },
);

// Non-2xx responses throw a typed FortressError with a stable `code`.
try {
  await fortress.call.login({ identifier: 'alice@example.com', password: 'wrong' });
}
catch (err) {
  if (err instanceof FortressError && err.code === 'UNAUTHORIZED') {
    // handle
  }
}
```

Under the hood, each call serializes to a `Request` and delegates to
`fortress.handleRequest`, so **everything runs** — plugin middleware,
rate limits, token verification, RBAC, JSON Schema validation, auth /
IAM observers, OpenTelemetry spans. Same pipeline a network client
would hit; same behavioral guarantees in tests as in production. This
is the foundation an over-the-wire client SDK will sit on top of: same
type surface, different transport.

> **Bypassing hooks in tests.** If a test fixture needs to create a
> user or log in *without* tripping rate limits, emitting audit
> entries, or running observers, use the service layer directly —
> `fortress.auth.createUser(...)`, `fortress.auth.login(...)`,
> `fortress.iam.createRole(...)`. Inputs still validate; the
> middleware chain is skipped.

## Configuration

The full `FortressConfig` interface:

```typescript
const fortress = createFortress({
  // Required
  database: adapter,
  jwt: {
    key: 'min-32-bytes-long-secret-here!!!', // string or string[] for rotation
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
    minLength: 15,                    // default: 15 (new passwords only)
    maxLength: 128,                   // default: 128
    checkBreached: false,             // default: false (Have I Been Pwned k-anonymity)
    breachedCacheTtlMs: 86400000,     // default: 24h
    breachedCacheMaxEntries: 1000,    // default: 1000; 0 disables caching
    breachedFailureMode: 'open',      // default: 'open'; or 'closed'
  },

  plugins: [/* ... */],

  // Host-application endpoint metadata, registered with the manifest,
  // OpenAPI, and protect()/protectedRoute() without authoring a one-field
  // FortressPlugin. Keyed by handler name, matching the `routes` field on
  // a plugin.
  routes: appEndpoints, // Record<handlerName, EndpointDefinition>
});
```

Fortress represents top-level routes internally under the reserved name `__host`. Declaring a user plugin named `__host` alongside `routes` is a configuration error.

Top-level `routes` are metadata-only: they participate in the manifest, OpenAPI, and protection helpers, but framework adapters do not mount or dispatch them. Requests fall through to your host router; direct `fortress.handleRequest()` calls return 404 rather than a fabricated success. They also do not create `fortress.call.*` entries because no handler methods are registered. If you need Fortress-mounted routes or typed in-process callables, use a real plugin with both `routes` and matching `methods`. Duplicate method/path or `fortress.call` keys across plugins fail at startup; a plugin may still intentionally override a core route.

### Secret Rotation

Pass an array of secrets for zero-downtime JWT key rotation. The first secret signs new tokens; all secrets are tried during verification:

```typescript
jwt: {
  key: ['new-secret-min-32-bytes!!!!!!!!!', 'old-secret-min-32-bytes!!!!!!!!!'],
}
```

### Custom Password Hasher

```typescript
import { PasswordHasher } from '@bajustone/fortress';

const nativeArgon2: PasswordHasher = {
  hash: (password) => argon2.hash(password),
  verify: (hash, password) => argon2.verify(hash, password),
};

createFortress({ database: db, jwt: { key: secret }, passwordHasher: nativeArgon2 });
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
  // No tokens exist yet. Route by result.pending.reason and retain the
  // single-use result.pending.continuationToken for the verification step.
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

`POST /auth/logout` revokes the refresh token and expires both configured auth cookies (`Max-Age=0`).

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

### Service Accounts

Service accounts are first-class IAM principals for CI/CD, M2M communication, devices, and anything that needs permissions without a human user. They hold roles and direct permissions the same way users do — but have no sessions, no passwords, and no group memberships. They authenticate via the `api-key` plugin using `Authorization: ApiKey <key>` or `X-API-Key: <key>` headers.

Why you'd use one: a regular user row represents a human who signs in. A service account represents a process. It can be deactivated or deleted without affecting any human's audit trail, its credentials are long-lived API keys (not JWT sessions), and the `name` is an immutable machine identifier — perfect for `ci-deploy` or `grafana-reader`.

**Create a service account.** The `name` is immutable after creation; everything else can be updated.

```typescript
const ci = await fortress.iam.createServiceAccount({
  name: 'ci-deploy',
  displayName: 'CI Deploy',
  description: 'Runs production deploys from GitHub Actions',
});
```

**Grant permissions.** Role bindings and direct bindings work the same as they do for users:

```typescript
// Via a role
const deployer = await fortress.iam.createRole('deployer', [
  { resource: 'deploy', action: 'run' },
]);
await fortress.iam.bindRoleToServiceAccount(ci.id, deployer.id);

// Or a direct permission binding
await fortress.iam.bindPermissionToServiceAccount(ci.id, {
  resource: 'audit',
  action: 'read',
});
```

**Mint an API key and authenticate requests.** Requires the `api-key` plugin ([docs](./docs/plugins/api-key.md)). The raw key is returned exactly once — Fortress stores only the SHA-256 hash.

```typescript
const { key } = await fortress.plugins['api-key'].createKey({
  subject: { type: 'SERVICE_ACCOUNT', id: ci.id },
  name: 'ci-deploy-key',
});
// store `key` immediately — it is never retrievable again
```

Incoming requests authenticate by sending the key in either header:

```
Authorization: ApiKey fortress_sk_a1b2c3...
X-API-Key: fortress_sk_a1b2c3...
```

The api-key plugin resolves the key to its owning service account and that subject flows through RBAC end-to-end — no middleware setup required.

**Check a permission.** `checkPermission` takes a discriminated `Subject`, so users and service accounts share the same API:

```typescript
await fortress.iam.checkPermission({ type: 'USER', id: userId }, 'post', 'read');
await fortress.iam.checkPermission({ type: 'SERVICE_ACCOUNT', id: ci.id }, 'deploy', 'run');
```

**Deactivate or delete.** Flipping `isActive` to `false` is a kill-switch: the api key stops authenticating and any permission check returns `false` immediately. Hard deletes cascade through role bindings, direct permission bindings, and every API key owned by the account.

```typescript
// Kill-switch
await fortress.iam.updateServiceAccount(ci.id, { isActive: false });

// Hard delete with cascade
await fortress.iam.deleteServiceAccount(ci.id);
```

**Tenancy.** Service accounts are global at the table level but hold tenant-scoped grants via `roleBindings.tenantId` — a single account can carry both tenant-scoped and global bindings. See [docs/plugins/tenancy.md](./docs/plugins/tenancy.md#service-accounts-and-tenancy).

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

### Seed permissions from the manifest

Every endpoint declared with `.permission(resource, action)` is a permission your
database needs to exist before any role can grant it. Instead of writing a seed
script that walks `fortress.endpoints` and calls `iam.createPermission(...)` for
each, call `fortress.syncPermissionsFromManifest()`:

```typescript
await fortress.syncPermissionsFromManifest({
  defaultRoles: {
    admin: '*',                            // bind every discovered permission
    member: ['school:read', 'school:list'], // bind only the named pairs
  },
});
```

Idempotent — re-running only adds what's missing and never revokes. `'*'` binds
only the permissions discovered from the supplied endpoint manifest, not stale
or unrelated rows already in the database. Returns a report of how many
permissions were discovered, how many already existed, and how many role
bindings were newly added during this run.

## Bootstrap and Migrations

Run Fortress's own migrations plus your app's schema migrations in one call:

```typescript
import { migrate } from 'drizzle-orm/node-postgres/migrator';

await fortress.migrate({
  // Optional — runs after fortress migrations complete. Any thrown error
  // propagates after fortress migrations have already been applied.
  migrateApp: () => migrate(drizzleDb, { migrationsFolder: './drizzle' }),
});
```

Fortress migrations always run first because app schemas commonly reference
fortress tables (FKs to `user.id`, etc.). Omit `migrateApp` to run only
fortress's migrations. Pair this with `syncPermissionsFromManifest()` for a
full, idempotent bootstrap on a fresh database:

```typescript
await fortress.migrate({ migrateApp: runAppMigrations });
await fortress.syncPermissionsFromManifest({
  defaultRoles: { admin: '*' },
});
```

## Schema Builder

Fortress includes a typed schema builder that produces `FortressSchema<T>` objects. Each schema is simultaneously:

- **JSON Schema** -- for OpenAPI 3.1 spec generation
- **Standard Schema V1** -- for runtime validation via `~standard.validate()`
- **TypeScript typed** -- for compile-time type inference via `Infer<T>`

Runtime validation runs on [`@bajustone/fetcher`](https://www.npmjs.com/package/@bajustone/fetcher)'s `fromJSONSchema` — the same toolkit is re-exported at `@bajustone/fortress/fetcher` so you can author schemas (and build validated outbound clients) with the exact builder fortress uses internally.

```typescript
import { obj, str, int, id, bool, arr, enums, nullable, nullType, record, recordOf, ref } from '@bajustone/fortress';

// Primitives — pass a description, or an options object for enforced constraints
str('description')               // FortressSchema<string>
str({ min: 3, max: 20, pattern: '^[a-z]+$' }) // enforced minLength/maxLength/pattern
int({ min: 1, max: 100 })        // enforced minimum/maximum
id('description')                // FortressSchema<string> — subject-id (RFC 7519 §4.1.2)
num('description')               // FortressSchema<number>
bool('description')              // FortressSchema<boolean>
nullType()                       // FortressSchema<null>

// Enforced string formats (ReDoS-safe patterns; emit `format` for OpenAPI)
email()                          // FortressSchema<string> — validated at runtime
uuid(); url(); datetime(); date(); time()

// Objects — required fields listed as rest params
obj({ name: str(), age: int() }, 'name')
// FortressSchema<{ name: string; age?: number }>
strict(obj({ name: str() }, 'name')) // additionalProperties: false — rejects unknown keys

// Combinators
arr(str())                       // FortressSchema<string[]>
enums('admin', 'user')           // FortressSchema<'admin' | 'user'>
literal('admin')                 // FortressSchema<'admin'> — const
nullable(str())                  // FortressSchema<string | null>
intersect(A, B)                  // FortressSchema<A & B> — allOf
record()                         // FortressSchema<Record<string, unknown>>
recordOf(str())                  // FortressSchema<Record<string, string>>
ref('User')                      // $ref to component schema
oneOf(str(), int())              // FortressSchema<string | number> (matches at least one)
discriminatedUnion('kind', A, B) // oneOf + discriminator, dispatched on `kind`
```

> `strFormat('email')` still exists as an annotation-only helper; prefer `email()`/`uuid()`/… when you want the value enforced.

### Authoring with fetcher's builder

Fortress's builder covers the common cases. For richer composition — `transform()`, `refined()`, `brand()`, `tuple()`, `pick`/`omit`/`partial`/`merge`/`extend` — author schemas with fetcher's own builder, re-exported at `@bajustone/fortress/fetcher`. Because fetcher schemas are JSON Schema objects that implement Standard Schema V1, they drop straight into `endpoint()` (and `vBody`/`vParam`/`vQuery`): they validate at runtime via fetcher's engine and serialize to clean OpenAPI (fetcher's internal `~`-keys are stripped automatically).

```typescript
import { endpoint } from '@bajustone/fortress';
import { schema as s } from '@bajustone/fortress/fetcher';

const CreateUser = s.object({
  email: s.email(),                 // enforced, emits format + pattern
  age: s.optional(s.integer()),     // optional → absent from `required`
  role: s.discriminatedUnion('kind', {
    member: s.object({ kind: s.literal('member') }),
    admin: s.object({ kind: s.literal('admin'), scopes: s.array(s.string()) }),
  }),
});

endpoint('POST', '/users')
  .summary('Create user')
  .body(CreateUser)                 // runtime validation + OpenAPI from one schema
  .handler('createUser')
  .build();
```

### Canonical error envelope

Fortress exports `ErrorEnvelope` — a schema that matches the exact wire shape `FortressError.toJSON()` emits:

```typescript
import { ErrorEnvelope, endpoint, obj, str } from '@bajustone/fortress';

// Inferred type:
// { code: string; message: string; statusCode: number; details?: unknown }

endpoint('GET', '/schools/:id')
  .summary('Get a school')
  .params(obj({ id: str() }, 'id'))
  .response(200, 'OK', SchoolEnvelope)
  .errorResponse(404, 'School not found')   // shorthand for .response(404, ..., ErrorEnvelope)
  .errorResponse(403, 'Forbidden')
  .handler('getSchool')
  .build();
```

Referencing `ErrorEnvelope` from host endpoints means clients only need one error parser — every Fortress and Fortress-hosted route emits the same `{ code, message, statusCode, details? }` body.

### Standard Schema V1

Fortress schemas implement the [Standard Schema](https://standardschema.dev) spec. This means any tool that accepts Standard Schema (tRPC, Hono, Remix, etc.) works with fortress schemas out of the box.

```typescript
const schema = obj({ name: str(), email: str() }, 'name', 'email');

// Runtime validation
const result = schema['~standard'].validate({ name: 'Alice', email: 'a@b.com' });
// { value: { name: 'Alice', email: 'a@b.com' } }

const invalid = schema['~standard'].validate({ name: 123 });
// { issues: [{ message: 'Expected string, got number', path: ['name'] }] }
```

The `endpoint().body()`, `.query()`, and `.params()` methods also accept external Standard Schema from Zod, Valibot, or ArkType:

```typescript
import { z } from 'zod';
import { endpoint, obj, int } from '@bajustone/fortress';

// Mix fortress schemas and Zod in the same endpoint
endpoint('POST', '/users/:id')
  .params(obj({ id: id() }, 'id'))                               // fortress
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

Schemas validate themselves via Standard Schema — no external validator needed. Validation runs automatically inside `fortress.handleRequest` for every Fortress-managed endpoint declared with `.body()` / `.params()` / `.query()`. Failures return a 422 with structured details.

```typescript
import { endpoint, obj, str } from '@bajustone/fortress';

const createUser = endpoint('POST', '/users')
  .body(obj({ name: str(), email: str() }, 'name', 'email'))
  .handler('createUser')
  .build();

// When `createUser` is registered as a plugin route, requests to POST /users
// are automatically validated by `fortress.handleRequest` before the handler
// runs. Invalid bodies → 422 VALIDATION_ERROR with `details: [...]`.
```

For **custom routes** outside the Fortress dispatch pipeline (your own
`/api/*` endpoints in Hono / Express / SvelteKit), use the `vBody` /
`vParam` / `vQuery` extract-and-validate helpers from the matching adapter
— they extract request data **and validate it at runtime** against your
Standard Schema, returning the parsed value or throwing
`FortressError('VALIDATION_ERROR', 422)` (the same shape every
fortress-managed endpoint produces). For runtimes without a fortress
adapter (Next.js, Remix, Astro, Bun.serve, Deno, edge functions), call the
framework-agnostic `validateRequest` from `@bajustone/fortress` directly.

The `.permission()` method on endpoints declares IAM permissions for RBAC enforcement:

```typescript
endpoint('DELETE', '/iam/roles/:id')
  .permission('fortress', 'deleteRole')  // requires this IAM permission
  .handler('deleteRole')
  .build();
```

---

## Framework Integration

### Framework-agnostic core: `fortress.handleRequest`

Every Fortress instance exposes a web-standard request handler:

```typescript
const response = await fortress.handleRequest(request); // Request → Response
```

It runs the full pipeline: plugin `before-auth` middleware → token
verification (cookie-first, `Authorization: Bearer` fallback) → plugin
`after-auth` → fortress-managed RBAC → plugin `after-rbac` → validation →
endpoint dispatch → cookie attachment.

Login / refresh / impersonate responses include `Set-Cookie` headers
automatically using {@link FortressConfig.cookies} (defaults: `__Host-`
prefixed names + `HttpOnly` + `Secure` + `SameSite=Lax` in production,
relaxed in dev).

This is the entry point all framework adapters delegate to. You can call
it directly from any runtime that speaks `Request`/`Response`: Cloudflare
Workers, Deno Deploy, Vercel Edge, etc.

### Hono

```typescript
import { Hono } from 'hono';
import { Hono } from 'hono';
import {
  createHonoMiddleware,
  getClaims,
  getUserId,
  mountFortress,
} from '@bajustone/fortress/hono';

const app = new Hono();

// One-line mount: handles all Fortress routes (auth, IAM, plugins, OAuth,
// OpenAPI). Auth-issuing endpoints (login/refresh) attach Set-Cookie
// headers automatically.
mountFortress(app, fortress);

// Optional: protect your own user routes via the IAM middleware.
const { authMiddleware, rbacMiddleware, errorHandler, pluginMiddleware } = createHonoMiddleware(fortress, {
  routeMap: {
    'GET /api/posts': { resource: 'post', action: 'list' },
    'POST /api/posts': { resource: 'post', action: 'create' },
    'PUT /api/posts/:id': { resource: 'post', action: 'update' },
    'DELETE /api/posts/:id': { resource: 'post', action: 'delete' },
  },
  skipPaths: ['/health'],
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

#### Fail-closed Unmapped Routes

By default a route with no `routeMap`/`mapRequest` entry is treated as
public (the RBAC middleware only guards routes you map). To fail closed
instead — so a forgotten mapping can't silently expose a route — set
`defaultDeny: true` (Hono) or `unmappedRoutes: 'deny'` (Express). Any
non-skipped, unmapped route is then refused with a 403; list genuinely
public routes in `skipPaths`.

```typescript
// Hono
createHonoMiddleware(fortress, {
  routeMap: { 'GET /api/posts': { resource: 'post', action: 'list' } },
  skipPaths: ['/api/public/*'],
  defaultDeny: true, // unmapped /api/* routes → 403
});

// Express (routeMap always uses the full original path, even when mounted
// under app.use('/api', ...))
createExpressMiddleware(fortress, {
  routeMap: { 'GET /api/posts': { resource: 'post', action: 'list' } },
  skipPaths: ['/api/public/*'],
  unmappedRoutes: 'deny', // unmapped routes → 403
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

#### Validated Extraction Helpers (custom routes)

For your own user routes (outside the Fortress dispatch pipeline), `vBody` /
`vParam` / `vQuery` extract request data **and validate it at runtime**
against the supplied Standard Schema. On success they return the parsed
value with full TypeScript inference; on failure they throw
`FortressError('VALIDATION_ERROR', 422)` and the registered Hono error
handler formats it identically to fortress-managed endpoint failures. Works
with any Standard Schema V1 library (Zod, Valibot, ArkType, or fortress's
built-in schemas). All three helpers are async.

```typescript
import { vBody, vParam, vQuery } from '@bajustone/fortress/hono';
import { obj, str } from '@bajustone/fortress';

const CreatePostBody = obj({ title: str(), content: str() }, 'title', 'content');
const IdParam = obj({ id: str('Post ID') }, 'id');
const SearchQuery = obj({ q: str('Search term'), page: str() }, 'q');

app.post('/posts', async (c) => {
  const { title, content } = await vBody(c, CreatePostBody);  // typed + validated
  const userId = getUserId(c);
  // ...
});

app.get('/posts/:id', async (c) => {
  const { id } = await vParam(c, IdParam);  // typed + validated
  // ...
});

app.get('/search', async (c) => {
  const { q, page } = await vQuery(c, SearchQuery);  // typed + validated
  // ...
});
```

The same helpers exist in the SvelteKit and Express adapters
(`@bajustone/fortress/sveltekit`, `@bajustone/fortress/express`) — they
take a `RequestEvent` or Express `Request` respectively and behave
identically.

For runtimes without a first-party adapter (Next.js, Remix, Astro,
Bun.serve, Deno, edge functions), import `validateRequest` from
`@bajustone/fortress` and call it directly inside your handler — it
validates body+query+params in one go and aggregates issues into a single
`VALIDATION_ERROR`.

### Express

```typescript
import express from 'express';
import {
  createExpressMiddleware,
  getClaims,
  getUserId,
  mountFortress,
} from '@bajustone/fortress/express';

const app = express();
app.use(express.json());
// Required for OAuth token/introspection/revocation form bodies.
app.use(express.urlencoded({ extended: false }));

// One-line mount: handles all Fortress routes (auth, IAM, plugins, OAuth,
// OpenAPI). Auth-issuing endpoints attach Set-Cookie headers automatically.
mountFortress(app, fortress);

// Optional: protect your own user routes via the IAM middleware.
const { authMiddleware, csrfMiddleware, rbacMiddleware, errorHandler } = createExpressMiddleware(fortress, {
  routeMap: {
    'GET /api/posts': { resource: 'post', action: 'list' },
    'POST /api/posts': { resource: 'post', action: 'create' },
  },
  skipPaths: ['/health'],
});

app.use('/api', csrfMiddleware); // standalone CSRF for host-owned routes
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

### SvelteKit

The SvelteKit adapter integrates as a single `handle` hook. It intercepts
Fortress-managed paths (`/auth/*`, `/iam/*`, plugin paths, OAuth, OpenAPI)
and delegates to `fortress.handleRequest`. For user routes, it auto-extracts
the access token from the configured cookie (or `Authorization: Bearer`),
verifies it, **silently refreshes when expired**, and populates
`event.locals.fortress` with the user ID, JWT claims, and a per-request DB
adapter.

```typescript
// src/lib/server/fortress.ts
import { createFortress } from '@bajustone/fortress';
import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';

export const fortress = createFortress({
  database: createDrizzleAdapter(/* ... */),
  jwt: { key: process.env.JWT_SECRET! },
});

// src/hooks.server.ts
import { sequence } from '@sveltejs/kit/hooks';
import { createSvelteKitHandle } from '@bajustone/fortress/sveltekit';
import { fortress } from '$lib/server/fortress';

export const handle = sequence(
  createSvelteKitHandle(fortress, { basePath: '/api' }),
);

// src/app.d.ts
import type { FortressLocals } from '@bajustone/fortress/sveltekit';

declare global {
  namespace App {
    interface Locals extends FortressLocals {}
  }
}
```

#### Server load functions and `+server.ts`

```typescript
// src/routes/dashboard/+page.server.ts
import { error } from '@sveltejs/kit';
import { getUserId, getScopedDb } from '@bajustone/fortress/sveltekit';

export const load = async (event) => {
  try {
    const userId = getUserId(event);
    const db = await getScopedDb(event, 'post');
    return { posts: await db.findMany({ model: 'post' }) };
  } catch {
    throw error(401, 'Unauthorized');
  }
};
```

#### Form-action login (primary flow)

```typescript
// src/routes/login/+page.server.ts
import { fortressActions } from '@bajustone/fortress/sveltekit';
import { fortress } from '$lib/server/fortress';

export const actions = {
  default: fortressActions.login(fortress, { redirectTo: '/dashboard' }),
};
```

```svelte
<!-- src/routes/login/+page.svelte -->
<script>
  import { enhance } from '$app/forms';
  export let form;
</script>

<form method="POST" use:enhance>
  <input name="identifier" required />
  <input name="password" type="password" required />
  {#if form?.error}<p>{form.error}</p>{/if}
  <button>Log in</button>
</form>
```

`fortressActions` ships `login`, `logout`, `register`, and `refresh`. Login/register return a discriminated result when no redirect is configured: `{ success: true, pending: false }` after cookies are issued, or `{ success: true, pending: true, challenge }` when another factor is required. Failures are real SvelteKit `ActionFailure`s and `redirectTo` uses SvelteKit's `redirect()` primitive (not a thrown raw `Response`).

The adapter silently refreshes expired access cookies only on safe methods and coalesces overlapping SSR refreshes for the same refresh token and user-agent fingerprint through the full request lifecycle. It forwards `x-forwarded-for`/`x-real-ip` and `user-agent` as refresh metadata, preserving hard fingerprint validation. This single-flight is process-local; use core `jwt.session.refreshGraceSeconds` for cross-worker/replica retries.

#### Optional catch-all `+server.ts` (escape hatch)

```typescript
// src/routes/api/fortress/[...path]/+server.ts
import { toSvelteKitHandler } from '@bajustone/fortress/sveltekit';
import { fortress } from '$lib/server/fortress';

export const { GET, POST, PUT, DELETE, PATCH } = toSvelteKitHandler(fortress);
```

#### Cookies and CSRF

- **Cookie defaults**: `__Host-fortress_access` / `__Host-fortress_refresh`
  with `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/` by default in all
  environments. Local HTTP development must opt out explicitly with
  `cookies: { secure: false }`, which drops the `__Host-` prefix.
- **CSRF**: Fortress-managed unsafe routes (`POST`/`PUT`/`PATCH`/`DELETE`)
  are protected by Fortress's pipeline CSRF check whenever the request
  carries either Fortress cookie (access **or** refresh):
  `Sec-Fetch-Site: cross-site` is rejected and the `X-Fortress-CSRF`
  header is required. The check is not bypassed just because an
  `Authorization` or API-key header is also present; pure bearer/API-key
  requests with no Fortress cookies skip it. Form actions (`?/login`) still
  go through `resolve()` and remain subject to SvelteKit's own
  `csrf.checkOrigin`.
- **Auto-refresh**: when an access cookie is expired but the refresh
  cookie is still valid, the handle hook silently refreshes both tokens
  and sets new cookies before `resolve(event)`. Opening N tabs at once
  triggers N parallel refreshes — JWT family rotation will fail all but
  one. (Out of scope; same trade-off as any cookie-based JWT setup.)

See `examples/sveltekit-app/` for a complete reference.

### CSRF Protection

Fortress-managed routes have pipeline CSRF enabled by default for unsafe
requests that carry a Fortress access or refresh cookie. The check still
applies when an `Authorization`/API-key header is also present alongside
cookies; only pure bearer/API-key requests with no Fortress cookies skip it.
The Hono middleware below is still available for user-owned Hono routes. It
uses the same custom-header strategy -- browsers enforce CORS preflight on
custom headers, preventing cross-site form submission:

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

Plugin-defined HTTP routes (OAuth endpoints, WebAuthn challenges, OpenAPI
spec/UI, etc.) are mounted automatically by `mountFortress` — there's
nothing extra to wire. Use the `prefix` option to namespace them under a
common base path:

```typescript
import { mountFortress } from '@bajustone/fortress/hono'; // or /express

mountFortress(app, fortress, {
  prefix: '/api',  // /api/auth/login, /api/iam/roles, /api/oauth/token, …
});
```

### Route Security Manifest

`fortress.manifest` is the generated route-security inventory used by the Hono,
Express, and SvelteKit adapters to identify Fortress-managed paths. It derives
from endpoint metadata and classifies each route as `public`, `authenticated`,
`rbac`, `oauth-protocol`, or `default-deny`, including permissions, CSRF
applicability, rate-limit coverage, and plugin origin.

```typescript
for (const route of fortress.manifest) {
  console.log(route.method, route.path, route.classification, route.permission);
}
```

CLI helpers are available for the core auth/IAM surface:

```sh
fortress manifest --out route-manifest.json
fortress manifest:check
```

See [docs/route-manifest.md](docs/route-manifest.md) for drift-checking in CI.

### Host-Owned Protected Routes

When your app owns a route but wants Fortress's security pipeline, wrap it with
`protect()` (core) or an adapter `protectedRoute()` helper — both are now
generic over the `EndpointDefinition` you pass, so `ctx.body` / `ctx.query`
/ `ctx.params` / `ctx.input` are typed from the endpoint's schemas with no
casts in your handler. The route's endpoint
metadata supplies CSRF, auth, RBAC, validation, plugin middleware, and optional
auth-cookie attachment.

```typescript
import { endpoint, obj, str } from '@bajustone/fortress';
import { protectedRoute } from '@bajustone/fortress/hono';

const statsEndpoint = endpoint('GET', '/api/stats')
  .summary('Stats')
  .security('bearer')
  .permission('stats', 'read')
  .response(200, 'OK', obj({ ok: str() }, 'ok'))
  .handler('stats')
  .build();

app.get('/api/stats', protectedRoute(fortress, statsEndpoint, async (_c, ctx) => {
  return { ok: ctx.subject?.type ?? 'unknown' };
}));
```

See [docs/host-owned-routes.md](docs/host-owned-routes.md) for Hono, Express,
and SvelteKit examples.

## Database Adapters

### Migration Tooling

Fortress ships versioned SQL migrations for Fortress-owned tables and indexes
under `migrations/{sqlite,pg}`. The bundled `0002_initial_schema` migration
creates every Fortress table, so `migrateUp` provisions a brand-new database
end-to-end through the adapter's `rawQuery` — no Drizzle or `drizzle-kit`
dependency at runtime. Runtime helpers compare your live database's
`fortress_schema_version` singleton row (and the actual tables/columns)
against the bundled catalog.

```typescript
import { detectMigrationDrift, hasMigrationDrift, migrateUp } from '@bajustone/fortress';

// Provision (or upgrade) a database — idempotent, safe on every deploy.
await migrateUp(fortress.config.database);

// Preflight: fails closed on missing tables OR missing columns.
const drift = await detectMigrationDrift(fortress.config.database);
if (hasMigrationDrift(drift))
  throw new Error('Schema drift detected');
```

CLI helpers expose the bundled catalog and SQL:

```sh
fortress migrate:status --dialect sqlite
fortress migrate:up --dialect pg --out migrations.sql
fortress migrate:check --dialect sqlite
```

See the per-release notes
([0001](docs/migrations/0001-schema-version.md),
[0002](docs/migrations/0002-initial-schema.md)) and the
[migration upgrade guide](docs/migrations/upgrade-guide.md).

### Drizzle Adapter

The Drizzle adapter supports PostgreSQL and SQLite.

#### SQLite

```typescript
import { drizzle } from 'drizzle-orm/bun-sqlite';
import { createDrizzleAdapter, fortressSchema } from '@bajustone/fortress/drizzle';

const drizzleDb = drizzle('app.db', { schema: fortressSchema });
const db = createDrizzleAdapter(drizzleDb); // dialect defaults to 'sqlite'
```

SQLite transactions are serialized with `BEGIN IMMEDIATE` to match
SQLite's single-writer model. Nested transactions on the same adapter are
not supported; calling `tx.transaction(...)` inside a SQLite transaction
throws a clear `BAD_REQUEST` error instead of deadlocking.

#### PostgreSQL

```typescript
import { drizzle } from 'drizzle-orm/node-postgres';
import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';
import { fortressPgSchema } from '@bajustone/fortress/drizzle/pg';

const drizzleDb = drizzle(connectionString, { schema: fortressPgSchema });
const db = createDrizzleAdapter(drizzleDb, { dialect: 'pg' });
```

> **Schema typing note:** `fortressSchema` and `fortressPgSchema` are typed as
> `Record<string, AnySQLiteTable>` / `Record<string, AnyPgTable>` so JSR can
> ship `.d.ts` files without "slow types" errors. This means
> `fortressSchema.users` does **not** carry column-level inference. The
> drizzle adapter itself accesses tables generically, so this is invisible to
> normal fortress usage. If you want to query the fortress tables directly
> with full column inference, declare your own typed Drizzle tables matching
> the same names and pass them via `createDrizzleAdapter(db, { tables })`.

**Constraint-error → `FortressError` mapping.** The adapter translates the
common driver constraint and concurrency states into the matching
`FortressError`, so `protect()` serializes them as the right HTTP status
without every host writing a try/catch around inserts and updates. On `pg`
this routes by SQLSTATE:

| SQLSTATE | Postgres meaning | Fortress error | HTTP |
| -------- | ---------------- | -------------- | ---- |
| `23505` | unique_violation | `CONFLICT` | 409 |
| `23503` | foreign_key_violation | `UNPROCESSABLE_ENTITY` | 422 |
| `23502` | not_null_violation | `BAD_REQUEST` | 400 |
| `23514` | check_violation | `UNPROCESSABLE_ENTITY` | 422 |
| `40001` | serialization_failure | `CONFLICT` | 409 |
| `40P01` | deadlock_detected | `CONFLICT` | 409 |
| `57014` | query_canceled | `SERVICE_UNAVAILABLE` | 503 |

On `sqlite`, the adapter maps the driver's constraint errors the same way:
`UNIQUE`/`PRIMARYKEY` → `CONFLICT/409`, `FOREIGN KEY` →
`UNPROCESSABLE_ENTITY/422`, `NOT NULL` → `BAD_REQUEST/400`. Unrecognized
errors pass through unchanged. The mapper is also exported for host routes
that use raw Drizzle directly:

```typescript
import { rethrowDbError } from '@bajustone/fortress/drizzle';

try {
  await db.insert(schools).values(input).returning();
}
catch (err) {
  rethrowDbError(err, 'pg'); // or 'sqlite'
}
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

  // Optional: raw SQL for multi-table queries. The public contract always
  // uses `?` positional placeholders; translate them to driver syntax here.
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
  jwt: { key: secret },
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
| [Rate Limit](#rate-limit) | Sliding-window rate limiting for Fortress auth endpoints and your own app routes (Hono/Express/SvelteKit wrappers + programmatic check()) |
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

Full IAM administration: users, roles, groups, permissions, role/permission bindings, and resource sync. Admin endpoints are protected by `fortress:*` permissions. The first-admin bootstrap route is opt-in and requires a one-time secret.

```typescript
import { admin } from '@bajustone/fortress/plugins/admin';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    admin({ bootstrap: { enabled: true, secret: process.env.FORTRESS_ADMIN_BOOTSTRAP_SECRET } }),
  ],
});

// Bootstrap: only succeeds while no fortress-admin bindings exist and the
// supplied secret matches the configured one-time bootstrap secret.
await fortress.plugins.admin.bootstrap({ userId: '1', secret: process.env.FORTRESS_ADMIN_BOOTSTRAP_SECRET! });

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

Sliding-window rate limiting across every Fortress sensitive endpoint (login, register, refresh, OAuth token, API-key issue) **and** any user-owned route via named rules + per-framework middleware. Tracks per-IP and per-user counters.

```typescript
import { rateLimit } from '@bajustone/fortress/plugins/rate-limit';
import { honoRateLimit } from '@bajustone/fortress/plugins/rate-limit/hono';

// 1. login + register are always on with safe defaults (credential-stuffing
//    / mass-registration protection). Configure to tune; opt out with
//    { disabled: true }. Other blocks (refresh, oauthToken, apiKeyIssue)
//    are opt-in.
rateLimit({
  // Overrides of the always-on defaults (omit these two to use defaults as-is):
  // login:    { maxPerIp: 10, maxPerAccount: 5, windowSeconds: 900 },
  // register: { maxPerIp: 3,  windowSeconds: 3600 },

  refresh:     { maxPerIp: 60, windowSeconds: 60 },
  oauthToken:  { maxPerIp: 60, windowSeconds: 60 },
  apiKeyIssue: { maxPerIp: 10, maxPerUser: 10, windowSeconds: 3600 },

  rules: {
    api: { maxPerIp: 200, maxPerUser: 1000, windowSeconds: 60 },
  },

  store: customStore,  // optional: custom RateLimitStore (default: in-memory)
})

// 2. Mount the framework wrapper on your own routes (or any Fortress path
//    the framework serves). Hono / Express / SvelteKit ship out of the box.
app.use('/api/*', honoRateLimit(fortress, 'api'));

// 3. Or call programmatically (any framework / context):
await fortress.plugins['rate-limit'].check('api', { ip, userId });
```

Two ways to apply a rule: **framework wrappers** (`honoRateLimit` / `expressRateLimit` / `svelteKitRateLimit`) for framework-mounted routes, and **config-driven `paths`** for serverless / framework-less deployments that call `fortress.handleRequest` directly. Don't stack both on the same path — each match increments the counter.

IPv6 addresses are normalized to `/64` prefixes to prevent bypass via address rotation.

When rate-limited, a `FortressError` with code `RATE_LIMITED` and a `retryAfter` value (in seconds) is thrown — adapters render it as a 429 with `Retry-After`.

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

// Step 2: Confirm setup -- activates 2FA
await fortress.plugins['two-factor'].confirmSetup(userId, '123456');

// Disable 2FA (removes secret, backup codes, and trusted devices)
await fortress.plugins['two-factor'].disable(userId);
```

**Login flow with 2FA:**

```typescript
const result = await fortress.auth.login('alice@example.com', 'password');

if (result.status === 'pending' && result.pending.reason === 'two-factor') {
  const code = await promptUser();
  const verification = await fortress.plugins['two-factor'].verify(
    result.pending.continuationToken,
    code,
    { userAgent: request.headers['user-agent'] },
  );

  // verification is AuthResult; a success contains the real session tokens.
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
const result = await fortress.plugins['magic-link'].verify(rawToken);
// AuthResult: success contains user + both session tokens; configured gates may return pending
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
  maxKeysPerSubject: 10,            // default: 10 (applies to USER and SERVICE_ACCOUNT alike)
  routes: true,                     // default: false -- mount HTTP endpoints (see below)
})
```

Keys are owned by a `Subject` -- either a `USER` or a `SERVICE_ACCOUNT`. Incoming requests that carry `Authorization: ApiKey <key>` or `X-API-Key: <key>` are automatically resolved to their owning subject via the plugin's `resolvePrincipal` capability; no middleware setup required. This works on **both** Fortress-owned routes (`/auth/*`, `/iam/*`, plugin routes, OAuth, OpenAPI) and your own user-owned routes protected by the Hono / Express / SvelteKit auth middleware — every adapter calls `fortress.resolvePrincipal(request)`, which tries the plugin chain before falling back to the JWT bearer token. The resolved principal is available on the adapter request context as `fortressSubject` (Hono `c.get('fortressSubject')` / Express `req.fortressSubject` / SvelteKit `event.locals.fortress.subject`), with `fortressUserId` populated only when `subject.type === 'USER'`.

**Self-service HTTP endpoints (opt-in via `routes: true`):**

```
POST   /api-key/keys                 create a key for the authenticated caller
GET    /api-key/keys                 list the caller's active keys
DELETE /api-key/keys/:id             revoke one of the caller's keys
POST   /api-key/keys/:id/rotate      rotate one of the caller's keys
```

All four require a bearer token. The authenticated caller can only manage
their own keys -- a body-supplied `subject` is ignored in favor of the JWT
subject, so clients cannot forge keys for other subjects.

**Admin HTTP endpoints** (for operating on *any* user's or service account's keys — register the `admin` plugin with `apiKeyRoutes: true`):

```typescript
import { admin } from '@bajustone/fortress/plugins/admin';

admin({ apiKeyRoutes: true })
```

This mounts six endpoints, all guarded by the `apiKey:manage` permission (auto-registered into the `fortress-admin` role by bootstrap when `apiKeyRoutes` is enabled):

```
# User-scoped admin routes
POST   /admin/users/:userId/api-keys               mint a key for any user
GET    /admin/users/:userId/api-keys               list any user's keys
DELETE /admin/users/:userId/api-keys/:id           revoke any user's key

# Service-account-scoped admin routes
POST   /admin/service-accounts/:id/api-keys        mint a key for a service account
GET    /admin/service-accounts/:id/api-keys        list a service account's keys
DELETE /admin/service-accounts/:id/api-keys/:keyId revoke a service account's key
```

The `POST /admin/service-accounts/:id/api-keys` endpoint is the primary path for **bootstrapping a service account's first credential** -- a fresh service account has no login flow, so an admin must mint its initial key. Admin-minted keys go through the same configured `maxKeysPerSubject` / `prefix` / `defaultExpirySeconds` knobs as self-service keys.

**Programmatic methods** (always available, regardless of the `routes` flag):

```typescript
// Create a key (same shape for USER and SERVICE_ACCOUNT)
const key = await fortress.plugins['api-key'].createKey({
  subject: { type: 'USER', id: userId },
  name: 'CI Pipeline',
  scopes: ['post:read', 'post:create'],
  expiresAt: new Date('2025-12-31'),  // optional
});
// key.key -- raw key, ONLY returned at creation (e.g., "fortress_sk_a1b2c3...")

// List active keys owned by a subject
const keys = await fortress.plugins['api-key'].listKeys({
  subject: { type: 'USER', id: userId },
});

// Revoke a key (caller must own it)
await fortress.plugins['api-key'].revokeKey({
  subject: { type: 'USER', id: userId },
  id: keyId,
});

// Rotate a key (revoke + create new with same name, scopes, and expiry)
const newKey = await fortress.plugins['api-key'].rotateKey({
  subject: { type: 'USER', id: userId },
  id: keyId,
});

// Resolve a raw key to its owning subject (used by resolvePrincipal internally;
// exposed for custom middleware)
const resolved = await fortress.plugins['api-key'].resolveKey('fortress_sk_a1b2c3...');
// resolved.subject = { type: 'USER' | 'SERVICE_ACCOUNT', id: string }
// resolved.scopes = string[] | null
// Returns null for unknown, revoked, expired, or inactive-subject keys.
```

---

### Social Login

OAuth/OIDC consumer for Google, GitHub, Microsoft, Apple, Discord, and custom OIDC providers. Supports automatic user registration, verified-email account linking, PKCE, OAuth state validation, OIDC ID-token verification, and AES-256-GCM encryption for stored provider tokens.

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
  linkAccounts: true,      // default: true (link by matching verified email only)
  tokenEncryptionKey: process.env.FORTRESS_SOCIAL_TOKEN_KEY!, // 32-byte AES key
  onFirstLogin: async (user, provider, profile) => {
    // Called when a user logs in via social for the first time
  },
})
```

**Methods:**

```typescript
// Step 1: Get the authorization URL (redirect the user here)
const { url, state, codeVerifier, nonce } = await fortress.plugins['social-login']
  .getAuthorizationUrl('google', 'https://myapp.com/auth/callback');
// Store state, codeVerifier, and nonce in the session

// Step 2: Handle the callback (after user authorizes)
const result = await fortress.plugins['social-login']
  .handleCallback('google', code, 'https://myapp.com/auth/callback', codeVerifier, returnedState, state, nonce);
// result.user, result.profile, result.isNewUser

// List linked social accounts
const accounts = await fortress.plugins['social-login'].getLinkedAccounts(userId);

// Read decrypted provider tokens when you need to call the provider API
const providerTokens = await fortress.plugins['social-login'].getProviderTokens(userId, 'google');

// Unlink a social account
await fortress.plugins['social-login'].unlinkAccount(userId, 'google');

// List configured providers
const providers = fortress.plugins['social-login'].getProviders();
```

Built-in providers: **Google**, **GitHub**, **Microsoft** (with tenant support), **Apple**, **Discord**. Any OIDC-compliant provider can be added via the `issuer` field.

---

### Tenancy

Schema-per-tenant isolation for PostgreSQL. Each tenant gets its own schema named from its numeric id (`tenant_<id>` by default). The active tenant comes from the verified JWT custom claim, not a client header.

```typescript
import { tenancy } from '@bajustone/fortress/plugins/tenancy';

tenancy({
  schemaPrefix: 'tenant_',
  routes: false, // opt in to /tenancy/* HTTP routes with true
  onSchemaCreated: async (schemaName, rawQuery) => {
    await rawQuery(`CREATE TABLE IF NOT EXISTS ${schemaName}.widgets (id SERIAL PRIMARY KEY)`);
  },
  dropSchemaOnDelete: false,
})
```

**Methods:**

```typescript
// Create a new tenant (creates PostgreSQL schema tenant_<id>)
const tenant = await fortress.plugins['tenancy'].createTenant({
  name: 'Acme Corp',
  taxId: 'acme-corp', // unique external code; not used in schema names
  description: 'Enterprise customer',
});

// Add a user to a tenant (first tenant becomes default)
await fortress.plugins['tenancy'].addUserToTenant(userId, tenant.id);

// List tenants
const tenants = await fortress.plugins['tenancy'].getUserTenants(userId);
const mine = await fortress.plugins['tenancy'].getMyTenants({ userId });
// => { tenants: TenantRecord[] } (matches GET /tenancy/tenants/mine)

// Switch the user's default tenant atomically; token refresh/login picks it up.
// A database invariant permits at most one default membership per user.
await fortress.plugins['tenancy'].switchTenant({ taxId: 'acme-corp', userId });

// Delete tenant row/memberships; schema drop requires dropSchemaOnDelete
await fortress.plugins['tenancy'].deleteTenant({ id: tenant.id });
```

The plugin automatically:
- Enriches JWT custom claims with `tenantId` and `tenantCode`
- Pins PostgreSQL `search_path` transaction-locally with a bound parameter
- Fails closed when no verified tenant claim is present

JWT staleness note: removing a user from a tenant takes effect when existing access tokens expire or are refreshed; revoke sessions for immediate removal.

---

### Data Isolation

Row-level data isolation that works with any database. Automatically injects WHERE filters on reads and default values on creates.

Runtime note: `withoutScope()` and `unscoped()` use `node:async_hooks` /
`AsyncLocalStorage` so bypasses are isolated to the current async request.
Use this plugin only in Node/Bun-compatible runtimes that provide
`node:async_hooks`; edge/browser-like runtimes may need a custom wrapper or
should avoid the bypass helpers.

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
| `LOGIN_SUCCESS` | `ROLE_CREATED` / `ROLE_UPDATED` / `ROLE_DELETED` |
| `LOGIN_FAILURE` | `ROLE_BOUND` / `ROLE_UNBOUND` |
| `LOGIN_PENDING` | `ROLE_PERMISSION_ADDED` / `ROLE_PERMISSION_REMOVED` |
| `MFA_VERIFY_SUCCESS` / `MFA_VERIFY_FAILURE` | `PERMISSION_CREATED` / `PERMISSION_DELETED` / `PERMISSION_CHANGED` |
| `LOGOUT` | `GROUP_CREATED` / `GROUP_UPDATED` / `GROUP_DELETED` |
| `REGISTER` | `GROUP_MEMBER_ADDED` / `GROUP_MEMBER_REMOVED` |
| `TOKEN_REFRESH` | `SERVICE_ACCOUNT_CREATED` / `SERVICE_ACCOUNT_UPDATED` / `SERVICE_ACCOUNT_DELETED` |
| `TOKEN_REUSE` | |

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

// Export for compliance/retention — JSON (default) or RFC 4180 CSV,
// using the same filters as getAuditLog
const csv = await fortress.plugins['audit-log'].exportEntries('csv', {
  userId: 42,
  from: new Date('2026-01-01'),
});
```

When `hashChain` is enabled, each log entry stores a SHA-256 hash of the previous entry. `verifyChain()` walks the entire chain and reports any mismatches.

---

### Webhook

Delivers events to consumer endpoints using the [Standard Webhooks](https://www.standardwebhooks.com) spec — HMAC-SHA256 signing, **custom events**, **Bring-Your-Own-Queue**, SSRF-safe delivery with connect-time IP pinning, failure classification, a circuit breaker, and DLQ hooks. See [docs/plugins/webhook.md](docs/plugins/webhook.md) for the full reference.

```typescript
import { builtinEvents, databaseQueue, webhook } from '@bajustone/fortress/plugins/webhook';
import { obj, str } from '@bajustone/fortress';

webhook({
  events: [
    ...builtinEvents(),                          // auth.login.success, auth.user.registered, …
    { name: 'order.paid', schema: obj({ orderId: str() }, 'orderId') }, // declare your own
  ],
  queue: databaseQueue({ pollMs: 10_000 }),      // default: dev-only inMemoryQueue()
  maxPayloadBytes: 256 * 1024,
  delivery: {
    timeoutMs: 10_000,
    maxConsecutiveFailures: 15,                  // circuit breaker
    onDeliveryFailed: d => deadLetter.push(d),   // DLQ seam
  },
})
```

Built-in events (dispatched automatically): `auth.login.success`, `auth.login.failure`, `auth.logout`, `auth.user.registered`, `auth.token.refreshed`. Retry ladder (jittered): 5s, 5min, 30min, 2h, 5h.

**Methods:**

```typescript
const wh = fortress.plugins.webhook;

// Register an endpoint — a CSPRNG secret is generated when omitted and returned ONCE.
const endpoint = await wh.registerEndpoint('https://myapp.com/webhooks', ['auth.login.success', 'order.paid']);
console.log(endpoint.secret); // whsec_… — store it now

// Emit a custom event (validated against its schema + the payload cap)
await wh.emit('order.paid', { orderId: 'o_123' }, { idempotencyKey: 'o_123' });

await wh.updateEndpoint(endpoint.id, { isActive: false });
await wh.rotateSecret(endpoint.id);              // returns a fresh secret once
const endpoints = await wh.listEndpoints();      // secret REDACTED
await wh.removeEndpoint(endpoint.id);
await wh.stop();                                 // tear down the queue worker on shutdown
```

Webhook payloads include Standard Webhooks headers:

```
webhook-id: msg_<unique-id>
webhook-timestamp: 1234567890
webhook-signature: v1,<base64-hmac-sha256>
```

---

### OAuth Server

Full OAuth 2.0 / OIDC server. Spec coverage:

- **RFC 6749** Authorization Code + PKCE, Client Credentials, **Refresh Token** (with rotation)
- **RFC 6750** Bearer Token Usage · **RFC 7009** revocation · **RFC 7662** introspection
- **RFC 7636** mandatory PKCE (RFC 9700 §2.1.1) — plain method rejected, S256 only
- **RFC 8252** OAuth for native apps (public clients via `tokenEndpointAuthMethod: 'none'`, loopback redirect URIs with any-port)
- **RFC 8414** AS Metadata + **OIDC Discovery 1.0** (full claims/scopes/algs metadata)
- **RFC 9207** issuer identification on the authorization response (anti-mix-up)
- **RFC 9700** OAuth Security BCP — mandatory PKCE, single-use codes, refresh-token rotation with replay detection
- **OpenID Connect Core 1.0** — id_token (RS256), userinfo with scope-gated standard claims, nonce echo, JWKS at `/oauth/.well-known/jwks.json`

See `docs/oauth-compliance-plan.html` for the full spec-by-spec compliance matrix.

```typescript
import { oauth } from '@bajustone/fortress/plugins/oauth';

oauth({
  authCodeExpirySeconds: 600,        // default: 600 (10 min)
  pendingFlowExpirySeconds: 600,     // default: 600 (10 min)
  accessTokenExpirySeconds: 3600,    // default: 3600 (1 hour)
  refreshTokenExpirySeconds: 30 * 24 * 3600, // default: 30 days; 0 disables
  idTokenExpirySeconds: 3600,        // default: 3600 (OIDC Core)
  issuerUrl: 'https://auth.myapp.com', // MUST be https:// in production
  scopePermissionMap: {
    'read:posts': { resource: 'post', action: 'read' },
    'write:posts': { resource: 'post', action: 'create' },
  },
  // Optional per-deployment claim extension for /oauth/userinfo + id_token.
  userinfoClaims: (user, scope) => ({
    tenant_id: (user as any).tenantId,
    ...(scope?.includes('profile') ? { picture: (user as any).avatarUrl } : {}),
  }),
  // Opt-in: SPA-friendly consent flow (Pattern B). The host app owns the
  // login + consent UI; Fortress only returns redirects and JSON.
  enableAuthorizeEndpoint: true,
  enableConsentApi: true,
  loginUrl:   'https://app.myapp.com/signin',
  consentUrl: 'https://app.myapp.com/oauth/consent',
})
```

**Public clients (RFC 8252):** SPAs and native apps register with
`tokenEndpointAuthMethod: 'none'` and authenticate via PKCE alone — no
client secret. Loopback redirect URIs (`http://127.0.0.1/cb`,
`http://[::1]/cb`) match any-port at runtime, so native apps can pick a
port dynamically. `localhost` (DNS) is *not* widened (DNS-rebinding
guidance, RFC 8252 §8.3).

**id_token + JWKS (OIDC Core):** when the request includes
`scope=openid`, `/oauth/token` issues an RS256 id_token alongside the
access token. The signing key is auto-generated on first use and
published at `/oauth/.well-known/jwks.json` (`kid` = RFC 7638
thumbprint). `nonce` from the authorize request is echoed verbatim;
`auth_time` is recorded at consent.

**Refresh tokens with rotation (RFC 9700 §2.2.2):** every successful
`exchangeCode` returns a refresh token. `grant_type=refresh_token` rotates
the pair on each use. Reuse of an already-rotated token is treated as
attack — the entire token family is revoked, forcing re-authentication.
Set `refreshTokenExpirySeconds: 0` to disable refresh-token issuance.

**Per-client scope allow-list (RFC 6749 §3.3):** pass
`allowedScopes: ['openid', 'email', 'profile']` to `createClient` to
gate which scopes a given client can request. Scope intersection is
applied at authorize and `client_credentials`; widening on refresh is
rejected; narrowing is permitted.

**Standard error wire shape:** `/oauth/token` returns the RFC 6749 §5.2
body `{ error, error_description, error_uri? }` with machine-readable
codes (`invalid_request`, `invalid_client`, `invalid_grant`,
`unauthorized_client`, `unsupported_grant_type`, `invalid_scope`,
`access_denied`, ...). Strict RPs that switch behaviour on the `error`
field work out of the box.

**SPA-friendly authorization (Pattern B):**

When `enableAuthorizeEndpoint` and `enableConsentApi` are on, Fortress runs
the OAuth state machine while your host app (e.g. SvelteKit) renders the
login and consent screens. The flow:

1. OAuth client redirects browser to `GET /oauth/authorize?client_id=...&redirect_uri=...&response_type=code&state=...&code_challenge=...`.
2. Fortress validates, creates an `oauth_pending_flow` row, and 302s to either `${loginUrl}?flow=<id>` (no session) or `${consentUrl}?flow=<id>` (logged in).
3. The consent page calls `GET /oauth/flows/<id>` for client name + scopes, then `POST /oauth/flows/<id>/approve` (or `/deny`) and navigates the browser to the returned `redirectUrl`.

No HTML is ever served from Fortress — the framework-agnostic stance is preserved.

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

**HTTP Routes** (auto-mounted via `mountFortress`):

| Method | Path | Description |
|--------|------|-------------|
| POST | `/oauth/token` | Token endpoint (auth code + client credentials) |
| POST | `/oauth/introspect` | Token introspection (RFC 7662) |
| POST | `/oauth/revoke` | Token revocation (RFC 7009) |
| GET | `/oauth/userinfo` | OIDC UserInfo endpoint |
| GET | `/.well-known/openid-configuration` | OIDC Discovery document |
| GET | `/oauth/authorize` | *(opt-in)* Front door for the auth-code flow — 302s to `loginUrl` / `consentUrl` |
| GET | `/oauth/flows/:flowId` | *(opt-in)* Pending-flow metadata for the consent UI |
| POST | `/oauth/flows/:flowId/approve` | *(opt-in)* Issue auth code, return `redirectUrl` |
| POST | `/oauth/flows/:flowId/deny` | *(opt-in)* Cancel flow, return `access_denied` redirect URL |

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
// Registration: generate options for navigator.credentials.create().
// Over HTTP (POST /webauthn/register/options), the dispatcher builds the
// PluginRouteContext from the bearer token — the caller never supplies a
// userId. For programmatic calls, construct a minimal ctx by hand:
const { options } = await fortress.plugins['webauthn'].generateRegistrationOptions(
  {},
  { userId, request: new Request('http://localhost') },
);

// Verify registration response and store credential for the authenticated caller
const result = await fortress.plugins['webauthn'].verifyRegistration(
  { response: registrationResponseFromBrowser },
  { userId, request: new Request('http://localhost') },
);

// Authentication: generate options for navigator.credentials.get()
const { options: authOpts } = await fortress.plugins['webauthn'].generateAuthenticationOptions({});

// Verify authentication and get tokens (passwordless mode)
const authResult = await fortress.plugins['webauthn'].verifyAuthentication({
  response: assertionFromBrowser,
});
// authResult is AuthResult; success carries user, method, accessToken, refreshToken
```

When `supportPasswordless` is `false`, the plugin acts as a second factor via the `postAuthGate` hook. Complete the pending challenge with `completeAuthentication(continuationToken, assertion, meta)`.

See [WebAuthn plugin docs](docs/plugins/webauthn.md) for the full configuration and API reference.

---

### OpenAPI

Fortress can emit an OpenAPI 3.1 spec directly from the endpoint definitions it knows about — core auth/IAM routes, plugin routes, and any top-level host `routes` registered on `createFortress`.

For env/DB-free codegen/build scripts, call the standalone helper with your endpoint list:

```typescript
import { toOpenAPI } from '@bajustone/fortress';
import { appEndpointList } from './routes/v1/endpoints';

const spec = toOpenAPI(appEndpointList, {
  title: 'My API',
  version: '1.0.0',
  servers: [{ url: 'http://localhost:3001', description: 'Local development' }],
  tags: [{ name: 'Schools' }],
});

await writeFile('openapi.json', `${JSON.stringify(spec, null, 2)}\n`);
```

If you already have a configured Fortress instance, use `fortress.toOpenAPI()` instead; it defaults the endpoint list to everything the instance knows about:

```typescript
const spec = fortress.toOpenAPI({ title: 'My API', version: '1.0.0' });
```

By default, both helpers use each endpoint's `handler` as the OpenAPI `operationId` (for example `schools.get`). Pass `operationId: 'methodPath'` to use Fortress's historical generated IDs.

For a mounted JSON spec + Scalar UI, use the OpenAPI plugin:

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

> **No Zod required.** If you author with fortress's or fetcher's builder, use the bundled converters from `@bajustone/fortress/hono` instead of a Zod converter: `toJSONSchemaConverter` for `convertRoutes` (import side), and `identitySchemaConverter` / `fetcherSchemaConverter` for `mountFortressOpenAPI` (mount side — the latter compiles to a validating Standard Schema for `hono-openapi`/`@hono/standard-validator`).

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
| `tags` | — | Top-level OpenAPI tags |
| `operationId` | generated method+path IDs | Operation ID strategy: `'methodPath'`, `'handler'`, or a callback |
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

## Observability

Fortress has three layered observability surfaces — none of them write to stderr or import OpenTelemetry unless you opt in.

### Pluggable logger

Pass any `pino()` instance, Fastify `app.log`, or hand-rolled structural logger via `config.logger`. The default is a silent no-op.

```typescript
import pino from 'pino';
import { createFortress } from '@bajustone/fortress';

const fortress = createFortress({
  jwt: { key: process.env.JWT_SECRET! },
  database: db,
  logger: pino({ level: 'info' }),
});
```

Fortress routes these events to the logger when they happen:
- Plugin token-claim overwrite warnings (dev only)
- Refresh token fingerprint mismatch (warn mode)
- Unhandled errors in `fortress.handleRequest` and the Express error handler
- Observer failures (see below)

### Auth / IAM / permission-check observers

Three independent listener lists on the Fortress services. Each `add…Observer` call returns an `() => void` unsubscribe function.

```typescript
// Auth lifecycle (async, cold path) — login/logout/register/refresh/token-reuse
const offAuth = fortress.auth.addAuthObserver(async (event) => {
  if (event.eventType === 'LOGIN_FAILURE') {
    await siem.log(event);
  }
});

// IAM mutations (async, cold path) — role/permission/binding changes
fortress.iam.addIamObserver(async (event) => {
  if (event.eventType.startsWith('ROLE_')) {
    await notifySlack(event);
  }
});

// Permission checks (SYNCHRONOUS, hot path) — per-check duration + cache hit flag
fortress.iam.addPermissionCheckObserver((event) => {
  // Keep this fast — runs on every check.
  if (!event.allowed) {
    metrics.increment('auth.denies');
  }
});
```

Listener exceptions never break the auth/IAM operation — they're routed to `logger.error` and the remaining listeners continue.

### OpenTelemetry adapter (opt-in)

Import from the `/otel` sub-path and pass the result to `config.observability`. The adapter dynamically imports `@opentelemetry/api`, so runtimes that don't import `/otel` never resolve the peer dep — Cloudflare Workers, Deno without OTel, and embedded deployments stay clean.

```typescript
import { createFortress } from '@bajustone/fortress';
import { createOtelTelemetry } from '@bajustone/fortress/otel';

const observability = await createOtelTelemetry({ name: 'my-app-auth' });
const fortress = createFortress({
  jwt: { key: process.env.JWT_SECRET! },
  database: db,
  observability,
});
```

The adapter keeps `fortress.handleRequest` active across the full async pipeline, so nested database/IAM spans inherit the request span. Logger, telemetry, Auth/IAM event/listener, permission-check listener, and `Unsubscribe` types are exported from both the package root and `/otel`.

When a global OTel `MeterProvider` / `TracerProvider` is registered (e.g., via `NodeSDK` or `BasicTracerProvider`), Fortress emits:

| Metric | Type | Unit | Attributes |
|---|---|---|---|
| `fortress.auth.events.total` | counter | — | `event`, `outcome`, `method` |
| `fortress.iam.events.total` | counter | — | `event` |
| `fortress.iam.permission_check.duration` | histogram | s | `subject_type`, `result`, `cached` |
| `fortress.iam.permission_check.cache.hits` | counter | — | — |
| `fortress.iam.permission_check.cache.misses` | counter | — | — |
| `db.client.operation.duration` | histogram | s | `db.system.name`, `db.operation.name`, `db.collection.name` |

The DB histogram uses the **stable OTel semantic-convention name** — Grafana dashboards built for `db.client.operation.duration` automatically pick up Fortress's auth/IAM queries.

Fortress also emits one span:
- `fortress.iam.permission_check.deny` — fired only on denied checks (security-interesting). Allowed checks are metric-only to keep the hot path cheap.

User IDs, emails, tenant IDs, and raw resource IDs are deliberately **not** on any metric attribute — they'd cause cardinality explosions. They go on spans and logs instead. HTTP request duration is not emitted by Fortress either; that's the host framework's job (`@opentelemetry/instrumentation-http`, `@opentelemetry/instrumentation-hono`, etc.).

**Install the peer dep** alongside the Fortress import:

```bash
bun add @opentelemetry/api
# plus whatever SDK you're using:
bun add @opentelemetry/sdk-node @opentelemetry/exporter-trace-otlp-http
```

## Testing

Use the built-in test adapter for unit and integration tests. It creates an in-memory SQLite database with all Fortress tables pre-created.

```typescript
import { createTestAdapter } from '@bajustone/fortress/testing';
import { createFortress } from '@bajustone/fortress';
import { describe, it, expect } from 'vitest';

describe('auth', () => {
  const fortress = createFortress({
    database: createTestAdapter(),
    jwt: { key: 'test-secret-min-32-bytes-long!!!' },
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
- [Threat model](docs/threat-model.md) -- OAuth/OIDC, refresh rotation, CSRF, IAM/RBAC, API keys, tenancy, and drift controls
- [Route manifest](docs/route-manifest.md) and [host-owned routes](docs/host-owned-routes.md)
- [Production deployment guide](docs/deployment.md), [migration upgrade guide](docs/migrations/upgrade-guide.md), [threat model](docs/threat-model.md), [typed adapter helpers](docs/adapter-typed-helpers.md), [CI checks](docs/ci.md), [policy-as-code](docs/policy-as-code.md), [admin recipes](docs/admin-recipes.md), [hardening guide](docs/hardening.md), [compatibility matrix](docs/compatibility.md), [examples](examples/README.md)
- Plugin guides: [Admin](docs/plugins/admin.md), [Rate Limit](docs/plugins/rate-limit.md), [Account Lockout](docs/plugins/account-lockout.md), [Email Verification](docs/plugins/email-verification.md), [Two-Factor](docs/plugins/two-factor.md), [Magic Link](docs/plugins/magic-link.md), [API Key](docs/plugins/api-key.md), [Social Login](docs/plugins/social-login.md), [Tenancy](docs/plugins/tenancy.md), [Data Isolation](docs/plugins/data-isolation.md), [Audit Log](docs/plugins/audit-log.md), [Webhook](docs/plugins/webhook.md), [OAuth](docs/plugins/oauth.md), [WebAuthn](docs/plugins/webauthn.md), [OpenAPI](docs/plugins/openapi.md)

## License

[MIT](LICENSE)
