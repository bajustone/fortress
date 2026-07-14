# Fortress Architecture

## Overview

Fortress (`@bajustone/fortress`) is a framework-agnostic, adapter-based authentication and authorization library for TypeScript. The core provides JWT-based auth (login, refresh tokens, password hashing, session management, impersonation) and IAM (groups, roles, resource+action permissions with conditions and deny rules). Everything else — OAuth, tenancy, 2FA, email verification, API keys, data isolation, social login, rate limiting, account lockout, audit logging, webhooks, magic links — is a plugin.

**Runtime dependencies:** `jose` (JWT via Web Crypto API) and `hash-wasm` (WASM Argon2id default — swappable via `PasswordHasher` interface). No native bindings — works on Bun, Deno, Node, and edge runtimes.

**Published on:** [JSR](https://jsr.io) as `@bajustone/fortress` and npm as `@bajustone/fortress`.

---

## Module Structure

```
src/
  index.ts                              # createFortress() factory, re-exports all public types

  core/
    types.ts                            # All domain types: FortressUser, TokenClaims, Permission, Role, etc.
    config.ts                           # FortressConfig type + defaults
    errors.ts                           # FortressError class + Errors factory
    fortress.ts                         # createFortress() + getPluginMethods()
    plugin.ts                           # FortressPlugin interface, hook types, model/route definitions
    plugin-runner.ts                    # processPlugins(), chainAdapterWrappers(), collectScopeRules(), executePluginMiddleware()
    plugin-methods-map.ts               # InferPlugins<T> type utility for type-safe plugin access
    internal-adapter.ts                 # Entity-specific query layer on top of generic CRUD

    auth/
      jwt.ts                            # JWT sign/verify (jose, HS256, key rotation)
      password.ts                       # PasswordHasher interface + WASM Argon2id default
      password-policy.ts                # NIST 800-63B policy + HIBP k-anonymity breach check
      refresh-token.ts                  # Token generation, SHA-256 hashing, family rotation
      auth-service.ts                   # Login, refresh, logout, sessions, impersonation, admin user CRUD
      auth-endpoints.ts                 # EndpointDefinition[] for all auth routes + component schemas

    iam/
      permission-evaluator.ts           # Resource+action evaluation, conditions, deny-overrides
      iam-service.ts                    # Groups, roles, permissions CRUD, checkPermission
      iam-endpoints.ts                  # EndpointDefinition[] for all IAM routes + component schemas
      resource-sync.ts                  # Load/export fortress.resources.json, DB sync, type generation

    json-schema.ts                      # JSON Schema type definitions (draft 2020-12 subset)
    endpoint.ts                         # EndpointDefinition interface
    schema-builder.ts                   # Fluent builder helpers: str(), obj(), endpoint(), etc.
      permission-cache.ts               # LRU cache with TTL and invalidation

    http/
      handle-request.ts                 # fortress.handleRequest(request) — top-level pipeline
      dispatch.ts                       # body parse + handler invoke (auth/iam/plugin/oauth/openapi)
      match.ts                          # endpoint route table + matchRoute()
      cookie-serialize.ts               # Set-Cookie builder + parseCookieHeader
      token-extraction.ts               # cookie-first then Authorization: Bearer
      error-response.ts                 # FortressError → web Response
      fortress-rbac.ts                  # default-deny for fortress-managed paths
      plugin-middleware.ts              # runPluginMiddleware(plugins, phase, ctx)

  adapters/
    database/
      index.ts                          # DatabaseAdapter interface (generic CRUD)
      types.ts                          # WhereClause, CoreOperator, ScopeRule

  testing/
    index.ts                            # createTestAdapter() — in-memory SQLite (bun:sqlite or better-sqlite3)
    adapter-conformance.test.ts         # runAdapterTests() — shared adapter contract test suite

  drizzle/
    index.ts                            # createDrizzleAdapter() export
    adapter.ts                          # DatabaseAdapter implementation (PostgreSQL, SQLite)
    schema.ts                           # SQLite reference table definitions (24 tables)
    pg/
      index.ts                          # PostgreSQL-specific export
      schema.ts                         # PostgreSQL table definitions (pgTable, serial, varchar, timestamp)

  hono/
    index.ts                            # createHonoMiddleware() + mountFortress() exports
    handle.ts                           # mountFortress(app, fortress) — delegates to core.handleRequest
    middleware/
      auth.ts                           # Bearer token extraction + JWT verify + plugin adapter wrapping
      rbac.ts                           # User-route routeMap RBAC (fortress-path RBAC moved to core)
      csrf.ts                           # Custom-header CSRF protection (X-Fortress-CSRF)
      security-headers.ts               # HSTS, CSP, X-Frame-Options, etc.
      error-handler.ts                  # Delegates to core errorToResponse
    helpers.ts                          # getUserId(), getClaims(), getDb(), getScopedDb()
    plugin-routes.ts                    # @deprecated — replaced by mountFortress + core.handleRequest

  express/
    index.ts                            # Express middleware + mountFortress() exports
    handle.ts                           # mountFortress(app, fortress) — bridges Express ↔ web Request/Response
    middleware.ts                       # Auth, RBAC, error handler for Express
    routes.ts                           # @deprecated — replaced by mountFortress

  sveltekit/
    index.ts                            # createSvelteKitHandle, toSvelteKitHandler, fortressActions, helpers
    handle.ts                           # createSvelteKitHandle(fortress, options) — primary handle hook
    catch-all.ts                        # toSvelteKitHandler(fortress) — escape hatch for +server.ts
    actions.ts                          # fortressActions.login/logout/register/refresh
    cookies.ts                          # setAuthCookies, clearAuthCookies, replayCookies
    helpers.ts                          # getUserId, getClaims, getDb, getScopedDb (read event.locals.fortress)
    types.ts                            # FortressLocals/options + real @sveltejs/kit-compatible Handle/Action types

  plugins/
    tenancy/index.ts                    # Schema-per-tenant isolation (PostgreSQL only)
    oauth/
      index.ts                          # OAuth 2.0 server (auth code + PKCE, client credentials, OIDC)
      pkce.ts                           # PKCE S256 challenge/verification
    two-factor/index.ts                 # TOTP, backup codes, trusted devices
    email-verification/index.ts         # Token-based email verification
    api-key/index.ts                    # Scoped API keys for service accounts / devices
    data-isolation/index.ts             # Row-level data isolation (any database)
    social-login/
      index.ts                          # OAuth/OIDC consumer flow, account linking
      types.ts                          # ProviderProfile, ProviderDefinition, SocialLoginConfig
      providers/
        index.ts                        # builtInProviders registry
        microsoft.ts                    # Microsoft Entra ID (tenant-parameterized)
        google.ts                       # Google OIDC
        github.ts                       # GitHub OAuth2 (not OIDC — uses userinfo endpoint)
        apple.ts                        # Apple Sign In (ID token only)
        discord.ts                      # Discord OAuth2
        oidc.ts                         # Generic OIDC provider factory
    rate-limit/index.ts                 # Sliding window rate limiting (per-IP + per-account)
    account-lockout/index.ts            # Progressive lockout with escalating duration
    audit-log/index.ts                  # Append-only event logging with optional hash chain
    webhook/index.ts                    # Standard Webhooks spec (HMAC-SHA256, retries)
    magic-link/index.ts                 # Passwordless token-based auth
    webauthn/index.ts                   # Passkeys/WebAuthn (registration, passwordless auth, 2FA mode)
    admin/index.ts                      # Full IAM admin: protected endpoints + opt-in secret bootstrap

bin/
  fortress.ts                           # CLI tool: init, sync:push, sync:pull, sync:types, generate-secret

examples/
  hono-app/
    index.ts                            # Full example demonstrating all features
    docker-compose.yml                  # PostgreSQL for examples
```

---

## Dependency Graph

```
fortress.ts ─────────────────────────────────────────────────────────┐
├── auth-service.ts                                                  │
│   ├── jwt.ts ← jose                                               │
│   ├── password.ts ← hash-wasm (Argon2id)                          │
│   ├── password-policy.ts ← HIBP API (fetch)                       │
│   ├── refresh-token.ts ← crypto.subtle (SHA-256), crypto.getRandomValues │
│   ├── internal-adapter.ts ← DatabaseAdapter                       │
│   └── plugin-runner.ts (hooks: before/after login, register, etc.) │
├── iam-service.ts                                                   │
│   ├── permission-evaluator.ts                                      │
│   ├── permission-cache.ts                                          │
│   ├── resource-sync.ts ← fs (fortress.resources.json)              │
│   └── internal-adapter.ts ← DatabaseAdapter                       │
├── plugin-runner.ts                                                 │
│   └── (chains plugin hooks, wrapAdapter, enrichTokenClaims, scopeRules) │
└── config.ts (defaults)                                             │
                                                                     │
Framework adapters (hono/, express/) ────────────────────────────────┘
└── Import Fortress instance, create middleware
```

**Key import rule:** `core/` modules never import from `hono/`, `express/`, `drizzle/`, or `plugins/`. Framework adapters and plugins depend on core, not the reverse.

---

## Key Design Decisions

### 1. Generic CRUD DatabaseAdapter

Per-entity adapter interfaces are an unsustainable complexity tax — adapter authors must update code for every new feature. Fortress uses a generic 7-method CRUD contract instead. Plugins declare new models (`oauth_client`, `two_factor_secret`) and query them through the same `create`/`findOne`/`update`/`delete` contract. No adapter changes needed.

See `src/adapters/database/index.ts` for the interface, `src/drizzle/adapter.ts` for the reference implementation.

### 2. jose for JWT (not jsonwebtoken)

`jsonwebtoken` doesn't support ESM, doesn't work on edge runtimes, and has no native TypeScript types. `jose` uses the Web Crypto API, works everywhere (Bun, Deno, Cloudflare Workers, Node), is zero-dependency, and tree-shakeable.

See `src/core/auth/jwt.ts`.

### 3. Pluggable PasswordHasher (cross-runtime)

`@node-rs/argon2` uses native bindings that break on Deno Deploy and serverless. Password hashing is a pluggable `PasswordHasher` interface with a WASM-based Argon2id default (via `hash-wasm`). Consumers can swap for `@node-rs/argon2`, `Bun.password`, or any custom implementation.

See `src/core/auth/password.ts`.

### 4. Framework-Agnostic Core HTTP Pipeline (`fortress.handleRequest`)

The core exposes a single web-standard entry point: `fortress.handleRequest(request: Request): Promise<Response>`. It runs the full pipeline — plugin `before-auth` middleware → token verification (cookie-first, `Authorization: Bearer` fallback) → plugin `after-auth` → fortress-managed default-deny RBAC → plugin `after-rbac` → Standard Schema validation → endpoint dispatch → cookie attachment for auth-issuing endpoints.

Login / refresh / impersonate responses get `Set-Cookie` headers automatically using `FortressConfig.cookies` (defaults: `__Host-` prefixed `httpOnly` `Secure` `SameSite=Lax` in production, relaxed in dev so localhost over HTTP works).

Adapters (`hono/`, `express/`, `sveltekit/`) detect Fortress-managed paths and delegate. New adapters are ~10-line wrappers — translate the framework's request to a `Request`, call `fortress.handleRequest`, send the `Response` back.

See `src/core/http/` for the implementation: `handle-request.ts`, `dispatch.ts`, `match.ts`, `cookie-serialize.ts`, `token-extraction.ts`, `error-response.ts`, `fortress-rbac.ts`, `plugin-middleware.ts`.

### 5. Everything Beyond Core Auth + IAM Is a Plugin

15 plugins, all optional. No special `modules` config, no `withX()` wrappers. This keeps the core small (~1500 lines) and makes extensibility uniform. See [Plugin System](#plugin-system) for the full interface.

### 6. Composable Entry Points

Users who only need JWT or password hashing shouldn't pull in the full system. Each piece is independently importable via sub-path exports (`@bajustone/fortress/jwt`, `@bajustone/fortress/crypto`).

### 7. Database-Agnostic Core

The Drizzle adapter works with PostgreSQL and SQLite. Only the tenancy plugin (schema-per-tenant via a transaction-pinned `search_path`) is PostgreSQL-specific. For database-agnostic multi-tenancy, use the data isolation plugin with row-level filtering.

### 8. Transport-Agnostic Permissions (Resource + Action)

Permissions are `resource` + `action`, not `path` + `httpVerb`. HTTP-to-resource mapping happens in the framework adapter layer. This means permissions work in HTTP, CLI, cron, WebSocket, and event contexts without modification.

### 9. Open WhereClause Operator

`WhereClause.operator` is `string`, not a closed union. New operators (`like`, `isNull`, `between`) can be added by plugins or consumers without breaking existing adapters. `CoreOperator` documents the required minimum that all adapters must support. Adapters throw on unsupported operators at runtime.

### 10. Secret Rotation

`jwt.key` accepts `string | string[]`. When an array, the first secret signs, all secrets verify. This allows zero-downtime rotation:

```typescript
// Step 1: Add new secret, keep old one for verification
jwt: { key: ['new-secret', 'old-secret'] }

// Step 2: After all old tokens expire, remove old secret
jwt: { key: 'new-secret' }
```

---

## Core: Authentication

**File:** `src/core/auth/auth-service.ts`

### Auth Service API

```typescript
interface AuthService {
  login(identifier: string, password: string, meta?: RequestMeta): Promise<AuthResult>;
  refresh(refreshToken: string, meta?: RequestMeta): Promise<AuthTokenPair>;
  logout(refreshToken: string): Promise<void>;
  me(userId: string): Promise<FortressUser>;
  createUser(data: CreateUserInput): Promise<FortressUser>;
  verifyToken(token: string): Promise<TokenClaims>;
  signToken(claims: Omit<TokenClaims, 'iat' | 'exp'>): Promise<string>;
  listSessions(userId: string): Promise<SessionInfo[]>;
  revokeSession(userId: string, tokenId: string): Promise<void>;
  revokeAllOtherSessions(userId: string, currentTokenId: string): Promise<void>;
  addLoginIdentifier(userId: string, type: 'email' | 'phone' | 'username', value: string): Promise<void>;
  removeLoginIdentifier(userId: string, type: string, value: string): Promise<void>;
  getLoginIdentifiers(userId: string): Promise<LoginIdentifier[]>;
  impersonate(adminUserId: string, targetUserId: string, options?: { reason?: string; expiresInSeconds?: number }): Promise<AuthResult>;

  // Admin user management
  listUsers(options: { limit?, offset?, search?, sortBy?, sortDirection? }): Promise<{ users: FortressUser[]; total: number }>;
  getUserById(userId: string): Promise<FortressUser>;
  updateUser(userId: string, data: { name?, email?, isActive? }): Promise<FortressUser>;
  deleteUser(userId: string): Promise<void>;
}
```

### Login Flow

Step-by-step walkthrough of `auth-service.ts:196`:

```
1. Run beforeLogin hooks (all plugins, in registration order)
   → Any plugin can short-circuit with { stop: true, response: {...} }
   → Account lockout plugin checks if user is locked here
   → Rate limit plugin checks IP/account limits here

2. Resolve user via internal adapter:
   a. Try login_identifier table (where value = identifier)
   b. Fall back to user table (where email = identifier)
   → If not found: run dummy password verify (timing oracle prevention), throw UNAUTHORIZED

3. Check user.isActive — throw UNAUTHORIZED if deactivated

4. Verify password: Argon2id verify(user.passwordHash, password)
   → If fails: run onLoginFailure hooks (account lockout increments counter), throw UNAUTHORIZED

5. Fetch user's groups via internal adapter (group_user → group names)

6. Run every registered post-auth gate before token issuance
   → A hold returns AuthPending with a single-use continuation challenge
   → Pending results have no accessToken or refreshToken properties

7. Collect enriched token claims from all plugins (enrichTokenClaims)
   → Tenancy plugin adds tenantId, tenantCode
   → Claims are shallow-merged; later plugin wins on key conflicts

8. Sign the access token and atomically persist the refresh-token family

9. Build AuthSuccess { status: 'success', method, user, accessToken, refreshToken }

10. Run success-only afterLogin hooks, then emit LOGIN_SUCCESS

11. Return the final AuthResult
```

### Refresh Flow

`auth-service.ts:248`:

```
1. Hash the incoming refresh token (SHA-256)
2. Look up token by hash in DB
3. If not found → throw UNAUTHORIZED
4. If already revoked → TOKEN REUSE DETECTED:
   a. Revoke ALL tokens in the same family (invalidate entire session)
   b. Throw TOKEN_REUSE error
5. Check expiration — throw UNAUTHORIZED if expired
6. Optional fingerprint validation:
   - 'hard' mode (validateRefreshFingerprint: true): reject mismatched fingerprint
   - 'warn' mode: log warning but allow
7. Revoke the current token (mark as used)
8. Generate new refresh token with SAME family ID
9. Update session metadata (lastActiveAt, IP, userAgent)
10. Sign new access token with fresh claims
11. Run afterTokenRefresh hooks
12. Return new { accessToken, refreshToken }
```

### JWT Implementation

**File:** `src/core/auth/jwt.ts`

- **Algorithm:** HS256 (HMAC-SHA256 via Web Crypto API)
- **Library:** `jose` — `SignJWT` for signing, `jwtVerify` for verification
- **Key encoding:** Secret string → `TextEncoder.encode()` → `Uint8Array`
- **Key rotation:** When `secret` is an array, the first key signs, all keys are tried for verification (first successful match wins)
- **Claims set:** `sub` (user ID as string), `iss` (issuer), `iat` (issued at), `exp` (expiration), `name`, `groups`, `customClaims`, optional `act` (impersonation)

### Password Hashing

**File:** `src/core/auth/password.ts`

```typescript
interface PasswordHasher {
  hash(password: string): Promise<string>;
  verify(hash: string, password: string): Promise<boolean>;
}
```

**Default implementation (WASM Argon2id):**
- Memory: 64 MB (`memorySize: 65536`)
- Iterations: 3
- Parallelism: 1
- Hash length: 32 bytes
- Salt: 16 bytes random

**Timing oracle prevention:** When a user is not found during login, a dummy `verify()` call is executed against a pre-hashed value. This ensures login attempts for nonexistent users take the same time as attempts for real users.

### Password Policy

**File:** `src/core/auth/password-policy.ts`

Enforced during `createUser()` when `config.passwordPolicy` is set.

- **Min length:** 15 characters for new passwords
- **Max length:** 128 characters
- **HIBP integration:** Optional k-anonymity check against the Have I Been Pwned API
  - Hash password with SHA-1, send first 5 chars as prefix
  - API returns all hashes with that prefix — check locally
  - **Cache:** Module-level bounded LRU of HIBP ranges with a 24-hour TTL
  - **Degradation:** `'open'` (default) accepts writes during outages; `'closed'` rejects with 503. Both emit `PASSWORD_BREACH_CHECK_DEGRADED`
- **Config:**
  ```typescript
  interface PasswordPolicyConfig {
    minLength?: number;                  // default: 15
    maxLength?: number;                  // default: 128
    checkBreached?: boolean;             // default: false — enables HIBP check
    breachedCacheTtlMs?: number;         // default: 86400000
    breachedCacheMaxEntries?: number;    // default: 1000; 0 disables
    breachedFailureMode?: 'open' | 'closed'; // default: 'open'
  }
  ```

### Refresh Tokens

**File:** `src/core/auth/refresh-token.ts`

- **Generation:** 32 bytes from `crypto.getRandomValues()`, base64url encoded
- **Storage:** Only SHA-256 hash persisted via `crypto.subtle.digest()` — raw token never stored
- **Family tracking:** Each token has a `tokenFamily` UUID. New tokens on refresh inherit the family ID. If a revoked token is reused, the entire family is revoked (all sessions for that login)
- **Fingerprint:** Optional `SHA-256(userAgent)` stored alongside token. On refresh, validated in hard or warn mode per `config.jwt.validateRefreshFingerprint`

### Session Management

`auth-service.ts:455-510`

Sessions are derived from active (non-revoked, non-expired) refresh tokens:

- **`listSessions(userId)`** — Returns all active refresh tokens as `SessionInfo[]` with `id`, `ipAddress`, `userAgent`, `deviceName`, `lastActiveAt`, `createdAt`
- **`revokeSession(userId, tokenId)`** — Revokes a specific refresh token (logs user out of that device)
- **`revokeAllOtherSessions(userId, currentTokenId)`** — Revokes all tokens except the current one ("log out everywhere else")

### Impersonation

`auth-service.ts:538`

Admin impersonation using RFC 8693 actor claim:

- Issues a **non-renewable** access token (no refresh token)
- Token includes `act: { sub: adminUserId }` claim per RFC 8693
- Short-lived: default 3600s, configurable
- Returns `AuthImpersonation { status: 'impersonation', refreshToken: null }`
- **Caller responsibility:** Verify the admin has `fortress:impersonate` permission before calling
- Includes `reason` and `expiresInSeconds` in `pluginData`

### Multi-Key Login

Users can log in with email, phone, or username — all sharing the same password via the `login_identifier` model:

```
login_identifier { id, userId, type: 'email'|'phone'|'username', value (globally unique) }
```

When a user is created via `createUser({ email, name, password })`, a `login_identifier` of type `email` is automatically created. Additional identifiers are managed via `addLoginIdentifier()` / `removeLoginIdentifier()`.

---

## Core: IAM

**File:** `src/core/iam/iam-service.ts`

### IAM Service API

```typescript
interface IamService {
  checkPermission(userId: string, resource: string, action: string, context?: PermissionContext): Promise<boolean>;
  getUserPermissions(userId: string, tenantId?: string): Promise<Permission[]>;
  createRole(name: string, permissions: PermissionInput[], description?: string): Promise<Role>;
  deleteRole(roleId: string): Promise<void>;
  bindRole(subjectType: SubjectType, subjectId: string, roleId: string, tenantId?: string): Promise<void>;
  bindRoleToUser(userId: string, roleId: string, tenantId?: string): Promise<void>;
  bindRoleToGroup(groupId: string, roleId: string, tenantId?: string): Promise<void>;
  unbindRole(subjectType: SubjectType, subjectId: string, roleId: string, tenantId?: string): Promise<void>;
  bindPermissionToUser(subjectId: string, permission: PermissionInput, tenantId?: string): Promise<void>;
  bindPermissionToGroup(subjectId: string, permission: PermissionInput, tenantId?: string): Promise<void>;
  unbindPermissionFromUser(subjectId: string, permissionId: string, tenantId?: string): Promise<void>;
  unbindPermissionFromGroup(subjectId: string, permissionId: string, tenantId?: string): Promise<void>;
  createGroup(name: string, description?: string): Promise<Group>;
  addUserToGroup(groupId: string, userId: string): Promise<void>;
  removeUserFromGroup(groupId: string, userId: string): Promise<void>;
  syncResources(direction: 'push' | 'pull', filePath?: string): Promise<void>;
  setIamObserver(listener: IamEventListener): void;
  clearPermissionCache(): void;

  // Admin CRUD
  getRole(roleId: string): Promise<Role & { permissions: Permission[] }>;
  updateRole(roleId: string, data: { name?, description? }): Promise<Role>;
  listGroups(options?: { limit?, offset? }): Promise<{ groups: Group[]; total: number }>;
  getGroup(groupId: string): Promise<Group & { users: FortressUser[] }>;
  updateGroup(groupId: string, data: { name?, description? }): Promise<Group>;
  deleteGroup(groupId: string): Promise<void>;
  getGroupUsers(groupId: string): Promise<FortressUser[]>;
  listPermissions(options?: { resource? }): Promise<Permission[]>;
  createPermission(permission: PermissionInput): Promise<Permission>;
  deletePermission(permissionId: string): Promise<void>;
  addPermissionToRole(roleId: string, permission: PermissionInput): Promise<void>;
}
```

### Permission Model

```typescript
interface Permission {
  id: string;
  resource: string;     // "user", "post", "invoice"
  action: string;       // "create", "read", "update", "delete"
  effect: 'ALLOW' | 'DENY';
  conditions?: PermissionCondition[];
  description?: string;
}

interface PermissionCondition {
  field: string;        // "resource.ownerId", "request.ip", "user.department"
  operator: 'eq' | 'neq' | 'in' | 'startsWith';
  value: ConditionValue;  // string, string[], { ref: string }, or "${user.id}" template
}
```

### Permission Chain

Role bindings reference subjects directly via `subjectType` + `subjectId` — no intermediate `principal` table:

```
User ──────────┐
               │
Group ─────────┼── RoleBinding ── Role ── RolePermission ── Permission
  (via group_user)  │
               │
ServiceAccount ┘
```

Permissions are also directly bindable to any subject type without a role (via `direct_permission_binding`).

### Service Accounts

Service accounts are non-human IAM principals — CI/CD pipelines, devices, M2M clients, anything that needs permissions without being tied to a human user. They're a first-class peer of `USER` and `GROUP` in the subject system.

**File:** `src/core/iam/iam-service.ts` (CRUD methods) + `src/drizzle/schema.ts` (`fortress_service_account`).

Key characteristics:

- **No sessions, passwords, or refresh tokens.** They don't sign in — they're authenticated by api keys (or future credential mechanisms: OAuth client_credentials, mTLS, signed JWT assertions).
- **No group memberships.** Service accounts hold roles and direct permission bindings directly. The permission resolver (`getSubjectPermissions`) skips the group-walk for any non-user subject — a service account with the same numeric id as a group will not inherit that group's permissions.
- **Globally scoped at the table level.** Tenant scoping happens at `role_binding.tenantId`, the same mechanism users use. A single service account can hold tenant-scoped or global bindings.
- **Immutable `name`.** The `name` column is the machine identifier and cannot be updated after creation (matches Kubernetes / IAM conventions). To rename, delete and recreate.
- **`isActive` kill-switch.** Flipping `isActive: false` makes `resolveApiKey` return `null` for every key owned by the service account, and makes `getSubjectPermissions` return an empty permission list — two independent layers of defense.
- **Hard delete with cascade.** `deleteServiceAccount` removes the account row and all `role_binding` / `direct_permission_binding` rows for that subject. The api-key plugin listens via `addIamObserver` for `SERVICE_ACCOUNT_DELETED` and hard-deletes its owned keys. Core IAM doesn't import from the api-key plugin; the cascade is plugin-owned.
- **JWT tokens are not issued for service accounts.** `auth-service.issueTokens` always mints `subjectType: 'USER'`. A future plugin (OAuth client_credentials, mTLS) that wants to issue tokens for service accounts can call `signAccessToken` directly with `subjectType: 'SERVICE_ACCOUNT'` — the claims pipeline already supports it.

### Request Principal Resolution

**Files:** `src/core/http/principal.ts` (shared resolver helpers), `src/core/http/handle-request.ts` (fortress-owned routes), adapter user-route middleware (`src/hono/middleware/auth.ts`, `src/express/middleware.ts`, `src/sveltekit/handle.ts`).

Fortress threads a single `Subject` type through the entire pipeline:

```ts
type Subject = { type: 'USER' | 'GROUP' | 'SERVICE_ACCOUNT'; id: string };
```

Every request resolves to a `Subject` (or `undefined` for public routes) via two ordered paths:

1. **Plugin `resolvePrincipal`**: plugins implementing the `resolvePrincipal` capability are tried in registration order. The first to return non-null wins; its subject becomes the request principal. The api-key plugin implements this for `Authorization: ApiKey <key>` and `X-API-Key: <key>` headers. Future credential plugins (OAuth client_credentials, mTLS, signed JWT assertions) plug in at the same point without core changes.
2. **JWT fallback**: if no plugin resolves the request, the configured JWT bearer token is verified (cookie-first, `Authorization: Bearer` second). `TokenClaims.subjectType` is read from the JWT payload (default `'USER'` for legacy tokens that don't carry the claim).

Crucially, this two-stage resolution fires on **both** surfaces:

- **Fortress-owned routes** (`/auth/*`, `/iam/*`, plugin routes, OAuth, OpenAPI) run it inside `fortress.handleRequest` via `tryPluginPrincipal`. The JWT fallback runs for `security: 'bearer'` routes and for any route with permission metadata, so permission-only declarations authenticate consistently before RBAC.
- **User-owned routes** (your own `app.get(...)` handlers in Hono / Express / SvelteKit) run it inside the adapter auth middleware via `fortress.resolvePrincipal(request)` — which is just `tryPluginPrincipal` + a non-throwing JWT fallback. Every adapter pinpoints the resolved subject on its framework-native request context:
  - Hono: `c.get('fortressSubject')` (plus `c.get('fortressUserId')` as a USER-only alias)
  - Express: `req.fortressSubject` (plus `req.fortressUserId` as a USER-only alias)
  - SvelteKit: `event.locals.fortress.subject` (plus `event.locals.fortress.userId` as a USER-only alias)

This is the fix for the gap where api-key headers authenticated `/auth/*` and `/iam/*` but silently 401'd on custom routes — every credential type now works the same way on both surfaces. Third-party adapters can wire up to the same pipeline with a single call to `fortress.resolvePrincipal(request)`.

The resolved `subject` flows into `enforceFortressPermission`, `fortress.iam.checkPermission`, and the adapter-level `createRbacMiddleware` — all of which are subject-aware. Downstream RBAC evaluates the same way regardless of how the principal was authenticated.

### Permission Evaluation

**File:** `src/core/iam/permission-evaluator.ts`

Two evaluation modes (configured via `config.rbac.evaluationMode`):

1. **`allow-only`** (default): If any ALLOW permission matches → allow. Otherwise deny.
2. **`deny-overrides`** (AWS-style):
   - Collect all matching permissions (from roles + direct bindings + group memberships)
   - If any DENY matches → deny (overrides everything)
   - If any ALLOW matches → allow
   - Otherwise → implicit deny

**Condition evaluation:**
- All conditions on a permission must be true (AND logic)
- Field paths resolve from context: `resource.ownerId`, `request.tenantId`, `user.id`
- Variable references: `${user.id}` template syntax or `{ ref: "user.id" }` typed alternative
- Operators: `eq`, `neq`, `in`, `startsWith`
- Wildcard: `*` matches any resource or action

**Permission resolution** (in `internal-adapter.ts:91`):
- **Optimized path:** If `db.rawQuery` is available, uses a single SQL JOIN query across `role_binding` → `role_permission` → `permission` tables
- **Fallback path:** Multiple sequential `findMany` calls — slower but correct for adapters without `rawQuery`
- Permissions come from: direct user bindings + group memberships (via `group_user` → group's role bindings)
- Tenant filtering: With a requested tenant, includes global (`tenantId IS NULL`) and matching tenant grants. Without a requested tenant, only global grants match.

### Permission Cache

**File:** `src/core/iam/permission-cache.ts`

LRU cache for permission query results:

- **Key:** `userId` (string)
- **Value:** Permission array with `expiresAt` timestamp
- **TTL:** Configurable via `config.rbac.cache.ttlSeconds`
- **Max entries:** Configurable via `config.rbac.cache.maxEntries`
- **Eviction:** When capacity reached, oldest entry deleted (Map insertion order)
- **Invalidation strategies:**
  - `invalidate(userId)` — Clear cache for a specific user (used after role/permission changes)
  - `invalidateAll()` — Clear entire cache (used after group membership changes, which affect all users in that group)
- **Tenant bypass:** Queries with a `tenantId` parameter always bypass cache (tenant varies per request)

### Resource Sync

**File:** `src/core/iam/resource-sync.ts`

Bidirectional sync between `fortress.resources.json` and the database:

- **`sync:push`** (JSON → DB): Reads resource file, creates/updates resources and permissions in DB. Upsert logic — creates only if not exists.
- **`sync:pull`** (DB → JSON): Exports all resources and permissions from DB to JSON file.
- **`sync:types`**: Generates TypeScript types from resource definitions:
  ```typescript
  // Generated: fortress.resources.d.ts
  type FortressResource = 'user' | 'post' | 'invoice';
  type FortressAction<R extends FortressResource> =
    R extends 'user' ? 'create' | 'read' | 'update' | 'delete' | 'list' | 'ban' :
    // ...
  ```

### IAM Events

`iam-service.ts` emits events via `setIamObserver()` for all mutations:

```
ROLE_CREATED, ROLE_DELETED, ROLE_BOUND, ROLE_UNBOUND,
PERMISSION_CHANGED, PERMISSION_CREATED, PERMISSION_DELETED, GROUP_CREATED, GROUP_UPDATED, GROUP_DELETED, GROUP_MEMBER_ADDED, GROUP_MEMBER_REMOVED
```

Events are consumed by the audit-log plugin (if registered) for tamper-evident logging.

---

## Database Layer

### DatabaseAdapter Interface

**File:** `src/adapters/database/index.ts`

```typescript
interface DatabaseAdapter {
  create<T>(params: { model: string; data: Record<string, unknown> }): Promise<T>;
  findOne<T>(params: { model: string; where: WhereClause[] }): Promise<T | null>;
  findMany<T>(params: { model: string; where?: WhereClause[]; limit?: number; offset?: number; sortBy?: { field: string; direction: 'asc' | 'desc' } }): Promise<T[]>;
  update<T>(params: { model: string; where: WhereClause[]; data: Record<string, unknown> }): Promise<T | null>;
  delete(params: { model: string; where: WhereClause[] }): Promise<void>;
  count(params: { model: string; where?: WhereClause[] }): Promise<number>;
  transaction<T>(fn: (tx: DatabaseAdapter) => Promise<T>): Promise<T>;

  /** Optional: raw SQL for performance-critical multi-table operations.
   *  Adapters that implement this get optimized IAM queries (single JOIN
   *  instead of 4 sequential findMany calls).
   *  Placeholders: `?` on every dialect; adapters translate to driver syntax. */
  rawQuery?<T>(sql: string, params?: unknown[]): Promise<T[]>;

  /** Database dialect hint for rawQuery SQL generation */
  readonly dialect?: 'sqlite' | 'pg';
}
```

**WhereClause:**
```typescript
interface WhereClause {
  field: string;
  operator: CoreOperator | string;  // open string for extensibility
  value: unknown;
}

type CoreOperator = '=' | '!=' | 'in' | 'gt' | 'lt' | 'gte' | 'lte';
```

**ScopeRule** (used by data isolation and plugin `scopeRules`):
```typescript
interface ScopeRule {
  filters: WhereClause[];                  // Auto-injected on findOne, findMany, count, update, delete
  defaults: Record<string, unknown>;       // Auto-injected on create
}
```

### Internal Adapter Layer

**File:** `src/core/internal-adapter.ts`

Wraps `DatabaseAdapter` with entity-specific query logic used by `auth-service` and `iam-service`. This layer exists so the auth and IAM services don't need to construct raw `WhereClause` arrays everywhere.

Key methods:
- **`findUserByIdentifier(identifier)`** — Tries `login_identifier` table first, falls back to `user.email`
- **`getUserGroups(userId)`** — Resolves `group_user` → `group` names
- **`getUserPermissions(userId, tenantId?)`** — Optimized: single `rawQuery` JOIN if available, fallback to multiple `findMany`. Returns all permissions from role bindings + direct bindings, deduplicated
- **`findRefreshTokenByHash(tokenHash)`** — Single `findOne` on `refresh_token`
- **`findOrCreatePermission(input)`** — Upsert by resource+action
- **`ensureResource(name)`** — Create resource if not exists

### Core DB Models

| Model | Key Fields | Notes |
|-------|-----------|-------|
| `user` | id, email, name, passwordHash, isActive, emailVerified, createdAt, updatedAt | Core identity. passwordHash nullable (social-only users). |
| `login_identifier` | id, userId, type, value, tenantId? | Multiple login methods per user. Value is globally unique. |
| `refresh_token` | id, userId, tokenHash, tokenFamily, isRevoked, expiresAt, ipAddress, userAgent, deviceName, fingerprintHash, lastActiveAt | Token rotation with family tracking. |
| `group` | id, name, description | User grouping. |
| `group_user` | groupId, userId | M2M junction. |
| `resource` | name (PK), description | Resource type registry. |
| `permission` | id, resource, action, effect, conditions (JSON), description | Transport-agnostic permission. |
| `role` | id, name, description, isSystem | Named permission collection. |
| `role_permission` | roleId, permissionId | M2M junction. |
| `role_binding` | id, roleId, subjectType, subjectId, tenantId? | Direct subject → role reference. |
| `permission_binding` | id, permissionId, subjectType, subjectId, tenantId? | Direct permission binding (no role). |

**Plugin models** (24 total across all plugins): `oauth_client`, `oauth_authorization_code`, `oauth_access_token`, `oauth_pending_flow`, `two_factor_secret`, `backup_code`, `trusted_device`, `email_verification_token`, `api_key`, `user_scope_assignment`, `social_account`, `tenant`, `tenant_user`, `account_lockout`, `audit_log`, `magic_link_token`, `webhook_endpoint`, `webhook_delivery`, `webauthn_credential`, `webauthn_challenge`, `rate_limit_counter`.

### Drizzle Adapter

**File:** `src/drizzle/adapter.ts`

Reference `DatabaseAdapter` implementation supporting SQLite and PostgreSQL via Drizzle ORM.

**Dialect handling:**
- SQLite: Synchronous `.get()`, `.all()`, `.run()` — results returned immediately
- PostgreSQL: Async — results awaited

**Transaction handling:**
- SQLite: Manual `BEGIN`/`COMMIT`/`ROLLBACK` (Drizzle SQLite transactions aren't truly async-compatible)
- PostgreSQL: Native `db.transaction()` support

**Field conversion:** Automatic `snake_case` ↔ `camelCase` mapping between JS objects and DB columns.

**Operator mapping:** Maps `CoreOperator` values to Drizzle equivalents (`eq`, `ne`, `inArray`, `gt`, `lt`, `gte`, `lte`).

**Table overrides:** For existing projects, accepts a `tables` map to use consumer's own Drizzle table definitions instead of Fortress defaults:

```typescript
const adapter = createDrizzleAdapter(db, {
  tables: {
    user: myUsersTable,           // your Drizzle table definition
    refresh_token: myTokensTable, // fortress maps model names to your tables
  },
});
```

**Schemas:**
- `src/drizzle/schema.ts` — SQLite tables (sqliteTable)
- `src/drizzle/pg/schema.ts` — PostgreSQL tables (pgTable, serial, varchar, timestamp)

### Testing Adapter

**File:** `src/testing/index.ts`

In-memory SQLite adapter for unit tests:

- **Runtime detection:** Tries `bun:sqlite` first (dynamic import), falls back to `better-sqlite3`
- **Auto-creates** all 24 fortress tables on initialization
- **Enables:** Foreign key constraints, WAL journal mode
- **Returns:** A fully functional `DatabaseAdapter` wrapping Drizzle over the in-memory SQLite

```typescript
import { createTestAdapter } from '@bajustone/fortress/testing';
const adapter = createTestAdapter(); // zero-setup, in-memory
```

**Conformance suite:** `src/testing/adapter-conformance.test.ts` exports `runAdapterTests()` — a shared test suite that any adapter implementation can run to verify it meets the `DatabaseAdapter` contract.

---

## OpenAPI & Endpoint Definitions

### JSON Schema-First Architecture + Standard Schema

Fortress uses JSON Schema (draft 2020-12) as the universal format for endpoint definitions. Every auth method, IAM method, and plugin route carries an `EndpointDefinition` with JSON Schema metadata describing its inputs and outputs.

Since OpenAPI 3.1 uses JSON Schema natively, spec generation is trivial (just wrapping).

**Standard Schema V1:** Fortress's schema builder (`obj()`, `str()`, `int()`, etc.) returns `FortressSchema<T>` — objects that are simultaneously valid JSON Schema AND valid [Standard Schema V1](https://standardschema.dev). This gives each schema three capabilities from a single definition:

1. **JSON Schema** — `schema.type`, `schema.properties` → OpenAPI 3.1
2. **Standard Schema** — `schema['~standard'].validate()` → runtime validation
3. **TypeScript types** — `Infer<typeof schema>` or `StandardSchemaV1.InferOutput<typeof schema>` → compile-time inference

**Validation engine:** `~standard.validate()` delegates to [`@bajustone/fetcher`](https://www.npmjs.com/package/@bajustone/fetcher)'s `fromJSONSchema`, which compiles the JSON Schema object into a validator (lazily, memoized). Fortress no longer ships a hand-rolled validator. The builder DSL stays thin and JSON-Schema-shaped, but because fetcher enforces the full keyword set, richer builders are available: `str({ min, max, pattern })` / `int({ min, max })` (enforced constraints), `literal()` (`const`), `intersect()` (`allOf`), `strict()` (`additionalProperties: false`), `discriminatedUnion()` (`oneOf` + `discriminator`), and enforced string formats `email()`/`uuid()`/`url()`/`datetime()`/`date()`/`time()` (ReDoS-safe patterns lifted from fetcher). `$ref` request fields validate permissively (compiled without the components map). The same fetcher toolkit is re-exported at `@bajustone/fortress/fetcher`.

Additionally, `endpoint().body()`, `.query()`, `.params()` accept external Standard Schema (Zod, Valibot, ArkType, or fetcher's own builder) directly — fortress extracts JSON Schema for OpenAPI and uses `~standard.validate()` for runtime validation. Fetcher's builder schemas (from `@bajustone/fortress/fetcher`) are first-class: they validate via fetcher's engine and serialize to clean OpenAPI because the spec builder's `cleanSchema` strips every `~`-prefixed key (and function/undefined value) recursively.

### EndpointDefinition

Replaces the old `RouteDefinition`. Backward-compatible — new fields are optional.

```ts
interface EndpointDefinition {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH';
  path: string;
  handler: string;
  meta?: { summary, description, tags, security, deprecated, permission? };
  input?: { body?: JSONSchema, query?: JSONSchema, params?: JSONSchema };
  responses?: Record<number, { description: string, schema?: JSONSchema }>;
}
```

`fortress.endpoints` exposes all endpoint definitions (auth + IAM + plugins).

**`meta.permission`** — Optional `{ resource, action }` declaration. When set, the RBAC middleware automatically enforces this IAM permission on the route. The admin plugin's bootstrap auto-discovers all declared permissions and registers them. IAM endpoints declare `permission: { resource: 'fortress', action: '...' }`.

### Builder Helpers

Fluent API for typed schema authoring:

```ts
import { obj, str, int, arr, endpoint, type Infer } from '@bajustone/fortress';

// Define a schema — typed + JSON Schema + Standard Schema in one object
const createRoleBody = obj(
  { name: str(), permissions: arr(ref('PermissionInput')) },
  'name', 'permissions',
);
type CreateRoleBody = Infer<typeof createRoleBody>;
// { name: string; permissions: unknown[] }

endpoint('POST', '/iam/roles')
  .summary('Create a role').tags('IAM').security('bearer')
  .permission('fortress', 'createRole')
  .body(createRoleBody)
  .response(201, 'Role created', ref('Role'))
  .handler('createRole').build()
```

**Additional helpers:**

```ts
nullType()             // FortressSchema<null>
record('desc')         // FortressSchema<Record<string, unknown>> — { type: 'object', additionalProperties: true }
recordOf(str(), 'desc') // FortressSchema<Record<string, string>> — typed values
enums('a', 'b')        // FortressSchema<'a' | 'b'>
nullable(str())        // FortressSchema<string | null>
```

**Detection utilities:** `isStandardSchema(value)`, `isFortressSchema(value)`, `extractJsonSchema(schema)`.

Schemas can also be external Standard Schema (Zod, Valibot, ArkType):

```ts
import { z } from 'zod';
endpoint('POST', '/users').body(z.object({ name: z.string() })).build()
```

### Runtime Validation

Two surfaces, one shared primitive.

**Fortress-managed endpoints** — auth, IAM, and plugin routes —
validate automatically inside `fortress.handleRequest`. The dispatcher
reads the parsed body, calls `validateRequest` from
`src/core/validation.ts`, and throws `FortressError('VALIDATION_ERROR',
422)` on failure (issues from body+query+params aggregated into a single
error). Adapter middleware (`mountFortress` for Hono/Express,
`createSvelteKitHandle` for SvelteKit) doesn't need to do anything extra
— delegating to `fortress.handleRequest` is enough.

**Consumer-defined routes** — handlers a fortress user mounts in their
own app — validate per call via the framework adapter's `vBody` /
`vParam` / `vQuery` helpers. Each helper extracts the relevant slice of
the request, calls the internal `validateValue` (a Standard Schema
wrapper around the same `Errors.validationError` factory used by
`validateRequest`), and returns the parsed value or throws
`VALIDATION_ERROR`. The Hono, SvelteKit, and Express adapters all ship
the same three helpers; only the receiver type differs (Hono `Context`,
SvelteKit `RequestEvent`, Express `Request`-like). All three are async
because Standard Schema's `validate()` may return a promise.

**Runtimes without an adapter** — Next.js, Remix, Astro, Bun.serve,
Deno, edge functions — call `validateRequest` directly. It is now a
public export from `@bajustone/fortress` and validates a `{ body, query,
params }` object against an `EndpointInput`, throwing the same
`VALIDATION_ERROR` shape as the per-handler helpers.

### OpenAPI Plugin

`openapi()` plugin generates OpenAPI 3.1 spec and serves Scalar UI:

```ts
import { convertRoutes } from '@bajustone/fortress/hono';
import { loginRoute, listUsersRoute } from './modules/auth/routes';
import { z } from 'zod'; // or Valibot, TypeBox, ArkType

const fortress = createFortress({
  plugins: [
    openapi({
      title: 'My API',
      // convertRoutes turns createRoute-style objects into EndpointDefinitions
      // using your own schema converter — fortress has zero schema deps
      additionalEndpoints: convertRoutes(
        [loginRoute, listUsersRoute],
        { prefix: '/api/v1', schemaConverter: z.toJSONSchema },
      ),
    }),
  ],
});
// GET /openapi.json — unified spec (fortress + app endpoints)
// GET /openapi — Scalar UI
// fortress.plugins.openapi.generateSpec() — programmatic access
```

### Schema-Library Agnostic Hono Adapter

`mountFortressOpenAPI()` accepts a user-provided `SchemaConverter` — Fortress has zero dependency on any schema library. Users pass their library's own JSON Schema converter:

```ts
import { mountFortressOpenAPI } from '@bajustone/fortress/hono';
import { z } from 'zod';                 // Zod v4 has built-in JSON Schema support
import { createRoute } from '@hono/zod-openapi';

mountFortressOpenAPI(app, fortress, {
  schemaConverter: z.fromJSONSchema,       // or TypeBox, ArkType, Valibot converter
  createRoute,
});
```

Supported schema libraries (via their own JSON Schema support):
- **Zod v4**: `z.fromJSONSchema()` (built-in)
- **TypeBox**: schemas ARE JSON Schema natively
- **ArkType**: `@ark/jsonschema`
- **Valibot**: `json-schema-to-valibot` (ecosystem package)

**Zod-free defaults.** Because fortress's and fetcher's builder schemas ARE JSON Schema, `@bajustone/fortress/hono` ships ready-made converters so you can skip Zod entirely: `identitySchemaConverter` (JSON Schema passthrough), `fetcherSchemaConverter` (`fromJSONSchema` → a validating Standard Schema, for `hono-openapi` / `@hono/standard-validator`), and `toJSONSchemaConverter` (`extractJsonSchema`, for importing fetcher/fortress-authored routes via `convertRoutes`).

**Spec-drift CI gate.** `src/core/openapi-drift.test.ts` runs `@bajustone/fetcher/spec-tools`' `lintSpec` over the emitted spec and fails on any keyword the runtime validator can't enforce except the intentional `format` (paired with an enforcing `pattern` via `email()`/`uuid()`) and `additionalProperties` — catching e.g. a `multipleOf`/`exclusiveMinimum` added to a request schema that would silently not validate.

### CLI Codegen

```bash
fortress openapi --out openapi.json          # Generate OpenAPI spec
fortress schemas --format zod --out schemas.ts  # Generate Zod schemas
fortress schemas --format json-schema --out schemas.json
```

---

## Plugin System

### FortressPlugin Interface

**File:** `src/core/plugin.ts`

```typescript
interface FortressPlugin {
  name: string;                           // Unique identifier (used as key in fortress.plugins)
  models?: ModelDefinition[];             // DB tables this plugin needs
  hooks?: PluginHooks;                    // Auth lifecycle interception
  methods?: (ctx: PluginContext) => Record<string, Function>;  // Operations exposed on fortress.plugins.<name>
  routes?: RouteDefinition[];             // HTTP endpoints (auto-mounted by framework adapter)
  middleware?: MiddlewareDefinition[];     // Per-request middleware
  wrapAdapter?: (adapter: DatabaseAdapter, requestContext: Record<string, unknown>) => DatabaseAdapter;
  enrichTokenClaims?: (userId: string, ctx: PluginContext) => Promise<Record<string, unknown>>;
  scopeRules?: (userId: string, model: string, ctx: PluginContext) => Promise<ScopeRule | null>;
}
```

### Plugin Runner Internals

**File:** `src/core/plugin-runner.ts`

**`processPlugins(plugins, ctx)`** (`plugin-runner.ts:11`):
- Creates the `methods` map for each plugin by calling `plugin.methods(ctx)`
- Returns `{ methods, plugins }` — methods are keyed by plugin name

**`chainAdapterWrappers(plugins, adapter, requestContext)`** (`plugin-runner.ts:31`):
- Iterates plugins in registration order
- Each `wrapAdapter` receives the result of the previous wrapper
- Last registered plugin's wrapper is **outermost** (processes queries first)
- Example: `[tenancy, dataIsolation]` → `dataIsolation.wrapAdapter(tenancy.wrapAdapter(adapter))`

**`collectScopeRules(plugins, userId, model, ctx)`** (`plugin-runner.ts:81`):
- Calls `scopeRules()` on each plugin that defines it
- Merges results: filters are AND'd together, defaults are shallow-merged
- Returns `null` only if no plugin returned a rule
- The merged scope rule is then applied by a **scope rule wrapper** that intercepts all DB operations (`findOne`, `findMany`, `update`, `delete`, `count`, `create`, `transaction`)

### Hook Lifecycle

```typescript
interface PluginHooks {
  // Before hooks — can short-circuit with { stop: true, response: {...} }
  beforeLogin?: (ctx: HookContext & { email: string }) => Promise<HookResult | void>;
  beforeRegister?: (ctx: HookContext & { data: CreateUserInput }) => Promise<HookResult | void>;
  beforeTokenRefresh?: (ctx: HookContext & { token: string }) => Promise<HookResult | void>;
  beforeLogout?: (ctx: HookContext & { token: string }) => Promise<void>;

  // Post-auth gates run before token issuance; afterLogin is success-only
  postAuthGate?: PostAuthGateProvider;
  afterLogin?: (ctx: AfterHookContext, result: AuthSuccess) => Promise<AuthSuccess>;
  afterRegister?: (ctx: AfterHookContext, user: FortressUser) => Promise<void>;
  afterTokenRefresh?: (ctx: AfterHookContext, result: AuthTokenPair) => Promise<AuthTokenPair>;

  // Failure hooks
  onLoginFailure?: (ctx: HookContext & { identifier: string; error: Error }) => Promise<void>;
}
```

**Execution order:** Plugins run in registration order. For `before` hooks, if any plugin returns `{ stop: true }`, subsequent plugins and the core operation are skipped. For `after` hooks, each plugin receives the result from the previous plugin (chain transformation).

**`AfterHookContext`** extends `HookContext` with `responseHeaders: Headers` — plugins can set response headers (e.g., `Set-Cookie`). The framework adapter forwards these to the HTTP response.

### Plugin Context

```typescript
interface PluginContext {
  db: DatabaseAdapter;
  config: FortressConfig;
  auth?: Record<string, Function>;  // AuthService methods — available at runtime, undefined during init
}
```

**Circular reference note:** `auth` is `undefined` when `plugin.methods(ctx)` is called during initialization (because the auth service hasn't been created yet). It's populated later. Plugin methods that need `auth` must access it lazily from the context at call time, not at binding time.

### Plugin Route Context

When a plugin route handler is invoked over HTTP, `fortress.handleRequest` passes a second positional argument of type `PluginRouteContext`:

```typescript
interface PluginRouteContext {
  userId?: string;       // Verified JWT subject (if security: ['bearer'])
  claims?: TokenClaims;  // Verified token claims
  meta?: RequestMeta;    // { ipAddress, userAgent } from forwarding headers
  request: Request;      // Raw Request — read headers, cookies, URL directly
}
```

Handlers signature: `(input: Record<string, unknown>, ctx: PluginRouteContext) => Promise<unknown>`. The `input` is the merged `{...body, ...pathParams}` the dispatcher already assembled.

This is the **only** safe way for a plugin route handler to know who is calling it — do not read a `userId` out of the request body for authorization, because the client controls that field. For `security: ['bearer']` endpoints the dispatcher has already verified the JWT and rejected unauthenticated callers before the handler runs, so `ctx.userId` is trustworthy.

When a plugin method is called **programmatically** (e.g. `fortress.plugins.admin.bootstrap({ userId })` from a seed script), `ctx` is `undefined`. Handlers that need both call paths should branch on `routeCtx` to decide whether to trust `body.userId`.

### Plugin Capability Matrix

| Capability | Use Case | Example Plugins |
|-----------|----------|-----------------|
| `models` | Declare new DB tables | 2FA (`two_factor_secret`, `backup_code`), OAuth (`oauth_client`), all plugins |
| `hooks` | Intercept auth lifecycle | 2FA (afterLogin), email verification (beforeLogin), account lockout (beforeLogin, onLoginFailure) |
| `methods` | Expose operations | All plugins — e.g., `fortress.plugins['two-factor'].enable(userId)` |
| `routes` | Add HTTP endpoints | OAuth (`/oauth/token`), social login (`/auth/social/:provider/callback`) — handlers receive `(input, ctx: PluginRouteContext)` where `ctx` carries the verified caller id/claims, request meta, and raw `Request` |
| `middleware` | Per-request logic | Rate limit, audit hooks |
| `wrapAdapter` | Modify DB per-request | Tenancy (transaction-pinned schema scoping), data isolation (row filtering) |
| `enrichTokenClaims` | Extend JWT claims | Tenancy (adds `tenantId`, `tenantCode`) |
| `scopeRules` | Auto-inject WHERE clauses | Data isolation (row-level scoping) |

### How to Add a New Plugin

1. Create `src/plugins/<name>/index.ts`
2. Export a factory function that returns `FortressPlugin`:
   ```typescript
   export function myPlugin(config: MyPluginConfig): FortressPlugin {
     return {
       name: 'my-plugin',
       models: [{ name: 'my_model', fields: { ... } }],
       hooks: { afterLogin: async (ctx, result) => { ... } },
       methods: (ctx) => ({
         doSomething: async (arg: string) => { ... },
       }),
     };
   }
   ```
3. Add JSR export in `jsr.json`: `"./plugins/<name>": "./src/plugins/<name>/index.ts"`
4. Add method types to `src/core/plugin-methods-map.ts` for type-safe access
5. Add tests in `src/plugins/<name>/<name>.test.ts`
6. Add Drizzle table definitions to `src/drizzle/schema.ts` (SQLite) and `src/drizzle/pg/schema.ts` (PostgreSQL)

---

## Official Plugins

### Security Plugins

#### Rate Limit

**File:** `src/plugins/rate-limit/index.ts`

Sliding window rate limiting with dual-key tracking (per-IP + per-account).

**Config:**
```typescript
{
  login: { maxPerIp: 10, maxPerAccount: 5, windowSeconds: 900 },
  register: { maxPerIp: 3, windowSeconds: 3600 },
  store?: RateLimitStore  // Custom counter backend; defaults to in-memory
}
```

**Hooks:** `beforeLogin`, `beforeRegister` — checks counters, throws `RATE_LIMITED` with `retryAfter` if exceeded.

**IP normalization:** `normalizeIp()` handles IPv6 /64 prefix grouping and IPv4-mapped IPv6 addresses.

**In-memory store:** Per-key counter with auto-expiring entries. Suitable for single-process; provide a custom `RateLimitStore` (e.g., Redis-backed) for multi-process.

#### Account Lockout

**File:** `src/plugins/account-lockout/index.ts`

Progressive lockout with escalating duration after repeated failed logins.

**Config:**
```typescript
{
  maxFailedAttempts: 5,         // Lock after this many failures
  lockoutDurationSeconds: 900,  // 15 minutes
  escalation: true,             // Double duration on repeat lockouts
  maxLockoutSeconds: 3600       // 1 hour cap
}
```

**Models:** `account_lockout` — `failedAttempts`, `lockedUntil`, `lockoutCount`

**Hooks:**
- `beforeLogin` — Throws `UNAUTHORIZED` if currently locked (with `lockedUntil` in error)
- `onLoginFailure` — Increments `failedAttempts`. If threshold reached, sets `lockedUntil`. With `escalation: true`, each successive lockout doubles the duration (capped at `maxLockoutSeconds`)
- `afterLogin` — Resets counter on successful login

**Methods:** `getLockoutStatus(userId)`, `resetLockout(userId)` (manual admin unlock)

#### Audit Log

**File:** `src/plugins/audit-log/index.ts`

Append-only event logging with optional SHA-256 hash chain for tamper detection.

**Config:**
```typescript
{
  events?: string[],     // Filter which events to log (null = all)
  hashChain?: boolean    // Enable SHA-256 chain linking each entry to the previous
}
```

**Models:** `audit_log` — `timestamp`, `eventType`, `actorId`, `targetId`, `targetType`, `metadata` (JSON), `previousHash`

**Events logged:** Auth lifecycle events plus `ROLE_CREATED`, `ROLE_UPDATED`, `ROLE_DELETED`, `ROLE_BOUND`, `ROLE_UNBOUND`, `ROLE_PERMISSION_ADDED`, `ROLE_PERMISSION_REMOVED`, `PERMISSION_CREATED`, `PERMISSION_DELETED`, `PERMISSION_CHANGED`, `GROUP_CREATED`, `GROUP_UPDATED`, `GROUP_DELETED`, `GROUP_MEMBER_ADDED`, `GROUP_MEMBER_REMOVED`, and service-account lifecycle events

**Hooks:** Integrated into `afterLogin`, `onLoginFailure`, `beforeLogout`, `afterRegister`, `afterTokenRefresh`. Also listens to IAM events via `setIamObserver()`.

**Methods:**
- `getAuditLog(filters)` — Query with filters (userId, eventType, date range, limit/offset)
- `logCustomEvent(event)` — Programmatic event logging for application-level events
- `verifyChain()` — Walk the hash chain and verify integrity (returns `{ valid, brokenAt? }`)

### Auth Plugins

#### Two-Factor Authentication

**File:** `src/plugins/two-factor/index.ts`

TOTP (RFC 6238), backup codes, and trusted devices.

**Config:**
```typescript
{
  totp: { issuer: 'Fortress', period: 30, digits: 6 },
  backupCodes: { count: 10 },
  trustedDeviceDays: 30
}
```

**Models:** `two_factor_secret` (Base32-encoded, enabled flag), `backup_code` (single-use), `trusted_device` (hash + expiry)

**Gate: `postAuthGate`** — If 2FA is enabled and the device is not trusted, returns an `AuthPending` challenge before any token row is written. The client presents its continuation token with the TOTP/backup code.

**Methods:**
- `enable(userId)` → `{ secret, otpauthUrl, backupCodes }` — generates TOTP secret + QR URL + backup codes
- `confirmSetup(userId, code, meta?)` → `{ verified: true }` — activates the newly configured factor
- `verify(continuationToken, code, meta?)` → `AuthResult` — atomically consumes the continuation, verifies the factor, reruns remaining gates, and issues the session on success
- `disable(userId)` — revokes secret, backup codes, and all trusted devices

**Internal TOTP implementation:** `generateTOTP()` uses HMAC-SHA1 over the time counter (`floor(now / period)`), extracts a 6-digit code via dynamic truncation per RFC 4226. `verifyTOTP()` checks the current window ±1 step.

#### Email Verification

**File:** `src/plugins/email-verification/index.ts`

Token-based email verification with optional login blocking.

**Config:**
```typescript
{
  tokenExpirySeconds: 86400,        // 24 hours
  requireVerification: true,        // Block unverified logins
  onSendVerification: async (email, token, userId) => { ... }  // Send email callback
}
```

**Models:** `email_verification_token` — single-use token

**Hooks:**
- `beforeLogin` — If `requireVerification: true`, blocks login for users with `emailVerified: false` (checks if any verification token was used)
- `afterRegister` — Auto-generates verification token, calls `onSendVerification`

**Methods:**
- `sendVerification(email)` — Generate new token (for email changes)
- `verify(token)` — Validate token, mark user `emailVerified: true`

#### Magic Link

**File:** `src/plugins/magic-link/index.ts`

Passwordless authentication via single-use tokens.

**Config:**
```typescript
{
  tokenExpirySeconds: 600,  // 10 minutes
  onSendMagicLink: async (email, token) => { ... }  // Send email/SMS callback
}
```

**Models:** `magic_link_token` — single-use token

**Methods:**
- `sendMagicLink(email)` — Generate token, call `onSendMagicLink`
- `verify(token, meta?)` — Atomically consume the token, JIT provision if needed, run post-auth gates, and return `AuthResult` (success with both tokens or a pending continuation)

#### API Key

**File:** `src/plugins/api-key/index.ts`

Long-lived API keys for service accounts, devices, CI/CD, and M2M communication.

**Config:**
```typescript
{
  prefix: 'fortress',           // Key prefix: fortress_sk_...
  defaultExpirySeconds: null,   // Never expire (revocable)
  maxKeysPerUser: 10,
  routes: false                 // Opt-in: mount /api-key/keys/* HTTP endpoints
}
```

**Key format:** `{prefix}_sk_{32-byte-hex}` (e.g., `fortress_sk_a1b2c3d4e5...`)

**Models:** `api_key` — `keyHash` (SHA-256), `keyPrefix` (first 8 chars for identification), `scopes` (JSON), `expiresAt`, `lastUsedAt`, `isRevoked`

**Methods** (dual-mode — accept `(input, routeCtx?)`):
- `createKey({ userId, name, scopes?, expiresAt? })` → `{ key, id }` — key shown once
- `listKeys({ userId })` — metadata only (prefix, scopes, expiry, lastUsedAt)
- `revokeKey({ userId, id })` — ownership-checked soft delete
- `rotateKey({ userId, id })` → `{ key, id }` — revoke old + create new atomically
- `resolveKey(rawKey)` — hash, lookup, validate expiry, update `lastUsedAt`

**Routes** (opt-in via `apiKey({ routes: true })`):
- `POST /api-key/keys` · `GET /api-key/keys` · `DELETE /api-key/keys/:id` · `POST /api-key/keys/:id/rotate`

All self-service routes use `security: ['bearer']` with no explicit permission. The route handlers read `userId` from `PluginRouteContext` (JWT subject) and ignore any client-supplied `userId` in the body, so authenticated callers can only manage their own keys.

**Admin-side routes** (opt-in via `admin({ apiKeyRoutes: true })`, lives in the admin plugin):
- `GET /admin/users/:userId/api-keys` · `DELETE /admin/users/:userId/api-keys/:id`

Guarded by `meta.permission: { resource: 'apiKey', action: 'manage' }`. The admin plugin's bootstrap auto-discovers this permission when the routes are mounted and binds it to the `fortress-admin` role. Requires the `api-key` plugin to also be registered (for the `api_key` model). Shared CRUD logic lives in `src/plugins/api-key/core.ts` so both plugins call the same helpers.

**Scope restriction:** Keys can be scoped to `resource:action` patterns. Permission checks are intersected: the account must have the permission AND the key scope must include it.

**Opt-in routes convention:** the `routes` flag on `apiKey()` and the `apiKeyRoutes` flag on `admin()` are the first adopters of a forward-looking design rule — plugins that ship HTTP endpoints gate them behind a boolean that defaults to `false`, keeping consumer URL namespaces under their control and leaving the programmatic methods always-on. Existing plugins (webauthn, two-factor, oauth, email-verification, magic-link, webhook, social-login, openapi) will migrate in a follow-up.

#### Social Login

**File:** `src/plugins/social-login/index.ts`

OAuth/OIDC consumer for authenticating via external providers.

**Config:**
```typescript
{
  providers: [
    { name: 'google', clientId: '...', clientSecret: '...' },
    { name: 'microsoft', clientId: '...', clientSecret: '...', tenant: '...' },
    { name: 'github', clientId: '...', clientSecret: '...' },
    // Custom OIDC: { name: 'corporate-sso', clientId, clientSecret, issuer: 'https://sso.company.com' }
  ],
  autoRegister: true,    // JIT user provisioning on first social login
  linkAccounts: true,    // Link social identity only by provider-verified email
  tokenEncryptionKey: process.env.FORTRESS_SOCIAL_TOKEN_KEY // 32-byte AES-256-GCM key
}
```

**Built-in providers** (`src/plugins/social-login/providers/`): Google, Microsoft Entra ID, GitHub, Apple, Discord. Each defines `authorizationUrl`, `tokenUrl`, `userInfoUrl`, `defaultScopes`, and `profileMapper`.

**Generic OIDC:** Any standards-compliant provider via `issuer` URL (uses `.well-known/openid-configuration` discovery). OIDC providers verify `id_token` signatures and `iss`/`aud`/`exp`/`nonce` via JWKS before linking or provisioning.

**Models:** `social_account` — `provider`, `providerAccountId`, `profile` (JSON), encrypted `accessToken`/`refreshToken`, `tokenExpiresAt`; unique on `(userId, provider)` and `(provider, providerAccountId)`.

**Flow:** `getAuthorizationUrl()` → store `{ state, codeVerifier, nonce }` and redirect to provider → `handleCallback()` verifies returned state + ID-token nonce, exchanges code, resolves user profile, then JIT provisions or links inside one transaction.

**Security:** PKCE (S256) on all flows, timing-safe `state` comparison for CSRF, separate OIDC `nonce`, verified-email-only by-email linking, active-user guard, unique social-account constraints, and provider tokens encrypted at rest (AES-256-GCM).

**Methods:** `getAuthorizationUrl(provider, redirectUri)`, `handleCallback(provider, code, redirectUri, codeVerifier, returnedState, storedState, storedNonce)`, `getLinkedAccounts(userId)`, `getProviderTokens(userId, provider)`, `unlinkAccount(userId, provider)`, `getProviders()`

#### WebAuthn (Stub)

**File:** `src/plugins/webauthn/index.ts`

Passkeys/WebAuthn — architecture complete, crypto deferred. Currently throws "WebAuthn not yet implemented" on all methods.

**Models:** `webauthn_credential` (credentialId, publicKey, counter, deviceType, backedUp, transports), `webauthn_challenge` (challenge, userId, expiresAt)

**Planned methods:** `generateRegistrationOptions()`, `verifyRegistration()`, `generateAuthenticationOptions()`, `verifyAuthentication()`

### Multi-Tenancy Plugins

#### Tenancy (Schema Isolation)

**File:** `src/plugins/tenancy/index.ts`

Schema-per-tenant isolation — **PostgreSQL only**. Tenant schemas use the numeric tenant id (`tenant_<id>` by default), not the external `taxId`.

**Config:**
```typescript
{
  schemaPrefix: 'tenant_',        // Schema naming: tenant_<id>
  routes: false,                  // Opt in to /tenancy/* HTTP routes
  onSchemaCreated: async (schemaName, rawQuery) => { /* per-tenant DDL */ },
  dropSchemaOnDelete: false       // Destructive schema drops are opt-in
}
```

**Models:** `tenant` (`taxId` unique, `name`, `description`), `tenant_user` (userId, tenantId, `isDefault` flag)

**Capabilities used:**
- `wrapAdapter` — Reads `tenantId` from the verified JWT custom claim, then uses a transaction-pinned `set_config('search_path', ?, true)` before each operation; with no claim or non-PG adapters it returns the adapter unchanged (fail closed/no-op)
- `enrichTokenClaims` — Adds `tenantId` and `tenantCode` to JWT custom claims from the user's default `tenant_user` membership

**Methods:** `createTenant(input)`, `deleteTenant(input)`, `addUserToTenant(userId, tenantId)`, `getUserTenants(userId)`, `getMyTenants(input, routeCtx?) → { tenants }`, `switchTenant(input, routeCtx?)`. Default-tenant switches are serialized, atomic, and backed by a partial unique index enforcing at most one default per user.

**Gotcha:** Schema switching/creation requires PostgreSQL `rawQuery`; adapters without it pass through unchanged.

#### Data Isolation (Row-Level)

**File:** `src/plugins/data-isolation/index.ts`

General-purpose row-level scoping. Works on any database.

**Config:**
```typescript
{
  scopes: [
    {
      name: 'organization',
      field: 'organizationId',              // Column name in scoped tables
      models: ['invoice', 'product'],       // Which tables (['*'] for all)
      resolveValue: async (userId, ctx) => { /* lookup user's org */ },
    },
  ]
}
```

**Capability: `scopeRules`** — For each matching model, injects:
- **Reads:** `WHERE organizationId = <resolved value>` on `findOne`, `findMany`, `count`, `update`, `delete`
- **Writes:** `data.organizationId = <resolved value>` on `create`

Multiple scopes stack — all applicable filters are AND'd together.

**Bypass methods:**
- `withoutScope(scopeName, fn)` — Skip named scope within callback
- `unscoped(fn)` — Skip all scopes within callback

Implementation uses a module-level `bypassedScopes` Set for per-request bypass tracking.

**Models:** `user_scope_assignment` (optional — for storing scope values if not derivable from existing tables)

### Integration Plugins

#### OAuth (Server)

**File:** `src/plugins/oauth/index.ts`

OAuth 2.0 authorization server with PKCE support. Makes Fortress an OAuth/OIDC *provider*.

**Config:**
```typescript
{
  authCodeExpirySeconds: 600,
  pendingFlowExpirySeconds: 600,
  accessTokenExpirySeconds: 3600,
  scopePermissionMap?: Record<string, { resource: string; action: string }[]>,
  issuerUrl?: string   // For OIDC discovery
}
```

**Models:** `oauth_client`, `oauth_authorization_code` (with PKCE challenge), `oauth_access_token`, `oauth_pending_flow`

**Routes:**
- `POST /oauth/token` — Token exchange (auth code + PKCE, client credentials)
- `POST /oauth/introspect` — Token introspection (RFC 7662)
- `POST /oauth/revoke` — Token revocation (RFC 7009)
- `GET /oauth/userinfo` — OpenID Connect userinfo
- `GET /oauth/.well-known/openid-configuration` — OIDC discovery

**Methods:** `createClient()`, `createAuthorizationCode()`, `exchangeCode()`, `clientCredentialsGrant()`, `revokeToken()`, `introspectToken()`, `createPendingFlow()`, `getPendingFlow()`, `resumePendingFlow()`, `getUserInfo()`, `handleTokenRequest()`, `handleIntrospectRequest()`, `handleRevokeRequest()`, `handleUserInfoRequest()`, `handleDiscovery()`, `handleAuthorizeRequest()`, `handleGetFlow()`, `handleApproveFlow()`, `handleDenyFlow()`, `resolveTokenPermissions()`

**Identity broker pattern:** When an unauthenticated user hits `/oauth/authorize`, the plugin stores OAuth params in `oauth_pending_flow`, redirects to login, then resumes the flow after authentication.

**SPA-friendly consent flow (Pattern B):** Opt-in via `enableAuthorizeEndpoint`/`enableConsentApi` + `loginUrl`/`consentUrl`. Fortress runs the OAuth state machine and returns 302s + JSON; the host app (SvelteKit/Next/etc.) renders login + consent screens. PKCE fields stay server-side. Plugin contributes four routes: `GET /oauth/authorize`, `GET /oauth/flows/:flowId`, `POST /oauth/flows/:flowId/approve`, `POST /oauth/flows/:flowId/deny` — each backed by a transport-agnostic method of the same `handle*` name.

**PKCE:** `src/plugins/oauth/pkce.ts` — S256 challenge generation and verification via `crypto.subtle`.

#### Webhook

**File:** `src/plugins/webhook/index.ts`

Event delivery following the [Standard Webhooks](https://www.standardwebhooks.com/) spec.

**Config:**
```typescript
{
  events?: string[],      // Filter which events to deliver (null = all)
  maxRetries: 5,
  deliver?: (url, payload, headers) => Promise<void>  // Custom delivery (e.g., for testing)
}
```

**Models:** `webhook_endpoint` (URL, events JSON, secret, isActive), `webhook_delivery` (eventType, payload, status, attempts, nextRetryAt)

**Retry strategy:** Intervals: 5s, 5m, 30m, 2h, 5h

**Signature:** HMAC-SHA256 per Standard Webhooks: `v1,<base64(hmac)>`. Headers: `webhook-id`, `webhook-timestamp`, `webhook-signature`.

**Events delivered:** `LOGIN_SUCCESS`, `LOGIN_FAILURE`, `LOGOUT`, `REGISTER`, `TOKEN_REFRESH`

**Hooks:** Integrated into `afterLogin`, `onLoginFailure`, `beforeLogout`, `afterRegister`, `afterTokenRefresh`.

### Admin Plugin

**File:** `src/plugins/admin/index.ts`

Protects IAM routes and provides full admin management endpoints. Mounts all core IAM endpoints as HTTP handlers plus admin-specific CRUD. Injects `after-auth` middleware on `/iam/*` paths that enforces `fortress:*` permission checks.

**Config:**
```typescript
{
  bootstrap?: { enabled: boolean; secret?: string }, // opt-in one-time first-admin bootstrap
  resource?: string,        // Resource name for admin permissions (default: 'fortress')
}
```

**Bootstrap:** `/iam/admin/bootstrap` is mounted only when explicitly enabled and requires a one-time secret; no superadmin middleware/bypass is registered.

**Routes (35 total):**
- `POST /iam/admin/bootstrap` — Mounted only with `bootstrap.enabled`; creates `fortress-admin` while zero admin bindings exist and the one-time secret matches
- `POST /iam/sync` — Push/pull resource definitions
- **User management:** `GET /auth/users`, `GET /auth/users/:id`, `POST /auth/users`, `PUT /auth/users/:id`, `DELETE /auth/users/:id`
- **Role management:** `GET /iam/roles`, `GET /iam/roles/:id`, `POST /iam/roles`, `PUT /iam/roles/:id`, `DELETE /iam/roles/:id`, `POST /iam/roles/:id/permissions`
- **Role bindings:** `POST /iam/roles/:id/bind/user`, `POST /iam/roles/:id/bind/group`, `DELETE /iam/roles/:id/bind`
- **Group management:** `GET /iam/groups`, `GET /iam/groups/:id`, `POST /iam/groups`, `PUT /iam/groups/:id`, `DELETE /iam/groups/:id`, `GET /iam/groups/:id/users`, `POST /iam/groups/:id/users`, `DELETE /iam/groups/:id/users/:userId`
- **Permission management:** `GET /iam/permissions`, `POST /iam/permissions`, `DELETE /iam/permissions/:id`, `GET /iam/users/:id/permissions`, `POST /iam/check`
- **Permission bindings:** `POST /iam/permissions/bind/user`, `POST /iam/permissions/bind/group`, `DELETE /iam/permissions/bind/user`, `DELETE /iam/permissions/bind/group`
- **Resources:** `GET /iam/resources`

**Methods:** Plugin methods delegate to core `AuthService` and `IamService` via typed `ctx.auth` and `ctx.iam` references (the `PluginContext` exposes both services with full type safety).

**Actions registered:** `viewResources`, `viewRoles`, `createRole`, `deleteRole`, `bindRole`, `unbindRole`, `createGroup`, `manageGroup`, `viewPermissions`, `managePermissions`, `viewUsers`, `manageUsers`, `viewGroups`, `manageRoles`.

**Default deny:** The RBAC middleware denies unmapped fortress-owned routes (`/iam/*`, `/auth/users`, `/auth/impersonate`, plugin routes) by default. The admin plugin provides the permission mapping. Opt-out via `allowUnmappedFortressPaths: true` in `RbacOptions`.

---

### Plugin Middleware

**File:** `src/core/plugin-runner.ts` — `executePluginMiddleware()`

Plugins can define `middleware[]` with `position: 'before-auth' | 'after-auth' | 'after-rbac'` and a `path` pattern. The middleware is executed in plugin registration order via `pluginMiddleware.beforeAuth`, `pluginMiddleware.afterAuth`, and `pluginMiddleware.afterRbac` from the adapter factories. Every runtime passes the same exported `PluginRequestContext` containing a web-standard `request: Request` plus optional `fortressSubject`, `fortressUserId`, `fortressClaims`, and `fortressScopes`; plugin middleware never depends on a Hono or Express native context.

---

## Framework Adapters

### Request Lifecycle

```
HTTP Request
  │
  ├─ Error Handler (catches FortressError → HTTP response)
  │
  ├─ Auth Middleware
  │   ├─ Extract Bearer token from Authorization header
  │   ├─ Verify JWT (fortress.auth.verifyToken)
  │   ├─ Set context: userId, claims
  │   ├─ Chain wrapAdapter from all plugins (tenancy sets search_path, etc.)
  │   ├─ Set context: fortressDb (plugin-wrapped adapter)
  │   └─ Set context: fortressGetScopedDb(model) — lazy scope rule applicator
  │
  ├─ RBAC Middleware
  │   ├─ Map HTTP method+path → resource+action (via routeMap or mapRequest)
  │   ├─ Skip if path matches skipPaths
  │   └─ Call fortress.iam.checkPermission(userId, resource, action)
  │
  ├─ CSRF Middleware (Hono + Express standalone)
  │   ├─ Require X-Fortress-CSRF header on unsafe methods (POST, PUT, DELETE, PATCH)
  │   └─ Check Sec-Fetch-Site header to reject cross-site requests
  │
  ├─ Security Headers Middleware (Hono only)
  │   └─ Set HSTS, X-Frame-Options, X-Content-Type-Options, CSP, Referrer-Policy
  │
  └─ Route Handler
      ├─ getUserId(c) — authenticated user ID
      ├─ getClaims(c) — full token claims
      ├─ getDb(c) — plugin-wrapped DatabaseAdapter (with tenancy scoping)
      └─ getScopedDb(c, model) — DatabaseAdapter with scope rules applied for model
```

### Hono Adapter

**Files:** `src/hono/middleware/*.ts`, `src/hono/helpers.ts`, `src/hono/plugin-routes.ts`

```typescript
import { createCsrfMiddleware, createHonoMiddleware, createSecurityHeadersMiddleware } from '@bajustone/fortress/hono';

const { authMiddleware, rbacMiddleware, errorHandler } =
  createHonoMiddleware(fortress, {
    routeMap: {
      'POST /api/users': { resource: 'user', action: 'create' },
      'GET /api/users/:id': { resource: 'user', action: 'read' },
    },
    mapRequest: (method, path) => { /* dynamic mapping */ },
    skipPaths: ['/health', '/auth/*'],
  });
const csrfMiddleware = createCsrfMiddleware();
const securityHeaders = createSecurityHeadersMiddleware();

app.onError(errorHandler);
app.use('*', securityHeaders);
app.use('/api/*', csrfMiddleware);
app.use('/api/*', authMiddleware);
app.use('/api/*', rbacMiddleware);
mountFortress(app, fortress);  // Mounts all Fortress routes (auth, IAM, plugins, OAuth, OpenAPI)
```

**Hono context variables** (set by auth middleware, read by helpers):
- `fortressUserId: string`
- `fortressClaims: TokenClaims`
- `fortressDb: DatabaseAdapter` — plugin-wrapped adapter
- `fortressGetScopedDb: (model: string) => Promise<DatabaseAdapter>` — lazy scope rules

**RBAC route mapping:** Supports both declarative `routeMap` and dynamic `mapRequest()`. Pattern matching for parameterized routes (`:id` → `[^/]+` regex).

**CSRF middleware** (`src/hono/middleware/csrf.ts`): Custom-header strategy — requires `X-Fortress-CSRF` header (any value) on unsafe methods. Also checks `Sec-Fetch-Site` to reject cross-site requests. Configurable safe methods (default: GET, HEAD, OPTIONS); skip paths match at segment boundaries, with trailing `/*` supported.

**Security headers** (`src/hono/middleware/security-headers.ts`): Sets HSTS, X-Frame-Options (DENY), X-Content-Type-Options (nosniff), Content-Security-Policy, Referrer-Policy (strict-origin-when-cross-origin), X-Permitted-Cross-Domain-Policies (none). All configurable.

**Error handler** (`src/hono/middleware/error-handler.ts`): Transforms `FortressError` to JSON `{ code, message, statusCode }`. Sets `Retry-After` header for `RATE_LIMITED`. Returns generic 500 for unhandled errors.

**Validated request helpers** (`src/hono/validated.ts`): `vBody(c, schema)`, `vParam(c, schema)`, `vQuery(c, schema)` — extract-and-validate helpers for **custom user routes**. Each takes any Standard Schema V1 (Zod, Valibot, ArkType, fortress built-in), runs `~standard.validate()` at runtime, and returns the parsed value typed via `InferOutput<T>` or throws `FortressError('VALIDATION_ERROR', 422)`. All three are async. The same triple is shipped by the SvelteKit (`src/sveltekit/validated.ts`, takes a `RequestEvent`) and Express (`src/express/validated.ts`, takes a structurally typed `Request`) adapters. Fortress-managed endpoints continue to validate themselves automatically inside `fortress.handleRequest`. Exports `InferOutput<T>` utility type.

### Express Adapter

**Files:** `src/express/index.ts`, `src/express/middleware.ts`

Parallel implementation of the Hono adapter for Express.js.

```typescript
import { createExpressMiddleware, getUserId, getClaims, getDb, getScopedDb } from '@bajustone/fortress/express';

const { authMiddleware, csrfMiddleware, rbacMiddleware, errorHandler } = createExpressMiddleware(fortress, {
  routeMap: { 'POST /api/users': { resource: 'user', action: 'create' } },
  skipPaths: ['/health'],
});

app.use('/api', csrfMiddleware);
app.use('/api', authMiddleware);
app.use('/api', rbacMiddleware);
app.use(errorHandler);
```

**Request extension:** Sets properties on `req`:
- `req.fortressUserId`
- `req.fortressClaims`
- `req.fortressDb`
- `req.fortressGetScopedDb`

**CSRF:** `createCsrfMiddleware` is also exported standalone; the factory's `csrfMiddleware` uses `options.csrf`. It mirrors Hono's custom-header/cross-site strategy and segment-safe skip matching.

**OAuth form bodies:** mount `express.urlencoded({ extended: false })` before `mountFortress`; the adapter re-encodes parsed objects to `application/x-www-form-urlencoded` before core OAuth dispatch.

**Key difference from Hono:** Uses minimal Express-compatible interface types (caller provides express package). Express is a peer dependency, not bundled.

### How to Add a New Framework Adapter

Most of the work lives in `fortress.handleRequest` (core HTTP pipeline).
A new adapter is typically a ~10-line wrapper that:

1. Translates the framework's incoming request into a web-standard `Request`
2. Detects whether the path matches a Fortress endpoint
   (`buildRouteTable(fortress.endpoints)` + `matchRoute(...)` from
   `src/core/http/match.ts`)
3. If yes, calls `await fortress.handleRequest(request)` and returns the
   `Response` to the framework
4. If no, falls through to the framework's normal routing

For user-route helpers (`getUserId`, etc.), reuse the `fortress.extractAccessToken`
+ `fortress.auth.verifyToken` + `chainAdapterWrappers` + `collectScopeRules`
flow — see `src/sveltekit/handle.ts` for the canonical reference.

Add the new sub-path to `jsr.json` and `package.json` exports.

---

## Fortress Instance

**File:** `src/core/fortress.ts`

```typescript
const fortress = createFortress({
  jwt: { key: env.JWT_SECRET },
  database: createDrizzleAdapter(db),
  plugins: [twoFactor({ ... }), tenancy({ ... })],
});

// fortress.auth   — AuthService (login, refresh, logout, sessions, impersonation)
// fortress.iam    — IamService (permissions, roles, groups)
// fortress.plugins — Type-safe plugin methods (InferPlugins<T>)
// fortress.config — Readonly<FortressConfig>
```

**Initialization** (`fortress.ts`):
1. Validates JWT secret strength (minimum 32 bytes for HS256)
2. Resolves `config.logger` → `SILENT_LOGGER` default
3. Resolves `config.observability` → `NO_OP_TELEMETRY` default
4. Wraps the raw `DatabaseAdapter` with `instrumentAdapter` to emit `db.client.operation.duration` metrics
5. Checks plugin name uniqueness
6. Creates `AuthService` with plugin hooks + auth observer list wired in
7. Creates `IamService` with permission cache + iam observer list + sync permission-check observer list
8. Creates metric instruments (counters + histograms) off the resolved telemetry provider
9. Registers internal observers that translate `AuthEvent` / `IamEvent` / `PermissionCheckEvent` into counter/histogram updates
10. Processes plugins via `processPlugins()` — creates methods map
11. Wires IAM events → audit-log plugin (if registered)
12. Returns frozen `Fortress` instance (now also exposing `fortress.logger` and `fortress.telemetry`)

**`getPluginMethods<T>(fortress, pluginName)`** (`fortress.ts:36`): Type-safe extraction of plugin methods. Used when you need plugin methods in a context where the generic type isn't available.

**Type-safe plugin access** via `InferPlugins<T>` (`src/core/plugin-methods-map.ts`):

```typescript
// Pre-defined plugin method interfaces:
'api-key' → ApiKeyMethods
'audit-log' → AuditLogMethods
'data-isolation' → DataIsolationMethods
'email-verification' → EmailVerificationMethods
'oauth' → OAuthMethods
'social-login' → SocialLoginMethods
'tenancy' → TenancyMethods
'two-factor' → TwoFactorMethods
'webauthn' → WebAuthnMethods
// ... custom plugins fall back to Record<string, Function>
```

---

## Configuration Reference

```typescript
interface FortressConfig {
  jwt: {
    key: string | string[];                    // Required. string[] for rotation: first signs, all verify. Min 32 bytes.
    issuer?: string;                              // Default: 'fortress'
    accessTokenExpirySeconds?: number;            // Default: 900 (15 min)
    refreshTokenExpirySeconds?: number;           // Default: 604800 (7 days)
    validateRefreshFingerprint?: boolean | 'warn'; // Optional fingerprint validation on refresh
  };
  rbac?: {
    evaluationMode?: 'allow-only' | 'deny-overrides';  // Default: 'allow-only'
    resourceFile?: string;                              // Default: './fortress.resources.json'
    cache?: {
      ttlSeconds?: number;       // Cache TTL
      maxEntries?: number;       // LRU max size
    };
  };
  database: DatabaseAdapter;                      // Required
  passwordHasher?: PasswordHasher;                // Default: WASM Argon2id
  passwordPolicy?: PasswordPolicyConfig;          // Optional NIST + HIBP checking
  plugins?: readonly FortressPlugin[];            // Optional
}
```

**Minimal setup — only `secret` and `database` required:**

```typescript
const fortress = createFortress({
  jwt: { key: env.JWT_SECRET },
  database: createDrizzleAdapter(db),
});
```

---

## Domain Types

```typescript
// --- Identity ---
interface FortressUser {
  id: string;
  email: string;
  name: string;
  isActive: boolean;
  emailVerified?: boolean;
  createdAt: Date;
  updatedAt: Date;
}

interface LoginIdentifier {
  id: string;
  userId: string;
  type: 'email' | 'phone' | 'username';
  value: string;
  tenantId?: string;
}

// --- Auth ---
interface TokenClaims {
  sub: string;                                 // User ID
  name: string;
  groups: string[];
  iss: string;                                 // Issuer
  iat: number;                                 // Issued at
  exp: number;                                 // Expiration
  act?: { sub: string };                       // RFC 8693 actor claim (impersonation)
  customClaims?: Record<string, unknown>;      // Plugin-injected claims
}

interface AuthTokenPair {
  accessToken: string;
  refreshToken: string;
}

// Discriminated union — check result.status to narrow
type AuthResult = AuthSuccess | AuthImpersonation | AuthPending;

interface AuthSuccess {
  status: 'success';
  user: FortressUser;
  method: AuthMethod;
  accessToken: string;
  refreshToken: string;
  pluginData?: Record<string, unknown>;
}

interface AuthImpersonation {
  status: 'impersonation';
  user: FortressUser;
  accessToken: string;                         // Non-renewable, short-lived
  refreshToken: null;                          // Never issued for impersonation
  pluginData?: Record<string, unknown>;
}

interface AuthPending {
  status: 'pending';
  user: FortressUser;
  pending: {
    reason: PendingReason;
    continuationToken: string;
  };
  pluginData?: Record<string, unknown>;
}

interface RequestMeta {
  ipAddress?: string;
  userAgent?: string;
  deviceName?: string;
}

interface SessionInfo {
  id: string;
  ipAddress?: string;
  userAgent?: string;
  deviceName?: string;
  lastActiveAt: Date;
  createdAt: Date;
}

// --- IAM ---
type SubjectType = 'USER' | 'GROUP' | 'SERVICE_ACCOUNT';

interface Permission {
  id: string;
  resource: string;
  action: string;
  effect: 'ALLOW' | 'DENY';
  conditions?: PermissionCondition[];
  description?: string;
}

interface PermissionCondition {
  field: string;                               // "resource.ownerId", "request.ip", "user.department"
  operator: 'eq' | 'neq' | 'in' | 'startsWith';
  value: ConditionValue;
}

type ConditionValue = string | string[] | ConditionRef | ConditionRef[];
interface ConditionRef { ref: string; }        // Typed alternative to "${user.id}" templates

interface PermissionContext {
  resource?: Record<string, unknown>;          // Resource instance attributes
  request?: Record<string, unknown>;           // Request metadata
  user?: Record<string, unknown>;              // Extra user attributes
  tenantId?: string;                           // Tenant scoping
}

interface Role {
  id: string;
  name: string;
  description?: string;
  isSystem?: boolean;
}

interface RoleBinding {
  id: string;
  roleId: string;
  subjectType: SubjectType;
  subjectId: string;
  tenantId?: string;
}

interface Group {
  id: string;
  name: string;
  description?: string;
}
```

---

## Error Handling

**File:** `src/core/errors.ts`

Single `FortressError` class discriminated by `code` — no subclass hierarchy.

```typescript
class FortressError extends Error {
  readonly code: FortressErrorCode;
  readonly statusCode: number;
  readonly retryAfter?: number;
  readonly details?: unknown;     // structured data (e.g., validation issues)
}

type FortressErrorCode =
  | 'UNAUTHORIZED'      // 401
  | 'TOKEN_REUSE'       // 401 — consumer should force-logout all devices
  | 'FORBIDDEN'         // 403
  | 'BAD_REQUEST'       // 400
  | 'NOT_FOUND'         // 404
  | 'CONFLICT'          // 409
  | 'RATE_LIMITED'      // 429 — includes retryAfter
  | 'VALIDATION_ERROR'  // 422 — includes details with issues array
  | 'DATABASE_ERROR';   // 500

// Factory functions (preferred API):
const Errors = {
  unauthorized: (message?) => new FortressError('UNAUTHORIZED', message, 401),
  tokenReuse: () => new FortressError('TOKEN_REUSE', 'Token reuse detected', 401),
  forbidden: (message?) => new FortressError('FORBIDDEN', message, 403),
  badRequest: (message?) => new FortressError('BAD_REQUEST', message, 400),
  notFound: (message?) => new FortressError('NOT_FOUND', message, 404),
  conflict: (message?) => new FortressError('CONFLICT', message, 409),
  rateLimited: (retryAfter) => new FortressError('RATE_LIMITED', 'Too many requests', 429, { retryAfter }),
  validationError: (issues) => new FortressError('VALIDATION_ERROR', 'Validation failed', 422, { details: issues }),
  database: (message?, cause?) => new FortressError('DATABASE_ERROR', message, 500, { cause }),
};
```

**Design rationale:**
- One class, no inheritance — `instanceof FortressError` works reliably across package boundaries
- Factory functions — tree-shakeable, clean API (`throw Errors.forbidden()`)
- Discriminated by `code` — exhaustive `switch(error.code)` in TypeScript
- `toJSON()` built in for logging and API responses

---

## Entry Points

### JSR Exports (`jsr.json`)

| Import | Contains |
|--------|----------|
| `@bajustone/fortress` | `createFortress()`, all types, errors, `DatabaseAdapter` interface, `FortressPlugin` interface |
| `@bajustone/fortress/crypto` | `PasswordHasher` interface, default WASM hasher |
| `@bajustone/fortress/jwt` | `signToken()`, `verifyToken()` standalone utilities |
| `@bajustone/fortress/testing` | `createTestAdapter()` — in-memory SQLite |
| `@bajustone/fortress/drizzle` | `createDrizzleAdapter()`, SQLite reference schema |
| `@bajustone/fortress/drizzle/pg` | PostgreSQL reference schema |
| `@bajustone/fortress/hono` | `createHonoMiddleware()`, context helpers |
| `@bajustone/fortress/express` | `createExpressMiddleware()`, request helpers |
| `@bajustone/fortress/plugins/tenancy` | `tenancy()` plugin factory |
| `@bajustone/fortress/plugins/oauth` | `oauth()` plugin factory |
| `@bajustone/fortress/plugins/two-factor` | `twoFactor()` plugin factory |
| `@bajustone/fortress/plugins/email-verification` | `emailVerification()` plugin factory |
| `@bajustone/fortress/plugins/api-key` | `apiKey()` plugin factory |
| `@bajustone/fortress/plugins/data-isolation` | `dataIsolation()` plugin factory |
| `@bajustone/fortress/plugins/social-login` | `socialLogin()` plugin factory, built-in providers |
| `@bajustone/fortress/plugins/rate-limit` | `rateLimit()` plugin factory |
| `@bajustone/fortress/plugins/audit-log` | `auditLog()` plugin factory |
| `@bajustone/fortress/plugins/account-lockout` | `accountLockout()` plugin factory |
| `@bajustone/fortress/plugins/webauthn` | `webauthn()` plugin factory |
| `@bajustone/fortress/plugins/admin` | `admin()` plugin factory |
| `@bajustone/fortress/plugins/magic-link` | `magicLink()` plugin factory |
| `@bajustone/fortress/plugins/webhook` | `webhook()` plugin factory |

### npm Exports (`package.json`)

npm exports use conditional imports (ESM + CJS) for the 6 main entry points only: `index`, `hono`, `drizzle`, `testing`, `crypto`, `jwt`. Plugin sub-paths are JSR-only.

---

## CLI Tool

**File:** `bin/fortress.ts`

```bash
fortress init              # Scaffold fortress.resources.json and config
fortress sync:push         # JSON → DB: seed/update resources on deploy
fortress sync:pull         # DB → JSON: export after runtime changes
fortress sync:types        # Generate TypeScript types from resource file
fortress generate-secret   # Generate a cryptographically secure JWT secret (32+ bytes)
```

---

## Build & Publish

### Build (`tsup.config.ts`)

```typescript
entry: {
  index: 'src/index.ts',
  hono: 'src/hono/index.ts',
  drizzle: 'src/drizzle/index.ts',
  testing: 'src/testing/index.ts',
  crypto: 'src/core/auth/password.ts',
  jwt: 'src/core/auth/jwt.ts',
}
format: ['esm', 'cjs']          // Dual format
dts: true                        // Generate .d.ts and .d.cts
splitting: false                 // Single bundle per entry
external: ['drizzle-orm', 'hono', 'better-sqlite3', 'bun:sqlite']
```

Output: `dist/{name}.js`, `dist/{name}.cjs`, `dist/{name}.d.ts`, `dist/{name}.d.cts`

### JSR Publishing

- JSR exports point to **source** (`src/` files), not `dist/`
- All exported functions must have **explicit return type annotations** (JSR "slow types" requirement)
- Use `npm:` prefix for npm dependencies in import map
- Validate: `bun run publish:dry`

### npm Publishing

- `prepublishOnly` runs `tsup` → builds to `dist/`
- `package.json` exports point to built files with conditional `import`/`require`

---

## Testing

### Unit Tests

- **Runner:** Vitest (`vitest.config.ts`)
- **Database:** In-memory SQLite via `createTestAdapter()`
- **Files:** `*.test.ts` alongside source files
- **Run:** `bun run test`

### Integration Tests

- **Config:** `vitest.integration.config.ts` (30s timeout)
- **Database:** PostgreSQL via `testcontainers`
- **Files:** `*.integration-test.ts`
- **Run:** `bun run test:integration`
- **Covers:** Drizzle adapter against real PostgreSQL, tenancy plugin schema operations

### Adapter Conformance

`src/testing/adapter-conformance.test.ts` exports `runAdapterTests(adapterFactory)` — a shared test suite any `DatabaseAdapter` implementation should pass. Tests all 7 CRUD methods, transactions, and edge cases.
