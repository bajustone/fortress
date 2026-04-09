# Changelog

## [0.0.29] - 2026-04-09

### Changed
- refactor(adapters)!: delete deprecated dispatch APIs, delegate fully to fortress.handleRequest
- refactor

## [Unreleased]

### Added
- **SvelteKit adapter** at `@bajustone/fortress/sveltekit`. Single
  `createSvelteKitHandle(fortress)` hook for `hooks.server.ts`. Intercepts
  Fortress paths and delegates to `fortress.handleRequest`. Auto-refreshes
  expired access tokens during SSR loads. Populates `event.locals.fortress`
  for user routes. Form-action helpers (`fortressActions.login` /
  `logout` / `register` / `refresh`). Optional catch-all `+server.ts`
  escape hatch via `toSvelteKitHandler(fortress)`.
- **`fortress.handleRequest(request: Request): Promise<Response>`** —
  framework-agnostic HTTP entry point on every Fortress instance. Composes
  plugin middleware → token verification → fortress-managed RBAC →
  validation → endpoint dispatch → cookie attachment. All adapters delegate
  to it; future runtimes (Cloudflare Workers, Deno Deploy, etc.) only need a
  ~10-line wrapper.
- **`FortressConfig.cookies`** — `__Host-` prefixed access/refresh cookie
  names with `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/` defaults in
  production. Auto-relaxes (drops `__Host-` and `Secure`) in
  `NODE_ENV !== 'production'` so localhost over HTTP works.
- **`fortress.runPluginMiddleware`**, **`fortress.extractAccessToken`**,
  **`fortress.serializeAuthCookies`**, **`fortress.cookies`** — auxiliary
  HTTP helpers exposed on the Fortress instance for adapters that compose
  custom flows on user-owned routes.
- **`mountFortress(app, fortress)`** in the Hono and Express adapters — new
  modern entry point that delegates Fortress-managed paths to
  `fortress.handleRequest` via a single middleware. Replaces the old split
  surface (`createHonoMiddleware` + `mountPluginRoutes`).

### Changed
- The Hono `createErrorHandler` now delegates to the framework-agnostic
  `errorToResponse` from core so the FortressError → HTTP mapping
  (`Retry-After`, sanitized 500s, etc.) stays in one place.
- The Hono `createAuthMiddleware` and Express `createAuthMiddleware` now
  use `fortress.extractAccessToken` (cookie-first, `Authorization: Bearer`
  fallback), so the same adapter serves both browsers and API clients.
- The Hono and Express RBAC middleware are simplified — they only handle
  user-route `routeMap` lookups now. The default-deny logic for
  Fortress-managed paths moved into core (`src/core/http/fortress-rbac.ts`)
  and runs inside `fortress.handleRequest`.

### Removed (breaking)
- **Deleted `mountPluginRoutes`** from the Hono adapter
  (`src/hono/plugin-routes.ts`). Replaced by `mountFortress`, which
  delegates to `fortress.handleRequest` and handles plugin routes
  (OAuth, OpenAPI, etc.) automatically.
- **Deleted `createValidationMiddleware`** from the Hono and Express
  adapters (`src/hono/validation-middleware.ts`,
  `src/express/validation-middleware.ts`). Validation now runs
  automatically inside `fortress.handleRequest` for every Fortress-managed
  endpoint. For custom user routes, use `vBody` / `vParam` / `vQuery`
  from `@bajustone/fortress/hono` plus your own
  `schema['~standard'].validate()` call.
- **Deleted `mountFortressRoutes` and `mountPluginRoutes`** from the
  Express adapter (`src/express/routes.ts`). Same migration: use
  `mountFortress(app, fortress)` from `@bajustone/fortress/express`.
- **Removed `RbacOptions.allowUnmappedFortressPaths`** from the Hono and
  Express adapters. The fortress-path default-deny now lives in core, so
  the adapter-side opt-out is gone. Core's default-deny is non-negotiable
  (it's part of the security contract).
- **Migration**: replace
  `mountPluginRoutes(app, fortress)` → `mountFortress(app, fortress)`,
  delete any `createValidationMiddleware(...)` calls, and rely on the
  automatic validation inside `fortress.handleRequest`.

## [0.0.28] - 2026-04-09

### Fixed
- fix jsr

## [0.0.27] - 2026-04-09

### Fixed
- fix jsr

## [0.0.26] - 2026-04-09

### Fixed
- fix jsr

## [0.0.25] - 2026-04-09

### Changed
- chore(jsr): eliminate all 62 slow-type errors by typing `fortressSchema` /
  `fortressPgSchema` as `Record<string, AnySQLiteTable>` /
  `Record<string, AnyPgTable>`. The drizzle adapter is unaffected (it already
  accesses tables generically), but consumers who relied on column-level
  inference from `fortressSchema.users.email` style access will now see the
  loose `AnySQLiteTable`/`AnyPgTable` type. Workaround: declare your own
  typed Drizzle tables and pass them via `createDrizzleAdapter(db, { tables })`.
- chore(jsr): drop `--allow-slow-types` from `publish:dry` and the publish
  workflow so future regressions fail loudly. JSR will now ship proper
  `.d.ts` files for Node consumers.
- docs: add `@module` JSDoc to every JSR entrypoint (22 files) and document
  every re-export in `src/index.ts`.

### Added
- chore(jsr): add `description`, `runtimeCompat` (node/deno/bun/workerd), and
  `publish.exclude` to `jsr.json`. The published tarball no longer bundles
  test files, vitest/tsup configs, `.github`, `examples`, `docs`, `scripts`,
  or local tooling files.

## [0.0.24] - 2026-04-07

### Fixed
- fix: prevent Zod schemas from being misidentified as FortressSchema

## [0.0.23] - 2026-04-07

### Added
- feat(hono): add typed validation helpers and unmatched route warnings

## [0.0.23] - 2026-04-08

### Added
- feat: add typed validation helpers (`vBody`, `vParam`, `vQuery`) to Hono adapter — zero-cost type-safe request extraction using Standard Schema V1 inference, works with Zod, Valibot, ArkType, or fortress built-in schemas
- feat: export `InferOutput` utility type from `@bajustone/fortress/hono`

## [0.0.22] - 2026-04-07

### Fixed
- fix: use relative URL in openapi plugin Scalar UI for prefix compatibility

## [0.0.21] - 2026-04-07

### Added
- docs: sync documentation with source code

## [Unreleased]

### Fixed
- docs: sync README, SECURITY.md, docs/security.md, and architecture.md with source code
  - WebAuthn plugin is fully implemented, not a stub — updated README, CLAUDE.md
  - Fixed plugin count from 12 to 15 in architecture.md
  - Fixed `breachedCacheTtlMs` default from 300000 to 86400000 in docs/security.md
  - Fixed account lockout config names (`maxFailedAttempts`, `lockoutDurationSeconds`, `maxLockoutSeconds`) in docs/security.md
  - Fixed rate limit config shape (`maxPerIp`, `maxPerAccount`, `windowSeconds`) in docs/security.md
  - Fixed CSRF middleware import (`createCsrfMiddleware`) in docs/security.md
  - Fixed supported version from 0.1.x to 0.0.x in SECURITY.md
  - Synced jsr.json version to 0.0.20

## [0.0.20] - 2026-04-07

### Added
- feat: complete admin plugin with all IAM endpoints, type safety, and bug fixes

## [0.0.20] - 2026-04-07

### Added
- Admin plugin now mounts all 16 core IAM endpoints (roles CRUD, role/group bindings, permission bindings, getUserPermissions, checkPermission)
- `POST /auth/users` — admin-initiated user creation with `fortress:manageUsers` permission
- `POST /iam/sync` — push/pull resource sync endpoint
- `safeInt()` / `requireInt()` helpers for safe numeric input coercion in admin plugin
- `updateUser` now supports `password` field — hashed via configured `PasswordHasher` with password policy validation

### Changed
- `PluginContext.auth` and `.iam` now typed as `AuthService` and `IamService` (was `Record<string, Function>`)
- Removed `as any` casts throughout admin plugin — all service calls are now type-checked
- All `Number(body.id)` calls replaced with `requireInt()` to prevent NaN propagation to database queries
- Endpoint deduplication in `fortress.ts` — plugin routes take priority over core definitions by `method+path`

### Fixed
- `mountPluginRoutes` now returns HTML with `c.html()` instead of `c.json()` for plugin methods returning HTML strings (fixes broken Scalar UI)
- CHANGELOG formatting errors in v0.0.19 and v0.0.16 entries

## [0.0.19] - 2026-04-07

### Added
- fix: pass path params to plugin route handlers in Hono adapter

## [0.0.18] - 2026-04-07

### Added
- feat: Standard Schema V1 support with typed schemas and runtime validation
- feat: add admin CRUD endpoints for users, roles, groups, and permissions

## [0.0.17] - 2026-04-07

### Added
- feat: security-aware default deny and endpoint permission declarations

## [0.0.16] - 2026-04-07

### Added
- feat: add admin plugin, plugin middleware wiring, and default deny for fortress routes
- feat(openapi): add additionalEndpoints and convertRoutes for unified spec generation

## [Unreleased]

### Added
- **Admin CRUD endpoints** — 15 new endpoints in the admin plugin for managing users, roles, groups, and permissions
  - Auth admin: `GET /auth/users`, `GET /auth/users/:id`, `PUT /auth/users/:id`, `DELETE /auth/users/:id`
  - IAM admin: `GET /iam/roles/:id`, `PUT /iam/roles/:id`, `GET /iam/groups`, `GET /iam/groups/:id`, `PUT /iam/groups/:id`, `DELETE /iam/groups/:id`, `GET /iam/groups/:id/users`, `GET /iam/permissions`, `POST /iam/permissions`, `DELETE /iam/permissions/:id`, `POST /iam/roles/:id/permissions`
- **Auth service admin methods** — `listUsers`, `getUserById`, `updateUser`, `deleteUser` on `AuthService`
- **IAM service admin methods** — `getRole`, `updateRole`, `listGroups`, `getGroup`, `updateGroup`, `deleteGroup`, `getGroupUsers`, `listPermissions`, `createPermission`, `deletePermission`, `addPermissionToRole` on `IamService`
- `iam` property on `PluginContext` — plugins can now access the IAM service via `ctx.iam`
- `like` operator support in Drizzle adapter
- **Standard Schema V1 support** — `obj()`, `str()`, `int()`, etc. now implement Standard Schema, providing runtime validation + TypeScript type inference + JSON Schema for OpenAPI from a single definition
- `FortressSchema<T>`, `Infer<T>`, `StandardSchemaV1.InferOutput` types for type extraction
- Built-in JSON Schema validator for fortress schemas' `~standard.validate()`
- New schema helpers: `nullType()`, `record()`, `recordOf()`
- `isStandardSchema()`, `isFortressSchema()`, `extractJsonSchema()` utilities
- `endpoint().body()`, `.query()`, `.params()` accept both `FortressSchema` and external Standard Schema (Zod, Valibot, ArkType)
- `/auth/users` added to `FORTRESS_AUTH_PROTECTED` for default-deny

### Changed
- Plugin route dispatch now merges path params into body, enabling plugin routes with `:id` params
- GET request handlers now receive query params (previously `undefined`) in both Hono and Express adapters
- Admin plugin superadmin middleware now covers `/auth/users/*` in addition to `/iam/*`

### Previously Released

- **Admin plugin** (`@bajustone/fortress/plugins/admin`) — protects IAM routes with `fortress:*` permissions, provides bootstrap endpoint to assign first admin, and lists available resources/roles
- **Plugin middleware wiring** — `MiddlewareDefinition` from plugins is now executed in the request pipeline via `pluginMiddleware.beforeAuth`, `pluginMiddleware.afterAuth`, and `pluginMiddleware.afterRbac`
- **Endpoint permission declarations** — `EndpointMeta.permission` field and `.permission(resource, action)` builder method allow endpoints to declare IAM requirements
- `GET /iam/resources` endpoint — lists all available resources and their actions
- `GET /iam/roles` endpoint — lists all roles
- `POST /iam/admin/bootstrap` endpoint — auto-discovers all declared permissions from endpoint definitions and creates fortress-admin role
- `getResources()` and `getRoles()` methods on `IamService`
- `createPluginMiddleware()` for Hono adapter
- `createExpressPluginMiddleware()` for Express adapter
- **Security-aware default deny** — RBAC middleware respects endpoint security metadata
- **Default deny for fortress-owned routes** — RBAC middleware denies unmapped `/iam/*`, `/auth/impersonate`, and plugin-owned routes by default

## [0.0.15] - 2026-04-07

### Added
- add version lifecycle script
- `additionalEndpoints` option for OpenAPI plugin — consumers can merge app-specific routes into a single unified spec
- `convertRoutes` utility in Hono adapter — schema-agnostic converter from `createRoute`-style objects to `EndpointDefinition[]`

## [0.0.14] - 2026-04-07

### Added
- v0.0.14
- feat: webauthn plugin
- openapi
- support openapi via JSONSchema
- examples

### Changed
- update doc/architecture.md
- improve tests

### Fixed
- fix read me

## [0.0.13] - 2026-04-07

### Added
- Core auth: JWT (jose), Argon2id password hashing, refresh token rotation with family tracking
- Core IAM: resource+action permissions, conditions, deny rules, groups, roles
- LRU permission cache with TTL and invalidation
- Plugin system: 8 capabilities (models, hooks, methods, routes, middleware, wrapAdapter, enrichTokenClaims, scopeRules)
- Plugins: email-verification, api-key, two-factor, social-login, data-isolation, tenancy, oauth, rate-limit, account-lockout, audit-log, webhook, magic-link, openapi, webauthn (stub)
- Declarative endpoint definitions with OpenAPI metadata
- JSON Schema builder DSL for fluent schema construction
- Drizzle adapter: PostgreSQL, MySQL, SQLite
- Hono middleware: auth, RBAC, CSRF, error handler, OpenAPI integration
- Express middleware: auth, RBAC, error handler, route mounting
- In-memory SQLite testing adapter
- Password policy with NIST 800-63B defaults and HIBP breach checking
- Session management: list, revoke, revoke all
- Token fingerprinting on refresh
- Admin impersonation with RFC 8693 `act` claim
- Security documentation
