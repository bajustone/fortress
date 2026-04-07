# Changelog

## [0.0.17] - 2026-04-07

### Added
- feat: security-aware default deny and endpoint permission declarations

## [0.0.16] - 2026-04-07

### Added
- feat: add admin plugin, plugin middleware wiring, and default deny for fortress routesfeafeat: add admin plugin, plugin middleware wiring, and default deny for fortress routes
- feat(openapi): add additionalEndpoints and convertRoutes for unified spec generation

## [Unreleased]

### Added
- **Admin plugin** (`@bajustone/fortress/plugins/admin`) — protects IAM routes with `fortress:*` permissions, provides bootstrap endpoint to assign first admin, and lists available resources/roles
- **Plugin middleware wiring** — `MiddlewareDefinition` from plugins is now executed in the request pipeline via `pluginMiddleware.beforeAuth`, `pluginMiddleware.afterAuth`, and `pluginMiddleware.afterRbac`
- **Endpoint permission declarations** — `EndpointMeta.permission` field and `.permission(resource, action)` builder method allow endpoints to declare IAM requirements
- `GET /iam/resources` endpoint — lists all available resources and their actions
- `GET /iam/roles` endpoint — lists all roles
- `POST /iam/admin/bootstrap` endpoint — auto-discovers all declared permissions from endpoint definitions and creates fortress-admin role
- `getResources()` and `getRoles()` methods on `IamService`
- `createPluginMiddleware()` for Hono adapter
- `createExpressPluginMiddleware()` for Express adapter

### Changed
- **Security-aware default deny** — RBAC middleware respects endpoint security metadata: `security: 'none'/'basic'` routes pass through, `permission`-declared routes are IAM-enforced, bearer-only routes require auth without IAM check, unknown routes are denied
- **Default deny for fortress-owned routes** — RBAC middleware denies unmapped `/iam/*`, `/auth/impersonate`, and plugin-owned routes by default (opt-out via `allowUnmappedFortressPaths`)
- Handler dispatch in Hono and Express adapters now checks plugin routes before core IAM routes, allowing plugins to register routes under `/iam/*`

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
