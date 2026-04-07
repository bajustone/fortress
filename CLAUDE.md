# CLAUDE.md

## Project Overview

Fortress (`@bajustone/fortress`) is a framework-agnostic, adapter-based authentication and authorization library for TypeScript, published on [JSR](https://jsr.io). The core provides auth (JWT, refresh tokens, password hashing) and IAM (groups, roles, resource+action permissions with conditions and deny rules). Everything else — OAuth, tenancy, 2FA, email verification, API keys, data isolation, social login — is a plugin.

## Commands

```bash
bun install              # Install dependencies
bun run dev              # Run example Hono app with watch mode
bun run lint             # ESLint check
bun run lint:fix         # ESLint auto-fix
bun run test             # Run tests (vitest)
bun run test:watch       # Run tests in watch mode
bun run typecheck        # TypeScript type check (tsc --noEmit)
bun run publish:dry      # Validate JSR publishing (dry run)
```

## Architecture

See `docs/architecture.md` for the full technical design.

**Core (always included):**
- `src/core/auth/` — JWT (jose), password hashing (pluggable), refresh tokens (SHA256, family rotation)
- `src/core/auth/auth-endpoints.ts` — Declarative auth endpoint definitions with OpenAPI metadata
- `src/core/iam/` — resource+action permissions, conditions, deny rules, groups, roles
- `src/core/iam/iam-endpoints.ts` — Declarative IAM endpoint definitions with OpenAPI metadata
- `src/core/iam/permission-cache.ts` — LRU permission cache with TTL and invalidation
- `src/core/endpoint.ts` — `EndpointDefinition`, `EndpointMeta`, `EndpointInput`, `EndpointResponse`
- `src/core/json-schema.ts` + `src/core/schema-builder.ts` — JSON Schema types and fluent builder DSL
- `src/core/errors.ts` — single `FortressError` class + `Errors` factory
- `src/core/plugin.ts` — `FortressPlugin` interface (8 capabilities)
- `src/core/config.ts` — `FortressConfig` type

**Adapters:**
- `src/adapters/database/` — `DatabaseAdapter` interface (7 required + 1 optional method)
- `src/drizzle/` — Drizzle adapter (PostgreSQL, MySQL, SQLite)
- `src/hono/` — Hono middleware (auth, RBAC, error handler, plugin mounting, OpenAPI integration)
- `src/express/` — Express middleware (auth, RBAC, error handler, route mounting)
- `src/testing/` — In-memory SQLite test adapter via bun:sqlite

**Plugins (all optional, 15 total):**
- `src/plugins/admin/` — IAM route protection, bootstrap, default deny for fortress routes
- `src/plugins/tenancy/` — Schema-per-tenant isolation (PostgreSQL only)
- `src/plugins/oauth/` — OAuth 2.0 server (auth code + PKCE, client credentials)
- `src/plugins/two-factor/` — TOTP, backup codes, trusted devices
- `src/plugins/email-verification/` — Token-based email verification
- `src/plugins/api-key/` — Scoped API keys for service accounts / devices
- `src/plugins/data-isolation/` — Row-level data isolation (any database)
- `src/plugins/social-login/` — OAuth/OIDC consumer (Microsoft, Google, GitHub, etc.)
- `src/plugins/rate-limit/` — Sliding window rate limiting
- `src/plugins/account-lockout/` — Progressive lockout with escalation
- `src/plugins/audit-log/` — Append-only event logging with hash chain
- `src/plugins/webhook/` — Standard Webhooks spec (HMAC-SHA256, retries)
- `src/plugins/magic-link/` — Passwordless token-based auth
- `src/plugins/openapi/` — Framework-agnostic OpenAPI 3.1 spec generation + Scalar UI
- `src/plugins/webauthn/` — Passkeys/WebAuthn (registration, passwordless auth, 2FA mode)

## Key Design Decisions

1. **Generic CRUD DatabaseAdapter** — 7 methods, not per-entity. Adapter doesn't change when new models/plugins are added.
2. **jose for JWT** — Web Crypto API, works on Bun/Deno/edge. Not jsonwebtoken.
3. **Pluggable PasswordHasher** — WASM Argon2id default, swappable for native.
4. **Database-agnostic** — Drizzle adapter works with PostgreSQL, MySQL, SQLite. Only the tenancy plugin is PostgreSQL-specific.
5. **Transport-agnostic permissions** — `resource + action`, not `path + httpVerb`. Works in HTTP, CLI, cron, WebSocket.
6. **Plugin system** — 8 capabilities: models, hooks, methods, routes, middleware, wrapAdapter, enrichTokenClaims, scopeRules.
7. **`WhereClause.operator` is an open string** — extensible without breaking adapters.
8. **Secret rotation** — `jwt.secret` accepts `string | string[]` for zero-downtime rotation.
9. **`scopeRules`** — handles both reads (WHERE filters) and writes (default values on create).
10. **Endpoint Definitions** — Declarative `EndpointDefinition` with OpenAPI metadata enables framework-agnostic route mounting and automatic OpenAPI spec generation.

## Testing

- **Unit tests**: Vitest + in-memory SQLite (`@bajustone/fortress/testing`)
- **Integration tests**: Vitest + testcontainers (PostgreSQL) for adapter and tenancy plugin tests
- Test files: `*.test.ts` or `*.spec.ts` alongside source files

## JSR Publishing Notes

- All exported functions MUST have **explicit return type annotations** (JSR "slow types" requirement)
- Use `npm:` prefix for npm dependencies in import map
- Sub-path exports isolate optional deps — consumers only install what they import
- Run `bun run publish:dry` to validate before publishing
- Test under both `bun test` and `deno test` in CI

## How to Add a New Plugin

1. Create `src/plugins/<name>/index.ts`
2. Export a factory function that returns `FortressPlugin`
3. Define `models` for any new DB tables
4. Use `hooks` to intercept auth lifecycle, `methods` for new operations, `routes` for new endpoints
5. Add JSR export in `jsr.json`: `"./plugins/<name>": "./src/plugins/<name>/index.ts"`
6. Add tests in `src/plugins/<name>/<name>.test.ts`

## How to Add a New Database Adapter

1. Implement the `DatabaseAdapter` interface (7 required methods + optional `rawQuery`)
2. Test against the adapter test suite (TODO: create shared adapter conformance tests)
3. Export as a sub-path: `"./adapter-name": "./src/adapter-name/index.ts"`

## Keeping Examples in Sync

Every time code changes (APIs, adapters, plugins, config, middleware), update `examples/` to reflect the changes. Examples are living documentation — they must always work with the current code.

## Reference Docs

- `docs/architecture.md` — Full technical design
