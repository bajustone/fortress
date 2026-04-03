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
- `src/core/iam/` — resource+action permissions, conditions, deny rules, groups, roles
- `src/core/errors.ts` — single `FortressError` class + `Errors` factory
- `src/core/plugin.ts` — `FortressPlugin` interface (9 capabilities)
- `src/core/config.ts` — `FortressConfig` type

**Adapters:**
- `src/adapters/database/` — `DatabaseAdapter` interface (7 required + 1 optional method)
- `src/drizzle/` — Drizzle adapter (PostgreSQL, MySQL, SQLite)
- `src/hono/` — Hono middleware (auth, RBAC, error handler, plugin mounting)
- `src/testing/` — In-memory SQLite test adapter via bun:sqlite

**Plugins (all optional):**
- `src/plugins/tenancy/` — Schema-per-tenant isolation (PostgreSQL only)
- `src/plugins/oauth/` — OAuth 2.0 server (auth code + PKCE, client credentials)
- `src/plugins/two-factor/` — TOTP, backup codes, trusted devices
- `src/plugins/email-verification/` — Token-based email verification
- `src/plugins/api-key/` — Scoped API keys for service accounts / devices
- `src/plugins/data-isolation/` — Row-level data isolation (any database)
- `src/plugins/social-login/` — OAuth/OIDC consumer (Microsoft, Google, GitHub, etc.)

## Key Design Decisions

1. **Generic CRUD DatabaseAdapter** — 7 methods, not per-entity. Learned from Lucia's deprecation.
2. **jose for JWT** — Web Crypto API, works on Bun/Deno/edge. Not jsonwebtoken.
3. **Pluggable PasswordHasher** — WASM Argon2id default, swappable for native.
4. **Database-agnostic** — Drizzle adapter works with PostgreSQL, MySQL, SQLite. Only the tenancy plugin is PostgreSQL-specific.
5. **Transport-agnostic permissions** — `resource + action`, not `path + httpVerb`. Works in HTTP, CLI, cron, WebSocket.
6. **Plugin system** — 9 capabilities: models, hooks, methods, routes, middleware, wrapAdapter, enrichTokenClaims, scopeRules, rawQuery.
7. **`WhereClause.operator` is an open string** — extensible without breaking adapters.
8. **Secret rotation** — `jwt.secret` accepts `string | string[]` for zero-downtime rotation.
9. **`scopeRules`** — handles both reads (WHERE filters) and writes (default values on create).

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

## Reference Docs

- `docs/architecture.md` — Full technical design
- `docs/watch-outs.md` — Known issues and gaps vs. industry standards
