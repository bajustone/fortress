# Compatibility

The Fortress test matrix that the maintainer runs locally and via CI.
Numbers are "tested, working" — Fortress is framework-agnostic by
construction so versions outside the matrix will usually work, just
without an explicit test guarantee.

## Runtime

| Runtime | Minimum | Tested |
|---|---|---|
| **Bun** | 1.0 | latest |
| **Node.js** | 20.19 | 20, 22, 24 |
| **Deno** | 1.40 | latest |
| **Cloudflare Workers (workerd)** | wrangler 3 | latest |
| Browsers | n/a | server-only |

Bun is the maintainer's primary runtime (test adapter prefers
`bun:sqlite`; the `bin/fortress.ts` CLI shebang targets Bun). The
package ships a Node-compatible CJS build via `tsup` so the same module
works under Node 20.19+ unchanged. Deno + workerd can import and use the runtime-neutral core because Node filesystem/path modules are dynamically loaded only when file-oriented policy/resource helpers are invoked. The Bun-targeted CLI and file helpers require a Node-compatible filesystem runtime.

## Frameworks

| Adapter | Package | Tested versions |
|---|---|---|
| Hono | `@bajustone/fortress/hono` | `hono@^4.12` |
| Express | `@bajustone/fortress/express` | `express@^4` and `^5` (duck-typed; no `@types/express` dep) |
| SvelteKit | `@bajustone/fortress/sveltekit` | `@sveltejs/kit@^2` |

The Express adapter uses minimal duck-typed interfaces (`ExpressRequest`,
`ExpressResponse`, `ExpressMiddleware`) so consumers bring their own
Express version. CI compiles the generated package declarations against real
`express@4.21.2` / `@types/express@4.17.23` and Express 5.2 / types 5.x
applications in isolated fixtures; the Express 4 lane verifies that its
transitive `express-serve-static-core` remains v4 rather than ambient v5. The
SvelteKit subpath uses the optional `@sveltejs/kit@^2`
peer directly for its strict public `Handle`/`Action` types and runtime
`redirect()`/`fail()` primitives; install that peer when using the adapter.

## TypeScript declarations

The package peer floor remains TypeScript 5.0. CI builds once, then exact
TypeScript 5.0.4 compiles both npm declaration branches: ESM `import.types`
(`.d.ts`) and Node16 CommonJS `require.types` (`.d.cts`). The current compiler
runs the same two consumer contracts first, plus the isolated Express 4 and
Express 5 fixtures. These checks validate generated package declarations; they
do not add Express as a production dependency or widen the documented support
ranges.

## Databases

| Driver | Adapter | Tested |
|---|---|---|
| PostgreSQL via `drizzle-orm/postgres-js` | `createPostgresDrizzleAdapter` | `postgres@^3.4` |
| PostgreSQL via `drizzle-orm/node-postgres` | `createPostgresDrizzleAdapter` | `pg@^8` |
| SQLite via `drizzle-orm/bun-sqlite` | `createSqliteDrizzleAdapter` | bundled with Bun |
| SQLite via `drizzle-orm/better-sqlite3` | `createSqliteDrizzleAdapter` | `better-sqlite3@^12.8` |

Drizzle minimum: `drizzle-orm@^0.45`. Earlier versions are missing
features Fortress relies on (`$dynamic()`, `getTableColumns`,
`getSetCookie` polyfill).

The `@bajustone/fortress/testing` subpath uses `bun:sqlite` under Bun and the optional `better-sqlite3@^12.8` peer under Node. Install that peer in Node test projects.

Custom adapters: implement the `DatabaseAdapter` interface in
`src/adapters/database/index.ts` to back Fortress with any datastore.
The IAM service uses a small set of generic operations
(`create`/`findOne`/`findMany`/`update`/`delete`/`count`/`transaction`,
optional `rawQuery`) so even non-SQL stores are workable. Fortress-managed
migrations require the stronger `MigratableDatabaseAdapter` contract with a
required literal dialect and `rawQuery`; both named Drizzle factories provide it.

## Optional integrations

| Capability | Peer | Tested |
|---|---|---|
| OpenTelemetry metrics + traces | `@opentelemetry/api@^1.9` | latest with `@opentelemetry/sdk-node` |
| Argon2id password hashing (native) | `argon2@^0.31` | optional; Fortress ships a `hash-wasm` fallback |
| WebAuthn server | `@simplewebauthn/server@^13.1` | bundled dependency |
| OAuth signing (RS256 id_token) | `jose@^6.2` | bundled dependency |

## What the CI matrix runs today

The repository workflow ([`.github/workflows/ci.yml`](../.github/workflows/ci.yml))
executes:

- **`lint`** — eslint, source typechecks, export parity, a fresh generated-package
  build, current-compiler ESM/CJS/Express 4+5 consumer contracts, and exact
  TypeScript 5.0.4 ESM/CJS declaration-floor checks (Bun, ubuntu-latest).
- **`unit`** — the full SQLite test suite across a runtime matrix:
  **Bun**, **Node 20**, **Node 22**, and **Node 24**. Bun runs `bun:sqlite`; the Node
  jobs run the same vitest suite under `better-sqlite3`, keeping the
  Node-compatible build honest.
- **`integration`** — the PostgreSQL suite via testcontainers
  (`bun run test:integration`), covering the `pg` dialect, the tenancy
  connection-pinning / `search_path` isolation, the migration upgrade
  fixture, and the framework adapters end-to-end. This is the heavier job,
  and runs on every pull request and push, plus a **nightly cron**.
- **`jsr-check`** — pinned Deno typechecking plus an attested JSR selected-file
  manifest to guard source-first publishability.

The consumer-facing drop-in workflow
([`docs/ci/github-actions.yml`](./ci/github-actions.yml)) is a separate
template that gates *your* deploys on Fortress's drift checkers
(`runFortressChecks`); it is not the library's own matrix.

> Deno and Cloudflare Workers remain smoke-tested locally rather than in
> the public matrix (no first-class GitHub runner for the workerd DB
> story). MySQL is not currently supported — `DrizzleDialect` is
> `'sqlite' | 'pg'`; it may be re-added once there is a real consumer and
> a CI lane to keep it honest.

## What's intentionally out of scope

- **Bun's web runtime APIs** beyond `Request`/`Response`/`crypto`/`fetch`.
  Fortress sticks to the web platform standard so any modern runtime
  works.
- **ESM-only consumers without an interop layer.** The dual `esm`+`cjs`
  build is shipped; if a consumer's bundler refuses CJS, use the
  `import` map entry.
- **Cloudflare Workers without external DB.** Workers cannot use
  `bun:sqlite` or `better-sqlite3`. Use the Postgres adapter (or a
  remote DB over HTTP) when targeting workerd.

## Reporting a compatibility issue

If a combination listed here breaks, open an issue with:

1. Runtime + version (`bun --version`, `node --version`, `deno --version`).
2. Driver + version (`drizzle-orm`, `postgres`, `better-sqlite3`).
3. The minimal reproduction \u2014 ideally a failing test using
   `createTestAdapter()`.
