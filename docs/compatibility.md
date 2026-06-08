# Compatibility matrix (P2-11)

The Fortress test matrix that the maintainer runs locally and via CI.
Numbers are "tested, working" — Fortress is framework-agnostic by
construction so versions outside the matrix will usually work, just
without an explicit test guarantee.

## Runtime

| Runtime | Minimum | Tested |
|---|---|---|
| **Bun** | 1.0 | latest |
| **Node.js** | 18 (LTS) | 20, 22 |
| **Deno** | 1.40 | latest |
| **Cloudflare Workers (workerd)** | wrangler 3 | latest |
| Browsers | n/a | server-only |

Bun is the maintainer's primary runtime (test adapter prefers
`bun:sqlite`; the `bin/fortress.ts` CLI shebang targets Bun). The
package ships a Node-compatible CJS build via `tsup` so the same module
works under Node 18+ unchanged. Deno + workerd work because Fortress
avoids Node-only globals on every code path that isn't gated by a
runtime check (the only such gate is the `bin:sqlite` vs
`better-sqlite3` selection in the test adapter).

## Frameworks

| Adapter | Package | Tested versions |
|---|---|---|
| Hono | `@bajustone/fortress/hono` | `hono@^4.12` |
| Express | `@bajustone/fortress/express` | `express@^4` and `^5` (duck-typed; no `@types/express` dep) |
| SvelteKit | `@bajustone/fortress/sveltekit` | `@sveltejs/kit@^2` |

The Express adapter uses minimal duck-typed interfaces (`ExpressRequest`,
`ExpressResponse`, `ExpressMiddleware`) so consumers bring their own
Express version. The SvelteKit adapter uses structural types compatible
with `@sveltejs/kit`'s real `RequestEvent` / `Handle` shapes; no peer
import is required.

## Databases

| Driver | Adapter | Tested |
|---|---|---|
| PostgreSQL via `drizzle-orm/postgres-js` | `@bajustone/fortress/drizzle` (`dialect: 'pg'`) | `postgres@^3.4` |
| PostgreSQL via `drizzle-orm/node-postgres` | same | `pg@^8` |
| SQLite via `drizzle-orm/bun-sqlite` | same (`dialect: 'sqlite'`) | bundled with Bun |
| SQLite via `drizzle-orm/better-sqlite3` | same | `better-sqlite3@^11` |
| MySQL via `drizzle-orm/mysql2` | same (`dialect: 'mysql'`) | smoke-tested |

Drizzle minimum: `drizzle-orm@^0.45`. Earlier versions are missing
features Fortress relies on (`$dynamic()`, `getTableColumns`,
`getSetCookie` polyfill).

Custom adapters: implement the `DatabaseAdapter` interface in
`src/adapters/database/index.ts` to back Fortress with any datastore.
The IAM service uses a small set of generic operations
(`create`/`findOne`/`findMany`/`update`/`delete`/`count`/`transaction`,
optional `rawQuery`) so even non-SQL stores are workable.

## Optional integrations

| Capability | Peer | Tested |
|---|---|---|
| OpenTelemetry metrics + traces | `@opentelemetry/api@^1.9` | latest with `@opentelemetry/sdk-node` |
| Argon2id password hashing (native) | `argon2@^0.31` | optional; Fortress ships a `hash-wasm` fallback |
| WebAuthn server | `@simplewebauthn/server@^13.1` | bundled dependency |
| OAuth signing (RS256 id_token) | `jose@^6.2` | bundled dependency |

## What the CI matrix runs today

The shipped GitHub Actions workflow
([`docs/ci/github-actions.yml`](./ci/github-actions.yml)) currently runs
on **Bun latest, ubuntu-latest** against the test adapter (SQLite). The
maintainer also runs a periodic local matrix:

- Bun + better-sqlite3
- Node 20 + better-sqlite3
- Node 20 + Postgres via testcontainers (slow; not in CI)
- Deno + better-sqlite3 (smoke only)

Expanding the public CI matrix to cover all three runtimes + Postgres
is tracked as a future ops task.

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
