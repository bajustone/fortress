# Watch-Outs & Gaps vs. Industry Standards

## Design Watch-Outs

### Generic CRUD DatabaseAdapter
- ~~`WhereClause` operator set may need `like`/`contains`, `isNull`, or `between` later.~~ **RESOLVED:** `operator` is now an open `string` type. Core operators (`=`, `!=`, `in`, `gt`, `lt`, `gte`, `lte`) are documented as required minimum. Adapters throw on unsupported operators at runtime.
- **`rawQuery` escape hatch** — optional method for performance-critical multi-table operations (IAM permission chain JOINs). Adapters that don't implement it fall back to multiple `findMany` calls. Design decision: the generic CRUD is for simple ops and plugins; core IAM queries can use `rawQuery` for performance.
- **`create` return type `Promise<T>` is unconstrained** — no type relationship between `model: 'user'` and return type `T`. Intentional trade-off (same as Better Auth). The internal adapter layer handles typing. Document as a known limitation.

### Plugin System
- **Plugin ordering** — hooks run in registration order. Document this clearly. Consider if any hooks need explicit priority.
- ~~**`wrapAdapter` composition** — if two plugins both `wrapAdapter`, define the composition strategy.~~ **RESOLVED:** Plugins chain in registration order. Each wrapper receives the result of the previous. Documented in architecture.md "Plugin Composition Rules".
- ~~**`enrichTokenClaims` collisions** — two plugins adding the same JWT claim key.~~ **RESOLVED:** Shallow merge, last plugin wins (registration order). Warning logged in development mode.
- ~~**`scopeFilters` only handles reads.**~~ **RESOLVED:** Renamed to `scopeRules` — returns both `filters` (for reads) and `defaults` (for writes). Data isolation plugin auto-injects scope values on `create` operations.

### Permission Evaluation
- **Performance at scale** — evaluation with conditions requires DB queries per check. Plan caching (per-request cache, short TTL cache of user permissions). Use `rawQuery` for the permission chain JOIN when available.
- **Wildcard permissions** — no `*` wildcards (e.g., `post:*` for all actions). AWS and GCP support these. Decide upfront.
- **Hierarchical resources** — GCP has `projects/*/buckets/*/objects/*`. Not needed now, but keep the door open.

### Data Isolation Plugin
- ~~**Write operations** — `scopeFilters` only handles reads.~~ **RESOLVED:** `scopeRules` handles both reads (WHERE clauses) and writes (default values on create).
- **Bulk operations** — `update` and `delete` with scope rules must be tested carefully to prevent cross-tenant mutations.

### Password Hasher
- WASM Argon2id is slower than native. Document the trade-off and make `@node-rs/argon2` / `Bun.password` swaps dead simple for users who don't need edge runtime.

### JWT
- ~~**Token secret rotation** — single `jwt.secret` string means rotating secrets invalidates all tokens.~~ **RESOLVED:** `jwt.secret` accepts `string | string[]`. First secret signs, all secrets are tried for verification. Zero-downtime rotation.

### General Risks
- **Adapter testing** — the generic CRUD contract needs thorough integration tests against real databases. Subtle adapter bugs is what killed Lucia. Mitigated by vitest + bun:sqlite in-memory for unit tests + testcontainers PostgreSQL for integration tests.
- **Scope creep** — the plugin list is ambitious (8 plugins). **Ship core + Drizzle adapter first, validate the plugin interface, then build plugins incrementally.**
- **Documentation** — Better Auth's biggest weakness is docs lagging features. Plan docs alongside code.
- **Soft deletes** — loyalbook uses `rowStatus`, tdmp uses `isActive`. Fortress core uses hard deletes. Soft deletes are a consumer concern (use `update` instead of `delete`). Document this decision.
- **`createdBy` / audit trail** — both source projects have `createdBy` on most tables. The generic CRUD adapter doesn't know about the authenticated user. Service layer explicitly passes `createdBy` in the `data` object. Not magic, not hidden — explicit and clear.

---

## Gaps vs. Industry Standards

| Gap | Who Has It | Priority | Notes |
|-----|-----------|----------|-------|
| **Rate limiting** | Keycloak, Auth0, Clerk | High | Critical for login/token endpoints. Build as plugin. `RateLimitError` (429) already in error hierarchy. |
| **Account lockout** | Most managed services | Medium | Lock after N failed login attempts. Simple plugin using `hooks.beforeLogin`. |
| **Audit logging** | Keycloak, Ory | Medium | Auth events (login, failed login, permission denied, role changes). Plugin using hooks. |
| **WebAuthn / Passkeys** | Auth.js, Clerk, @oslojs/webauthn | Medium | Growing fast. Plugin using routes + models. Architecture validated — no gaps. |
| **Magic link auth** | Better Auth, Auth.js | Low | Easy plugin — same pattern as email verification but issues tokens. |
| **Session management (stateful)** | Auth.js, Lucia (was), Better Auth | Low | JWT + refresh tokens is valid. Cookie handling via `AfterHookContext.responseHeaders: Headers`. |
| **SCIM (directory sync)** | WorkOS, Okta | Low | Enterprise feature for syncing users from external directories. Not needed initially. |

---

## Library Authoring Critique (vs. Industry Standards)

_Reviewed 2026-04-03 against TypeScript library authoring best practices._

### P0 — Critical

#### No-op Transaction Implementation
- `src/drizzle/adapter.ts:191-193`: `async transaction(fn) { return fn(adapter); }` — calls the function with the same adapter, **no actual DB transaction**.
- Token rotation in `auth-service.ts` (revoke old + create new) is not atomic. If the process crashes between them, the user's session is silently destroyed with no recovery path.
- `deleteRole` in `iam-service.ts` does 3 sequential deletes (role_permissions, role_bindings, role) without a transaction — orphaned data on partial failure.
- **Fix:** Use Drizzle's `db.transaction()` (supported on all dialects) and pass a wrapped adapter backed by the transaction handle.

#### `hono` Is a Runtime Dependency
- `hono` is in `dependencies` in `package.json` but only used by the `./hono` sub-path export.
- For a "framework-agnostic" library, bundling a web framework as mandatory is a direct contradiction. Every consumer installs Hono whether they use it or not.
- **Fix:** Move to `peerDependencies` with `"optional": true` in `peerDependenciesMeta`, or publish the Hono adapter as a separate package.

#### `drizzle-orm` Is a devDependency but Imported at Runtime
- `src/drizzle/adapter.ts` imports `{ and, eq, ... }` from `drizzle-orm`.
- Listed as `devDependency`, not `dependencies` or `peerDependencies`.
- Works on JSR (source resolution) but is semantically wrong and would break npm consumers.
- **Fix:** Move to `peerDependencies`.

### P1 — High

#### No npm Publishing Path
- JSR-only. No build step, no `dist/` output, no compiled `.js` + `.d.ts` files.
- `package.json` has no `exports` field, no `main`, no `types`. The `module: "src/index.ts"` field is a Bun convention, not a Node standard.
- npm is where 95%+ of the TS ecosystem lives. JSR adoption is still small.
- **Fix:** Add a build step (e.g., `tsup` or `pkgroll`) producing ESM + CJS bundles with declarations. Add `exports` map to `package.json`. Dual-publish to JSR and npm.

#### No Adapter Conformance Tests
- `CLAUDE.md` acknowledges "TODO: create shared adapter conformance tests."
- The `DatabaseAdapter` interface is the core abstraction. Without a conformance test suite, adapter bugs go undetected. This is the exact failure mode that killed Lucia.
- **Fix:** Create a `runAdapterTests(createAdapter: () => DatabaseAdapter)` function that exercises every method, edge case (empty results, duplicate inserts, concurrent transactions), and verifies the contract. Run it against every adapter.

#### 7 Stub Plugins in Export Map
- Every plugin file (`src/plugins/*/index.ts`) contains only `// TODO: Implement` and `export {}`.
- These are published as sub-path exports in `jsr.json`. A consumer who sees `@bajustone/fortress/plugins/oauth` has no way to know it's empty until they import it.
- **Fix:** Remove stub exports from `jsr.json` until they have actual implementations.

#### Timing Oracle on Login
- `login()` in `auth-service.ts:169-228` skips password verification entirely for non-existent users. Both paths throw `Errors.unauthorized('Invalid credentials')`, but timing differs: missing user = fast, wrong password = slow Argon2.
- Attackers can enumerate valid identifiers via timing analysis.
- **Fix:** Run a dummy `hasher.verify()` call on the "user not found" path to normalize timing.

### P2 — Medium

#### `createDrizzleAdapter(db: any)` — Core Type Safety Hole
- The main adapter factory at `src/drizzle/adapter.ts:104` accepts `any`, losing all type safety. Every `db.insert/select/update/delete` call inside the adapter is unchecked.
- Drizzle exposes typed DB instances (`BunSQLiteDatabase`, `BetterSQLite3Database`, `PostgresJsDatabase`, etc.).
- **Fix:** Accept a constrained generic or a union of Drizzle DB types.

#### `WhereClause.operator` Ignores `CoreOperator` Type
- `src/adapters/database/types.ts` defines `CoreOperator` as a proper union (`'=' | '!=' | 'in' | ...`) but `WhereClause` uses `operator: string`.
- **Fix:** Use `operator: CoreOperator | (string & {})` to preserve autocomplete for core operators while allowing extension.

#### `update` Return Type on No-Match Is Undefined Behavior
- The adapter contract says "may return undefined or the unchanged input" when no rows match.
- A contract with undefined behavior at its boundaries is not a contract.
- **Fix:** Change return type to `T | null` (null = no match) or throw on no match.

#### `InferPlugins` Utility Type Is Never Used
- `src/core/plugin.ts` defines `InferPlugins` but the `Fortress` interface doesn't use it. `fortress.plugins.myPlugin.myMethod()` has no type safety.
- **Fix:** Wire `InferPlugins` into the `Fortress` type so plugin methods are typed.

#### No README
- JSR and npm both surface README as primary documentation. Without one, the library has no public-facing docs.
- `CLAUDE.md` is an AI context file, not user documentation.

#### No CHANGELOG or Release Process
- Version `0.0.1` with no CHANGELOG, no release workflow in CI, no conventional commits.
- For an auth library where security patches must be communicated clearly, this is a significant gap.

#### `passWithNoTests: true` in Vitest Config
- Silently passes test files with zero assertions. Dangerous with 7 plugin stubs that export empty modules.
- **Fix:** Remove `passWithNoTests: true`.

#### No `createUser` Duplicate Email Check
- Relies on DB UNIQUE constraint, but the generic `DatabaseAdapter` doesn't declare or enforce constraints.
- An adapter without UNIQUE on email silently creates duplicate users.
- **Fix:** Document as a hard requirement for adapters and verify in conformance tests, or add an explicit check.

#### No JWT Secret Strength Validation
- Consumers can pass `secret: 'a'` with no warning. HS256 requires minimum 32 bytes for security.
- **Fix:** Warn or throw on secrets shorter than 32 bytes.

### P3 — Low

#### `moduleResolution: "bundler"` Is Wrong for a Library
- `tsconfig.json` uses `"bundler"` resolution, which allows extensionless imports that fail with Node's native ESM.
- **Fix:** Use `"node16"` or `"nodenext"` for library code.

#### `"types": ["bun-types"]` in tsconfig
- Adds Bun-specific globals. Type-checking passes for Bun APIs but produces incorrect types for Node consumers.
- **Fix:** Scope bun-types to test/dev tsconfig only.

#### Pre-commit Hook Runs Full Test Suite
- `.husky/pre-commit` runs `bun run lint && bun run typecheck && bun run test` on every commit.
- Industry standard: `lint-staged` for changed files only in pre-commit, full suite in CI.
- **Fix:** Switch to `lint-staged` in pre-commit.

#### No Drizzle Adapter Isolation Tests
- No tests for PostgreSQL dialect path, `buildWhereCondition` error cases, or `sanitizeForSqlite`.
- Tested only indirectly through SQLite integration tests.

#### Unconstrained `DatabaseAdapter` Generics
- `create<T>`, `findOne<T>` etc. have no link between the `model` string and return type `T`. You can write `db.findOne<FortressUser>({ model: 'refresh_token' })` with no compiler error.
- **Fix:** Consider a mapped type linking model names to their shapes, or document as an intentional trade-off.
