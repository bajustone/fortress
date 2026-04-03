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
| **Password policy & breach checking** | Auth0, Clerk, Keycloak, Better Auth | **Critical** | No password validation anywhere. Configurable min/max length (NIST 800-63B: 8/128). HIBP k-anonymity API to reject breached passwords. Hook into `beforeRegister` and password reset. Config: `passwordPolicy?: { minLength?, maxLength?, checkBreached? }`. New file: `src/core/auth/password-policy.ts`. |
| **Rate limiting** | Keycloak, Auth0, Clerk | **Critical** | Critical for login/token endpoints. Build as plugin. `RateLimitError` (429) already in error hierarchy. |
| **Account lockout** | Most managed services | High | Lock after N failed login attempts. Simple plugin using `hooks.beforeLogin`. Exponential backoff (15min → 30min → 1hr). Required for SOC 2, ISO 27001, HIPAA. |
| **Session/device management** | Auth0, Clerk, Keycloak, Better Auth | High | Refresh tokens store IP/userAgent but no list/revoke API. Add `listSessions(userId)`, `revokeSession(tokenId)`, `revokeAllOtherSessions(userId, currentTokenId)`. Enrich refresh token with `deviceName?`, `lastActiveAt`. Modify `auth-service.ts`. |
| **Token fingerprinting on refresh** | Auth0, Clerk | High | Fortress stores IP/userAgent but doesn't validate on refresh. Optionally compare fingerprint on token refresh. Config: `jwt.validateRefreshFingerprint?: boolean \| 'warn'`. `'warn'` mode logs mismatch but allows (mobile users); `true` rejects. Prevents stolen token reuse. |
| **CSRF explicit strategy** | Auth.js, Better Auth, Keycloak | High | Architecture mentions `SameSite` cookies via `responseHeaders` but no explicit CSRF token pattern. Provide `csrfMiddleware()` for Hono. Document that `SameSite=Strict` + custom header requirement is sufficient for modern browsers. New files: `src/hono/middleware/csrf.ts`, `docs/security.md`. |
| **Audit logging** | Keycloak, Ory | High | Auth events (login, failed login, permission denied, role changes). Plugin using hooks. Immutable event log, 2-year retention recommended. Required for SOC 2, HIPAA, PCI-DSS. |
| **Admin impersonation** | Keycloak, Auth0, WorkOS, Ory | Medium | Admin acts as user without knowing password. Method: `fortress.auth.impersonate(adminUserId, targetUserId)`. Returns scoped token with `impersonatedBy` claim + shorter expiry (30min). Requires `fortress:impersonate` permission. Audit log entry. |
| **Webhooks plugin** | Auth0, Clerk, WorkOS, Ory | Medium | Not in architecture.md. Notify external systems on auth events. `fortress_webhook` model. HMAC-SHA256 signed payloads, delivery retries (3x exponential backoff). New plugin: `src/plugins/webhook/index.ts`. |
| **`isSystem` flag on roles** | Keycloak | Medium | Prevents accidental deletion of seeded roles. Add `isSystem: boolean` (default false) to role model. `deleteRole` throws if `isSystem === true`. Roles from `sync:push` marked as system. Modify `schema.ts`, `iam-service.ts`, `resource-sync.ts`. |
| **WebAuthn / Passkeys** | Auth.js, Clerk, @oslojs/webauthn | Medium | Growing fast. Plugin using routes + models. Architecture validated — no gaps. |
| **Magic link auth** | Better Auth, Auth.js | Low | Easy plugin — same pattern as email verification but issues tokens. |
| **Session management (stateful)** | Auth.js, Lucia (was), Better Auth | Low | JWT + refresh tokens is valid. Cookie handling via `AfterHookContext.responseHeaders: Headers`. |
| **SCIM (directory sync)** | WorkOS, Okta | Low | Enterprise feature for syncing users from external directories. Not needed initially. |

---

## Library Authoring Critique (vs. Industry Standards)

_Reviewed 2026-04-03 against TypeScript library authoring best practices._

### P0 — Critical

#### ~~No-op Transaction Implementation~~ **RESOLVED**
- ~~`src/drizzle/adapter.ts:191-193`: `async transaction(fn) { return fn(adapter); }` — calls the function with the same adapter, **no actual DB transaction**.~~
- **Fix applied:** Drizzle adapter now uses real transactions. SQLite uses manual `BEGIN`/`COMMIT`/`ROLLBACK` for async compatibility; PG/MySQL use Drizzle's native async `transaction()`. Transaction callback receives a new adapter backed by the transaction handle. Conformance tests verify commit and rollback behavior.

#### ~~`hono` Is a Runtime Dependency~~ **RESOLVED**
- ~~`hono` is in `dependencies` in `package.json` but only used by the `./hono` sub-path export.~~
- **Fix applied:** Moved `hono` to `peerDependencies` with `"optional": true` in `peerDependenciesMeta`.

#### ~~`drizzle-orm` Is a devDependency but Imported at Runtime~~ **RESOLVED**
- ~~`src/drizzle/adapter.ts` imports `{ and, eq, ... }` from `drizzle-orm`. Listed as `devDependency`, not `dependencies` or `peerDependencies`.~~
- **Fix applied:** Moved `drizzle-orm` to `peerDependencies` with `"optional": true` in `peerDependenciesMeta`.

### P1 — High

#### No npm Publishing Path
- JSR-only. No build step, no `dist/` output, no compiled `.js` + `.d.ts` files.
- `package.json` has no `exports` field, no `main`, no `types`. The `module: "src/index.ts"` field is a Bun convention, not a Node standard.
- npm is where 95%+ of the TS ecosystem lives. JSR adoption is still small.
- **Fix:** Add `tsup` for ESM + CJS bundles with declarations. Add `exports` map to `package.json`. Add `prepublishOnly` script. CI workflow: publish to both JSR and npm on git tag. New files: `tsup.config.ts`, `.github/workflows/publish.yml`.

#### ~~No Adapter Conformance Tests~~ **RESOLVED**
- ~~`CLAUDE.md` acknowledges "TODO: create shared adapter conformance tests."~~
- **Fix applied:** Created `src/testing/adapter-conformance.test.ts` with `runAdapterTests(createAdapter)` — 17 tests covering all CRUD methods, operators (`=`, `!=`, `in`), limit/offset, transaction commit/rollback, and edge cases (empty results, no-op delete). Run against the built-in SQLite test adapter. Custom adapters can import and run the same suite.

#### ~~7 Stub Plugins in Export Map~~ **RESOLVED**
- ~~Every plugin file (`src/plugins/*/index.ts`) contains only `// TODO: Implement` and `export {}`.~~
- **Fix applied:** Removed all 7 stub plugin exports from `jsr.json`. They will be re-added as each plugin is implemented.

#### ~~Timing Oracle on Login~~ **RESOLVED**
- ~~`login()` in `auth-service.ts` skips password verification entirely for non-existent users. Timing differs: missing user = fast, wrong password = slow Argon2.~~
- **Fix applied:** Dummy `hasher.verify()` runs on user-not-found and no-password paths to normalize response timing. Catch suppresses the expected verification failure.

### P1 — High

#### No Security Documentation
- No `docs/security.md` exists. Recommended CSRF strategy, JWT secret requirements, rotation procedure, password hashing guide, rate limiting deployment patterns, token storage best practices (httpOnly cookies vs localStorage), HTTPS requirements — none documented.
- **Fix:** Create `docs/security.md` covering all security recommendations.

#### CLI Tool Not Implemented
- `architecture.md` references `sync:push`, `sync:pull`, `sync:types` commands but no CLI exists.
- **Fix:** Create `bin/fortress.ts` with commands: `init` (scaffold config, .env template, fortress.resources.json), `sync:push`, `sync:pull`, `sync:types`, `generate-secret` (64-byte cryptographically random hex).

### P2 — Medium

#### ~~`createDrizzleAdapter(db: any)` — Core Type Safety Hole~~ **RESOLVED**
- ~~The main adapter factory at `src/drizzle/adapter.ts` accepts `any`, losing all type safety.~~
- **Fix applied:** Replaced `any` with a `DrizzleDB` structural interface requiring `insert`, `select`, `update`, `delete`, and `transaction` methods. Internal calls still use `as any` casts (Drizzle's dialect-specific return types vary), but the public API surface is typed.

#### ~~`WhereClause.operator` Ignores `CoreOperator` Type~~ **RESOLVED**
- ~~`WhereClause` uses `operator: string`, ignoring `CoreOperator`.~~
- **Fix applied:** Changed to `operator: CoreOperator | (string & {})` — preserves autocomplete for core operators while allowing extension.

#### `update` Return Type on No-Match Is Undefined Behavior
- The adapter contract says "may return undefined or the unchanged input" when no rows match.
- A contract with undefined behavior at its boundaries is not a contract.
- **Fix:** Change return type to `Promise<T | null>` (null = no match). Update adapter conformance tests to verify null on no-match.

#### `InferPlugins` Utility Type Is Never Used
- `src/core/plugin.ts` defines `InferPlugins` but the `Fortress` interface doesn't use it. `fortress.plugins.myPlugin.myMethod()` has no type safety.
- **Fix:** Wire `InferPlugins` into the `Fortress` type so plugin methods are typed.

#### No README
- JSR and npm both surface README as primary documentation. Without one, the library has no public-facing docs.
- `CLAUDE.md` is an AI context file, not user documentation.

#### No CHANGELOG, Release Process, or Security Policy
- Version `0.0.1` with no CHANGELOG, no release workflow in CI, no conventional commits.
- No `SECURITY.md` for vulnerability disclosure.
- For an auth library where security patches must be communicated clearly, this is a significant gap.
- **Fix:** Create `README.md` (quick start, API overview, plugin list), `CHANGELOG.md` (start at v0.1.0), `SECURITY.md` (disclosure process). Enforce conventional commits via commitlint. Semantic versioning.

#### ~~`passWithNoTests: true` in Vitest Config~~ **RESOLVED**
- ~~Silently passes test files with zero assertions.~~
- **Fix applied:** Removed `passWithNoTests: true` from `vitest.config.ts`.

#### ~~No `createUser` Duplicate Email Check~~ **RESOLVED**
- ~~Relies on DB UNIQUE constraint, but the generic `DatabaseAdapter` doesn't declare or enforce constraints.~~
- **Fix applied:** Added explicit `findOne` check before `create` in `createUser`. Throws `Errors.conflict('A user with this email already exists')` on duplicate. New `CONFLICT` error code (409) added to error hierarchy.
- **Note:** `CONFLICT` error code exists in implementation but is missing from the error hierarchy in `architecture.md`. Update architecture.md to include it.

#### ~~No JWT Secret Strength Validation~~ **RESOLVED**
- ~~Consumers can pass `secret: 'a'` with no warning.~~
- **Fix applied:** `createFortress()` throws `BAD_REQUEST` if any JWT secret is shorter than 32 bytes. Applies to all secrets in rotation arrays.

### P3 — Low

#### `moduleResolution: "bundler"` Is Wrong for a Library
- `tsconfig.json` uses `"bundler"` resolution, which allows extensionless imports that fail with Node's native ESM.
- **Fix:** Use `"node16"` or `"nodenext"` for library code.

#### ~~`"types": ["bun-types"]` in tsconfig~~ **RESOLVED**
- ~~Adds Bun-specific globals. Type-checking passes for Bun APIs but produces incorrect types for Node consumers.~~
- **Fix applied:** Replaced `"types": ["bun-types"]` with `"types": ["node"]` in `tsconfig.json`. Added `@types/node` as devDependency. `@types/bun` remains as devDep for Bun runtime detection in test adapter.

#### ~~Pre-commit Hook Runs Full Test Suite~~ **RESOLVED**
- ~~`.husky/pre-commit` runs `bun run lint && bun run typecheck && bun run test` on every commit.~~
- **Fix applied:** Pre-commit now runs `lint-staged` (eslint --fix on changed `.ts` files) + typecheck only. Full test suite belongs in CI.

#### No Drizzle Adapter Isolation Tests
- No tests for PostgreSQL dialect path, `buildWhereCondition` error cases, or `sanitizeForSqlite`.
- Tested only indirectly through SQLite integration tests.

#### Unconstrained `DatabaseAdapter` Generics
- `create<T>`, `findOne<T>` etc. have no link between the `model` string and return type `T`. You can write `db.findOne<FortressUser>({ model: 'refresh_token' })` with no compiler error.
- **Fix:** Consider a mapped type linking model names to their shapes, or document as an intentional trade-off.
