# Watch-Outs & Gaps vs. Industry Standards

## Design Watch-Outs

### Generic CRUD DatabaseAdapter
- **`rawQuery` escape hatch** — optional method for performance-critical multi-table operations (IAM permission chain JOINs). Adapters that don't implement it fall back to multiple `findMany` calls. Design decision: the generic CRUD is for simple ops and plugins; core IAM queries can use `rawQuery` for performance.
- **`create` return type `Promise<T>` is unconstrained** — no type relationship between `model: 'user'` and return type `T`. Intentional trade-off (same as Better Auth). The internal adapter layer handles typing. Document as a known limitation.

### Plugin System
- **Plugin ordering** — hooks run in registration order. Document this clearly. Consider if any hooks need explicit priority.

### Plugin Runtime Integration
- ~~**`wrapAdapter` and `scopeRules` are not wired into request handling.**~~ **RESOLVED.** The auth middleware now calls `chainAdapterWrappers` after JWT verification and exposes `fortressDb` (adapter with wrappers applied) and `fortressGetScopedDb(model)` (additionally applies scopeRules) on the Hono context. Helpers: `getDb(c)`, `getScopedDb(c, model)`.

### Permission Evaluation
- **Performance at scale** — evaluation with conditions requires DB queries per check. Plan caching (per-request cache, short TTL cache of user permissions). Use `rawQuery` for the permission chain JOIN when available.
- **Wildcard permissions** — no `*` wildcards (e.g., `post:*` for all actions). AWS and GCP support these. Decide upfront.
- **Hierarchical resources** — GCP has `projects/*/buckets/*/objects/*`. Not needed now, but keep the door open.

### Data Isolation Plugin
- **Bulk operations** — `update` and `delete` with scope rules must be tested carefully to prevent cross-tenant mutations.

### Password Hasher
- WASM Argon2id is slower than native. Document the trade-off and make `@node-rs/argon2` / `Bun.password` swaps dead simple for users who don't need edge runtime.

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
| ~~**Password policy & breach checking**~~ | Auth0, Clerk, Keycloak, Better Auth | ~~Critical~~ **RESOLVED** | `src/core/auth/password-policy.ts`: configurable min/max length (NIST 800-63B defaults 8/128), HIBP k-anonymity breach checking (opt-in). Wired into `createUser()`. Config: `passwordPolicy?: { minLength?, maxLength?, checkBreached?, breachedCacheTtlMs? }`. |
| ~~**Rate limiting**~~ | Keycloak, Auth0, Clerk | ~~Critical~~ **RESOLVED** | `src/plugins/rate-limit/`: sliding window plugin with dual-key (per-IP + per-account) limiting. Hooks into `beforeLogin`/`beforeRegister`. Configurable limits and window. In-memory store default, custom store interface for Redis/DB. IPv6 /64 normalization. |
| ~~**Account lockout**~~ | Most managed services | ~~High~~ **RESOLVED** | `src/plugins/account-lockout/`: progressive lockout with exponential backoff. Tracks by identifier (not userId) to handle non-existent accounts. Configurable max attempts (5), duration (15min), escalation, max lockout (1hr). Uses `onLoginFailure` hook. Methods: `getLockoutStatus()`, `resetLockout()`. |
| ~~**Session/device management**~~ | Auth0, Clerk, Keycloak, Better Auth | ~~High~~ **RESOLVED** | Added `listSessions()`, `revokeSession()`, `revokeAllOtherSessions()` to AuthService. Refresh tokens now store `deviceName`, `lastActiveAt`. `RequestMeta` extended with `deviceName`. |
| ~~**Token fingerprinting on refresh**~~ | Auth0, Clerk | ~~High~~ **RESOLVED** | SHA-256(userAgent) stored as `fingerprintHash` on refresh tokens. Config: `jwt.validateRefreshFingerprint?: boolean \| 'warn'`. `true` invalidates token family on mismatch; `'warn'` logs but allows. |
| ~~**CSRF explicit strategy**~~ | Auth.js, Better Auth, Keycloak | ~~High~~ **RESOLVED** | `src/hono/middleware/csrf.ts`: custom-header strategy (`X-Fortress-CSRF: 1`). Skips safe methods (GET/HEAD/OPTIONS). Checks `Sec-Fetch-Site` header. Configurable header name, skip paths, safe methods. |
| ~~**Audit logging**~~ | Keycloak, Ory | ~~High~~ **RESOLVED** | `src/plugins/audit-log/`: append-only event logging via hooks. Events: LOGIN_SUCCESS/FAILURE, LOGOUT, REGISTER, TOKEN_REFRESH, TOKEN_REUSE. Optional hash chain for tamper detection. Methods: `getAuditLog(filters)`. SOC 2 / HIPAA / PCI-DSS compliant schema. |
| ~~**Admin impersonation**~~ | Keycloak, Auth0, WorkOS, Ory | ~~Medium~~ **RESOLVED** | `fortress.auth.impersonate(adminUserId, targetUserId, options?)`. RFC 8693 `act` claim. Default 60-min expiry, non-renewable (no refresh token). Caller verifies `fortress:impersonate` permission. Includes reason in pluginData. |
| ~~**Webhooks plugin**~~ | Auth0, Clerk, WorkOS, Ory | ~~Medium~~ **RESOLVED** | `src/plugins/webhook/`: Standard Webhooks spec (HMAC-SHA256 signing, `webhook-id`/`webhook-timestamp`/`webhook-signature` headers). Exponential backoff retries (5s→5min→30min→2h→5h). Methods: `registerEndpoint()`, `listEndpoints()`, `removeEndpoint()`, `processRetries()`. |
| ~~**`isSystem` flag on roles**~~ | Keycloak | ~~Medium~~ **RESOLVED** | Added `isSystem: boolean` (default false) to role schema. `deleteRole` throws `'Cannot delete a system role'` if `isSystem === true`. |
| ~~**WebAuthn / Passkeys**~~ | Auth.js, Clerk, @oslojs/webauthn | ~~Medium~~ **STUBBED** | `src/plugins/webauthn/`: plugin stub with model definitions (`webauthn_credential`, `webauthn_challenge`), route declarations, and placeholder methods. Architecture validated. Full crypto implementation deferred. |
| ~~**Magic link auth**~~ | Better Auth, Auth.js | ~~Low~~ **RESOLVED** | `src/plugins/magic-link/`: token-based passwordless auth. `sendMagicLink(email)` + `verifyMagicLink(token)`. JIT user provisioning. SHA-256 hashed tokens. |
| **Session management (stateful)** | Auth.js, Lucia (was), Better Auth | Low | JWT + refresh tokens is valid. Cookie handling via `AfterHookContext.responseHeaders: Headers`. |
| **SCIM (directory sync)** | WorkOS, Okta | Low | Enterprise feature for syncing users from external directories. Not needed initially. |

---

## Library Authoring Issues

_Reviewed 2026-04-03 against TypeScript library authoring best practices._

### P1 — High

#### ~~No npm Publishing Path~~ — RESOLVED
- Added `tsup.config.ts` for ESM + CJS bundles with declarations. `package.json` has `exports` map with conditional `import`/`require`/`types`. `prepublishOnly` script. CI workflow: `.github/workflows/publish.yml` publishes to both JSR and npm on git tag.

#### ~~No Security Documentation~~ — RESOLVED
- Created `docs/security.md` covering JWT secrets, password hashing, password policy, rate limiting, account lockout, token storage, CSRF, refresh token security, HTTPS, audit logging, and admin impersonation.

#### ~~CLI Tool Not Implemented~~ — RESOLVED
- Created `bin/fortress.ts` with commands: `init`, `sync:push`, `sync:pull`, `sync:types`, `generate-secret`.

### P2 — Medium

#### ~~`update` Return Type on No-Match Is Undefined Behavior~~ — RESOLVED
- Changed `DatabaseAdapter.update<T>` return type to `Promise<T | null>`. Updated Drizzle adapter, plugin-runner wrapper, and tenancy wrapper.

#### ~~`InferPlugins` Utility Type Is Never Used~~ — RESOLVED
- `createFortress` is now generic: `createFortress<const T>()` infers plugin types via `InferPlugins<T>`. Each plugin augments `PluginMethodsMap` via declaration merging, and factory return types include `readonly name: 'literal'`. Result: `fortress.plugins['two-factor'].enable(userId)` is fully typed with no casting. `getPluginMethods<T>()` kept as fallback for untyped contexts.

#### ~~No README~~ — RESOLVED
- Created `README.md` with features, quick start, plugin list, framework integrations, database support.

#### ~~No CHANGELOG, Release Process, or Security Policy~~ — RESOLVED
- Created `CHANGELOG.md` (v0.1.0), `SECURITY.md` (vulnerability disclosure process), `.github/workflows/publish.yml` (CI release on git tag).

### P3 — Low

#### `moduleResolution: "bundler"` — KEPT AS-IS
- `tsconfig.json` uses `"bundler"` resolution. Changing to `"node16"` would require `.js` extensions on 100+ imports with no practical benefit — JSR consumes TypeScript source directly, tsup handles npm bundling. Intentional trade-off.

#### ~~No Drizzle Adapter Isolation Tests~~ — RESOLVED
- Created `src/drizzle/adapter.test.ts` with 15 tests: buildWhereCondition edge cases (unknown field, unsupported operator, AND logic, snake_case mapping), sanitizeForSqlite (Dates, booleans, null, undefined), unknown model, count, transactions (rollback + commit), update null on no-match.

#### Unconstrained `DatabaseAdapter` Generics
- `create<T>`, `findOne<T>` etc. have no link between the `model` string and return type `T`. You can write `db.findOne<FortressUser>({ model: 'refresh_token' })` with no compiler error.
- Intentional trade-off (same as Better Auth). Documented in CLAUDE.md and architecture.md.
