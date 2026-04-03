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
