# Fortress Lock-In Remediation Roadmap (v0.0.x → freezable API)

_Derived from `fortress-audit-report.html` (audit @ v0.2.8) — generated 2026-06-15._


Six phases on a lock-in spine with a security hotfix bolted to the front. Phase 1 is a deploy-safety hotfix: every remaining critical auth-bypass / account-takeover and the highs that make a running deployment exploitable, shipped regardless of API freeze (breaking changes accepted because security trumps stability and these fixes also happen to pin the social-login surface). Phases 2-4 are the freeze spine: front-load every finding whose fix is FORCED to change a public surface, sequenced subsystem-by-subsystem (auth-core/2FA contracts → framework & DatabaseAdapter contracts → packaging/observability/IAM-policy/admin) so each subsystem can be frozen the moment its breaking changes land, each phase fanned out into disjoint-file parallel workstreams. Phases 5-6 are internal-only correctness (NULL-query bugs, SQLite serialization, validation, schema/migration hardening, plugin integrity) and the verification gate (conformance + CI publish-gate) that makes "frozen" provable. Findings are grouped by cluster so duplicates collapse into single work items.


## Phases at a glance

| # | Phase | Work items | Breaking surface | Releasable on its own |
|---|-------|-----------|------------------|------------------------|
| 1 | Security hotfix: make any deployment safe | 13 | 8 breaking | Yes — security patch |
| 2 | Auth-core & 2FA behavioral-contract freeze | 7 | 5 breaking | Freeze gate |
| 3 | Framework-adapter & DatabaseAdapter contract freeze | 5 | 5 breaking | Freeze gate |
| 4 | Packaging, observability & IAM/policy public-API freeze | 9 | 9 breaking | Freeze gate |
| 5 | Internal correctness: data-access, validation, IAM internals, schema & migrations | 8 | 0 breaking | No |
| 6 | Plugin integrity, CLI, testing utilities & CI/release gating (verification gate) | 5 | 1 breaking | No (verification gate) |

---

## Phase 1 — Security hotfix: make any deployment safe

**Objective.** Close every remaining account-takeover / auth-bypass vector exploitable on v0.2.8 today and ship as an emergency patch, independent of the freeze timeline. Because the social-login fixes are forced to change handleCallback/ProviderProfile/getAuthorizationUrl, landing them here also pins the Social Login and Hono-OpenAPI public surfaces first.


**Why here.** These are the only findings exploitable against a live deployment: unauthenticated IAM admin dispatch, forged-id_token + unverified-email account takeover, missing OAuth state CSRF, replayable TOTP, sessions surviving password change, webhook SSRF inside auth hooks, lockout self-DoS, first-user admin self-grant, cross-scope writes, and a tenant-scoped grant working globally. Security ordering (security-first) overrides API cost; the heavy social-login gating load is absorbed here for free.


**Work items:**

- **[L · BREAKING]** Verify provider id_token (JWS signature via JWKS + iss/aud/exp + nonce) and complete provider wiring (OIDC discovery, Apple ES256 client-secret JWT)
  - findings: #1, #4, M3, M69, #42, M65, #40, M67
  - files: `src/plugins/social-login/index.ts`, `src/plugins/social-login/providers/oidc.ts`, `src/plugins/social-login/providers/github.ts`
- **[M · BREAKING]** Gate by-email account linking on emailVerified + add isActive/null guard (carry emailVerified through ProviderProfile + every provider mapper)
  - findings: #5, #7, M68
  - files: `src/plugins/social-login/index.ts`
- **[M · BREAKING]** Validate returned OAuth state (timing-safe) and separate state(CSRF) from nonce(OIDC) in the auth URL + handleCallback signature
  - findings: #6
  - files: `src/plugins/social-login/index.ts`
- **[M]** Wrap social-account link/provision in a transaction + add (provider, providerAccountId) and (userId, provider) UNIQUE across all dialects
  - findings: #44, M66
  - files: `src/plugins/social-login/index.ts`, `src/core/migrations/migrations.ts`, `migrations/sqlite/0002_initial_schema.sql`, `src/drizzle/schema.ts`, `src/drizzle/pg/schema.ts`
- **[M · BREAKING]** **[DECIDED: secure it]** Route mountFortressOpenAPI/createAutoHandler through fortress.handleRequest (principal resolution + enforceFortressPermission + CSRF/validation + M7 context sanitization). Keep the export; it now performs the same auth as handleRequest
  - findings: #2, #3
  - files: `src/hono/openapi.ts`
- **[M]** Enforce TOTP single-use: persist lastUsedCounter, return matched counter, reject via atomic conditional UPDATE
  - findings: #8, #37
  - files: `src/plugins/two-factor/index.ts`
- **[S · BREAKING]** Revoke all active refresh-token sessions on password/credential change in updateUser
  - findings: #10, M7
  - files: `src/core/auth/auth-service.ts`
- **[M]** Deliver webhooks out-of-band with timeout + SSRF guard + try/catch on event-row parse (stop blocking/breaking auth hooks)
  - findings: #48
  - files: `src/plugins/webhook/index.ts`
- **[M · BREAKING]** Fix account-lockout self-DoS/escalation: reset failedAttempts on window expiry, key by normalized identifier, atomic increment, recovery bypass
  - findings: #34, #35, M1, M57
  - files: `src/plugins/account-lockout/index.ts`, `src/core/plugin.ts`
- **[M · BREAKING]** **[DECIDED: remove adminUserIds + one-time-secret opt-in bootstrap]** Remove the dead `adminUserIds` option (drop from AdminConfig + docs). Make the bootstrap route **opt-in (not mounted by default)**; when enabled it succeeds **only while zero fortress-admins exist AND the caller presents a one-time bootstrap secret** from env/config (constant-time compared). A plain authenticated user can never self-grant admin
  - findings: #45, #46
  - files: `src/plugins/admin/index.ts`
- **[S]** data-isolation: force resolved scope on create, reject/strip scope key on update (block cross-scope create/move)
  - findings: #47
  - files: `src/core/plugin-runner.ts`
- **[M · BREAKING]** **[DECIDED: tenant_id IS NULL only]** Enforce tenant-less permission-check semantics so a tenant-scoped grant cannot match a tenant-less check — a tenant-less `checkPermission` matches **only `tenant_id IS NULL` bindings**. Document the authorization-outcome change
  - findings: #14
  - files: `src/core/internal-adapter.ts`
- **[M · BREAKING]** **[DECIDED: encrypt at rest]** Implement AES-256-GCM at-rest encryption for stored provider access/refresh tokens using a config-provided encryption key (new config field; throw if persistence enabled without a key) — makes the existing docs true. Correct social-login README/architecture/SECURITY to the real verified-callback flow
  - findings: #43, #41
  - files: `README.md`, `docs/architecture.md`, `src/plugins/social-login/index.ts`

**Public-surface changes this phase locks in:**
- social-login handleCallback() gains returnedState + storedNonce params and becomes async-config (JWKS/discovery); getAuthorizationUrl return shape redefined to {url,state,codeVerifier,nonce}
- ProviderProfile exported type gains emailVerified; all provider mappers populate it; auto-link semantics now require email_verified===true
- Apple provider config gains teamId/keyId/privateKey; generic OIDC provider gains discovery + endpoint overrides
- mountFortressOpenAPI/createAutoHandler documented behavior changes (now enforces auth) or the export is removed/deprecated
- updateUser now revokes all active refresh tokens on password change (documented session-invalidation contract)
- AfterHookContext gains the login identifier (consumed by the lockout reset)
- admin: adminUserIds becomes a real allowlist (or is removed); bootstrap route gated/opt-in
- tenant-less checkPermission tenancy semantics pinned + documented (authorization-outcome change)

**Exit criteria.** Forged/unsigned id_tokens are rejected (jose jwtVerify validates signature/iss/aud/exp/nonce; regression test with a tampered token → 401). By-email auto-link fires only when emailVerified===true and the resolved user is non-null + isActive. Returned OAuth state is timing-safe-compared. Every auto-mounted IAM admin route returns 401/403 without a resolved principal passing enforceFortressPermission. A captured TOTP code is rejected on replay. Old refresh tokens stop working after a password change. Webhooks never block or crash an auth hook and cannot reach internal IPs. A locked account self-recovers after the window and cannot be re-locked by one failure; the first authenticated caller cannot self-grant admin. A scoped subject cannot create/move rows into another scope. A tenant-scoped grant no longer satisfies a tenant-less check. This phase is releasable as a security patch on its own.


---

## Phase 2 — Auth-core & 2FA behavioral-contract freeze

**Objective.** Pin every AuthService / 2FA / JWT / password / event-taxonomy contract the lock-in matrix flags as must-decide-now, so AuthEvent, AfterHookContext, the 2FA verify() return type, and the refresh-rotation behavior can freeze. Downstream plugins/adapters in later phases are then written against final shapes once.


**Why here.** These define exported discriminated unions, return shapes, and documented behavioral contracts that Phase 3-4 plugin/adapter code consumes; they must precede the fan-out. The 2FA completion rework and refresh grace-window are coherent reworks best done before anything depends on verify() or rotation semantics. Excludes already-fixed #9/#15/M27/M29.


**The spine (design resolved 2026-06-16).** A single unified post-auth result, `AuthResult = AuthSuccess | AuthImpersonation | AuthPending` (discriminated on `status`), returned by `auth.login`, `twoFactor.verify`, `magicLink.verify`, and a new `auth.completePendingAuth`. The `pending` variant carries **no token fields at all** — reading a token after narrowing to pending is a compile error and the server has nowhere to write a premature one. A shared **post-auth gate** (`src/core/auth/post-auth-gate.ts`; plugins register a `PostAuthGateProvider` instead of overriding `afterLogin`) runs **before `issueTokens`**, so a held login never reaches the refresh-row writer — the orphan-refresh bug becomes structurally impossible, not merely defended-against. A single-use, hashed-at-rest, short-TTL **`auth_continuation`** token replaces the orphaned refresh token as the cross-leg carrier; `completePendingAuth` **atomically consumes** it (closing the magic-link/email-verify TOCTOU in the same mechanism) and **re-runs the gate** before minting — so magic-link stops being a 2FA backdoor. One union, one gate, one issuance path.

**Locked decisions (2026-06-16):** M61 → 2FA `verify()` returns full `Promise<AuthResult>` (narrow via `isSuccess()`; layered factors can return pending). M4 → password min-length default **8→15** (new passwords only). M40 → `breachedFailureMode: 'open'|'closed'`, default **'open'**, always emit `PASSWORD_BREACH_CHECK_DEGRADED` + log. Continuation token bound to **(userId, reason) only** (no IP/UA pin — preserves cross-device 2FA).

**Work items:**

- **[L · BREAKING]** **Foundation** — land the union + renames in `src/core/types.ts` (`AuthResult`/`AuthSuccess`/`AuthPending`/`AuthImpersonation`, `AuthChallenge`, `PendingReason`, `AuthMethod`, `isSuccess`/`isPending`/`isImpersonation`/`assertSuccess` guards); extend the `AuthEvent` union + export `AuthEvent`/`AuthEventListener`; re-export all from `src/index.ts`. Compile-anchor for everything below.
  - files: `src/core/types.ts`, `src/core/auth/auth-service.ts`, `src/index.ts`
- **[L · BREAKING]** **Schema/migration (one v3)** — new `auth_continuation` table (`StoredContinuation`) + three `refresh_token` columns (`familyCreatedAt` non-null, `successorTokenHash` nullable, `rotatedAt` nullable); `lastActiveAt` now seeded at issuance. Apply across all 5 sync points (models, both drizzle schemas, `migrations.ts`, bundled `migrations/{pg,sqlite}`, inline DDL in `pg.integration-test.ts`) — run pg integration to catch drift.
  - files: `src/drizzle/schema.ts`, `src/drizzle/pg/schema.ts`, `src/core/migrations/migrations.ts`, `migrations/{pg,sqlite}/*`, `src/core/internal-adapter.ts`
- **[L · BREAKING]** **Gate spine (items 1+5 core)** — build `src/core/auth/post-auth-gate.ts` (`PostAuthGateProvider` registry + mint/peek/atomic-consume continuation helpers); reorder `login()` to run gates before `issueTokens`; add `completePendingAuth` to `AuthService` + expose on `PluginContext.auth`; gate `LOGIN_SUCCESS` on `status==='success'`, emit `LOGIN_PENDING` on hold.
  - findings: M8, M60, M61, M62, M63, #38
  - files: `src/core/auth/post-auth-gate.ts`, `src/core/auth/auth-service.ts`, `src/core/plugin.ts`
- **[L · BREAKING]** **Plugin migration (items 1+5)** — two-factor (`afterLogin` override → `postAuthGate`; `verify(continuationToken, code) → AuthResult` via `completePendingAuth`, emit `MFA_VERIFY_*`), webauthn (same), magic-link (`verifyMagicLink → verify` returning `AuthResult`, atomic consume), email-verification (`beforeLogin → postAuthGate`, atomic consume, drop the `as unknown` cast). Update audit-log `AuditEventType` in lockstep.
  - findings: M8, M60, M62, M63, #38
  - files: `src/plugins/{two-factor,webauthn,magic-link,email-verification,audit-log}/index.ts`
- **[L · BREAKING]** **Refresh grace window + session caps (items 2/3)** — successor-pointer grace-window return in `refresh()`'s replay branch (CAS against successor, not fresh mint); idle + absolute caps after the expiry check; new opt-in `jwt.session` config block; new error codes `SESSION_IDLE_TIMEOUT`/`SESSION_ABSOLUTE_TIMEOUT`; emit `TOKEN_REUSE_GRACED`/`SESSION_EXPIRED_*`.
  - findings: #18, #24, M5, M6, M10
  - files: `src/core/auth/auth-service.ts`, `src/core/config.ts`, `src/core/errors.ts`
- **[M · BREAKING]** **Event fixes (item 4 non-pending half)** — M9 hard-mode fingerprint mismatch commit-then-emit sentinel + `action` field; M12 per-`onLoginFailure`-hook try/catch so a throwing hook can't suppress `LOGIN_FAILURE`.
  - findings: M9, M11, M12
  - files: `src/core/auth/auth-service.ts`
- **[M · BREAKING]** **Password (item 6)** — default min length **8→15**; bound HIBP cache (LRU + `breachedCacheMaxEntries`); add `breachedFailureMode` (default `'open'`) + `PasswordPolicyObserver`; thread observer closure emitting `PASSWORD_BREACH_CHECK_DEGRADED`. (`isPasswordBreached` 2nd arg → options object.)
  - findings: M4, M28, M40
  - files: `src/core/auth/password-policy.ts`, `src/core/config.ts`
- **[S]** **Cookie (item 7)** — fail closed at **config time** in `resolveCookieConfig` (NOT `cookie-serialize.ts`) on `SameSite=None`-without-`Secure` and caller-supplied `__Host-`/`__Secure-` prefix violations; auto-default-name path unchanged.
  - findings: M2
  - files: `src/core/config.ts`
- **[M · BREAKING]** **Wire + consumers** — regenerate the `auth-endpoints.ts` wire mirror (pending member drops null tokens, gains typed challenge) + runtime `FortressSchema` oneOf; add `POST /auth/2fa/verify` + `/auth/magic-link/verify`; update `dispatch.ts`, SvelteKit actions, smoke test, Hono/Express examples.
  - files: `src/core/auth/auth-endpoints.ts`, `src/core/http/dispatch.ts`, adapters, `examples/`

**Public-surface changes this phase locks in:**
- `AuthResponse*` replaced by `AuthResult`/`AuthSuccess`/`AuthPending`/`AuthImpersonation`; pending variant drops `accessToken:null`/`refreshToken:null` and gains required `pending: AuthChallenge`; `AuthSuccess` gains required `method: AuthMethod`
- `twoFactor.verify(userId, code)→{verified}` becomes `verify(continuationToken, code)→AuthResult` and issues the session; `magicLink.verifyMagicLink→verify`, returns `AuthResult` with a real refresh token + enriched claims
- `emailVerification` `beforeLogin` hook removed → `PostAuthGateProvider`; `afterLogin` narrowed to `AuthSuccess` only; `PluginHooks` gains `postAuthGate`; `PluginContext.auth` gains `completePendingAuth`
- new `auth_continuation` table + `refresh_token` v3 columns; new opt-in `jwt.session` block (grace window, idle/absolute caps, max sessions/user) + two new error codes
- `AuthEvent` gains `LOGIN_PENDING`/`MFA_VERIFY_*`/`TOKEN_REUSE_GRACED`/`SESSION_EXPIRED_*`/`PASSWORD_BREACH_CHECK_DEGRADED` + `pendingReason`/`action`/`outcome:'pending'`; `LOGIN_SUCCESS` now only on `status==='success'`
- default password min length **8→15**; `breachedFailureMode` (default `'open'`); `resolveCookieConfig` throws on RFC-6265bis MUST violations

**Exit criteria.** A held login never issues a token (gate runs before `issueTokens`; no orphaned refresh row); 2FA/webauthn/magic-link/email-verify all flow through the shared gate + `completePendingAuth` and consume their tokens atomically; `verify()` returns a real `AuthResult` session and re-runs the gate; concurrent legitimate double-refresh within the grace window returns the successor (one-winner CAS preserved); idle + absolute caps enforced with distinct error codes/events; `LOGIN_PENDING`/`MFA_VERIFY_*`/fingerprint/`onLoginFailure` events emit correctly; password min-length 15 + bounded HIBP cache + `breachedFailureMode` opt-in with `PASSWORD_BREACH_CHECK_DEGRADED` observability; cookie config throws on MUST violations. `AuthResult`, the post-auth gate, `AuthEvent`, and the 2FA `verify()` contract are frozen.


---

## Phase 3 — Framework-adapter & DatabaseAdapter contract freeze

**Objective.** Land every breaking public-surface change in the SvelteKit/Express/Hono adapters and the DatabaseAdapter contract so those subsystems can freeze: the cross-adapter PluginRequestContext, fail-closed RBAC options, the SvelteKit type/redirect surface compiled against the real peer dep, and the DrizzleDialect/rawQuery/empty-where contract.


**Why here.** This is the matrix's heaviest 'do not lock yet' cluster after social-login. PluginRequestContext is a serialization point (defined once, adopted by both adapters); it and the core refresh grace-window from Phase 2 are prerequisites for the middleware and silent-refresh fixes. The DatabaseAdapter contract must be pinned before third-party adapters depend on it.


**Work items:**

- **[L · BREAKING]** Define + lock PluginRequestContext as the single cross-adapter plugin-middleware contract; normalize the Express slot and Hono createPluginMiddleware to it (fixes silent rate-limit fail-open)
  - findings: #22, M42
  - files: `src/core/http/plugin-middleware.ts`, `src/express/middleware.ts`, `src/hono/middleware/plugin-middleware.ts`
- **[L · BREAKING]** Fix SvelteKit integration: redirectTo no longer throws a raw Response, public types compile against real @sveltejs/kit in strict mode, FortressActionSuccess gains a pending discriminator; complete silent-refresh single-flight + RequestMeta forwarding (adapter half of #18/#24)
  - findings: #19, #20, M37
  - files: `src/sveltekit/actions.ts`, `src/sveltekit/types.ts`, `src/sveltekit/handle.ts`
- **[M · BREAKING]** Make route-map RBAC fail closed: Express unmappedRoutes:'deny' + stop mount-path stripping; Hono createRbacMiddleware defaultDeny option
  - findings: #23, M43
  - files: `src/express/index.ts`, `src/hono/middleware/rbac.ts`
- **[M · BREAKING]** Fix Express form-urlencoded body handling (OAuth token/introspect/revoke); add Express createCsrfMiddleware; make standalone Hono CSRF skip-path segment-safe
  - findings: #21, M38, M41
  - files: `src/express/handle.ts`, `src/express/index.ts`, `src/hono/middleware/csrf.ts`
- **[L · BREAKING]** **[DECIDED: drop mysql for now]** Pin the Drizzle/DatabaseAdapter contract: **remove `mysql` from `DrizzleDialect` + README/docs** (clean removal, re-add later if implemented), throw on empty where[] for update/delete/findOne, canonicalize the rawQuery placeholder style + document it, map sqlite unique-violations to 409 like pg
  - findings: #17, M30, M17, M36, M32
  - files: `src/drizzle/adapter.ts`, `src/drizzle/pg-error-map.ts`, `src/adapters/database/index.ts`, `src/core/internal-adapter.ts`

**Public-surface changes this phase locks in:**
- PluginRequestContext locked as the single cross-adapter plugin-middleware contract; both adapters normalize to it
- SvelteKit exported types (TLocals default, resolve signature) change to be assignable against real @sveltejs/kit; redirectTo stops throwing a raw Response; FortressActionSuccess gains {pending} discriminator
- Express + Hono RBAC gain a strict/defaultDeny option; documented default-allow behavior changes
- new public Express createCsrfMiddleware export; Hono CSRF skip-path matching changes
- DrizzleDialect union changes (mysql dropped or implemented); empty-where update/delete now throws; rawQuery placeholder contract pinned; sqlite unique-violation now maps to 409

**Exit criteria.** rate-limit path middleware fires through both Express and Hono (no fail-open); the full SvelteKit public type surface typechecks against the real @sveltejs/kit in a CI type-level test; redirectTo produces a real redirect and pending logins are discriminated; concurrent SvelteKit silent refreshes no longer family-revoke; routeMap RBAC can fail closed on both adapters; Express OAuth endpoints accept form-urlencoded bodies; DrizzleDialect reflects only working dialects, empty-where mutations throw, the rawQuery placeholder contract is conformance-enforced, and unique violations map consistently to 409. The Express, SvelteKit, Hono, and Drizzle adapter surfaces are frozen.


---

## Phase 4 — Packaging, observability & IAM/policy public-API freeze

**Objective.** Finish all remaining gating public-surface changes — the npm export map, root type exports, observability/OTel types + span context, the IamEvent taxonomy, createFortress collision behavior, core logout/permission wire behavior, the policy/CLI public contracts, and host-route dispatch/tenancy shapes — so the entire freezable API has been touched exactly once.


**Why here.** These are gating but not security-shaped, so they land after the exploit and auth-core contracts. After this phase every public surface the lock-in matrix flags is pinned and the library can declare API stability subsystem-by-subsystem. Workstreams touch disjoint packaging/observability/iam/policy/admin/tenancy files.


**Work items:**

- **[L · BREAKING]** **[DECIDED: npm is a supported channel]** Packaging/export parity: add ./express, ./drizzle/pg, all ./plugins/* (incl. rate-limit/{hono,express,sveltekit}) to package.json exports + tsup entries to match jsr.json; re-export all public-API-reachable types from root; add a CI parity test so npm/jsr/tsup never drift again
  - findings: #33, M18, M19, M53
  - files: `package.json`, `tsup.config.ts`, `jsr.json`, `src/index.ts`
- **[M · BREAKING]** Finalize observability public API: export FortressLogger/TelemetryProvider/AuthEvent+IamEvent listener types/Unsubscribe from root + /otel; add span context propagation (startActiveSpan/parent) before the tracer type freezes
  - findings: M51, M52
  - files: `src/otel/index.ts`, `src/core/fortress.ts`, `src/index.ts`
- **[M · BREAKING]** Extend IamEvent union (PERMISSION_CREATED/DELETED, GROUP_UPDATED/DELETED) and emit on createPermission/deletePermission/updateGroup/deleteGroup; cascade deleteGroup group_user/GROUP bindings in app code
  - findings: M25, M26
  - files: `src/core/iam/iam-service.ts`
- **[M · BREAKING]** createFortress fails fast (or picks a documented winner) on duplicate method+path and on fortress.call key collisions
  - findings: M13, M14
  - files: `src/core/fortress.ts`
- **[S · BREAKING]** Core pipeline: logout response attaches clearAuthCookies; meta.permission no longer 401s without security:['bearer']
  - findings: M20, M21
  - files: `src/core/http/handle-request.ts`
- **[L · BREAKING]** Make policy apply/diff converge: apply resource ops (new applyPolicyPlan param or IamService.pushResources), diff SA bindings against real fortress_role_binding rows (new IamService.listRoleBindingsForSubject), converge description-clear and zero-permission roles, fix prune ordering
  - findings: #26, #27, #28, M48, M49
  - files: `src/core/policy/apply.ts`, `src/core/policy/diff.ts`, `src/core/iam/iam-service.ts`
- **[M · BREAKING]** Canonicalize fortress.resources.json to the map shape (reject arrays); validate policy shape + prune-empty interlock + explicit env-file fallback in loadPolicy
  - findings: #30, M47
  - files: `bin/fortress.ts`, `src/core/policy/loader.ts`
- **[M · BREAKING]** Fix host (plugin:null) route dispatch: manifest marks them mounted:false and dispatch falls through to user handlers / 404-501 instead of fake {ok:true} 200
  - findings: #11
  - files: `src/core/manifest/route-manifest.ts`, `src/core/http/dispatch.ts`
- **[M · BREAKING]** Tenancy: wrap GET /tenancy/tenants/mine to {tenants:[...]} per the OpenAPI schema; make switchTenant default-tenant flip atomic (single UPDATE + partial unique)
  - findings: M73, M74
  - files: `src/plugins/tenancy/index.ts`

**Public-surface changes this phase locks in:**
- package.json exports map + tsup entries gain express, drizzle/pg, all plugins/*; root re-exports all public-API types
- observability types exported from root + /otel; TelemetryProvider Tracer/Span API gains context propagation
- IamEvent union gains PERMISSION_CREATED/DELETED, GROUP_UPDATED/DELETED
- createFortress now fails fast on duplicate route/call-key collisions
- logout response now attaches clearAuthCookies (Set-Cookie wire change across adapters)
- applyPolicyPlan signature OR new IamService.pushResources/listRoleBindingsForSubject methods; fortress.resources.json canonicalized to map (arrays rejected)
- host-route dispatch wire behavior changes (404/501/fall-through instead of {ok:true} 200)
- GET /tenancy/tenants/mine response body shape changes to {tenants:[...]}

**Exit criteria.** Every documented plugin/Express/drizzle-pg import resolves for npm consumers (guarded by a parity test); all public-API-reachable + observability types export from root; spans form a real parent/child hierarchy; IamEvent/AuthEvent unions are complete; duplicate plugin routes/call-keys fail fast; logout clears auth cookies through all adapters; policy apply converges (applies twice to inSync) for resource ops, real SA bindings, description-clears and prune ordering; resources.json round-trips as a map and loadPolicy validates shape with a prune interlock; host routes fall through/404; tenancy/mine returns the declared shape and switchTenant keeps exactly one default. All gating public surfaces are now pinned; the freezable API is complete.


---

## Phase 5 — Internal correctness: data-access, validation, IAM internals, schema & migrations

**Objective.** Land the high-impact internal-only correctness fixes that change behavior but force no public-surface change, so they can safely follow the freeze: NULL-query data-access bugs, SQLite concurrency, validation/coercion gaps, path canonicalization, IAM evaluator/cache internals, schema/index/normalization drift, and migration-engine hardening.


**Why here.** None of these breaks a consumer (per the breaking-change classification, all are internal-only logic/SQL/constraint/index fixes), so per the lock-in spine they are deferred behind the gating work. They are still high-value (a per-issuance keypair regen, broken usernameless login, a trailing-slash middleware bypass, unsound condition evaluation) and grouped into disjoint parallel workstreams.


**Work items:**

- **[M]** Fix '= NULL' data-access bugs: webauthn discoverable lookup and oauth jwks active-key lookup → operator:'isNull' (stop per-issuance keypair regen; fix usernameless login); add the documented jwks rotation/grace window
  - findings: #36, #39, M64
  - files: `src/plugins/webauthn/index.ts`, `src/plugins/oauth/jwks.ts`
- **[M]** Serialize all non-transactional SQLite ops through the same async chain so they don't join/rollback with an open transaction
  - findings: #16
  - files: `src/drizzle/adapter.ts`
- **[M]** Harden validation: JSON Schema validator honor const/additionalProperties/allOf/$ref/format; fix query/param coercion (no empty-string→0, reject hex/exponent numerics)
  - findings: M15, M16
  - files: `src/core/json-schema-validator.ts`, `src/core/validation.ts`
- **[M]** One shared path canonicalization for route + middleware matching so trailing/double-slash can't bypass rate-limit/audit middleware
  - findings: #12
  - files: `src/core/http/match.ts`, `src/core/http/plugin-middleware.ts`, `src/core/plugin-runner.ts`
- **[L]** IAM evaluator soundness: explainPermission reuses evaluatePermissions (honors mode/conditions/SA-isActive); condition eval treats unresolved as fail + pins authoritative identity over caller context; permission cache uses a generation counter to drop stale writes
  - findings: #13, M22, M23, M24
  - files: `src/core/iam/explain.ts`, `src/core/iam/permission-evaluator.ts`, `src/core/iam/iam-service.ts`
- **[L]** **[DECIDED: normalize email]** Schema/index/normalization: add social_account UNIQUE + hot-column indexes across all dialects with a drift-checker; **normalize email (lowercase + NFC) in core on write + case-insensitive unique index, with a one-time dedup migration for existing rows**; PG timestamps → TIMESTAMPTZ
  - findings: M31, M34, M46, M33, M35
  - files: `migrations/sqlite/0002_initial_schema.sql`, `src/core/migrations/migrations.ts`, `src/drizzle/schema.ts`, `src/drizzle/pg/schema.ts`
- **[M]** Normalize the rate-limit/lockout account key (lowercase/trim/NFC) and fix the memory store undercount for windows >1h
  - findings: M58, M59
  - files: `src/plugins/rate-limit/index.ts`, `src/plugins/rate-limit/memory-store.ts`
- **[L]** Migration-engine hardening: concurrent-migration lock + version re-read, fix migrateDown target-above-current bound, add a per-migration journal with checksums
  - findings: #31, M44, M45
  - files: `src/core/migrations/engine.ts`

**Exit criteria.** WebAuthn discoverable login and oauth jwks lookup use isNull (one keypair per issuance; usernameless login matches on SQL adapters); non-tx SQLite writes serialize cleanly; the JSON Schema validator and query/param coercion reject the documented edge cases; trailing/double-slash paths always run path-scoped middleware; explainPermission verdict equals checkPermission across a fixture matrix; condition eval fails on unresolved values and pins authoritative identity; the cache never re-caches a revoked grant; social-account UNIQUE + hot-column indexes exist and are drift-checked, email uniqueness is case-insensitive and normalized in core, PG timestamps are TIMESTAMPTZ; rate-limit/lockout keys are normalized and long windows count correctly; the migration engine has a concurrency lock, correct migrateDown bounds, and a checksummed journal.


---

## Phase 6 — Plugin integrity, CLI, testing utilities & CI/release gating (verification gate)

**Objective.** Land the remaining internal plugin-integrity work, fix the crashing CLI commands, harden the test architecture, and gate the release pipeline so the now-frozen API ships with publish jobs that actually run tests/lint and a conformance suite strong enough to protect the frozen DatabaseAdapter contract.


**Why here.** This goes last because it must assert the final shape produced by Phases 1-5 and is what makes 'frozen' provable. The conformance-suite strengthening and the testing peerDep are mildly breaking (they pin what third-party adapters must satisfy and add an install requirement) but only matter once the contracts they protect are frozen.


**Work items:**

- **[M]** Audit-log integrity: chain the hash over all 13 fields seeded by the previous hash, make the chain write race-safe under concurrency, and make CSV export injection-safe
  - findings: M70, M71, M72
  - files: `src/plugins/audit-log/index.ts`
- **[S]** Fix crashing CLI commands (fortress openapi / schemas --format zod pass the endpoint map instead of Object.values) and add a smoke test invoking every command
  - findings: #29
  - files: `bin/fortress.ts`
- **[L · BREAKING]** Harden the adapter conformance suite (all operators/sortBy/update-return/multi-row/boolean round-trip/unknown-operator-throw/cross-dialect duplicate→409); make createTestAdapter run under pure ESM Node and declare better-sqlite3 an optional peerDependency; fix runFortressChecks default + smokeTestAuth docstring
  - findings: #49, #50, M75, M76
  - files: `src/testing/adapter-conformance.test.ts`, `src/testing/index.ts`, `src/testing/checks.ts`, `package.json`
- **[M]** Typecheck examples/ in CI, fix root/JSDoc examples that reference non-existent APIs, and add an exports/tsup/jsr parity test guarding against drift
  - findings: M54, M55, M56
  - files: `package.json`, `tsup.config.ts`, `jsr.json`, `tsconfig.json`
- **[M]** Gate CI/release: publish-npm/publish-jsr require tests + lint to pass; run the pg/testcontainers integration job on the relevant push triggers
  - findings: #25, #51, M39, M78
  - files: `.github/workflows/publish.yml`, `.github/workflows/ci.yml`

**Public-surface changes this phase locks in:**
- better-sqlite3 declared an optional peerDependency and documented as an install requirement for the ./testing subpath
- runAdapterTests conformance contract strengthened — previously-conformant third-party adapters that are subtly broken now fail

**Exit criteria.** Audit-log hash chain covers all fields seeded by the previous hash, concurrent writes don't race, and CSV export is injection-safe; `fortress openapi` and `fortress schemas --format zod` run without TypeError and a smoke test invokes every CLI command; runAdapterTests fails a deliberately-broken adapter and dist/testing imports cleanly under Node ESM; runFortressChecks default config passes and smokeTestAuth matches its docstring; examples/ are typechecked in CI and JSDoc examples reference real APIs; publish jobs cannot ship unless tests + lint pass and the pg integration job runs on the relevant triggers. With this phase green the public API is verifiably lock-in-ready.


---

## Already fixed since the audit (excluded from phases)

- #9
- #15
- M27
- M29

> Verified against current code: login timing-oracle (#9/#15) now runs a real Argon2id verify (commit `4dc8e20`); `verifyAccessToken` rejects missing claims (M27); password NFKC normalization is applied (M29); `jwt.secret`→`jwt.key` rename landed (`18a3289`). **Note:** the admin bootstrap self-grant (#46) is only *partially* fixed — re-bootstrap is gated but the first authenticated caller can still self-grant; it stays in Phase 1.


## Product decisions

### Resolved (2026-06-15)

- **mountFortressOpenAPI (#2/#3): SECURE IT.** Route createAutoHandler through fortress.handleRequest (full auth + RBAC + M7 sanitization). Keep the export.
- **Drizzle MySQL (#17): DROP FOR NOW.** Remove `mysql` from `DrizzleDialect` + docs; clean removal, re-add only if a real implementation lands later.
- **admin adminUserIds (#45): REMOVE.** Delete the dead `adminUserIds` option from AdminConfig + docs rather than implementing it.
- **Tenant-less permission semantics (#14): `tenant_id IS NULL` ONLY.** A tenant-less checkPermission matches only tenant-less bindings; a tenant-scoped grant never works globally. Document the outcome change.
- **npm channel (#33): SUPPORTED.** Commit to npm — add all missing subpaths + tsup entries to match jsr.json, plus a CI parity test.
- **Email normalization (M33): NORMALIZE.** Lowercase + NFC in core on write, case-insensitive unique index, one-time dedup migration for existing rows.

### Resolved (continued)

- **admin bootstrap (#46): ONE-TIME SECRET, OPT-IN.** Route not mounted by default; succeeds only while zero fortress-admins exist AND the caller presents a one-time bootstrap secret (env/config, constant-time compared).
- **Social-login provider tokens (#41): ENCRYPT AT REST.** AES-256-GCM with a config-provided key; throw if persistence is enabled without a key. Docs corrected to match.

### Resolved — Phase 2 contract freeze (2026-06-16)

- **Unified post-auth result (the spine): ONE `AuthResult` + pre-issuance gate + single-use continuation token.** `AuthResult = AuthSuccess | AuthImpersonation | AuthPending`; the pending variant has no token fields (compile-error to read one). Shared `PostAuthGateProvider` runs before `issueTokens` → orphan-refresh bug structurally impossible. `completePendingAuth` atomically consumes the `auth_continuation` token (also closes magic-link/email-verify TOCTOU) and re-runs the gate (magic-link no longer bypasses 2FA).
- **Password min length (M4): RAISE 8→15** (NIST 800-63B-4); enforced on new passwords only, opt back via `passwordPolicy.minLength`.
- **HIBP failure mode (M40): `breachedFailureMode: 'open'|'closed'`, DEFAULT 'open'** + always emit `PASSWORD_BREACH_CHECK_DEGRADED` + log.
- **2FA verify() return shape (M61): full `Promise<AuthResult>`** (narrow via `isSuccess()`; layered factors can return pending); verify() issues the real session.
- **Continuation-token binding: (userId, reason) ONLY** (+ single-use, short-TTL, hash-at-rest); no IP/UA pin, to preserve cross-device 2FA flows.

### Still open

- rawQuery placeholder contract (M17/M36): pick the canonical placeholder style ('?' positional, matching core today, vs. '$1') and enforce it via conformance tests — third-party adapters depend on this. _(Phase 3.)_

## Cross-cutting risks

- Phase 1 ships breaking changes (handleCallback/ProviderProfile/getAuthorizationUrl signatures, updateUser revocation, admin gating, tenant semantics) as a security hotfix. v0.0.x 'no compat burden' makes this acceptable, but consumers on v0.2.8 must be told these are not drop-in.
- The social-login id_token-verification cluster (#1/#4/#42/M65) is the single largest and riskiest work item: it pulls in jose, JWKS fetching/caching, OIDC discovery, and Apple ES256 client-secret JWT generation. Underestimating it stalls Phase 1 and the social-login freeze.
- PluginRequestContext (Phase 3, #22/M42) is a serialization point: if its shape is wrong, both the Express and Hono middleware fixes plus all built-in path-middleware (rate-limit) must be reworked. Design it before adopting it in adapters.
- The 2FA verify() rework (Phase 2) and the magic-link post-auth gate (#38) share the 'shared post-auth gate' helper; if Phase 2 doesn't extract it cleanly, the magic-link fix duplicates logic and the two can diverge.
- Schema/normalization changes (M33 email case-insensitivity, M35 TIMESTAMPTZ, social_account UNIQUE) need data-migration care on existing deployments (dedup before adding a unique index). Deferred to Phase 5 but the policy decision must be made in Phase 1/2 timeframe so the lock isn't retrofitted later.
- Strengthening runAdapterTests (Phase 6, #49) retroactively fails previously-'conformant' third-party adapters; if any are already in the wild this is a coordination cost. Lower risk pre-1.0 but worth flagging.
- Phases 2-4 each touch auth-service.ts / fortress.ts / iam-service.ts from multiple workstreams; the parallel workstreams within a phase must coordinate ownership of these shared files or serialize against each other to avoid merge churn.
- The audit HTML report referenced in the task was removed mid-session; the roadmap relies on /tmp/findings-curated.md and findings.json as the canonical source. If any finding text was lost, the curated list is authoritative.
