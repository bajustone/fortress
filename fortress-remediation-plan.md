# Fortress Lock-In Remediation Roadmap (v0.0.x → freezable API)

_Derived from `fortress-audit-report.html` (audit @ v0.2.8) — generated 2026-06-15._


Six phases on a lock-in spine with a security hotfix bolted to the front. Phase 1 is a deploy-safety hotfix: every remaining critical auth-bypass / account-takeover and the highs that make a running deployment exploitable, shipped regardless of API freeze (breaking changes accepted because security trumps stability and these fixes also happen to pin the social-login surface). Phases 2-4 are the freeze spine: front-load every finding whose fix is FORCED to change a public surface, sequenced subsystem-by-subsystem (auth-core/2FA contracts → framework & DatabaseAdapter contracts → packaging/observability/IAM-policy/admin) so each subsystem can be frozen the moment its breaking changes land, each phase fanned out into disjoint-file parallel workstreams. Phases 5-6 are internal-only correctness (NULL-query bugs, SQLite serialization, validation, schema/migration hardening, plugin integrity) and the verification gate (conformance + CI publish-gate) that makes "frozen" provable. Findings are grouped by cluster so duplicates collapse into single work items.


## ⚠️ Due-diligence update — 2026-06-16

_This roadmap was written 2026-06-15. **Five commit clusters plus uncommitted work landed after it** and are **not** reflected in the phase bodies below. This section is the authoritative status overlay; the original phase sections remain the spec for everything still outstanding. Everything here was verified against the **current code** (not commit messages) in a full re-audit, including adversarial re-checks of every "done" claim._

### What landed since the plan was written

| Commit | What it did | Plan impact |
|--------|-------------|-------------|
| `be1753f` | **Executed almost all of Phase 1** — social-login id_token verify (jose/JWKS), Apple ES256, OAuth state, admin bootstrap, TOTP single-use, updateUser revocation, lockout, data-isolation, tenant-`IS NULL`, AES-GCM token encryption | **Phase 1 implementation DONE** (verification tests outstanding) |
| `2edf217` | Adopted `@bajustone/fetcher` for schema validation; **deleted `src/core/json-schema-validator.ts`**; new `./fetcher` subpath; Node floor → `>=20.19.0` | **Phase 5 M15 obsolete**; new breaking 422/`oneOf` surfaces; export/engine deltas |
| `8249a2b` | New `src/core/http/outbound.ts`; routed OAuth/OIDC/GitHub/HIBP through a shared client with timeouts | **Phase 2 F7/M40 now PARTIAL** (timeout half done) |
| `0b20b53` | **Subject IDs are strings everywhere** — a NEW lock-in fix, not in any phase | Touches Phase 2/3/4 files; provenance corrections |
| `39f1643` + **uncommitted** | Webhook plugin split into modules + hardening: 5 new columns, circuit breaker, idempotency, persistent outbox | **Phase 1 #48 DONE but re-architected**; new contract still undocumented |

> **These are deliberate, separately-tracked workstreams**, not random drift. The fetcher swap follows `scratch/fetcher-adoption-plan-2026-06-16.md`; the webhook rewrite is a full "v1" rebuild per `scratch/webhook-v1-plan-2026-06-16.md` whose **Increment 4 already owns the docs/examples gap** flagged below. They are "out of plan" only relative to *this* lock-in roadmap. What follows is how they move the lock-in needle.

### Revised phase status

- **Phase 1 — IMPLEMENTATION COMPLETE; verification tests outstanding.** All 13 work items are coded and correct in the current tree. ⚠️ Three are **implemented but not test-proven** — do **not** treat Phase 1's exit criteria as met until these land:
  - **#5/#7/M68 (verified-email linking):** guards correct (`social-login/index.ts:513,518-519`) but **zero tests** exercise `email_verified:false` blocking or the `isActive` guard. **+ latent Microsoft bypass** (watch-outs).
  - **#34/#35/M1/M57 (lockout):** CAS/reset/normalize correct, but the window-expiry-reset branch, "cannot be re-locked by one failure", and identifier-normalization (M1) have **no tests**.
  - **#45/#46 (admin bootstrap):** the self-grant gate the old footnote flagged as "only partially fixed" **now exists and is correct** — but there is **no test asserting a second bootstrap returns 403**, and the count-gate→insert is **non-transactional** (low sev; both callers hold the one-time secret).
  - **Action:** add those three regression tests, then move Phase 1 into "Already fixed." #46 is implemented; its footnote is resolved-pending-test.
- **Phase 2 — NOT STARTED except F7 (password), now PARTIAL.** `8249a2b` delivered the HIBP **timeout** (`outbound.ts`, 6 s). Still missing: `breachedFailureMode` + `PASSWORD_BREACH_CHECK_DEGRADED` (M40 — **0 grep hits**) and the **bounded HIBP cache** (M28 — still an unbounded `Map`). F9 (wire regen) must **rebase onto `auth-endpoints.ts` as rewritten by `0b20b53`**.
- **Phase 3 — NOT STARTED; two corrections.** **PluginRequestContext already exists** in core (`plugin-middleware.ts:28`) → narrow item 1 from "define" to "**adopt** in the Express+Hono slots." The Drizzle-contract item now **overlaps `0b20b53`'s `stringifyIds`/`isIdField`** on the same read path — design empty-`where`-throw + rawQuery canonicalization to coexist, fold in the `isIdField` false-positive + the undocumented write-path coercion (watch-outs), and add `src/testing/adapter-conformance.test.ts` to its file list. Re-target file pointers: Express RBAC + form/CSRF logic lives in `src/express/{middleware,handle}.ts`, not `index.ts`.
- **Phase 4 — NOT STARTED; export-parity is a LIVE ship bug.** `package.json` exports = **9 keys**, `jsr.json` = **29**: `./express` (already on disk), `./drizzle/pg`, and **all `./plugins/*`** are missing from npm — any npm consumer of a plugin subpath is **broken today** (also needs matching `tsup.config.ts` entries or the dist subpaths won't exist). Add `./fetcher` to the parity allowlist. Reframe the IamEvent item: `IamEvent.eventType` is a **free-form string, not a closed union** → "emit the 4 missing events + `deleteGroup` cascade + add them to the audit-log eventType allowlist." Drop the non-existent `applyPolicyPlanWithDb` reference in the policy item; note `applyResourceOps` does a `node:fs` disk write that breaks in workerd/Deno-no-fs.
- **Phase 5 — NOT STARTED; M15 obsolete, M16 now HIGH.** `2edf217` deleted the file M15 targets; validation now delegates to fetcher's `fromJSONSchema` (already enforces const/additionalProperties/allOf/min/max/discriminator, prototype-pollution-safe). **Re-scope M15** to its one surviving gap: **`$ref` bodies are present-but-unconstrained** (`schema-builder.ts:35` resolves refs to `{}`). **M16 is fully unaddressed and now HIGH:** `validation.ts:52,58` still does `Number('')→0`, `Number('0x1f')→31`, `Number('1e3')→1000`, and that coerced value now flows into a **stricter** validator. M24's cache lives in **`permission-cache.ts`**, not `iam-service.ts`. Schema item: **social_account UNIQUE already done** (be1753f) → narrow to email-normalization + TIMESTAMPTZ + hot-column indexes.
- **Phase 6 — NOT STARTED; two sweeps to add.** Audit-log (M70) must also fix the **string-id inconsistency** `0b20b53` left: TS interface `id:string` vs the plugin model field still `type:'number'`, and `getLastHash` orders by `id DESC` assuming numeric-monotonic ids (wrong link with string ids). Conformance (M76) must add a **runtime** string-id assertion (`typeof id === 'string'`) — today only the TS generic changed, so a numeric-id third-party adapter still passes. CLI #29: fix is `Object.values()` on the **endpoint maps** only (component-schema object-spreads already work).

### Watch-outs introduced by the out-of-plan work (NEW — not in any phase yet)

| Sev | Watch-out | Where | Action |
|-----|-----------|-------|--------|
| **HIGH** | M16 coercion bypass **amplified** — `Number('')→0`, hex/exponent params pass a now-stricter validator | `core/validation.ts:48-62` | Fix in Phase 5 M16; no longer "just an edge case" |
| **MED** | Microsoft provider sets `emailVerified=true` when the claim is absent → unconditional by-email auto-link | `providers/microsoft.ts:19` | Fail-closed like the other 6, or document as a known per-provider trust assumption |
| **MED** | Breaking **422 issue-path** shape change (`['email']` vs `[{key:'email'}]`) shipped ungated | `core/validation.ts:119-123` | Add to the Phase 4 error-envelope freeze checklist + CHANGELOG migration note |
| **MED** | `oneOf` silently changed exactly-one → at-least-one (union) — validation-tightness regression | `core/schema-builder.ts:411` | Audit `oneOf()` sites; migrate exclusive ones to `discriminatedUnion()` |
| **MED** | Write-path string-id coercion is **driver-dependent & undocumented** (no parse-back; relies on pg coercing string→int) | `drizzle/adapter.ts:78-107` | Pin + document in the Phase 3 DatabaseAdapter contract |
| **MED** | Conformance suite doesn't **runtime-enforce** the new string-id contract (only TS generics changed) | `testing/adapter-conformance.test.ts:26` | Add runtime assertion (Phase 6 M76) |
| **MED** | New webhook circuit-breaker / idempotency / 5-column contract shipped with **no docs/CHANGELOG/examples** | `docs/plugins/webhook.md` | Document + freeze before lock-in (violates standing sync rule) |
| **LOW** | `response_body` persists ≤2 KB of receiver output → can capture receiver secrets/PII, emitted unredacted to `onDeliveryFailed` | `webhook/delivery.ts:115-123` | Redact / flag-gate / strip from the DLQ hook payload |
| **LOW** | `isIdField` regex `/[a-z]Id$/` will silently stringify any future **numeric** `*Id` column | `drizzle/adapter.ts:133-168` | Document "any `*Id` column is an opaque string id"; optional drift-check |
| **LOW** | Webhook timeout default silently rose 5000→10000 ms; full response buffered before the 2 KB slice | `webhook/delivery.ts:53-65,95` | Note in #48 / CHANGELOG; consider a streaming read cap |
| **LOW** | Degraded OIDC discovery can disable id_token JWKS verification for providers without a static `jwksUri` | `social-login/index.ts:182-211` | Add a fail-closed regression test |
| **LOW** | ReDoS-safety/format-correctness now depend entirely on `@bajustone/fetcher ^1.0.0` (unpinned); no test pins the lifted patterns | `schema-builder.ts:362-385` | Pin fetcher or snapshot the patterns |
| **LOW** | Node engine floor bumped to `>=20.19.0` (fetcher) — CI matrix / docs / jsr `runtimeCompat` must match | `package.json:8-10` | Doc/CI sync |

### New work items to fold into the phases

- **Phase 4 + 6 — freeze & document the webhook contract** (= **Increment 4 of `scratch/webhook-v1-plan-2026-06-16.md`**, already owned but not yet done): the 5 columns (`consecutive_failures`, `deactivated_reason`, `idempotency_key`, `response_body`, `error_kind`), `maxConsecutiveFailures` (15), `permanentStatuses` ([404,410,421]) auto-deactivation, the `deactivatedReason` taxonomy, the `error_kind` enum, and `(endpointId, idempotencyKey)` dedup. Update `docs/plugins/webhook.md`, CHANGELOG, README, examples. **Note:** the uncommitted webhook changes have **not** been run through the pg/testcontainers integration suite — do that before publish (the memory flags this).
- **Phase 4 freeze checklist:** capture the **422 issue-path** + **`oneOf` union** breaking changes with a documented migration window before the validation/error surface is frozen.
- **Phase 5 M16:** coercion fix + regression test (reject empty-string, whitespace, hex, exponent, Infinity/NaN).
- **Phase 6 M76:** runtime string-id conformance assertion; webhook tests for the parse try/catch + circuit-breaker + idempotency dedup; the three Phase-1 verification tests above.
- **Provenance corrections** (see "Already fixed" register): **M27** landed in `0b20b53` (not `4dc8e20`); **M29** NFKC was wired via `normalizePasswordInput` in `0b20b53`; record **subject-IDs-as-strings (`0b20b53`)** as the resolution of the 2026-06-13 numeric-id lock-in.
- **Process:** the PG-schema-sync gotcha is now **7 locations**, not 5 — it also includes `src/drizzle/pg/pg.integration-test.ts` and `src/drizzle/pg/adapter.integration-test.ts` inline DDL.


## Phases at a glance

| # | Phase | Work items | Breaking surface | Releasable on its own | Status (2026-06-16) |
|---|-------|-----------|------------------|------------------------|---------------------|
| 1 | Security hotfix: make any deployment safe | 13 | 8 breaking | Yes — security patch | **Implemented (be1753f)** — 3 verification tests outstanding |
| 2 | Auth-core & 2FA behavioral-contract freeze | 7 | 5 breaking | Freeze gate | Not started (F7 password **partial**: timeout done, M40/M28 left) |
| 3 | Framework-adapter & DatabaseAdapter contract freeze | 5 | 5 breaking | Freeze gate | Not started (PluginRequestContext already exists; file re-targets) |
| 4 | Packaging, observability & IAM/policy public-API freeze | 9 | 9 breaking | Freeze gate | Not started (**export parity is a live npm ship bug**) |
| 5 | Internal correctness: data-access, validation, IAM internals, schema & migrations | 8 | 0 breaking | No | Not started (**M15 obsolete**, M16 now HIGH, schema item narrowed) |
| 6 | Plugin integrity, CLI, testing utilities & CI/release gating (verification gate) | 5 | 1 breaking | No (verification gate) | Not started (+2 string-id sweeps) |

---

## Phase 1 — Security hotfix: make any deployment safe

> **[2026-06-16 status] IMPLEMENTED by `be1753f`** (+ `8249a2b` HTTP routing, `39f1643`/uncommitted webhook rework). All 13 work items verified present and correct in the current tree. **Outstanding before exit criteria are met:** regression tests for #5/#7 (email_verified=false blocked + isActive guard), #34/#35 (window-expiry reset + cannot-re-lock + M1 normalization), and #46 (second-bootstrap→403). Plus the Microsoft-mapper watch-out below. See the Due-diligence update for details.

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

> **[2026-06-16 status] NOT STARTED**, except **F7 (password) is PARTIAL**: `8249a2b` added the HIBP request timeout via `src/core/http/outbound.ts` (6 s, never-throws fail-open). Still to do in F7: `breachedFailureMode: 'open'|'closed'` + `PASSWORD_BREACH_CHECK_DEGRADED` (M40 — 0 grep hits) and the bounded HIBP cache (M28 — still an unbounded `Map`). **F9 (wire regen) must rebase onto `auth-endpoints.ts` as already rewritten by `0b20b53`.** `default password min length 8→15` (M4) is still not applied.

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

> **[2026-06-16 status] NOT STARTED.** Export parity (#33) is a **live npm ship bug today**: `package.json` exports = 9 keys vs `jsr.json` = 29 — `./express` (on disk), `./drizzle/pg`, all `./plugins/*` are unreachable for npm consumers (backfill needs matching `tsup.config.ts` entries too). Add `./fetcher` to the parity allowlist. Reframe the IamEvent item — `IamEvent.eventType` is a free-form string, not a closed union (emit the 4 events + `deleteGroup` cascade + audit-log allowlist). The policy item references a non-existent `applyPolicyPlanWithDb`; `applyResourceOps` also does a `node:fs` disk write that breaks in workerd/Deno. Also fold in the webhook-contract freeze (new columns/breaker/idempotency) + the 422/`oneOf` migration note (see overlay).

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

> **[2026-06-16 status] NOT STARTED**, with two scope changes from `2edf217`: **M15 is OBSOLETE** (its target file `json-schema-validator.ts` was deleted; fetcher's `fromJSONSchema` now enforces const/additionalProperties/allOf/min/max/discriminator — re-scope M15 to just `$ref`-body enforcement in `schema-builder.ts`). **M16 is now HIGH, not low**: `validation.ts:52,58` still coerces `''→0`/hex/exponent and that value now hits a stricter downstream validator. M24's cache is in `permission-cache.ts` (not `iam-service.ts`); the schema/normalization item drops `social_account UNIQUE` (already done by be1753f) and keeps email-normalization + TIMESTAMPTZ + hot-column indexes.

**Objective.** Land the high-impact internal-only correctness fixes that change behavior but force no public-surface change, so they can safely follow the freeze: NULL-query data-access bugs, SQLite concurrency, validation/coercion gaps, path canonicalization, IAM evaluator/cache internals, schema/index/normalization drift, and migration-engine hardening.


**Why here.** None of these breaks a consumer (per the breaking-change classification, all are internal-only logic/SQL/constraint/index fixes), so per the lock-in spine they are deferred behind the gating work. They are still high-value (a per-issuance keypair regen, broken usernameless login, a trailing-slash middleware bypass, unsound condition evaluation) and grouped into disjoint parallel workstreams.


**Work items:**

- **[M]** Fix '= NULL' data-access bugs: webauthn discoverable lookup and oauth jwks active-key lookup → operator:'isNull' (stop per-issuance keypair regen; fix usernameless login); add the documented jwks rotation/grace window
  - findings: #36, #39, M64
  - files: `src/plugins/webauthn/index.ts`, `src/plugins/oauth/jwks.ts`
- **[M]** Serialize all non-transactional SQLite ops through the same async chain so they don't join/rollback with an open transaction
  - findings: #16
  - files: `src/drizzle/adapter.ts`
- **[M]** Harden validation: ~~JSON Schema validator honor const/additionalProperties/allOf/$ref/format~~ (**M15 OBSOLETE** — file deleted by `2edf217`; fetcher's `fromJSONSchema` now enforces all of these except `$ref`. Re-scope to: **pass the OpenAPI components/`$defs` map into `fromJSONSchema` so `ref()` bodies are constrained**, file `src/core/schema-builder.ts`); fix query/param coercion (no empty-string→0, reject hex/exponent numerics) — **M16 still fully live and now HIGH-severity**, file `src/core/validation.ts:48-62`
  - findings: ~~M15~~ ($ref only), M16
  - files: `src/core/schema-builder.ts` ($ref enforcement), `src/core/validation.ts` (M16 coercion)
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
- M27 — _re-credit to `0b20b53` (verifyAccessToken per-claim validation block), NOT `4dc8e20`_
- M29 — _password NFKC wired via `normalizePasswordInput` in `0b20b53`_
- **Numeric-id lock-in (2026-06-13 audit)** — resolved by `0b20b53` "subject IDs are strings everywhere"; `TokenClaims.sub`/`FortressUser.id`/all IAM & plugin ids are now `string`, deleting the `String()`/`Number()` round-trip. _Residual: write-path string→int coercion is driver-dependent + undocumented, and the conformance suite only type-checks (not runtime-checks) the new contract — see Phase 3 / Phase 6 watch-outs._
- **All of Phase 1** (pending the 3 verification tests) — see the Phase 1 status banner.

> Verified against current code: login timing-oracle (#9/#15) now runs a real Argon2id verify (commit `4dc8e20`); `verifyAccessToken` rejects missing claims (M27, landed in `0b20b53`); password NFKC normalization is applied (M29, `0b20b53`); `jwt.secret`→`jwt.key` rename landed (`18a3289`).
>
> **#46 update (2026-06-16):** the admin bootstrap self-grant is now **fully gated** by `be1753f` — bootstrap is opt-in (not mounted by default), requires a one-time secret (constant-time compared) **and** zero existing fortress-admin bindings (`admin/index.ts:996-1003`), so the first authenticated caller can no longer self-grant. The old "only partially fixed" caveat is **resolved**, pending one regression test asserting a second bootstrap returns 403. A non-transactional count-gate→insert window remains (low sev: both racers hold the one-time secret).


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
- **Microsoft `emailVerified` default (NEW 2026-06-16):** `providers/microsoft.ts:19` treats an absent `email_verified` claim as `true`, so every Microsoft login satisfies the #5/#7 verified-email auto-link gate. **Decide:** fail-closed like the other 6 providers, or accept + document it as a known per-provider trust assumption in SECURITY.md. _(Phase 1 follow-up.)_
- **`@bajustone/fetcher` version pin (NEW):** it is depended on as `^1.0.0` and is now the sole source of ReDoS-safe/format-correct patterns + the 422/`oneOf` validation semantics. Decide whether to pin an exact version (and/or snapshot the lifted patterns) before the validation surface is frozen, and whether the re-exported `./fetcher` API is in-scope for the freeze. _(Phase 4/5.)_
- **422 issue-path + `oneOf` migration window (NEW):** both already shipped as breaking runtime changes (`2edf217`). Decide the documented migration note before Phase 4 freezes the error envelope. _(Phase 4.)_
- **Webhook circuit-breaker/idempotency contract (NEW):** the 5 new columns + breaker + idempotency dedup shipped undocumented. Decide the frozen column/enum names + defaults and document them. _(Phase 4/6.)_

## Cross-cutting risks

- Phase 1 ships breaking changes (handleCallback/ProviderProfile/getAuthorizationUrl signatures, updateUser revocation, admin gating, tenant semantics) as a security hotfix. v0.0.x 'no compat burden' makes this acceptable, but consumers on v0.2.8 must be told these are not drop-in.
- The social-login id_token-verification cluster (#1/#4/#42/M65) is the single largest and riskiest work item: it pulls in jose, JWKS fetching/caching, OIDC discovery, and Apple ES256 client-secret JWT generation. Underestimating it stalls Phase 1 and the social-login freeze.
- PluginRequestContext (Phase 3, #22/M42) is a serialization point: if its shape is wrong, both the Express and Hono middleware fixes plus all built-in path-middleware (rate-limit) must be reworked. Design it before adopting it in adapters.
- The 2FA verify() rework (Phase 2) and the magic-link post-auth gate (#38) share the 'shared post-auth gate' helper; if Phase 2 doesn't extract it cleanly, the magic-link fix duplicates logic and the two can diverge.
- Schema/normalization changes (M33 email case-insensitivity, M35 TIMESTAMPTZ, social_account UNIQUE) need data-migration care on existing deployments (dedup before adding a unique index). Deferred to Phase 5 but the policy decision must be made in Phase 1/2 timeframe so the lock isn't retrofitted later.
- Strengthening runAdapterTests (Phase 6, #49) retroactively fails previously-'conformant' third-party adapters; if any are already in the wild this is a coordination cost. Lower risk pre-1.0 but worth flagging.
- Phases 2-4 each touch auth-service.ts / fortress.ts / iam-service.ts from multiple workstreams; the parallel workstreams within a phase must coordinate ownership of these shared files or serialize against each other to avoid merge churn.
- The audit HTML report referenced in the task was removed mid-session; the roadmap relies on /tmp/findings-curated.md and findings.json as the canonical source. If any finding text was lost, the curated list is authoritative.
- **(NEW 2026-06-16) The PG-schema-sync gotcha is now 7 locations, not 5:** the two drizzle schemas, both `migrations.ts` blocks (sqlite + pg), both `migrations/{pg,sqlite}` SQL files, **and** the inline DDL in `src/drizzle/pg/pg.integration-test.ts` **plus** `src/drizzle/pg/adapter.integration-test.ts`. Any Phase 2 (`auth_continuation` + refresh v3) or Phase 5 (TIMESTAMPTZ, indexes, migration-journal table) schema change must hit all 7. The uncommitted webhook columns already exercised this.
- **(NEW) Out-of-plan work shipped three ungated breaking runtime changes** the freeze must reconcile: the 422 issue-path shape, `oneOf`→union semantics (`2edf217`), and the webhook re-architecture/column contract (uncommitted). They are breaking under the no-compat 0.x policy but were not part of any phase; the Phase 4 freeze checklist must explicitly absorb them so a consumer-visible shape isn't locked without a migration note.
- **(NEW) `0b20b53` rewrote files three later phases plan to touch** (`auth-endpoints.ts` → Phase 2 F9, `dispatch.ts` → Phase 4 #11, `drizzle/adapter.ts` → Phase 3 contract). Those phase items must rebase onto the new code, not the pre-`0b20b53` context the plan was written against, or the diffs will be stale.
