# Fortress — Remediation Implementation Plan

Date: 2026-06-05
Source: `docs/independent-code-review-2026-06-05.html`
Scope: Every Critical/High/Medium finding from the independent review **except the tenancy plugin** (C1, C2, H2, H3), which is a known skeleton and out of scope here.

> Tenancy note: the tenancy SQL-identifier injection / fail-open / header-trust findings are deferred. They must be resolved as part of building out the tenancy plugin properly, before it is mounted in any real deployment. Until then, tenancy should be documented as experimental and left unmounted.

---

## How to use this plan

Work top-to-bottom. Each item lists: **the problem**, **the fix**, **files to touch**, **tests to add**, and a rough **effort**. Per project conventions, when each item lands also update `CHANGELOG.md`, the relevant docs (`README.md`, `SECURITY.md`, `docs/`), and `examples/` if behavior changes.

Phases are ordered by risk. Phase 0 unblocks the integrity guarantees the rest of the library assumes, so do it first.

---

## Phase 0 — Critical correctness foundation

### P0.1 — Make the SQLite adapter transaction actually isolate (C3)

**Problem.** `drizzle/adapter.ts:300-315` runs `(drizzle).run(sql\`BEGIN\`)` then `await fn(self)` — it passes the *shared* adapter, not a transaction-scoped one, under a plain (deferred) `BEGIN`. Because the callback `await`s, a second concurrent refresh issues `BEGIN` on the same connection ("cannot start a transaction within a transaction") and a COMMIT/ROLLBACK from one path closes the other's. The compare-and-swap that core refresh rotation, OAuth refresh rotation, and (after P1.1) OAuth code exchange all depend on is therefore not atomic on the default dialect.

**Fix (recommended): serialize + `BEGIN IMMEDIATE`.** better-sqlite3 / bun:sqlite are single-connection and synchronous at the driver level; the only hazard is async interleaving between `BEGIN` and `COMMIT`. Serialize transactions through an async mutex (a promise chain) so at most one transaction is open at a time, and use `BEGIN IMMEDIATE` to take the write lock up front:

```ts
let sqliteTxChain: Promise<unknown> = Promise.resolve();

async transaction<T>(fn) {
  if (dialect === 'sqlite') {
    const run = async () => {
      (drizzle as any).run(sql`BEGIN IMMEDIATE`);
      try { const r = await fn(self); (drizzle as any).run(sql`COMMIT`); return r; }
      catch (e) { (drizzle as any).run(sql`ROLLBACK`); throw e; }
    };
    const result = sqliteTxChain.then(run, run); // run regardless of prior outcome
    sqliteTxChain = result.catch(() => {});       // keep the chain alive on error
    return result;
  }
  // Postgres/MySQL branch unchanged (already correct).
}
```

This keeps the existing CAS logic correct on SQLite without rewriting callers. Document clearly that the SQLite adapter serializes write transactions (acceptable: SQLite is single-writer anyway).

**Alternative (if a real tx-scoped adapter is wanted):** build a tx adapter over a dedicated connection/savepoint and pass it to `fn` instead of `self`. More work; only needed if you want true concurrent SQLite transactions, which the engine doesn't provide anyway.

**Files:** `src/drizzle/adapter.ts`.

**Tests:** in `src/drizzle/adapter.test.ts` add a concurrency test: fire two `transaction()` calls that each read-modify-write the same row; assert exactly one observes the pre-state and the result is consistent (no "cannot start a transaction within a transaction" error). Add the concurrent-refresh tests the roadmap already lists (`auth-service` refresh + `oauth` refresh: two racing refreshes, exactly one succeeds, family revoked on the loser's replay) and ensure they run against the SQLite adapter.

**Effort:** S–M (small code, careful tests).

---

## Phase 1 — High-severity security gaps

### P1.1 — Make OAuth authorization-code exchange single-use under concurrency (H1)

**Problem.** `oauth/index.ts:607-643` does read → `if (authCode.usedAt)` → unconditional `update` on `id`. No `usedAt IS NULL` guard, no transaction. Two concurrent exchanges of the same code both mint tokens.

**Fix.** Mirror the refresh-rotation pattern already in this file: wrap lookup + claim + issuance in `ctx.db.transaction`, and make "mark used" a conditional update that returns whether it claimed the row:

```ts
return ctx.db.transaction(async (tx) => {
  const authCode = await tx.findOne({ model: 'oauth_authorization_code', where: [{ field: 'code', operator: '=', value: codeHash }] });
  // ...existing validity / client / redirect_uri / PKCE checks...
  const claimed = await tx.update({
    model: 'oauth_authorization_code',
    where: [
      { field: 'id', operator: '=', value: authCode.id },
      { field: 'usedAt', operator: 'isNull', value: null },
    ],
    data: { usedAt: new Date() },
  });
  if (!claimed) throw Errors.oauth('invalid_grant', 'Authorization code already used');
  // ...issue tokens inside the same tx...
});
```

Depends on P0.1 for the SQLite branch to be sound. Stronger follow-up (RFC 6749 §4.1.2): on detecting reuse of an already-used code, revoke the access/refresh tokens previously issued from it. Track this as a stretch goal.

> Confirm `update` semantics: the CAS relies on the conditional `update` returning falsy when zero rows match. Verify `adapter.ts` `update` returns `null` for no-match (the review flagged it only reads `row[0]` of `.returning()`); if it can't distinguish "no rows" reliably, fix `update` to surface affected-row count first. This also benefits the existing refresh CAS.

**Files:** `src/plugins/oauth/index.ts`; possibly `src/drizzle/adapter.ts` (update row-count semantics).

**Tests:** `src/plugins/oauth/oauth.test.ts` — two concurrent `exchangeCode` calls with the same code; exactly one returns tokens, the other gets `invalid_grant`.

**Effort:** M.

---

### P1.2 — OAuth consent-flow ownership / IDOR (H6)

**Problem.** `oauth_pending_flow` (model at `oauth/index.ts:196-207`) has no `userId` and is keyed by a sequential `serial`. `handleGetFlow` returns another user's `state` (the RP's CSRF token); approve/deny act on arbitrary flows. Gated only by `security:['bearer']`.

**Fix.**
1. Add `userId` to the `oauth_pending_flow` model and bind it when the user authenticates / reaches consent (set from `context.userId`).
2. In `handleGetFlow`, `handleApproveFlow`, `handleDenyFlow`, after loading the flow assert `flow.userId === context.userId`, else `404` (not 403 — don't confirm existence).
3. Replace the sequential `serial` flow id with an opaque random token (same generator used for codes/tokens), so flows aren't enumerable.

**Files:** `src/plugins/oauth/index.ts`; `src/drizzle/schema.ts` + `src/drizzle/pg/schema.ts` (add column / change id type — coordinate with migration notes).

**Tests:** user A creates a flow; user B's get/approve/deny all 404. Enumeration test: guessing adjacent ids fails.

**Effort:** M (touches schema → needs a migration note).

---

### P1.3 — Enforce PKCE at code mint + exchange for public clients (H7)

**Problem.** PKCE is enforced only in the opt-in authorize endpoint, not in `createAuthorizationCode` (`oauth/index.ts:509-555`), which is reachable via the programmatic/consent path. At exchange, verification is skipped entirely when the code has no challenge (`if (authCode.codeChallenge && authCode.codeChallengeMethod)` at `:624`).

**Fix.**
1. In `createAuthorizationCode`, look up the client; if it's public (`tokenEndpointAuthMethod === 'none'`) — or generally unless `allowNonPkceConfidentialClients` — require `codeChallenge` present and `codeChallengeMethod === 'S256'`, else reject.
2. In `exchangeCode`, if the client is public, treat a missing `authCode.codeChallenge` as `invalid_grant` rather than skipping verification.

**Files:** `src/plugins/oauth/index.ts`.

**Tests:** public client minting a code without a challenge is rejected at authorize *and* at the programmatic path; a public-client code with no challenge can't be exchanged.

**Effort:** S–M.

---

### P1.4 — Registration account-enumeration oracle (H8)

**Problem.** `createUser` (`auth-service.ts:564-570`) throws `409 "A user with this email already exists"` on the public `security('none')` register route — a direct enumeration oracle.

**Fix (pick one, document the choice):**
- **Preferred:** return a generic 200/202 "if this email is new, you'll receive a verification email" and, when the email already exists, send a "you already have an account" email instead of a 409. Requires the email-verification plugin path.
- **Minimum:** keep the 409 but document it as an accepted tradeoff in `SECURITY.md`, and make sure rate-limiting covers the register route to slow bulk enumeration.

Note this interacts with M3 (disabled-account enumeration on login) — fix them together for a consistent "no oracle" story.

**Files:** `src/core/auth/auth-service.ts`, `src/core/auth/auth-endpoints.ts`, possibly `src/plugins/email-verification/index.ts`; `SECURITY.md`.

**Tests:** register with an existing email returns the same response shape/status as a fresh email (preferred path).

**Effort:** M (preferred) / S (documented-minimum).

---

### P1.5 — Wire CSRF protection into the pipeline by default (H5)

**Problem.** `mountFortress` / `createSvelteKitHandle` route straight into `handleRequest`, which has no CSRF check; `createCsrfMiddleware` exists but is never installed. SvelteKit's handle returns before `resolve()`, deliberately skipping SvelteKit's own origin CSRF with no replacement. Cookie-authed state-changing routes are cross-site reachable.

**Fix.** Apply an origin / custom-header CSRF check inside the request pipeline for unsafe methods (`POST/PUT/PATCH/DELETE`) on **cookie-authenticated** routes, on by default with an opt-out for pure bearer/API deployments:
- The check only applies when auth was resolved from a cookie (bearer/API-key requests are CSRF-immune and should skip it).
- Reject when `Sec-Fetch-Site: cross-site`, or when the required custom header / double-submit token is absent.
- Tighten the existing middleware's `skipPaths` from `startsWith` to segment-boundary matching, and consider rejecting `same-site` for single-host deployments (see L-tier).
- For the SvelteKit adapter, run the same check before short-circuiting `resolve()` so the bypass is replaced, not just removed.

**Files:** `src/core/http/handle-request.ts` (or a shared pre-dispatch step), `src/hono/handle.ts`, `src/sveltekit/handle.ts`, `src/hono/middleware/csrf.ts`; config flag in `src/core/config.ts`.

**Tests:** cross-site POST to `/auth/logout` / `/auth/refresh` with cookie auth is rejected; same request with a valid CSRF header passes; bearer-auth POST is unaffected.

**Effort:** M.

---

### P1.6 — Per-request state for the data-isolation plugin (H4)

> First verify whether `data-isolation` is actually mounted/used (like tenancy, it may be skeleton). If it's not wired anywhere, downgrade to "fix before mounting" and move it to the backlog. If it is used, this is a real cross-request data-leak and stays in Phase 1.

**Problem.** `data-isolation/index.ts:30-31` declares module-level `bypassedScopes`/`bypassAll`, mutated by `unscoped()`/`withoutScope()` (`:104`, `:90`) and read by `scopeRules` (`:58`). Across concurrent requests, one request's `unscoped()` window disables isolation for every other in-flight request.

**Fix.** Replace the module globals with `AsyncLocalStorage`:

```ts
import { AsyncLocalStorage } from 'node:async_hooks';
const bypassStore = new AsyncLocalStorage<{ all: boolean; scopes: Set<string> }>();
// scopeRules reads bypassStore.getStore(); unscoped/withoutScope run fn inside bypassStore.run(...)
```

`scopeRules` treats a missing store as "no bypass". Confirm the runtime targets support `node:async_hooks` (Node yes; for edge/Workers add a fallback or document the limitation).

**Files:** `src/plugins/data-isolation/index.ts`.

**Tests:** interleave two async flows — A inside `unscoped()` awaiting, B calling `scopeRules` concurrently — and assert B still gets its scope filters. Add a test that `withoutScope` only bypasses the named scope for the calling flow.

**Effort:** S–M.

---

## Phase 2 — Medium: quick, high-value auth/JWT fixes

### P2.1 — `await validatePassword` in `updateUser`, validate unconditionally (M1)

**Problem.** `auth-service.ts:864-866`: `validatePassword(...)` is async (can do an HIBP check) but not awaited, so its rejection is an unhandled rejection and the weak/breached password is hashed and saved anyway. Also it's only called when `config.passwordPolicy` is set, while `createUser` validates unconditionally.

**Fix.** `await validatePassword(data.password, config.passwordPolicy)` and align the conditional logic with `createUser` (validate whenever a policy applies; apply the same default behavior in both paths).

**Files:** `src/core/auth/auth-service.ts`. **Tests:** `updateUser` with a breached/weak password rejects and does not persist. **Effort:** S.

---

### P2.2 — Strip reserved/`act` claims from `customClaims` (M2)

**Problem.** `jwt.ts:43-49` spreads `...(claims.customClaims ?? {})` last; the public `signToken` and plugin `enrichTokenClaims` flow arbitrary claims through, letting a caller set/override `act`, `sub`, `groups`, `subjectType`, etc. — including a forged impersonation marker.

**Fix.** Define a reserved-key denylist (`sub, iss, iat, exp, nbf, aud, act, groups, subjectType, name`) and strip those keys from `customClaims` (and from `enrichTokenClaims` output) before spreading. Throw or warn-and-drop on collision (throw in dev, drop in prod).

**Files:** `src/core/auth/jwt.ts`, `src/core/auth/auth-service.ts`. **Tests:** a `customClaims` containing `act`/`sub` does not appear in the verified token; impersonation `act` can only be set by the impersonate path. **Effort:** S.

---

### P2.3 — Constant-time disabled-account login (M3)

**Problem.** `auth-service.ts:293-295` returns a distinct `"Account is disabled"` message and skips the Argon2 verify, leaking account existence by message and timing.

**Fix.** For an inactive user, still run `hasher.verify` against the stored hash (to equalize timing) and return the generic `Invalid credentials` message. Optionally surface "disabled" only after a *correct* password, if product wants that signal — but default to the generic path.

**Files:** `src/core/auth/auth-service.ts`. **Tests:** timing-insensitive test asserting identical response/message for disabled vs wrong-password. **Effort:** S.

---

### P2.4 — Bound impersonation token lifetime (M4)

**Problem.** `auth-service.ts:745` uses caller-supplied `options?.expirySeconds ?? 3600` with no ceiling; the endpoint accepts `expirySeconds` from the body. An admin can mint a years-long impersonation token.

**Fix.** Clamp to a hard maximum (e.g. `Math.min(requested, MAX_IMPERSONATION_TTL)` with `MAX_IMPERSONATION_TTL` ≤ access-token expiry or 3600s), configurable but capped. While here, add the Low-tier audit event (see P4) for impersonation.

**Files:** `src/core/auth/auth-service.ts`, `src/core/auth/auth-endpoints.ts`, config. **Tests:** request with an oversized expiry is clamped. **Effort:** S.

---

### P2.5 — Pin JWT verification algorithm + issuer (M5)

**Problem.** `jwt.ts:69` calls `jwtVerify(token, key)` with no `algorithms` allowlist and no `issuer` check; safety currently relies on jose's key-type defaulting.

**Fix.** `jwtVerify(token, key, { algorithms: ['HS256'], issuer: resolved.issuer })`. Validate `issuer` against the configured value. (Defense-in-depth even though jose rejects `alg:none` by default.) Optionally add a config check that rejects HS256 secrets shorter than 32 bytes.

**Files:** `src/core/auth/jwt.ts`, possibly `src/core/config.ts`. **Tests:** token signed with a different alg/issuer is rejected. **Effort:** S.

---

## Phase 3 — Medium: remaining correctness/hardening

### P3.1 — `deleteRole` cache invalidation (M6)
`iam-service.ts:333-347` deletes a role but never calls `cache?.invalidateAll()`, leaving stale ALLOW decisions for group members up to TTL. Add `invalidateAll()` (a deleted role can affect any subject via group bindings). Test: deleting a role removes cached access immediately. **Effort:** S.

### P3.2 — Harden `/iam/check` against caller-supplied context (M7)
`dispatch.ts:459-474` passes attacker-controlled `subject`, `resource`, `action`, and full `context` straight into `checkPermission`, making it an ABAC oracle. Strip `credentialScopes` from caller context server-side; either require an elevated permission for cross-subject checks or refuse caller-supplied `resource.*`/`user.*` context unless the caller is elevated. Document `/iam/check` as an admin diagnostic. Test: caller can't satisfy an ownership condition by supplying `resource.ownerId`. **Effort:** S–M.

### P3.3 — Partial unique index for `permission.conditions IS NULL` (M8)
`drizzle/{schema,pg/schema}.ts:88-90` — the plain `unique()` over `(resource, action, effect, conditions)` doesn't prevent duplicates when `conditions` is NULL, and `findOrCreatePermission` dedupe is TOCTOU. Add the same partial-index pattern used for bindings (`uniq_permission_no_conditions WHERE conditions IS NULL` + `uniq_permission_with_conditions WHERE conditions IS NOT NULL`) and normalize JSON before storing (key-order/whitespace sensitive). Coordinate with migration + duplicate-cleanup notes. Test: concurrent `findOrCreatePermission` yields one row. **Effort:** M (schema + migration).

### P3.4 — Per-client `grantTypes` enforcement (M9)
`oauth/index.ts` — only `clientCredentialsGrant` checks the client's registered grant types. Add the same check in `exchangeCode` (`authorization_code`) and `refreshTokenGrant` (`refresh_token`), rejecting with `unauthorized_client`. Also mirror the public-client "must not present a client_secret" check from `exchangeCode` into `refreshTokenGrant`. Test: a client not registered for a grant is rejected. **Effort:** S.

### P3.5 — Constant-time PKCE verifier compare (M10)
`pkce.ts:32-33` uses `===`. Switch to a constant-time compare over the base64url challenge (reuse `timingSafeEqualHex` by hex-encoding both, or a length-safe constant-time equal). While here, validate `code_verifier` against `^[A-Za-z0-9\-._~]{43,128}$` (RFC 7636 §4.1) before computing the challenge. **Effort:** S.

### P3.6 — Decouple `bearerKind:'oauth'` flag (M11)
`handle-request.ts:106-196` — one flag disables principal resolution, RBAC, *and* validation. Split it (e.g. `selfAuth` vs `formBody`) so skipping RBAC doesn't silently skip validation, and add a startup assertion that any handler with self-auth is on a known protocol-route allowlist. No current live bypass; this is latent-risk reduction. **Effort:** M.

### P3.7 — Cookie/bearer precedence + `Secure` default (M12)
`token-extraction.ts:25-35` prefers the cookie over `Authorization: Bearer` (shadowing risk on shared cookie domains). Prefer the `Authorization` header when present, or only read the cookie when no `Authorization` header exists. In `config.ts:92-108`, default `secure` to `true` with an explicit opt-out for local HTTP dev, rather than inferring from `NODE_ENV === 'production'` (many prod runtimes don't set it), and ensure `__Host-` is used whenever `secure` is on. **Effort:** S–M. (Note: changes default cookie behavior — call out in CHANGELOG.)

---

## Phase 4 — Low: hardening backlog

- **HIBP fail-open is silent** (`password-policy.ts:79-94`): log at warn level when the breach check can't reach the API so operators notice the control is down.
- **`revokeAllOtherSessions` non-atomic N+1** (`auth-service.ts:678-696`): replace the read-then-loop with a single `UPDATE ... WHERE userId=? AND id!=? AND isRevoked=false`.
- **`getNestedValue` lacks `__proto__`/`constructor` guard** (`permission-evaluator.ts:169-180`): skip those keys (read-only today, but cheap to harden).
- **`neq`-on-undefined condition footgun** (`permission-evaluator.ts:102-115`): document the semantics; consider treating a missing field in a condition as non-match.
- **CSRF `skipPaths` prefix match** (`csrf.ts:39`): segment-boundary matching (folded into P1.5).
- **`none` + `permission` metadata**: add a startup assertion that `security:['none']` and a `permission` field are mutually exclusive (fail-fast on misconfig).
- **Impersonation auditing**: emit an `AuthEvent` (admin id, target id, reason) from `impersonate` (folded into P2.4).
- **OIDC refresh `id_token`**: when a refreshed grant included `openid`, re-issue an `id_token` (spec conformance for strict RPs).
- **UA-only refresh fingerprint** (`auth-service.ts:219-222`): document the false-positive risk of `validateRefreshFingerprint` on UA changes (browser auto-update); consider a more stable signal.

---

## Suggested sequencing & milestones

1. **Milestone A (integrity):** P0.1 → P1.1. Lands atomic transactions + single-use auth codes. Gate: concurrency tests green on SQLite and Postgres.
2. **Milestone B (authz/exposure):** P1.2, P1.3, P1.4, P1.5, P1.6. Closes the IDOR, PKCE, enumeration, CSRF, and cross-request-leak gaps.
3. **Milestone C (auth quick wins):** P2.1–P2.5. Small, high-value; can ship as one PR.
4. **Milestone D (correctness/hardening):** P3.x, then the P4 backlog.

Cross-cutting for every milestone: update `CHANGELOG.md`, `SECURITY.md`, `README.md`, affected `docs/`, and `examples/`; add a regression test for each fix (the roadmap's §4 list plus the new tests above); and note any schema change (P1.2, P3.3, P3.7) in a migration guide with duplicate-cleanup SQL where relevant.
