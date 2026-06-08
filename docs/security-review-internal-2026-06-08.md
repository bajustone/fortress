# Fortress internal adversarial security review — 2026-06-08

Companion to the review packet `docs/security-review-2026-06-08.md` and the
threat model `docs/threat-model.md`. This is the **internal pre-screen**
the remediation plan calls for before an external reviewer (P0-5).

## Methodology

A multi-agent adversarial pass over the six review areas from the plan.
One finder per area hunted for real, code-grounded vulnerabilities
(file:line evidence required; hypotheticals and best-practice nits
disallowed). Every candidate was then independently checked by three
skeptical lenses — **exploitability**, **code-accuracy**, and
**mitigation-search** — each defaulting to "false positive." A finding was
**confirmed only on a 2-of-3 majority**. Every confirmed finding below was
additionally re-verified by hand against the cited code.

## Result summary

| Area | Candidates | Confirmed |
|---|---|---|
| OAuth/OIDC flows | 0 | 0 |
| Refresh-token rotation & replay | 0 | 0 |
| CSRF & cookie behavior | 1 | 1 |
| IAM/RBAC authorization & cache | 1 | 1 |
| API-key & service-account flows | 1 | 1 |
| Tenancy & data-isolation | 2 | 2 |
| **Total** | **5** | **5** |

OAuth/OIDC and refresh-token rotation came back clean — consistent with
the two prior remediation passes that focused there. The confirmed
findings cluster in **data-isolation write paths** and **non-JWT
credential lifecycle**, which earlier passes touched less.

| # | Sev | Area | Title | Status |
|---|---|---|---|---|
| F1 | High | data-isolation | `create()` lets caller override the scope default → cross-scope write | ✅ Fixed |
| F2 | High | api-key | Deactivated/deleted USER keeps access via existing API key | ✅ Fixed |
| F3 | Medium | data-isolation | `update()` does not constrain the scope field in `data` → row moved across scope | ✅ Fixed |
| F4 | Low | csrf | Standalone Hono CSRF middleware skip-path is fail-open (no segment boundary) | ✅ Fixed |
| F5 | Low | iam-rbac | Permission-cache TOCTOU repopulates stale ALLOW after revocation | ✅ Fixed |

**All five remediated on 2026-06-08** with regression tests (see the CHANGELOG `[Unreleased] › Security` entry). Per-finding fixes are noted inline below.

---

## F1 — data-isolation `create()` lets the caller override the scope default (High)

**Location:** `src/core/plugin-runner.ts:135-138`

The data-isolation wrapper enforces isolation asymmetrically. Reads
(`findOne`/`findMany`/`count`) and `update`/`delete` **AND** the scope
filters into the `WHERE` clause, so they can't be defeated. But `create`
merges the scope's required value as a *default* that caller data
overrides:

```ts
adapter.create<T>({
  ...params,
  data: { ...defaults, ...params.data }, // params.data spread LAST → wins
})
```

Because `params.data` is spread last, any scope field present in the
caller's payload (e.g. `orgId`, `tenantId`) overrides the value resolved
from the user's own scope assignment.

**Exploit:** With `getScopedDb(req, 'post').create({ model: 'post', data: req.body })`
(the documented pattern), an attacker in org `attacker` POSTs
`{ "title": "x", "orgId": "victim" }`. The default `{ orgId: 'attacker' }`
is overwritten, inserting the row into `victim`'s scope.

**Fix:** spread `defaults` last so scope fields are authoritative on
create: `data: { ...params.data, ...defaults }`.

---

## F2 — Deactivated/deleted USER keeps access via existing API key (High)

**Location:** `src/plugins/api-key/core.ts:248-256`,
`src/core/internal-adapter.ts:142-149`

The API-key path enforces the active-account gate **only for
SERVICE_ACCOUNT subjects**. `resolveApiKey` checks `isRevoked`, expiry,
and `service_account.isActive` — but for `subjectType === 'USER'` it never
loads the owning user, so it checks neither `user.isActive` nor existence.
`getSubjectPermissions` is symmetric: it short-circuits on
`service_account.isActive` but lets USER subjects fall straight through to
binding resolution. The JWT path, by contrast, blocks inactive users at
login (`auth-service.ts:300`) and refresh (`auth-service.ts:440`).

Consequently, deactivating a user (`updateUser({ isActive: false })`) or
deleting one does **not** invalidate their previously-issued API keys —
the key keeps authenticating and resolving the user's full permissions.

**Exploit:** Off-board a user with `isActive: false`; their JWT sessions
die but `Authorization: ApiKey fortress_sk_…` continues to authorize with
their full permissions until the key is explicitly revoked.

**Fix:** mirror the SERVICE_ACCOUNT gate for USER subjects — check
`user.isActive` (and existence) in `resolveApiKey`, and short-circuit
USER on `isActive === false` in `getSubjectPermissions`. (Defense in
depth: also revoke a user's API keys on `deleteUser`.)

---

## F3 — data-isolation `update()` does not constrain the scope field in `data` (Medium)

**Location:** `src/core/plugin-runner.ts:161-169`

`update` appends the scope filters to `WHERE` (so the caller can only
target rows already in their scope) but leaves `data` unconstrained. A
user can take a row they legitimately own and rewrite its scope field,
moving it into another tenant/scope.

```ts
adapter.update<T>({
  ...params,
  where: [...params.where, ...filters], // guards WHERE only; data passes through
})
```

**Exploit:** Attacker owns post 10 in org `attacker`; `update` with
`{ "orgId": "victim" }` succeeds (the WHERE filter still matches their own
row) and relocates it into `victim`'s scope.

**Fix:** force scope fields to the resolved scope value on update too:
`data: { ...params.data, ...defaults }` (symmetric with the F1 fix), or
reject payloads that contain a scope field.

---

## F4 — Standalone Hono CSRF middleware skip-path is fail-open (Low)

**Location:** `src/hono/middleware/csrf.ts:38-43`

The exported, documented `createCsrfMiddleware` (for protecting host-owned
Hono routes) skips CSRF with `path === skipPath || path.startsWith(skipPath)`
— a raw prefix match with **no segment boundary**. The hardened core
matcher `matchesSkipPath` (`src/core/http/csrf.ts:81-89`) deliberately
only skips on exact match or a `${skip}/` boundary, precisely so `/foo`
doesn't skip `/foobar`. The two matchers disagree and the user-facing one
is the weaker, fail-open variant.

**Exploit:** A skip entry of `/api/public` also disables CSRF on a sibling
mutating route `/api/public-keys` (`'/api/public-keys'.startsWith('/api/public')`).
Requires a developer skip-path that is a string prefix of a sensitive
sibling, plus a SameSite=None deployment or a Lax-permitted top-level
navigation — hence Low.

**Fix:** reuse the core segment-boundary matcher in the Hono middleware
(exact match or `${skip}/` prefix).

---

## F5 — Permission-cache TOCTOU repopulates stale ALLOW after revocation (Low)

**Location:** `src/core/iam/iam-service.ts:266-276`,
`src/core/iam/permission-cache.ts`

Only when the optional RBAC decision cache (`config.rbac.cache`) is
enabled. `checkPermission` for a global (no-tenant) check does an
unguarded read-then-write: miss → load from DB → `cache.set(...)`. The
cache is a plain `Map` with no generation/version counter, and revocation
methods invalidate by deleting the key. If a revocation's `invalidate()`
runs in the gap between an in-flight check's DB read and its `cache.set()`,
the invalidate is a no-op (key absent) and the subsequent `set()`
re-stores the now-stale permission list — keeping a revoked subject
authorized until the entry expires (default TTL 30s).

**Exploit:** Race a revocation against the about-to-be-revoked account's
own request to extend access by one TTL window.

**Fix:** add a generation counter to the cache; bump it on every
invalidate, capture it before the DB read, and drop the `set()` if the
generation advanced in the meantime. (Disabled-cache deployments — the
default — are unaffected.)

---

## Recommended remediation order

1. **F1, F2** (High) — genuine access-control bypasses; small, contained fixes.
2. **F3** (Medium) — same `data`-merge fix family as F1.
3. **F4, F5** (Low) — config-dependent; fix opportunistically.

F1/F2/F3 are one-to-three-line changes each plus regression tests. None
require schema or API changes.

## Caveat

This internal pass complements but does not replace an independent
external review (P0-5). It is one harness's adversarial sweep; absence of
findings in the OAuth/refresh areas is evidence of prior hardening, not a
proof of correctness.
