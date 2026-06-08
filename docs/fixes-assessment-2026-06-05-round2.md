# Fortress Fixes Assessment — Second Pass Update

Date: 2026-06-05  
Repo: `/Users/bajustone/dev/fortress`  
Scope: Update to the second-pass assessment after fixing all remaining non-tenancy findings.

## Executive Summary

All remaining issues from the second-pass report have been addressed **except the intentionally deferred tenancy plugin**.

Newly closed since the previous assessment:

- OAuth consent-flow approval is now transaction-backed and atomically single-use.
- Core refresh-token strict replay semantics are explicitly tested and documented.
- OAuth refresh-token strict replay semantics are explicitly tested.
- Core replay-family revocation now commits before throwing, so the family is actually invalidated.
- CSRF documentation now matches implementation: unsafe requests with either Fortress access or refresh cookies are checked, even if bearer/API-key headers are also present.
- SQLite nested transactions now fail fast with a clear error instead of deadlocking.
- SQLite multi-row `UPDATE ... RETURNING` now steps all returned rows, so family/session revocation updates every matching row.
- Data-isolation docs now call out the `node:async_hooks` runtime requirement.
- API-key self-management negative tests now cover `GET`, `DELETE`, and `rotate`.
- Permission identity tests now cover `effect` and `conditions`.
- OAuth refresh now re-issues an `id_token` when the token family scope includes `openid`.
- Migration notes now include the pending-flow `used_at` column and updated behavior.

**Verdict:** Core auth/IAM/OAuth without tenancy mounted is now in a much stronger controlled-production posture. The main blocker that remains from this report is still tenancy: it should remain experimental/unmounted until hardened or removed from production-facing surfaces.

---

## Validation Performed

Commands run in `/Users/bajustone/dev/fortress`:

```bash
bun run typecheck
bun run lint
bun test src/plugins/oauth/oauth.test.ts \
  src/plugins/api-key/api-key.test.ts \
  src/core/iam/iam-service.test.ts \
  src/core/http/csrf.test.ts \
  src/plugins/data-isolation/data-isolation.test.ts
bun test src/integration.test.ts \
  src/core/auth/auth-observer.test.ts \
  src/drizzle/adapter.test.ts
bun test
bun run test:integration
```

Results:

- `bun run typecheck` — passed
- `bun run lint` — passed
- targeted remediation tests — passed
- full unit suite — passed: 989 tests / 67 files
- integration suite — passed: 66 tests / 2 files

---

## Newly Confirmed Fixes

### 1. OAuth consent-flow approval is atomically single-use

Files:

- `src/plugins/oauth/index.ts`
- `src/plugins/oauth/oauth.test.ts`
- `src/drizzle/schema.ts`
- `src/drizzle/pg/schema.ts`
- `src/testing/index.ts`
- `docs/security-remediation-migration-2026-06-05.md`

`handleApproveFlow` now executes inside a transaction. It loads the pending flow, checks expiry/ownership, conditionally claims `usedAt IS NULL`, creates the authorization code, and deletes the pending flow in the same transaction.

A new regression verifies two concurrent approvals of the same flow produce exactly one redirect/code and one failure, and only one authorization-code row.

### 2. Refresh-token concurrency behavior is explicit and tested

Files:

- `src/core/auth/auth-service.ts`
- `src/integration.test.ts`
- `src/plugins/oauth/index.ts`
- `src/plugins/oauth/oauth.test.ts`
- `SECURITY.md`
- `docs/security.md`
- `docs/security-remediation-migration-2026-06-05.md`

Fortress intentionally keeps **strict replay semantics**: when two refresh attempts present the same token, one may rotate successfully, but the losing duplicate is treated as reuse and revokes the entire token family.

Core auth and OAuth refresh now both have explicit concurrency tests for this behavior. Core auth also fixed an important transactional bug: replay-family revocation now commits before `TOKEN_REUSE` is thrown.

### 3. CSRF docs now match implementation

Files:

- `README.md`
- `SECURITY.md`
- `docs/security.md`
- `docs/security-remediation-migration-2026-06-05.md`

The documentation now states the exact behavior:

- unsafe request + Fortress access cookie or refresh cookie ⇒ CSRF applies;
- CSRF still applies if bearer/API-key headers are present alongside cookies;
- pure bearer/API-key request with no Fortress cookies ⇒ skipped.

### 4. SQLite nested transactions no longer deadlock

Files:

- `src/drizzle/adapter.ts`
- `src/drizzle/adapter.test.ts`
- `README.md`
- `docs/security-remediation-migration-2026-06-05.md`

The SQLite adapter now uses `AsyncLocalStorage` to detect an active SQLite transaction context and rejects nested transactions with a clear `BAD_REQUEST` error. A regression test covers the no-deadlock behavior.

### 5. SQLite multi-row updates are fixed

Files:

- `src/drizzle/adapter.ts`
- `src/drizzle/adapter.test.ts`

SQLite `UPDATE ... RETURNING` now calls `.all()` so every returned row is stepped/applied. This matters for family-wide token revocation and other multi-row updates. The adapter still returns one row/null to preserve the existing `DatabaseAdapter.update` contract.

### 6. Data-isolation runtime limitation is documented

Files:

- `README.md`
- `docs/plugins/data-isolation.md`

Docs now state that `withoutScope()` and `unscoped()` depend on `node:async_hooks` / `AsyncLocalStorage` and are intended for Node/Bun-compatible runtimes.

### 7. Lower-priority tests/follow-ups were added

Files:

- `src/plugins/api-key/api-key.test.ts`
- `src/core/iam/iam-service.test.ts`

Added coverage for:

- API-key credentials denied from self-service `GET /api-key/keys`;
- API-key credentials denied from self-service revoke;
- API-key credentials denied from self-service rotate;
- permission identity differs by `effect`;
- permission identity differs by serialized `conditions`.

### 8. OIDC refresh now returns `id_token` for `openid` grants

Files:

- `src/plugins/oauth/index.ts`
- `src/plugins/oauth/oauth.test.ts`

When a refresh-token family carries an `openid` scope, `refreshTokenGrant` now issues a fresh `idToken`, and `/oauth/token` includes it as `id_token` in refresh responses.

---

## Remaining High-Importance Issue

### Tenancy plugin remains unsafe if mounted

Status: **Critical if used; intentionally excluded from this remediation pass**

File:

- `src/plugins/tenancy/index.ts`

Remaining problems:

- `CREATE SCHEMA IF NOT EXISTS ${schemaName}` interpolates an identifier derived from `taxId`.
- `SET LOCAL search_path TO ${schemaName}, public` interpolates an identifier derived from tenant code/header context.
- `SET LOCAL` is executed separately before CRUD; outside a transaction it is discarded, so isolation can silently fail open to `public`.
- Tenant code is request/header-derived unless a trusted resolution layer wraps it.

Required before production use:

- validate and quote SQL identifiers;
- pin search-path changes to the same transaction as the tenant-scoped operation;
- resolve tenant context from authenticated/authorized server-side state, not untrusted headers alone;
- or remove/export-hide tenancy from production-facing docs/packages until hardened.

---

## Remaining Lower-Priority Follow-Ups

- Add migration/upgrade fixtures for existing databases covering `flow_id`, `user_id`, `used_at`, and partial unique indexes.
- Consider making public registration non-enumerating by default, or keep the 409 UX tradeoff with prominent rate-limit guidance.
- Keep tenancy marked experimental/unmounted until separately remediated.
- External review of the now-remediated code is still recommended before broad “production-grade auth library” claims.

---

## Updated Production Readiness Verdict

For **core auth/IAM/OAuth without tenancy mounted**, the reported non-tenancy blockers are now closed and validated by tests. Fortress is plausibly close to controlled-production readiness assuming careful migrations, version pinning, rate limits, HTTPS/cookie configuration, and operational monitoring.

For a blanket general-purpose production-auth-library claim, the outstanding condition remains the tenancy story: harden it, or keep it clearly experimental and out of production-facing recommendations.
