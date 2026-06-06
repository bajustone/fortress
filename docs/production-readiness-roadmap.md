# Fortress Production Auth Library Readiness Roadmap

Date: 2026-06-05  
Updated after commit: `56459b3 fix: remediate security audit findings`  
Scope: Bringing Fortress from a promising pre-1.0 auth/IAM library to a production-grade authentication library.

## Executive Summary

Fortress has a strong architecture and useful primitives. The recent security remediation work materially improved its production posture:

- API-key scopes now flow into principal resolution and IAM checks.
- API-key credentials are blocked from managing/minting API keys through self-service routes.
- Built-in impersonation is permission-gated at both HTTP route and direct service-call level.
- Core refresh-token rotation is transaction-backed and conditionally claims the token.
- OAuth refresh-token rotation is transaction-backed and conditionally claims the token.
- Permission identity now includes `resource`, `action`, `effect`, and `conditions`.
- Drizzle now exposes `rawQuery`, enabling the optimized IAM permission path.
- `isNull` is now part of the core adapter contract.
- Role/direct-permission binding uniqueness is improved, including partial unique indexes for nullable tenant IDs.
- Regression tests were added for API-key scopes, API-key self-management denial, impersonation denial, and idempotent bindings.

The roadmap has therefore shifted: the original P0 correctness issues are mostly closed. The highest remaining concern is now **safe raw SQL / identifier handling in the tenancy plugin**, because enabling `rawQuery` makes Postgres tenancy SQL paths active.

The short version: Fortress is moving in the right direction. The next work is focused hardening: identifier safety, migrations, broader regression coverage, operational controls, docs, and external review.

---

## Current Readiness Snapshot

| Area | Status | Notes |
|---|---:|---|
| API-key scope enforcement | Mostly done | Scopes constrain IAM checks; API keys cannot self-manage API keys. Add more negative tests for GET/DELETE/rotate self-service routes. |
| Impersonation permission | Done | HTTP route and direct service call now require `fortress:impersonate`. |
| Core refresh rotation atomicity | Mostly done | Transaction + conditional update added. Add explicit concurrent refresh tests. |
| OAuth refresh rotation atomicity | Mostly done | Transaction + conditional `usedAt IS NULL` update added. Add explicit concurrent refresh tests. |
| Permission identity | Improved | Identity includes effect and conditions. Remaining DB-level nullable `conditions` uniqueness should be reviewed. |
| Binding uniqueness | Improved | Code-level idempotency + partial unique indexes for nullable tenant IDs. |
| Drizzle optimized IAM path | Improved | `rawQuery` added. Needs security review for consumers that build SQL dynamically. |
| Adapter contract | Improved | `isNull` promoted to core operator. |
| Tenancy raw SQL safety | Needs work | Schema names are built from tenant/header values and interpolated into raw SQL. Must sanitize/quote identifiers. |
| Tests | Improved | Full suite passing; add concurrency and more negative API-key route tests. |
| Docs/release discipline | In progress | SECURITY/package docs improved; still need production config, threat model, migration guide. |

---

## 1. Correctness and Security Blockers

### 1.1 API-key scopes

Status: **Mostly done**

API keys now return credential scopes during principal resolution and IAM checks apply credential-level narrowing.

Expected behavior:

```text
effectivePermission = subject IAM permission ∩ apiKey scopes
```

The self-service API-key escalation issue was also addressed: API-key credentials are denied from API-key management routes so a scoped key cannot mint or rotate into a broader key.

Remaining work:

- Add explicit tests for API-key credentials denied on:
  - `GET /api-key/keys`
  - `DELETE /api-key/keys/:id`
  - `POST /api-key/keys/:id/rotate`
- Document API-key scope semantics clearly:
  - `null`/`undefined` = unscoped credential
  - `[]` = no permissions
  - `resource:action`, `resource:*`, `*` supported
- Consider whether API-key credentials should ever be allowed to self-manage keys through an explicit opt-in permission/scope.

### 1.2 Impersonation

Status: **Done**

Built-in impersonation now requires:

```text
fortress:impersonate
```

This is enforced by:

- endpoint metadata on `/auth/impersonate`
- direct service-call defense in `fortress.auth.impersonate(...)`

Remaining work:

- Document impersonation operational guidance:
  - short expiry
  - no refresh token
  - audit logging strongly recommended
  - reason field should be required by policy in sensitive deployments

### 1.3 Refresh rotation atomicity

Status: **Mostly done**

Core auth refresh now uses transaction + conditional token claim:

```text
token_hash = X AND is_revoked = false → set is_revoked = true
```

OAuth refresh now uses transaction + conditional token claim:

```text
id = X AND used_at IS NULL → set used_at = now()
```

Remaining work:

- Add explicit concurrent refresh tests where two refreshes race and exactly one succeeds.
- Add the same concurrency regression test for OAuth refresh-token grant.
- Verify behavior on all supported adapters, especially Postgres and SQLite.

### 1.4 Database uniqueness constraints

Status: **Improved**

Added/improved uniqueness for:

- permissions by resource/action/effect/conditions
- role bindings
- direct permission bindings
- partial global/tenant indexes for nullable tenant IDs

Remaining work:

- Review migration impact for existing databases with duplicate rows.
- Provide cleanup SQL for duplicates before adding constraints.
- Review permission uniqueness when `conditions IS NULL`; nullable unique columns may still allow duplicate rows at the DB level depending on dialect.

### 1.5 Permission identity

Status: **Improved**

Permission lookup/creation now includes:

- `resource`
- `action`
- `effect`
- `conditions`

Remaining work:

- Add explicit tests that permissions with the same resource/action but different effect or conditions are distinct.
- Document condition canonicalization. JSON object ordering can affect equality unless conditions are serialized consistently.

---

## 2. Immediate Remaining Security Work

### 2.1 Sanitize or quote tenancy schema identifiers

Status: **Needs work**  
Priority: **High**

Because the Drizzle adapter now exposes `rawQuery`, the Postgres tenancy plugin's raw SQL paths become active:

```ts
await ctx.db.rawQuery(`CREATE SCHEMA IF NOT EXISTS ${schemaName}`);
await adapter.rawQuery(`SET LOCAL search_path TO ${schemaName}, public`);
```

`schemaName` is derived from tenant tax ID or request header tenant code. That creates a potential SQL identifier injection surface unless the value is strictly validated or safely quoted.

Recommended fix:

- Restrict tenant schema identifiers to a safe pattern, for example:

```ts
/^[a-zA-Z_][a-zA-Z0-9_]*$/
```

- Or implement a proper Postgres identifier quoting helper.
- Reject unsafe tenant codes/tax IDs before they reach raw SQL.
- Add tests with malicious tenant codes, for example:

```text
foo; drop schema public; --
foo", public; --
foo bar
../foo
```

### 2.2 Review rawQuery safety boundaries

Status: **Needs work**  
Priority: **High**

`rawQuery` supports parameterized values, but identifiers cannot be parameterized like normal values. Any code that injects table names, schema names, column names, or SQL fragments into `rawQuery` needs special review.

Recommended work:

- Document: `rawQuery` parameters are for values only, not identifiers.
- Provide helper functions for safe identifiers if Fortress plugins need dynamic identifiers.
- Audit every internal `rawQuery` caller.

---

## 3. Harden the Auth Threat Model

Production auth needs an explicit written threat model and tests mapped to it.

The threat model should cover at least:

- brute force attacks
- credential stuffing
- account enumeration
- refresh-token theft and replay
- API-key leakage
- OAuth authorization code interception
- OAuth mix-up attacks
- CSRF when cookie auth is used
- session fixation
- route metadata mistakes causing privilege escalation
- service-account blast radius
- impersonation abuse
- stale sessions after user/service-account deactivation
- tenant identifier injection / schema breakout
- raw SQL misuse

Fortress now has stronger primitives for several of these. The next step is making the security guarantees explicit and testable.

---

## 4. Add Serious Test Coverage

### 4.1 Already improved

Recent tests now cover:

- API-key scope narrowing on IAM-protected routes
- API-key credential denial on self-service key minting
- direct impersonation denial without `fortress:impersonate`
- HTTP impersonation denial without `fortress:impersonate`
- global direct-permission binding idempotency
- global role-binding idempotency

### 4.2 Add next

Recommended next tests:

- API-key credentials denied on all API-key self-management routes:
  - list
  - revoke
  - rotate
- concurrent core refresh: exactly one succeeds
- concurrent OAuth refresh: exactly one succeeds
- duplicate global role binding cannot be inserted even under direct DB access
- duplicate global direct permission binding cannot be inserted even under direct DB access
- permission identity differs by `effect`
- permission identity differs by `conditions`
- malicious tenant codes are rejected before raw SQL
- `rawQuery` placeholder handling for `?` and `$1` forms

### 4.3 Integration tests

Keep/expand integration coverage for:

- Hono mounted app
- Express mounted app
- SvelteKit integration if supported
- Drizzle/Postgres adapter
- migration-generated schema
- custom app route + Fortress route coexistence
- service-account API-key access to user-owned routes
- cookie auth and bearer auth behavior
- tenancy with Postgres search-path switching

### 4.4 OAuth/OIDC compatibility tests

At minimum, test with:

- `openid-client`
- Moodle-like OIDC flow
- public PKCE client
- confidential authorization-code client
- client-credentials client
- refresh-token grant
- userinfo scope gating
- id_token verification through JWKS
- discovery document autoconfiguration

---

## 5. Adapter and Database Production Safety

### 5.1 Optimized permission resolution

Status: **Improved**

The default Drizzle adapter now exposes `rawQuery`, enabling optimized IAM permission resolution.

Remaining work:

- Benchmark optimized vs fallback permission checks.
- Add explicit tests that the raw-query path is exercised on Postgres.
- Document adapter requirements for custom adapters.

### 5.2 Transactions for security mutations

Status: **Improved but ongoing**

Already improved:

- core refresh-token rotation
- OAuth refresh-token rotation

Still review:

- role creation with permission attachment
- service-account deletion and key cleanup
- user deletion and session cleanup
- API-key rotation
- admin bootstrap

### 5.3 Indexes for hot paths

Recommended indexes:

- refresh token hash
- refresh token family
- API key hash
- API key subject tuple
- OAuth access-token hash
- OAuth refresh-token hash/family
- OAuth client ID
- role bindings by subject
- direct permission bindings by subject
- group memberships by user

### 5.4 Migrations and upgrade guides

Production users need more than table exports.

Provide:

- migration files or migration-generation guidance
- versioned schema changes
- duplicate cleanup scripts before adding unique constraints
- upgrade notes
- rollback considerations
- compatibility tests between versions

---

## 6. Tighten Route and Security Metadata

A production auth library should not rely on humans remembering to mark every sensitive route correctly.

### 6.1 Default deny everywhere

Every mounted route should be either:

- explicitly public; or
- authenticated; or
- authenticated plus permission-gated.

Unknown or incomplete security metadata should fail closed.

### 6.2 Add route security audit tooling

Fortress should ship a route audit command or function that checks for dangerous routes.

Example:

```bash
fortress audit-routes
```

It should flag routes involving:

- impersonation
- admin
- IAM
- API keys
- OAuth consent
- OAuth token handling
- user management

### 6.3 Add static or test-time assertions

Add tests that assert every registered endpoint has appropriate security metadata.

For example:

- `impersonate` must require `fortress:impersonate`
- admin routes must require admin permissions
- IAM routes must require Fortress permissions
- OAuth protocol routes must explicitly declare `bearerKind: oauth`
- OAuth consent routes must not accidentally bypass JWT auth
- API-key self-management must not be available to API-key credentials by default

---

## 7. Improve Operational Security

Production deployments need first-class operational controls.

Document and support:

- JWT secret rotation
- OAuth signing-key rotation
- API-key rotation
- refresh-token cleanup jobs
- expired OAuth token cleanup jobs
- session revocation
- user kill switch
- service-account kill switch
- audit-log retention
- emergency credential revocation
- backup/restore implications
- production cookie settings
- CSRF deployment guidance
- proxy and `X-Forwarded-*` trust model
- tenant schema provisioning and naming policy
- duplicate-binding cleanup before migration

---

## 8. Make Documentation Exact, Not Aspirational

The documentation should clearly distinguish between:

- implemented guarantees
- recommended configuration
- known limitations
- future work

Needed docs:

- Security guarantees
- Known limitations
- Threat model
- Recommended production configuration
- Versioned migration guide
- Schema and indexes guide
- OAuth compliance matrix backed by tests
- API-key scope semantics
- RBAC/ABAC semantics
- Tenancy identifier safety
- Raw SQL safety model
- What Fortress does not do

Already improved:

- supported-version table updated
- package now includes docs/examples/SECURITY/CHANGELOG

---

## 9. Improve Versioning and Release Discipline

For auth libraries, process matters as much as implementation.

Recommended release discipline:

- strict semantic versioning
- security advisory process
- clear supported versions
- changelog with migration notes
- deprecation windows
- compatibility matrix
- no silent breaking auth behavior
- regression tests for every security bug
- signed releases if practical

---

## 10. Get External Review

Before claiming production auth library status, Fortress should receive external review.

Recommended review steps:

- internal security review
- independent code review
- dependency audit
- fuzz/property tests for token parsing, route matching, and validation
- OAuth/OIDC review by someone familiar with the specs
- Postgres/SQL review for tenancy and raw-query use
- paid security audit once APIs stabilize

---

## Suggested Roadmap

### Phase 1: Controlled Production Hardening

Status: **Mostly complete, with one high-priority remaining item**

Done or mostly done:

- API-key scope enforcement
- API-key self-management denial for API-key credentials
- impersonation permission enforcement
- atomic core refresh rotation
- atomic OAuth refresh rotation
- critical binding constraints/idempotency
- Drizzle `rawQuery`
- `isNull` adapter contract
- targeted regression tests

Still required:

- sanitize/quote tenancy schema identifiers
- add concurrent refresh tests
- add full API-key self-management denial tests
- provide migration notes for new constraints

### Phase 2: Production Library

Goals:

- migration system or migration guides
- hardened Postgres/Drizzle adapter
- OAuth/OIDC compatibility suite
- operational security docs
- written threat model
- cleanup jobs
- stable public API
- known limitations page
- route audit tooling

### Phase 3: Trustworthy External Auth Product

Goals:

- external security audit
- compatibility matrix
- long-term version support
- security advisories
- production examples for Hono, Express, SvelteKit, and Postgres
- hardened default production config
- release/signing discipline

---

## Final Take

Fortress is architecturally on the right path, and the recent fixes significantly reduce the most serious risks identified in the audit.

The remaining work is no longer mainly about the original P0 items. The most important next step is to harden newly-active raw SQL paths, especially tenancy schema handling. After that, the path to production-grade is about tests, migrations, exact docs, operational tooling, and external review.

If those are completed, Fortress can become a solid production auth/IAM library. Until then, it is much stronger than before but should still be deployed with careful review and version pinning.
