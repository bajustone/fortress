# Fortress Production Auth Library Readiness Roadmap

Date: 2026-06-05  
Scope: Bringing Fortress from a promising pre-1.0 auth/IAM library to a production-grade authentication library.

## Executive Summary

Fortress has a strong architecture and useful primitives, but becoming a production auth library requires hardening more than feature expansion. The priority should be correctness, atomicity, security defaults, route-policy verification, database constraints, regression tests, operational documentation, and external review.

The short version: **less feature work, more boring security engineering.**

---

## 1. Fix Correctness and Security Blockers

These should be treated as table-stakes before calling Fortress production-grade.

### 1.1 Enforce API-key scopes

API keys should not only resolve to their owning subject. Their scopes must constrain what the key can do.

Expected behavior:

```text
effectivePermission = subject IAM permission ∩ apiKey scopes
```

If a service account has broad IAM permissions but a key was issued with narrow scopes, the key should only be able to exercise the narrow scope.

### 1.2 Lock down impersonation

Built-in impersonation routes must require an explicit permission, for example:

```text
fortress:impersonate
```

The service-level warning that callers must check permission is not enough for a mounted HTTP route.

### 1.3 Make refresh rotation atomic

Core refresh and OAuth refresh flows need transactions, row locks, or atomic conditional updates so parallel refresh requests cannot mint multiple valid descendants.

Refresh-token rotation should be safe under concurrent requests.

### 1.4 Add database uniqueness constraints

Add uniqueness constraints for security-sensitive binding tables, especially:

- role bindings
- direct permission bindings
- role permissions where not already covered
- API-key ownership/index constraints where appropriate

Suggested role-binding uniqueness:

```text
(role_id, subject_type, subject_id, tenant_id)
```

### 1.5 Clarify or fix permission identity

Current permission identity should be reviewed carefully. If permissions are found/created only by `resource + action`, then `effect` and `conditions` are not truly part of the permission identity.

Either:

- make permission identity include `resource`, `action`, `effect`, and condition semantics; or
- explicitly document that conditions/deny rules have limited composability in the current model.

---

## 2. Harden the Auth Threat Model

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

Fortress already has some good primitives. The next step is making the security guarantees explicit and testable.

---

## 3. Add Serious Test Coverage

### 3.1 Unit tests

Cover:

- password hashing and verification
- JWT signing and verification
- JWT secret rotation
- refresh-token rotation
- refresh-token reuse detection
- IAM allow/deny evaluation
- IAM conditions
- service-account activation/deactivation
- API-key scope enforcement
- route metadata RBAC behavior

### 3.2 Integration tests

Cover:

- Hono mounted app
- Express mounted app
- SvelteKit integration if supported
- Drizzle/Postgres adapter
- migration-generated schema
- custom app route + Fortress route coexistence
- service-account API-key access to user-owned routes
- cookie auth and bearer auth behavior

### 3.3 Security regression tests

Every past auth/security bug should become a permanent regression test.

Especially important:

- `/oauth/*` bearer-kind regression
- consent-flow routes requiring Fortress JWTs
- OAuth protocol routes self-managing OAuth bearer tokens
- route-map/mounting behavior
- API-key principal resolution on both Fortress-owned and user-owned routes

### 3.4 OAuth/OIDC compatibility tests

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

## 4. Make Adapter and Database Behavior Production-Safe

### 4.1 Optimize permission resolution

The default Drizzle adapter should expose an optimized path for permission resolution, either through:

- `rawQuery`; or
- dedicated adapter methods for IAM permission lookup.

Without this, permission checks can fall back to multiple queries per request.

### 4.2 Use transactions for security mutations

Use transactions for multi-step security-sensitive operations such as:

- refresh-token rotation
- OAuth refresh-token rotation
- role creation with permission attachment
- service-account deletion and key cleanup
- user deletion and session cleanup
- key rotation

### 4.3 Add indexes for hot paths

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

### 4.4 Provide migrations or migration guides

Production users need more than table exports.

Provide:

- migration files or migration-generation guidance
- versioned schema changes
- upgrade notes
- rollback considerations
- compatibility tests between versions

---

## 5. Tighten Route and Security Metadata

A production auth library should not rely on humans remembering to mark every sensitive route correctly.

### 5.1 Default deny everywhere

Every mounted route should be either:

- explicitly public; or
- authenticated; or
- authenticated plus permission-gated.

Unknown or incomplete security metadata should fail closed.

### 5.2 Add route security audit tooling

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

### 5.3 Add static or test-time assertions

Add tests that assert every registered endpoint has appropriate security metadata.

For example:

- `impersonate` must require `fortress:impersonate`
- admin routes must require admin permissions
- IAM routes must require Fortress permissions
- OAuth protocol routes must explicitly declare `bearerKind: oauth`
- OAuth consent routes must not accidentally bypass JWT auth

---

## 6. Improve Operational Security

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

---

## 7. Make Documentation Exact, Not Aspirational

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
- What Fortress does not do

Also fix stale documentation, such as supported-version tables that do not match the current package version.

---

## 8. Improve Versioning and Release Discipline

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

## 9. Get External Review

Before claiming production auth library status, Fortress should receive external review.

Recommended review steps:

- internal security review
- independent code review
- dependency audit
- fuzz/property tests for token parsing, route matching, and validation
- OAuth/OIDC review by someone familiar with the specs
- paid security audit once APIs stabilize

---

## Suggested Roadmap

### Phase 1: Safe for Controlled Production

Goals:

- fix API-key scope enforcement
- fix impersonation permission enforcement
- make refresh rotation atomic
- add critical DB constraints and indexes
- add route security audit tests
- add TDMP-style integration tests
- enable/test rate limiting and account lockout

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

Fortress is architecturally on the right path. To become production-grade, it needs hardening more than new features.

The important work is:

- atomicity
- constraints
- stricter defaults
- complete tests
- exact docs
- operational tooling
- external review

If those are done, Fortress can become a solid production auth/IAM library. Without them, it should remain a promising library used with local hardening and careful review.
