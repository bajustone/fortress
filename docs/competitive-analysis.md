# Competitive Analysis: Fortress vs Better Auth

*Last updated: 2026-04-06*

## Overview

| Dimension | **Fortress** (v0.0.3) | **Better Auth** (v1.5.6) |
|---|---|---|
| Community | Solo project | 27.6k stars, 2.4k forks |
| Framework support | Hono (first-class) | 20+ frameworks (Next.js, Nuxt, SvelteKit, Hono, Express…) |
| Database support | PostgreSQL, MySQL, SQLite via Drizzle | Pg, MySQL, SQLite, MongoDB, LibSQL + 6 ORMs |
| Social login | 5 providers + generic OIDC | 40+ providers |
| Plugins | 13 (12 implemented, WebAuthn stubbed) | 50+ |
| 2FA | TOTP + backup codes + trusted devices | Plugin-based 2FA |
| Passkeys/WebAuthn | Stubbed (architecture only) | Fully implemented |
| IAM/Permissions | Resource+action, conditions, deny rules, groups, roles, inheritance | Basic RBAC |
| Multi-tenancy | Schema-per-tenant (Pg) + row-level isolation | Supported |
| OAuth server | Auth code + PKCE, client credentials | Consumer-side only |
| Audit logging | Append-only, hash-chained, SOC2/HIPAA schema | Not built-in |
| Rate limiting | Sliding window, IP+account, IPv6 normalization | Brute-force protection, IP blocking |
| API keys | Scoped, per-service-account | Supported |
| Session model | JWT + refresh token rotation (stateless-first) | Cookie-based sessions (stateful-first) |
| Enterprise (SAML, SCIM) | Not planned | Available |

## Where Fortress Is Stronger

- **IAM depth** — transport-agnostic `resource+action` permissions with conditions, deny rules, and inheritance is more sophisticated than Better Auth's RBAC
- **OAuth server** — Fortress can *issue* OAuth tokens (auth code + PKCE, client credentials); Better Auth only *consumes* them
- **Audit logging** — hash-chained, compliance-ready audit trail is built-in
- **Security hardening** — HIBP breach checking, progressive account lockout, CSRF custom-header strategy, refresh token family rotation with reuse detection

## Where Better Auth Is Stronger

- **Ecosystem maturity** — stable v1.5+, massive community, battle-tested in production
- **Framework breadth** — first-class support for 20+ frameworks vs Hono-only
- **Database breadth** — 6 ORM adapters + MongoDB vs Drizzle-only
- **Social providers** — 40+ vs 5
- **WebAuthn/Passkeys** — fully working vs stubbed
- **Enterprise features** — SAML 2.0, SCIM provisioning
- **Client SDK** — `createAuthClient()` with `signIn`, `signOut`, `useSession`
- **Plugin ecosystem** — 50+ plugins, community-contributed

## Developer Experience Comparison

### Setup & Time-to-Working-Auth

| Aspect | **Fortress** | **Better Auth** |
|---|---|---|
| Lines to basic auth | ~10 lines | ~15-25 lines |
| Required config | `jwt.secret` + `database` | `database` + enable features |
| CLI scaffold | `fortress init` | `npx auth@latest migrate/generate` |
| Client SDK | None (server-only) | Yes — `createAuthClient()` |

### Type Safety

| Aspect | **Fortress** | **Better Auth** |
|---|---|---|
| Core API typing | Strong — all types exported | Good — typed config |
| Plugin methods | Weak — `Record<string, Function>` | Unclear |
| Error types | Excellent — union-typed codes, `FortressError` | Undocumented |
| Hono context | Typed via `FortressEnv` | N/A |

### Error Handling

| Aspect | **Fortress** | **Better Auth** |
|---|---|---|
| Error class | Unified `FortressError` with code, statusCode, retryAfter | Not documented |
| Error factory | `Errors.unauthorized()`, `Errors.rateLimited(retryAfter)` | Unknown |
| HTTP handling | Auto-serializes, scrubs stack traces, sets Retry-After | Unknown |

### Testing

| Aspect | **Fortress** | **Better Auth** |
|---|---|---|
| Test setup | `createTestAdapter()` → in-memory SQLite, zero Docker | Not documented |
| Lines to test | 3 lines | Unknown |

### Documentation

| Aspect | **Fortress** | **Better Auth** |
|---|---|---|
| Getting started | README quick-start (example app placeholder) | Docs site with step-by-step |
| API reference | Source code only | Docs site |
| Architecture docs | Excellent | Standard |
| Plugin guides | Missing | Sparse |

### Fortress DX Strengths

1. 3-line test setup — in-memory SQLite, no containers
2. Best-in-class error handling — unified, typed, HTTP-aware
3. Minimal required config — 2 fields, sensible defaults
4. Domain-focused API — `checkPermission(user, resource, action)` not HTTP verbs
5. CLI scaffolding — `fortress init` + `generate-secret` + `sync:types`

### Fortress DX Gaps

1. No client SDK — devs must wire up fetch/axios themselves
2. Plugin methods aren't type-safe — kills autocomplete
3. Example app is a placeholder — no runnable E2E demo
4. No API reference docs — must read source
5. No plugin usage guides

## Bottom Line

Better Auth is a **mature, broad ecosystem** — batteries-included for any framework/database. Fortress is a **deeper, more opinionated security toolkit** — stronger on IAM, OAuth-as-a-server, audit compliance, and security hardening, but narrower and earlier in lifecycle. The realistic gap is ecosystem maturity and breadth, not capability.
