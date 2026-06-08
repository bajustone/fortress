# Fortress Library Improvements

Date: 2026-06-08  
Scope: Improvements Fortress should prioritize as a reusable authentication and identity library.

## P0 — Library-critical

### 1. First-class migration and upgrade tooling

Fortress owns security-critical database tables and indexes. Package upgrades must be safe and predictable.

Needed:

- Versioned migration guides per release.
- Generated SQL or Drizzle migration helpers.
- Machine-checkable schema/version status.
- Rollback, backfill, and cleanup instructions.
- Upgrade fixtures against existing production-like databases.

### 2. Single route-security manifest

Fortress should expose one canonical route security manifest derived from endpoint metadata.

Needed:

- Classify every route as public, authenticated, RBAC-protected, or OAuth self-managed protocol route.
- Make adapters consume the manifest directly.
- Add drift checks between route metadata, mounted routes, OpenAPI, and RBAC mappings.
- Treat manifest diffs as security-sensitive changes.

### 3. Host-owned route protection helpers

Apps often call `fortress.auth.*`, `fortress.iam.*`, or plugin methods directly from their own routes. Those routes need consistent protections.

Needed:

- Wrappers/helpers for direct service calls.
- Consistent CSRF, rate-limit, audit, cookie, metadata, and validation behavior.
- Clear documentation of what runs inside `fortress.handleRequest()` versus host-owned routes.
- Tests proving wrapper routes receive equivalent protections where required.

### 4. Tenancy hardening release and operations docs

The hardened tenancy implementation should be released and documented before broad use.

Needed:

- Publish the hardened tenancy implementation.
- Document claim-based tenant resolution.
- Document schema creation and deletion operations.
- Ensure schema switching is transaction-pinned and fail-closed.
- Provide migration notes for existing tenant schemas.

### 5. Formal security review

Fortress is security-critical and should receive independent review.

Review areas:

- OAuth/OIDC flows.
- Refresh-token rotation and replay semantics.
- CSRF and cookie behavior.
- IAM/RBAC authorization and cache invalidation.
- API-key and service-account flows.
- Tenancy and data-isolation plugins.

## P1 — Developer experience and operational maturity

### 6. Better typed adapter helpers

Reduce TypeScript friction for host apps.

Needed:

- Typed Hono, Express, and SvelteKit helpers for apps extending Fortress env types.
- Fewer `Context<AppEnv>` ↔ `Context<FortressEnv>` casts.
- Cleaner `getSubject`, `getUserId`, and `getClaims` host-app helpers.
- Better typed plugin method access.

### 7. Policy-as-code

Auth policy should be declarative, diffable, and CI-friendly.

Needed:

- Declarative roles, groups, permissions, service accounts, and OAuth clients.
- Environment-specific policy files.
- Dry-run diff.
- Apply/sync command.
- Drift detection.
- Reviewable CI output.

### 8. Admin/operator console

Fortress exposes APIs, but operators need safe workflows.

Needed workflows:

- Users.
- Roles, groups, and permissions.
- Service accounts and API keys.
- OAuth clients.
- Sessions and revocation.
- Audit logs.
- Permission debugging.

### 9. Production deployment guide

Fortress needs stronger deployment guidance for real applications.

Needed docs:

- JWT secret generation, length, and rotation.
- Cookie settings behind reverse proxies.
- CSRF behavior and opt-out rules.
- CORS recipes for browser clients.
- HTTPS requirements.
- PostgreSQL versus SQLite guarantees.
- OAuth/OIDC relying-party setup.
- API-key and service-account operational practices.

### 10. CI/test utility package

Fortress should provide reusable checks for consumers.

Needed:

- Route-manifest drift checker.
- OpenAPI diff checker.
- Migration drift checker.
- Forbidden public-route drift checker.
- Auth smoke-test helpers.
- OAuth end-to-end fixtures.

## P2 — Ecosystem maturity

### 11. Compatibility matrix

Document and test supported versions for:

- Bun.
- Node.js.
- Deno.
- Hono.
- Drizzle.
- PostgreSQL.
- SQLite.
- SvelteKit.
- OpenTelemetry packages.

### 12. More production examples

Needed examples:

- Cookie + CSRF Hono app.
- Bearer-token API app.
- API-key/service-account app.
- OAuth/OIDC provider app.
- Admin bootstrap and policy-sync app.
- Tenancy app after hardening is released.

### 13. Observability defaults

Fortress should ship opinionated observability guidance.

Needed:

- Metric and audit event catalog.
- Recommended dashboards.
- Alerts for auth failures, token reuse, RBAC denies, OAuth errors, API-key usage, and latency.
- High-cardinality attribute guidance.

### 14. Public maturity signals

If Fortress is intended to be a general-purpose auth library, it needs visible maturity signals.

Needed:

- Security policy with supported versions.
- Release notes that clearly mark security fixes.
- Threat model documentation.
- Changelog discipline.
- Public examples and hardening guides.
- Independent audit summary when available.

## Top three priorities

If only three improvements can be done first, prioritize:

1. Migration and upgrade tooling.
2. Single route-security manifest.
3. Host-owned route protection helpers.
