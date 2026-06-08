# Fortress Needed Improvements

Date: 2026-06-08  
Scope: TDMP usage of `@bajustone/fortress` and local Fortress source at `~/dev/fortress`.

## Priority 0 — Must fix before relying on Fortress as TDMP's long-term identity foundation

### 1. Publish and deploy the security fixes

TDMP currently depends on:

```json
"@bajustone/fortress": "npm:@jsr/bajustone__fortress@0.1.1"
```

The local Fortress checkout is at `0.1.2`, with additional unreleased tenancy hardening on top.

Needed:

- Publish the latest security-remediated Fortress version.
- Upgrade TDMP from `0.1.1`.
- Generate and review Drizzle migrations for Fortress-owned schema changes.
- Run full auth/OAuth/API-key regression tests before deployment.

### 2. Add first-class migration and upgrade tooling

Fortress owns database tables for users, sessions, IAM, API keys, OAuth, tenants, audit logs, and related indexes. Package upgrades can require schema changes.

Needed:

- Versioned migration guides per release.
- Machine-checkable migration status.
- Upgrade fixtures for existing production-like databases.
- Clear rollback guidance.
- Explicit notes for required data cleanup/backfills.

### 3. Unify the route security model

TDMP currently has several security-related sources of truth:

- Fortress endpoint metadata.
- Hono route mounting.
- `SKIP_PATHS` in auth middleware.
- `SKIP_PATHS` in route-map generation.
- Generated `src/generated/route-map.ts`.
- Mounted Fortress-owned routes via `mountFortress()`.
- TDMP-owned wrapper routes that call `fortress.auth.*` directly.

Needed:

- A single generated security manifest for routes.
- CI checks that fail when route metadata and mounted routes drift.
- Explicit classification of every route as public, authenticated, RBAC-protected, or self-managed OAuth protocol.
- Security review required for every route-map diff.

### 4. Make host-owned wrapper behavior explicit

TDMP wraps some Fortress functionality in its own routes, for example login, refresh, logout, self-service permissions, and OAuth client creation.

Needed:

- Document which protections apply to `fortress.handleRequest()` routes versus direct service calls.
- Provide helper middleware or wrappers so host-owned routes consistently apply CSRF, rate limits, audit events, cookie handling, and validation.
- Add tests proving TDMP-owned auth routes have equivalent protections where required.

### 5. Complete and release tenancy hardening before any production use

The local Fortress source has an unreleased tenancy-hardening commit that fixes earlier critical findings.

Needed before mounting tenancy anywhere:

- Release the hardened tenancy implementation.
- Re-review the implementation externally or independently.
- Verify tenant context comes only from verified JWT custom claims.
- Verify schema switching is transaction-pinned and fail-closed.
- Add migration/operations docs for tenant schema creation and deletion.
- Keep tenancy unmounted until this is complete.

### 6. External security review

Fortress is security-critical. It implements auth, IAM, OAuth/OIDC, API keys, sessions, CSRF behavior, JWT handling, and optional tenancy.

Needed:

- Independent review of OAuth/OIDC flows.
- Review of refresh-token replay semantics.
- Review of CSRF and cookie behavior.
- Review of IAM authorization and cache invalidation.
- Review of tenancy and data-isolation plugins.
- Review of service-account/API-key flows.

## Priority 1 — High-value improvements

### 7. Reduce TypeScript casting and integration friction

TDMP currently needs repeated casts between `Context<AppEnv>` and `Context<FortressEnv>`.

Needed:

- Better typed Hono helpers for apps that extend `FortressEnv`.
- Safer plugin method typing without local narrowing facades.
- Cleaner `getSubject`, `getUserId`, and `getClaims` helpers for host apps.

### 8. Add an admin/operator console

Fortress exposes admin APIs, but operators still need safe workflows.

Needed UI/workflows for:

- Users.
- Roles and permissions.
- Groups.
- Service accounts.
- API keys.
- OAuth clients.
- Sessions and revocation.
- Audit logs.
- Permission debugging.

### 9. Policy-as-code support

Roles, permissions, groups, service accounts, and OAuth clients should be declarative and diffable.

Needed:

- Environment-specific policy files.
- Dry-run diff.
- Sync/apply command.
- Drift detection.
- Reviewable output for CI/CD.

### 10. Better deployment documentation

Needed docs for:

- Required JWT secret length and rotation.
- Cookie settings behind reverse proxies.
- CSRF behavior and opt-out rules.
- CORS setup for browser clients.
- HTTPS requirements.
- Postgres versus SQLite guarantees.
- OAuth client setup for Moodle/OIDC relying parties.
- API-key/service-account operational practices.

### 11. Stronger CI checks for TDMP consumers

Needed:

- Route-map regeneration check.
- OpenAPI diff check.
- Migration diff check.
- Forbidden public-route drift check.
- Auth smoke tests for protected routes.
- OAuth end-to-end test in CI.

## Priority 2 — Maturity and ecosystem improvements

### 12. Compatibility matrix

Document and test supported versions for:

- Bun.
- Node.js.
- Hono.
- Drizzle.
- PostgreSQL.
- SQLite.
- SvelteKit.
- OpenTelemetry packages.

### 13. More examples

Needed examples:

- Production Hono app with CSRF/cookies/CORS.
- Pure API bearer-token app.
- Service-account/API-key app.
- OAuth/OIDC provider with Moodle-like relying party.
- Admin bootstrap and policy sync.
- Tenancy example after hardening is released.

### 14. Better observability defaults

Needed:

- Standard dashboards for auth failures, token reuse, OAuth errors, API-key usage, RBAC denies, and latency.
- Recommended alerts.
- Structured audit event catalog.
- Guidance for high-cardinality attributes.

### 15. Public maturity signals

If Fortress is intended to become a general-purpose auth library, it needs stronger maturity signals.

Needed:

- Security policy with supported versions.
- Release notes that clearly mark security fixes.
- Threat model documentation.
- Changelog discipline.
- Public examples and hardening guides.
- Independent audit summary when available.

## TDMP-specific immediate checklist

- [ ] Publish/release Fortress version containing `0.1.2` fixes.
- [ ] Decide whether the unreleased tenancy hardening should be included in the next release.
- [ ] Upgrade TDMP dependency from `0.1.1`.
- [ ] Generate and review DB migrations.
- [ ] Regenerate `src/generated/route-map.ts`.
- [ ] Run auth, API-key, IAM, and OAuth regression tests.
- [ ] Verify Moodle/OIDC login flow.
- [ ] Audit TDMP-owned auth wrapper routes for CSRF/rate-limit/audit behavior.
- [ ] Keep tenancy unmounted until hardening is released and reviewed.
