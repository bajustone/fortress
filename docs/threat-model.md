# Fortress Threat Model

Date: 2026-06-08
Scope: Fortress core auth/IAM, HTTP pipeline, adapters, and first-party plugins.

## Security goals

- Authenticate users and non-human principals with bounded, revocable credentials.
- Authorize every non-public Fortress route by default-deny metadata (`security`, `permission`, `bearerKind`).
- Keep browser-cookie flows protected against CSRF.
- Prevent tenant/data isolation bypass across users, service accounts, tenants, and pooled DB connections.
- Preserve auditability for security-relevant state changes.
- Make route, OpenAPI, and migration drift visible in CI.

## Trust boundaries

| Boundary | Trusted side | Untrusted side | Controls |
|---|---|---|---|
| HTTP request ingress | Fortress pipeline / adapter wrapper | Browser, API clients, reverse proxies | route manifest, CSRF, auth, RBAC, validation |
| JWT verification | Fortress `verifyToken` with pinned algorithm/issuer | Client-supplied bearer/cookie token | HS256 pinning, issuer check, reserved-claim stripping |
| Plugin principal resolution | Registered plugin code | API key/OAuth/mTLS-like credential values | first non-null resolver wins, RBAC still applies |
| Plugin descriptor publication | Post-factory validated capability snapshot | Caller-owned mutable descriptors and containers | construction-fixed callable identities and copied/frozen internal envelopes |
| Database adapter | Fortress services + configured adapter | User-controlled fields | schema validation, parameterized adapter queries, migrations |
| Tenant schema switching | Verified JWT custom claim + transaction-pinned adapter | Headers / route body tenant hints | no `X-Tenant-Code`, numeric schema ids, bound `set_config` |
| OAuth redirects | Registered clients and redirect URI list | Browser redirect parameters | exact/loopback URI matching, issuer identification, PKCE |

## Assets

- Password hashes and login identifiers.
- Access/refresh tokens, OAuth authorization codes, OAuth access/refresh tokens, API-key hashes.
- IAM roles, permissions, bindings, groups, service accounts.
- Tenant memberships and tenant-scoped business data.
- Audit logs and webhook delivery records.
- OAuth signing keys and OIDC JWKS metadata.

## Threats and mitigations

### OAuth/OIDC flows

Threats:
- Authorization-code interception/replay.
- Public client without PKCE.
- Redirect URI mix-up or open redirect.
- Client grant/scope escalation.
- Non-standard token endpoint errors confusing relying parties.

Mitigations:
- PKCE required for public clients and enforced at authorization-code issuance/exchange.
- Authorization codes are single-use and exchanged atomically.
- Redirect URI matching is exact except RFC 8252 loopback dynamic-port allowance.
- Authorization responses include `iss`; discovery advertises support.
- Per-client `grantTypes`, `tokenEndpointAuthMethod`, and `allowedScopes` are enforced.
- OAuth protocol routes are explicitly marked `bearerKind: 'oauth'`; other `/oauth/*` routes use normal Fortress JWT/RBAC.

Residual risks:
- Legacy compatibility flags can weaken posture if enabled; document and monitor them.
- Client compromise remains out of scope except revocation/removal controls.

### Refresh-token rotation/replay

Threats:
- Stolen refresh token reused after rotation.
- Concurrent refresh racing to mint multiple valid descendants.
- Timing leaks on token hash comparison.

Mitigations:
- Refresh rotation records token family and revokes family on reuse.
- SQLite transactions are serialized with `BEGIN IMMEDIATE`; PostgreSQL uses adapter transactions.
- Constant-time hash compare is used for security-critical token/code hashes.
- Refresh-cookie CSRF is detected even when only the refresh cookie remains.

Residual risks:
- Already-issued access tokens remain valid until expiry unless sessions are revoked and checked by the host flow.

### CSRF and cookies

Threats:
- Cross-site POST using ambient auth/refresh cookies.
- Silent SvelteKit refresh on unsafe requests.
- Hosts explicitly disabling secure cookies outside plain-HTTP local development.

Mitigations:
- Pipeline CSRF is on by default for unsafe methods carrying access or refresh cookies.
- Rejects `Sec-Fetch-Site: cross-site`; requires custom CSRF header.
- SvelteKit silent refresh is restricted to safe methods.
- Cookies default to `Secure` and `__Host-` names unless explicitly opted out for local HTTP.

Residual risks:
- Hosts can disable CSRF or widen skip paths; review configuration and CORS policy together.

### IAM/RBAC authorization and cache invalidation

Threats:
- Public route accidentally declares permission or protected route lacks permission.
- Stale permission cache after role/binding mutation.
- Service account inherits user/group permissions unexpectedly.

Mitigations:
- Startup rejects `security: ['none']` plus `permission` collisions.
- Fortress-managed route pipeline default-denies routes with no usable security metadata.
- Route manifest classifies every mounted route; drift helpers compare manifest/OpenAPI/RBAC.
- IAM service invalidates permission cache on permission/role/group/binding mutations.
- Service accounts have their own subject type and do not inherit group membership.

Residual risks:
- Host-owned routes must opt into `protect()` or adapter route maps; unwrapped routes are application responsibility.

### API-key and service-account flows

Threats:
- API key mints broader keys or manages other principals.
- API key bypasses IAM by being accepted as a user session.
- Leaked key continues indefinitely.

Mitigations:
- API keys resolve through plugin principal chain to `USER` or `SERVICE_ACCOUNT` subject.
- API-key routes without `meta.permission` require a resolved subject and return 401 when resolution fails; they do not invoke IAM.
- Routes with `meta.permission` use subject type and optional credential scopes in the IAM decision.
- Self-service API-key routes deny API-key credentials from minting/listing/revoking/rotating keys.
- Keys are stored hashed and can expire/revoke; admin routes require explicit permissions.

Residual risks:
- API-key scopes are credential-level narrowing for declared IAM permissions, not standalone route permissions. Sensitive routes must declare `.permission(...)`; an authenticated-only route accepts any successfully resolved subject without an IAM decision.
- Route security metadata does not add credential-provenance tagging beyond the configured principal resolver pipeline.
- Hosts should rate-limit key usage and rotate/revoke leaked keys quickly.

### Plugin descriptor mutation

Threats:
- A caller adds or replaces a principal resolver, middleware handler, auth hook, adapter wrapper, or scope rule after startup validation.
- Mutation of middleware/hook arrays changes ordering or makes the manifest disagree with the request pipeline.
- Framework adapters or built-in plugins observe a different plugin view from core request handling.

Mitigations:
- Plugin factories run first; Fortress then materializes and validates known descriptor fields exactly once into a construction-owned capability view.
- Membership, descriptors, hook/middleware envelopes, and ordering are fixed internally without freezing or rewriting caller-owned values.
- Core, auth services, Express, Hono, SvelteKit, manifest generation, OpenAPI, and Admin share the same published view, including provenance-bearing endpoint snapshots.
- Present callable slots and nested middleware/post-auth-gate definitions fail construction when malformed.

Residual risks:
- Captured plugin code is trusted. Callables retain their original descriptor/hook/middleware receiver for compatibility; state on that receiver, inside a closure, or in any external object the callable chooses to consult remains dynamic.
- The object returned by `methods()` has a separate identity/dispatch compatibility boundary tracked independently; replacing the descriptor's `methods` factory after construction is already ineffective.

### Tenancy and data isolation

Threats:
- Header-selected tenant lets one user choose another tenant.
- Tenant code/tax ID injected into SQL identifiers.
- `search_path` set on one pooled connection but query runs on another.
- Missing tenant claim silently falls back to public/shared data.

Mitigations:
- Tenant context comes from verified `claims.customClaims.tenantId`, issued from `tenant_user` membership.
- Tenant schema names use numeric database ids (`tenant_<id>`) and validated prefix.
- Invalid tenant claims are rejected before schema switching.
- PostgreSQL `search_path` is pinned with bound `set_config('search_path', ?, true)` inside the same transaction/connection as the operation.
- Tenant business tables should live only in tenant schemas, not `public`.

Residual risks:
- JWT tenant membership is stale until access token expiry/refresh/session revocation.
- Per-tenant business-table migrations are host-owned via `onSchemaCreated` or deployment tooling.

## Security review packet

Provide an independent reviewer with:

- This threat model.
- `docs/security.md` and `SECURITY.md`.
- Route manifest JSON from the reviewed configuration (`fortress.manifest`).
- OpenAPI spec from the same configuration.
- Migration status/drift output (`getMigrationStatus`, `detectMigrationDrift`).
- Architecture overview: `docs/architecture.md`.
- Relevant prior review/remediation docs in `docs/*review*` and `docs/*remediation*`.

## CI checks recommended

- `bun run lint`
- `bun run typecheck`
- `bun run test`
- `fortress manifest:check --module <path>` for your full route surface (without `--module` it covers Fortress's core surface only), plus app-level `detectRouteManifestDrift()`.
- `fortress migrate:check` plus live `detectMigrationDrift()` against deployment DBs.
- OpenAPI diff review for newly-public endpoints.
