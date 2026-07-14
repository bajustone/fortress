# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Fortress, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: security@bajustone.dev

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 1.0.x release candidates | Yes |
| 0.2.x   | Yes       |
| 0.1.x   | Security fixes only |
| 0.0.x   | No (please upgrade) |

Until 1.0 final, breaking changes may ship in a release candidate or minor release. Pin deliberately and review the migration notes.

## Security Best Practices

### Route security manifest

Use `fortress.manifest` (or `fortress manifest` for the core auth/IAM surface) to review which routes are public, authenticated, RBAC-protected, OAuth self-managed, CSRF-applicable, and rate-limited. Add `detectRouteManifestDrift()` to CI when generating OpenAPI specs or mounting plugin routes so route protection metadata cannot silently drift.

For app-owned routes that call Fortress services directly, prefer `protect()` / adapter `protectedRoute()` wrappers so CSRF, auth, RBAC, validation, and plugin middleware still run from endpoint metadata. See [docs/host-owned-routes.md](docs/host-owned-routes.md).

### Input validation

Request validation runs on `@bajustone/fetcher`'s `fromJSONSchema` engine. For security-sensitive inputs:
- Use the **enforced** format builders (`email()`, `uuid()`, `url()`, `datetime()`) rather than the annotation-only `strFormat()` — their patterns are ReDoS-safe (linear-time) and checked at runtime.
- Wrap request-body objects in `strict()` (`additionalProperties: false`) to reject unknown keys and prevent over-posting / mass-assignment.
- Object validators are prototype-pollution-safe (null-prototype accumulation; a literal `__proto__` key is treated as an ordinary property).
- Note: `$ref` fields in request bodies are present-but-unconstrained at validation time — validate referenced shapes inline (or in the handler) when their contents are security-relevant.

### Outbound HTTP

Fortress's outbound calls (OAuth/OIDC token exchange, discovery, provider userinfo, GitHub profile, and the HIBP breach check) run through a shared `@bajustone/fetcher` client with a request **timeout**, so a hung or slow upstream cannot stall a login or registration. The HIBP breach check **fails open** — a timeout or error never blocks a password — and only ever sends the 5-character k-anonymity hash prefix. OIDC discovery/issuer URLs are consumer-supplied: if you accept untrusted issuer configuration, treat outbound discovery as an SSRF surface (an opt-in IP-pinning guard for outbound calls is planned, mirroring the webhook plugin's transport).

### Webhook delivery

Webhook endpoint URLs are consumer-supplied, so the **webhook plugin** treats delivery as a live SSRF surface: it delivers over HTTPS only, resolves and validates the target (rejecting private/loopback/link-local/CGNAT addresses across IPv4, IPv6, `::ffff:`-mapped, and `64:ff9b::/96` NAT64 forms), and **pins the connection to the resolved IP** to close the DNS-rebinding window between validation and connect. Overriding `delivery.fetch` bypasses this guard — only do so for targets you control. Signing secrets are CSPRNG-generated, returned only at `registerEndpoint`/`rotateSecret`, and **redacted** from `listEndpoints`/`updateEndpoint`; rotate with `rotateSecret`. Webhook payloads are HMAC-signed but **not encrypted** — never include secrets or PII in a payload. See [docs/plugins/webhook.md](docs/plugins/webhook.md).

Track Fortress-owned table/index upgrades with `fortress_schema_version`, `getMigrationStatus()`, and the bundled SQL under `migrations/{sqlite,pg}`. Auth, IAM, OAuth, API-key, tenancy, and audit-log tables are security-critical; do not skip migration drift checks during upgrades.

See [docs/security.md](docs/security.md) for comprehensive security guidance, [docs/threat-model.md](docs/threat-model.md) for the current formal threat model, [docs/hardening.md](docs/hardening.md) for the production hardening checklist, [docs/deployment.md](docs/deployment.md) for the production deployment guide (JWT secret rotation, cookies behind reverse proxies, CSRF/CORS recipes, HTTPS requirements, OAuth/OIDC RP setup), and [docs/migrations/upgrade-guide.md](docs/migrations/upgrade-guide.md) for the migration runbook.

## Registration account-enumeration tradeoff

The built-in public `POST /auth/register` endpoint intentionally returns a
409 when the submitted email already exists. This is useful UX for many
first-party apps but is an account-enumeration signal. Treat this as an
accepted tradeoff unless your product requires non-enumerating registration.
If you do, wrap registration with your own flow (e.g. always return 202 and
send either a verification email or an "already have an account" email).

When using the built-in endpoint publicly, mount the rate-limit plugin with
`register` protection enabled to slow bulk enumeration.

## Login is not an enumeration oracle

In contrast to `register`, `auth.login()` is intentionally
timing-equalized: the "user not found / no password set" branch runs a real
Argon2id verify against a well-formed reference hash produced by the
configured `PasswordHasher`, not a hard-coded dummy. Both that branch and
the "wrong password" branch take the same wall-clock time and return the
same generic `Invalid credentials` error, so a remote attacker cannot
distinguish "account exists" from "account missing" via response timing or
error text. The same path also covers disabled accounts to avoid leaking
`isActive` state. The regression test lives in
`src/core/auth/login-timing.test.ts`.

## Tenancy isolation model

The tenancy plugin derives the active tenant from the verified JWT custom
claim (`claims.customClaims.tenantId`) that is issued from `tenant_user`
membership, never from a client-controlled header.

Tenant schema names use the numeric tenant id (`tenant_<id>` by default), so
untrusted tenant codes/tax IDs are not interpolated as SQL identifiers. For
PostgreSQL requests with a tenant claim, the adapter wrapper pins
`search_path` with `set_config('search_path', ?, true)` inside the same
transaction and connection as the operation. Without a tenant claim, the
adapter is unchanged; tenant business tables should live outside `public`, so
missing tenant context fails closed.

Tenant access in JWTs has the normal staleness tradeoff: removing a user from
a tenant does not revoke already-issued access tokens until they expire or are
refreshed. Use short access-token lifetimes and session/token revocation when
immediate removal is required.

## Cookie posture (SvelteKit / `fortress.handleRequest`)

When using `fortress.handleRequest` directly or the SvelteKit adapter, auth
tokens are written to two `httpOnly` cookies. Defaults from
`FortressConfig.cookies` are now production-safe regardless of `NODE_ENV`:

| Default | Access cookie | Refresh cookie | Attributes |
|---|---|---|---|
| All environments | `__Host-fortress_access` | `__Host-fortress_refresh` | `HttpOnly; Secure; SameSite=Lax; Path=/` |

The `__Host-` prefix binds the cookie to the exact origin (no `Domain`, no
subpath, must be `Secure`) — the strongest browser-enforced isolation.
Many production runtimes do not reliably set `NODE_ENV=production`, so
Fortress no longer infers cookie security from that variable.

Local HTTP development must opt out explicitly:

```ts
createFortress({
  // ...
  cookies: { secure: false }, // drops __Host- prefix; localhost HTTP only
})
```

Override via `FortressConfig.cookies` if you need a `Domain`, `Path`,
custom names, or `SameSite=strict`. Note: `SameSite=strict` blocks
top-level cross-site navigation cookies, which breaks magic-link email
flows and OAuth callbacks. Stick with `lax` unless you know you don't need
them.

## CSRF posture

Fortress now performs its own pipeline CSRF check on Fortress-managed
routes (`/auth/*`, `/iam/*`, plugin paths) before dispatch. The check is on
by default for unsafe methods (`POST`, `PUT`, `PATCH`, `DELETE`) whenever
the request carries a Fortress access **or refresh** cookie:

- `Sec-Fetch-Site: cross-site` is rejected.
- A custom header is required (`X-Fortress-CSRF` by default).
- The check is not bypassed just because an `Authorization` or API-key
  header is also present; cookies remain ambient browser credentials.
- Pure bearer/API-key requests with no Fortress cookies skip the check.

Configure via:

```ts
createFortress({
  // ...
  csrf: {
    enabled: true,
    headerName: 'X-Fortress-CSRF',
    skipPaths: [],
  },
})
```

Set `csrf.enabled = false` only for pure bearer/API deployments where no
Fortress route is reachable with ambient cookies. SvelteKit form actions
that go through `resolve()` remain subject to SvelteKit's own
`csrf.checkOrigin`; keep that enabled as defense in depth.

## Refresh-token concurrency posture

Fortress uses strict refresh-token replay semantics. When two concurrent
refresh attempts present the same refresh token, exactly one can rotate it;
the loser is treated as token reuse and the entire token family is revoked,
including the winner's newly issued refresh token. This favors theft
containment over a concurrency grace window. Applications with aggressive
multi-tab auto-refresh should coordinate refreshes client-side or add a
server-side single-flight/grace mechanism.

## SSR auto-refresh race

The SvelteKit handle hook auto-refreshes an expired access cookie when a
valid refresh cookie is present. Opening N tabs simultaneously triggers N
parallel refresh attempts; Fortress's refresh-token family rotation will
succeed for one and fail for the others (with `TOKEN_REUSE`). This is a
fundamental trade-off of the JWT + family-rotation model. If your UX
requires zero-friction multi-tab opens, consider:

- Adding a short grace window on rotation (`refreshTokenExpirySeconds`
  overlap)
- Storing the refresh attempt in a per-user lock (custom plugin)
- Falling back to a server-side session table for the refresh side

## Social login hardening

Social-login callbacks verify OAuth `state` with a timing-safe comparison and keep it separate from the OIDC `nonce`. OIDC providers must return an `id_token`; Fortress verifies its JWS signature through the provider JWKS and validates issuer, audience, expiry, and nonce before account linking or provisioning. By-email account linking requires `emailVerified === true` and an active local user; provider profile mappers fail closed on an absent `email_verified` claim (including Microsoft/Entra, whose Graph `/me` and id_tokens commonly omit it), so a missing claim never satisfies the auto-link gate. Provider access and refresh tokens are stored only when `persistTokens: true` is explicitly enabled, and then are encrypted at rest with AES-256-GCM using `tokenEncryptionKey`; persistence fails closed without the key.

## Admin bootstrap hardening

The admin bootstrap endpoint is not mounted by default. Enable it explicitly with `admin({ bootstrap: { enabled: true, secret } })` (or `FORTRESS_ADMIN_BOOTSTRAP_SECRET`). It succeeds only while no `fortress-admin` role bindings exist and only when the one-time secret matches; there is no `adminUserIds` superadmin bypass.

## Tenant-less permission checks

Tenant-less permission checks match only tenant-less (`tenant_id IS NULL`) role/direct-permission bindings. Tenant-scoped grants are considered only when the check supplies the matching tenant id.
