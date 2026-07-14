# Hardening

A focused checklist for operators running Fortress in production. Pair
with [deployment.md](./deployment.md) (configuration), [security.md](./security.md) (architecture),
and [threat-model.md](./threat-model.md) (attacker model).

Each item is "what to do" + "why" + "how to verify".

## Identity and credentials

### JWT secret

- **Do:** Generate via `fortress generate-secret` (64 bytes hex, exceeds the 32-byte HS256 minimum). Store in a secret manager. Rotate at least annually and immediately on suspected compromise.
- **Why:** A leaked HS256 secret lets an attacker forge any access token. Fortress validates secret length at boot — anything shorter throws.
- **Verify:** `createFortress` accepts an array for rotation (`jwt.key: [new, old]`) — make sure your rotation playbook adds `new` to position 0, redeploys, waits past `accessTokenExpirySeconds`, removes `old`.

### Cookie posture

- **Do:** Keep the `__Host-` prefix defaults. Only set `cookies: { secure: false }` for localhost HTTP dev.
- **Why:** `__Host-` cookies are scoped to the origin, have no `Domain`, and refuse to be set without HTTPS — the strongest browser-enforced isolation.
- **Verify:** `curl -I https://your-domain/auth/login` returns `Set-Cookie: __Host-fortress_*` with `Secure; HttpOnly; SameSite=Lax; Path=/`.

### Password policy

- **Do:** Keep the default `passwordPolicy.minLength` of 15 and enable `checkBreached`; choose `breachedFailureMode: 'closed'` when assurance is more important than registration availability.
- **Why:** Length plus breached-password screening provides useful resistance without brittle composition rules. Every HIBP outage emits `PASSWORD_BREACH_CHECK_DEGRADED` for alerting.
- **Verify:** Try registering with `"abc"` — it should reject with `BAD_REQUEST`; simulate an HIBP outage and verify your chosen open/closed behavior.

### Refresh-token posture

- **Do:** Keep `refreshTokenExpirySeconds` ≤ 30 days. Enforce per-device refresh family rotation (Fortress default). Treat any `TOKEN_REUSE_DETECTED` event as a paging incident.
- **Why:** Refresh-token reuse detection turns a stolen refresh token into a same-day revocation event. Without rotation, the attacker has the full token lifetime.

## Authorization

### Default-deny everywhere

- **Do:** Every Fortress-managed route should carry either `.security('none')` (intentional public) or `.permission(resource, action)` (default-deny). The mutual-exclusion check at boot will throw if you mix them.
- **Why:** The plan's stated goal — operators should never have to remember to add a guard.
- **Verify:** `fortress check:public-routes` in CI catches a stray `.security('none')`; the bootstrap allow-list covers only Fortress's intentional public surface.

### RBAC drift

- **Do:** Add `fortress manifest:check` to CI; also run `runFortressChecks({ fortress })` in a test that constructs your real `Fortress` instance.
- **Why:** Manifest drift catches "I added a route and forgot the `.permission` decorator" before it ships.

### Policy as code

- **Do:** Manage roles/groups/service accounts via `fortress.policy.json` instead of imperative `iam.createRole(...)` from production code. Reconcile in CI with `applyPolicyPlan(...)`.
- **Why:** Reviewable Git history for permission grants; no "who gave Bob role X?" mystery.

## Transport and edge

### HTTPS

- **Do:** Terminate TLS at the edge; redirect HTTP to HTTPS. Set HSTS via your edge (`Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`).
- **Why:** All security guarantees in this guide assume HTTPS in the browser.

### CSRF

- **Do:** Keep the default pipeline check on for cookie-authenticated browser sessions. Add `csrf: { rejectSameSite: true }` if your app is single-host (`example.com` only). Skip the check for routes that absolutely must accept third-party POSTs (webhooks) and replace it with signature verification per-route.
- **Why:** Cookies are ambient credentials; without a CSRF check, any malicious page can trigger a state change.
- **Verify:** A POST from a third-party origin (no `X-Fortress-CSRF` header, `Sec-Fetch-Site: cross-site`) returns 403.

### Rate limiting

- **Do:** Mount the `rate-limit` plugin with `login`, `register`, `refresh`, `oauthToken`, and `apiKeyIssue` blocks. In multi-replica deployments, bring your own `RateLimitStore` (Redis, Memcached) — the in-memory default does not coordinate across replicas.
- **Why:** Per-IP and per-account limits stop credential-stuffing and account-enumeration before they reach the password hasher.

## Data isolation

### Tenancy

- **Do:** Use the verified `tenantId` JWT claim (set by `enrichTokenClaims`); never an `X-Tenant-Code` header. Use numeric tenant IDs in schema names (`tenant_<id>`). For PostgreSQL, the adapter pins `search_path` per transaction via `set_config('search_path', ?, true)`.
- **Why:** The hardening plan documented in [docs/plugins/tenancy.md](./plugins/tenancy.md) closes a class of cross-tenant data-leak bugs.

### Multi-tenant scope rules

- **Do:** For row-level isolation across databases (not just PG), use the `data-isolation` plugin with explicit `scopes` per model.
- **Why:** Tenancy-via-schema only works on PG; everywhere else, scope rules are the safety net.

## Audit and logging

### Audit chain

- **Do:** Mount `auditLog({ hashChain: true })`. Schedule a nightly `verifyChain()` job. Mirror auth events into the audit log via an `addAuthObserver` (see [observability.md §6](./observability.md)).
- **Why:** Hash-chaining detects after-the-fact deletions; verification turns it into an enforced invariant.

### Structured logging

- **Do:** Pass a structured logger to `FortressConfig.logger` (`pino`, `fastify.log`, etc.). Default is silent — production without a logger means you'll never see token reuse or RBAC denials.
- **Why:** Security events are useless if no one sees them.

## Cryptographic posture

- **Do:** Stick with Argon2id (the default). Don't downgrade to PBKDF2/bcrypt without a measured reason.
- **Do:** Use the bundled OAuth signing key rotation (`oauth_signing_key` table); rotate quarterly.
- **Do:** When using social-login, pin provider issuer URLs to HTTPS; the bundled providers do this.

## Deployment hygiene

- **Do:** Run `bun run lint` + `bun run typecheck` + `bun run test` + `fortress migrate:check` + `fortress manifest:check` + `fortress check:public-routes` on every CI build. The shipped GitHub Actions workflow does all six (see [docs/ci/github-actions.yml](./ci/github-actions.yml)).
- **Do:** Take a database backup before every deploy that bumps a migration version; test restores quarterly.
- **Do:** Pin to a minor version (`@bajustone/fortress@~0.1`). Pre-1.0 Fortress reserves the right to ship breaking changes in any minor.

## Release notes discipline

The maintainer commits to:

- Every change that affects a security-relevant code path lands with a `### Security` or `### Changed` entry in the CHANGELOG noting the impact.
- Migration-bearing changes ship with a `docs/migrations/<version>.md` note (forward, rollback, backfill).
- Findings from external reviews land in `docs/security-review-<date>.md` with a remediation plan.

If a CHANGELOG entry for a security-affecting change is missing in a release, file an issue — it's a process bug.

## Reporting a vulnerability

See [SECURITY.md](../SECURITY.md). Email `security@bajustone.dev`. Acknowledgement within 48 hours, fix targeted within 7 days for criticals.
