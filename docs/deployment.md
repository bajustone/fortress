# Fortress production deployment guide

This guide covers what changes between local dev and production for a
Fortress-backed service. Treat each section as a checklist — every
production deployment should explicitly answer or skip each item.

## 1. JWT secret

The JWT signing secret (`FortressConfig.jwt.key`) must be **at least
32 bytes** of cryptographically random material. Anything shorter throws
at `createFortress` startup.

Generate one with the bundled CLI:

```sh
fortress generate-secret
# 64-byte hex string (128 chars); paste into your secret manager
```

Recommendations:

- Store the secret in your platform's secret manager (AWS Secrets
  Manager, GCP Secret Manager, Vault, Doppler, Fly secrets, etc.).
  Never commit it.
- Rotate the secret periodically. Fortress supports an array of secrets
  on `jwt.key` — the first entry is used for **signing**, all entries
  are accepted for **verification**. Add the new secret to position 0,
  redeploy, wait until every issued token has expired (typically the
  access-token lifetime + grace), then remove the old one.
- For multi-region deployments, replicate the same secret across regions
  so tokens issued in one region verify in another.

## 2. Cookies behind reverse proxies

Fortress defaults to `__Host-fortress_access` / `__Host-fortress_refresh`
cookies with `HttpOnly; Secure; SameSite=Lax; Path=/`. The `__Host-`
prefix is the strongest browser-enforced isolation: the cookie is bound
to the exact origin, has no `Domain` attribute, and **must** be sent
over HTTPS.

When deploying behind a reverse proxy (nginx, Caddy, ELB, Fly, Cloud
Run, fly-replay):

- **Terminate TLS at the proxy.** Set `X-Forwarded-Proto: https` so the
  app sees the original scheme. Fortress only relies on this for IP /
  user-agent metadata, but most frameworks (Hono, Express, SvelteKit)
  use it to construct absolute URLs and cookie attributes.
- **Forward the original host.** Set `Host` to the client-facing
  hostname — `__Host-` cookies are pinned to it.
- **Forward `X-Forwarded-For`.** Fortress reads `X-Forwarded-For` then
  `X-Real-IP` for rate-limit keys and refresh-token metadata. Strip any
  client-supplied values at the edge; only trust hops you control.
- **Do not strip cookies.** Some CDN configurations drop `Set-Cookie`
  by default on cacheable responses. Whitelist
  `set-cookie: __Host-fortress_*` (or your renamed prefix) on every
  Fortress-served path.

To opt into a custom cookie name / scope, set
`FortressConfig.cookies` — for example a top-level apex domain:

```ts
createFortress({
  // ...
  cookies: {
    accessName: 'app_access',
    refreshName: 'app_refresh',
    domain: 'example.com',
    secure: true,
    sameSite: 'lax',
    path: '/',
  },
});
```

Setting a `domain` removes the `__Host-` prefix automatically because
the prefix forbids cross-subdomain cookies.

## 3. CSRF: opt-out rules and recipes

Pipeline CSRF is on by default for unsafe methods (POST/PUT/PATCH/DELETE)
on Fortress-managed routes when the request carries a Fortress auth
cookie. Bearer-only and API-key requests are immune by construction and
are skipped.

Common production tweaks:

- **Pure API backends (no browser cookies):** set `csrf: { enabled: false }`.
  Every request authenticates via bearer/API-key; there is no ambient
  credential to protect.
- **SPA on the same origin:** keep the default. The SPA sends a custom
  header (`X-Fortress-CSRF: 1` by default — value is not validated, the
  *presence* is what matters because cross-site code cannot set custom
  headers without a CORS preflight you've allowed).
- **SPA on a sibling subdomain** (`app.example.com` calling
  `api.example.com`): keep the default `rejectSameSite: false`; the
  legitimate `Sec-Fetch-Site: same-site` traffic must pass.
- **Single-host browser app, no cross-subdomain calls:** set
  `csrf: { rejectSameSite: true }` to also reject same-site requests,
  closing the residual risk of a malicious subdomain.

Skip specific paths if a third party must call them without a custom
header (webhooks, OAuth `/oauth/token`, etc.):

```ts
csrf: {
  enabled: true,
  skipPaths: ['/oauth/token', '/oauth/revoke', '/webhooks/incoming'],
}
```

`/oauth/*` protocol endpoints are already classified as
`oauth-protocol` in the route manifest and self-authenticate via
bearer tokens; they don't need a CSRF skip unless you've put them
behind cookie auth somehow.

## 4. CORS

Fortress does not ship a CORS middleware — each adapter delegates to its
host framework. Mount your framework's CORS middleware **before**
`mountFortress`, and:

- Set `Access-Control-Allow-Credentials: true` if your SPA sends
  cookies.
- Set `Access-Control-Allow-Origin` to the explicit SPA origin (never
  `*`) when credentials are allowed.
- Include `X-Fortress-CSRF` (and any custom header you renamed it to)
  in `Access-Control-Allow-Headers`.
- Include `Authorization` and `X-API-Key` if you authenticate via
  bearer/API-key from the browser.

Example (Hono):

```ts
import { cors } from 'hono/cors';

app.use('*', cors({
  origin: 'https://app.example.com',
  credentials: true,
  allowHeaders: ['Content-Type', 'Authorization', 'X-API-Key', 'X-Fortress-CSRF'],
  exposeHeaders: ['Retry-After'],
}));
mountFortress(app, fortress);
```

## 5. HTTPS requirements

- The OAuth plugin **refuses to start** in production
  (`NODE_ENV=production`) unless `issuerUrl` is HTTPS. Loopback URLs are
  exempt for dev.
- `__Host-` cookies require HTTPS at the browser. If you do not run
  HTTPS in production, set `cookies: { secure: false }` — but you are
  giving up the strongest cookie isolation and exposing tokens to any
  on-path attacker.
- Every external dependency Fortress speaks to (social-login providers,
  webhook destinations, OIDC discovery URLs) should use HTTPS. The
  social-login plugin assumes provider URLs are HTTPS; provider configs
  with `http://` URLs are accepted but should be flagged in code review.

## 6. PostgreSQL vs SQLite guarantees

| Concern | PostgreSQL | SQLite (`bun:sqlite`, `better-sqlite3`) |
|---|---|---|
| Concurrent writers | Yes, MVCC | One writer at a time (serialized in the adapter via `BEGIN IMMEDIATE`) |
| Tenancy `search_path` switching | Supported (transaction-pinned `set_config`) | Not supported — tenancy plugin is pass-through |
| Recommended for production | ✅ | Single-node deployments only (Fly Volumes, edge SQLite) |
| Migrations against a live DB | Standard | Use a small migration window; SQLite serializes writers |
| Drift checker `missingTables` | Reads `information_schema` | Reads `sqlite_master` |
| OAuth `oauth_signing_key` | Persisted; rotation safe | Persisted; rotation safe |

SQLite is perfectly fine for small to medium services that don't need
horizontal write scaling. Use Postgres when you need multi-region, true
tenancy schema isolation, or when an external tool needs to read the
schema (BI, replication).

## 7. OAuth / OIDC RP setup

The OAuth plugin acts as an **authorization server**. To enable it:

```ts
oauth({
  issuerUrl: 'https://auth.example.com',           // HTTPS mandatory in prod
  loginUrl: 'https://app.example.com/signin',      // your SPA login page
  consentUrl: 'https://app.example.com/oauth/consent', // your SPA consent page
  // Optional: per-deployment OIDC userinfo claim shaping
  userinfoClaims: async (user, scope) => ({ /* ... */ }),
})
```

Key production knobs:

- **`issuerUrl`** is signed into every id_token (`iss` claim) and is the
  base of every discovery URL. Setting it wrong locks every client out
  — pick once, document, treat as part of your stable public API.
- **Discovery** is served from
  `${issuerUrl}/oauth/.well-known/openid-configuration`. Cache for
  minutes, not hours; the JWKS rotation cadence depends on your
  `oauth_signing_key` rotation policy.
- **JWKS** is served from `${issuerUrl}/oauth/.well-known/jwks.json`.
  RPs typically cache it for 5–15 minutes; signing-key rotations are
  picked up next cache refresh.
- **Refresh tokens** are rotated by default; reuse triggers a
  family-wide revocation per RFC 9700 §2.2.2. Configure
  `refreshTokenExpirySeconds` to match your session policy (0 disables
  refresh entirely).
- **Public clients** (SPAs, native apps) must register with
  `tokenEndpointAuthMethod: 'none'` and use PKCE. Confidential clients
  default to `client_secret_basic`; opt into `'client_secret_post'` per
  client if needed.
- **Per-client `allowedScopes`** narrows what each RP can request.
  Leave blank for legacy clients with broad scopes; set explicitly for
  any new integration.

## 8. API-key and service-account operations

- API-key plugin endpoints are opt-in (`apiKey({ routes: true })`). In
  production, decide:
  - User self-service rotation: mount `routes: true` and put rate-limit
    on `/api-key/keys`.
  - Admin-only rotation: leave `routes: false` and rotate via the
    admin plugin's `/admin/users/:userId/api-keys` endpoints (requires
    `apiKey:manage` permission).
- Service accounts have no sessions and no group memberships. Provision
  them via `/iam/service-accounts` (admin plugin) or
  `fortress.iam.createServiceAccount(...)`. Mint API keys against them
  via `/admin/service-accounts/:id/api-keys`.
- Hash storage: API keys are stored as SHA-256 of the prefix + secret
  with the plaintext returned only on issuance. If a key leaks, revoke
  it via `DELETE /api-key/keys/:id` (or admin route); rotation via
  `POST /api-key/keys/:id/rotate` keeps the same `name` and revokes the
  predecessor in a single transaction.
- Rate-limit API-key issuance separately from user logins:
  `rateLimit({ apiKeyIssue: { maxPerIp: 5, maxPerUser: 5, windowSeconds: 3600 } })`.

## 9. Migration runbook

1. **Pre-deploy:** use `fortress migrate:check --dialect <dialect>` to
   validate the installed bundled catalog. Fortress contributors additionally
   run `bun run generate:migrations --check`; this fails on any missing, extra,
   or byte-modified committed SQL projection. Neither command inspects a live
   database.
2. **Deploy:** call `migrateUp(adapter)` on application start or run
   `fortress migrate:up --module ./src/fortress.ts` in a one-shot job. The
   `MigratableDatabaseAdapter` selects the live dialect; no separate override
   exists. Runtime data steps and their SQL execute atomically. Both
   `migrateUp` and `migrateDown` are idempotent.
3. **Post-deploy:** in your healthcheck, call
   `detectMigrationDrift(adapter)` and fail the healthcheck on
   `missingTables` / `missingVersionTable`. The load balancer pulls the
   instance out of rotation until drift is fixed.

For irreversible migrations (column drops, type narrowing), keep the
old code shape supported for at least one release before removing it,
and take a database snapshot immediately before applying. See
[docs/migrations/upgrade-guide.md](./migrations/upgrade-guide.md) for
the runtime API and CLI reference.

## 10. Observability

- Pass a structured logger (`pino`, `bunyan`, framework-provided) to
  `FortressConfig.logger` so security-critical events (token reuse,
  account lockout, OAuth errors) are searchable.
- Wire OpenTelemetry via `@bajustone/fortress/otel`'s
  `createOtelTelemetry()`. Fortress emits stable
  `db.client.operation.duration`,
  `fortress.auth.events.total`, IAM permission-check histograms, and
  a deny-only span (`fortress.iam.permission_check.deny`).
- High-cardinality data (user IDs, emails, tenant IDs) is deliberately
  kept off metric attributes — it lives on spans and structured logs.

## 11. Backups & disaster recovery

- Back up the database before every deploy that ships a migration.
  Test restores quarterly.
- The `oauth_signing_key` row is **the** RSA signing material for every
  OIDC id_token. Losing it invalidates every outstanding id_token (RPs
  re-authenticate). Treat it like a JWT secret — back it up with the
  database, never export it.
- Audit-log rows are append-only and hash-chained when
  `auditLog({ hashChain: true })` is enabled. Restoring from backup
  preserves the chain; appending out-of-order rows breaks it. If you
  restore, run a chain verification job before resuming writes.
- Rate-limit counter store (the in-memory default) is **not** durable.
  In production with multiple instances, bring your own store
  (Redis, Memcached) so limits apply across replicas.

## 12. Checklist

Use this before promoting a release to production:

- [ ] JWT secret is ≥ 32 bytes, stored in a secret manager, rotated on a
      schedule.
- [ ] HTTPS terminated end-to-end; `X-Forwarded-Proto`, `Host`, and
      `X-Forwarded-For` set by the proxy.
- [ ] Cookies: `__Host-` prefix or explicit `domain` + `secure: true`.
- [ ] CSRF policy chosen explicitly (default, `rejectSameSite`, or
      disabled) and documented in code review.
- [ ] CORS allow-list pins exact SPA origin and exposes the CSRF
      header.
- [ ] OAuth `issuerUrl` is HTTPS in production; discovery and JWKS
      endpoints reachable from RPs.
- [ ] Rate-limit plugin mounted with `login`/`register`/`refresh`
      defaults; named rules cover `/api/*`.
- [ ] Audit-log plugin mounted with `hashChain: true` for any flow
      that ships compliance evidence.
- [ ] Bundled catalog validation in CI; live `migrateUp` (or explicit-module
      CLI migration) plus an adapter-backed drift check in the deploy path.
- [ ] OpenTelemetry exporter or structured logger wired so security
      events leave the box.
- [ ] Backup + restore tested for the database; signing keys included.
