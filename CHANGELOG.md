# Changelog

## [0.2.8] - 2026-06-10

### Fixed
- fix(release): keep jsr.json version in sync with package.json

## [0.2.7] - 2026-06-10

### Fixed
- fix

## [0.2.6] - 2026-06-10

### Fixed
- fix

## [Unreleased]

### Added
- **Release verification is now a hard publish prerequisite.** Tag publishing waits for lint, source and example typechecks, the full unit/OpenAPI-drift suite, PostgreSQL/Testcontainers integration tests, build/export parity, and a pure-Node-ESM `dist/testing` smoke test. PostgreSQL integration now runs on every CI push as well as pull requests and nightly schedules. The same checks are available locally through `bun run check:release`.
- **`@bajustone/fetcher` is now a runtime dependency, re-exported at `@bajustone/fortress/fetcher`.** The zero-dependency, Standard-Schema-V1-native fetch client + schema builder that fortress uses internally is surfaced so consumers can author endpoint schemas with the same toolkit and build their own validated outbound clients without a separate install. The subpath re-exports fetcher's root (`createFetch`, middleware, errors, types) flat, plus `schema`, `openapi`, and `specTools` namespaces.
- **Richer schema-builder DSL.** `str()`, `num()`, and `int()` now accept an options object as well as a bare description: `str({ min, max, pattern, format })`, `int({ min, max })` — the constraints are **enforced at runtime**. New builders: `literal(value)` (`const`), `intersect(...schemas)` (`allOf`), `strict(objSchema)` (`additionalProperties: false`, to reject over-posting/mass-assignment), and `discriminatedUnion(propertyName, ...variants)` (`oneOf` + `discriminator`).
- **Enforced string formats.** `email()`, `uuid()`, `url()`, `datetime()`, `date()`, and `time()` emit both a `format` annotation (for OpenAPI) and a ReDoS-safe `pattern` lifted from `@bajustone/fetcher`, so the value is now validated at runtime — previously `strFormat('email')` was annotation-only and never checked.
- **Author endpoint schemas with fetcher's builder.** `endpoint().body()/.query()/.params()/.response()` (and `vBody`/`vParam`/`vQuery`) accept schemas from `@bajustone/fortress/fetcher`'s `schema` namespace directly — fetcher's `object`/`optional`/`discriminatedUnion`/`transform`/`refined`/`brand`/`tuple`/… . They validate at runtime via fetcher's engine and serialize to clean OpenAPI (internal `~`-prefixed keys are stripped by the spec builder), unlocking combinators fortress's own DSL doesn't expose.
- **Outbound HTTP hardened via `@bajustone/fetcher`.** OAuth token exchange, OIDC discovery, provider userinfo, the GitHub profile fetch, and the HIBP breach check now route through a shared fetcher client (`src/core/http/outbound.ts`) that adds a request **timeout** — native `fetch` has none, so a hung upstream previously blocked login/registration indefinitely — and replaces unchecked `as` casts with schema-validated parsing (`access_token` presence on token exchange; JSON object/array shape on discovery/userinfo/GitHub). The HIBP check keeps its **fail-open**, plaintext, k-anonymity-prefix-only contract (6 s timeout, body read as text, never schema-parsed). No public API change.
- **Webhook plugin v1 — custom events + Bring-Your-Own-Queue.** Full rewrite of `@bajustone/fortress/plugins/webhook`:
  - **Custom events**: declare your own events (`{ name, schema?, description? }`) alongside the built-ins via `events`, and `emit(name, payload, { idempotencyKey? })` them through the same path. `emit()` validates the payload against the event's Standard Schema and a `maxPayloadBytes` cap, throwing a tagged `WebhookEmitError` (`unknown_event` / `invalid_payload` / `payload_too_large`).
  - **Bring-Your-Own-Queue**: delivery is always queued behind a `WebhookQueue` interface. Bundled `inMemoryQueue()` (default, dev-only — loses scheduled retries on restart) and crash-safe `databaseQueue({ pollMs })`; the `webhook_delivery` table is the transactional outbox.
  - **Delivery over `@bajustone/fetcher`** with an SSRF-safe transport that pins the connection to the resolved IP (now also blocking `64:ff9b::/96` NAT64 forms). Failure classification (404/410/421 → deactivate; other 4xx → fail-fast; 408/425/429/5xx/network → retry), jittered backoff, a per-endpoint **circuit breaker** (`maxConsecutiveFailures`), and `onDeliveryFailed`/`onEndpointDeactivated` DLQ hooks.
  - **Secrets** are CSPRNG-generated (returned once at `registerEndpoint`/`rotateSecret`) and **redacted** from `listEndpoints`/`updateEndpoint`. New `updateEndpoint`, `rotateSecret`, `listEventTypes`, `stop` methods. Stable per-delivery `webhook-id` (`msg_<deliveryId>`) for receiver dedup.
- **Observability types and trace parenting are now public and complete.** The package root and `/otel` export `FortressLogger`, `TelemetryProvider` and supporting tracer/meter/span types, Auth/IAM event and listener types, permission-check observer types, and `Unsubscribe`. Optional `Tracer.startActiveSpan` is part of the provider contract; `fortress.handleRequest` uses it across the async pipeline so nested database/IAM spans inherit the request span, while existing providers with only `startSpan` retain their prior runtime behavior. An SDK-backed regression verifies the parent span ID.
- **IAM mutation events now cover the full admin lifecycle.** `createPermission`/`deletePermission`, `updateGroup`, and `deleteGroup` emit `PERMISSION_CREATED`, `PERMISSION_DELETED`, `GROUP_UPDATED`, and `GROUP_DELETED`; audit-log filtering accepts those names plus the previously emitted role-update/role-permission events. Permission creation emits exactly once only for the concurrent caller that inserts the row. Group deletion transactionally removes the group identity and all memberships/GROUP role/direct-permission bindings under one serialized mutation lock, so non-cascading adapters cannot leave authorization orphans.
- **OpenAPI: Zod-free schema converters + a spec-drift CI gate.** `@bajustone/fortress/hono` now exports `identitySchemaConverter`, `fetcherSchemaConverter`, and `toJSONSchemaConverter` so you can `mountFortressOpenAPI` / `convertRoutes` using fortress's or fetcher's builder **without installing Zod** (existing Zod callers unaffected). A new gate (`src/core/openapi-drift.test.ts`) runs `@bajustone/fetcher/spec-tools`' `lintSpec` over the emitted spec and fails on any unenforced request-schema keyword beyond the intentional `format`/`additionalProperties`. The `/auth/register` body's `email` field now uses the **enforced** `email()` builder (ReDoS-safe pattern) instead of annotation-only `strFormat('email')`, so malformed emails are rejected at registration.

### Fixed
- **SvelteKit helpers now accept Fortress instances with strongly typed plugin maps.** Adapter signatures previously instantiated the default `Fortress` generic, rejecting instances whose inferred plugin methods lacked a string index signature; the accepted instance type is now generic-map agnostic while preserving the real SvelteKit `Handle`/`Action` return contracts.
- **The `openapi` and `schemas --format zod` CLI commands no longer crash.** Endpoint definition maps are now converted with `Object.values(...)`; a subprocess smoke suite invokes every documented command and verifies controlled failures do not surface runtime exceptions.
- **Audit hash chains now protect every stored field and cannot fork under concurrent writes.** The audit plugin hashes an unambiguous serialization of all 13 entry fields, including `previousHash`, traverses links without assuming numerically ordered string IDs, serializes writes transactionally (with a PostgreSQL advisory lock), and refuses to append to an invalid chain. Audit `id`, `actorId`, and `targetId` model metadata now match their public string types. CSV exports neutralize spreadsheet-formula prefixes in addition to RFC 4180 escaping.
- **Migrations are serialized, atomic, and checksummed.** SQLite migrators acquire a database writer lock (plus a same-process queue for synchronous drivers); PostgreSQL uses a transaction-scoped advisory lock. Both re-read the schema checkpoint only after locking and apply the selected run transactionally. `migrateDown(target > current)` is now a true no-op and never stamps a fictitious future version. `fortress_migration_journal` records a SHA-256 checksum for every applied migration—including data-step identity—backfills legacy checkpoints once, rejects missing/edited/unexpected rows before any DDL, removes rows on rollback, and is cleaned up at version zero.
- **Email identity is lowercase, NFC-normalized, and case-insensitively unique.** Registration, admin updates, email login identifiers, mixed-case login lookup, and social-login linking/JIT provisioning now use one canonical email representation. Migration `0006_canonical_email` normalizes legacy rows before adding SQLite `NOCASE` / PostgreSQL `lower(...)` unique indexes for users and email identifiers. If legacy accounts collapse to the same identity, the oldest account remains authoritative; later accounts are disabled, moved to deterministic non-routable tombstones, and have all refresh tokens revoked rather than being silently merged. This data cleanup is intentionally irreversible when rolling the index migration down. Because Unicode NFC normalization requires the runtime data step, SQL-only `migrate:up` export now refuses to emit an incomplete migration; use `fortress.migrate()` with the configured adapter.
- **Database hot paths are indexed and PostgreSQL timestamps are timezone-safe.** Migration `0005_hot_indexes_timestamptz` adds ten cross-dialect indexes for refresh families/users, verification and magic-link tokens, IAM subjects, backup/trusted-device users, webhook retries, and audit chronology. PostgreSQL upgrades explicitly interpret historical timestamp-without-time-zone values as UTC before converting all Fortress timestamp columns to `TIMESTAMPTZ`; rollback uses the inverse explicit UTC conversion. Migration drift now reports missing required indexes.
- **Component `$ref` request schemas are enforced at runtime.** Refs created by `defineComponents()` or typed `ref(name, schema)` now carry their real component definitions into the fetcher-backed validator, including nested, transitive, and recursive refs. Independent component registries remain isolated even when they reuse the same component name. A bare `ref(name)` remains permissive when no definition is available; when composed with a bound ref of that same OpenAPI component name, both resolve to the shared component definition, matching OpenAPI's global component semantics.
- **Non-transactional SQLite writes can no longer be lost to a concurrent transaction's rollback.** The Drizzle adapter's single-connection SQLite path now serializes every standalone op (`create`/`findOne`/`findMany`/`update`/`delete`/`count`/`rawQuery`) on the same async chain that orders `transaction()` calls, so a plain write issued while another request's transaction is mid-`BEGIN…COMMIT` can no longer interleave into that open transaction and be swept away by its `ROLLBACK`. Ops issued inside a transaction callback still run directly on the open transaction (no self-deadlock), and PostgreSQL (native async transactions) is unaffected.
- **IAM evaluation and cache behavior now fail closed.** Missing condition fields/references never satisfy any operator (including `neq`), authoritative subject identity overwrites caller context, and `explainPermission` delegates its verdict to the configured evaluator with condition context. Permission-cache generations reject stale async writes after per-subject or global invalidation.
- **Rate-limit account keys and long windows are stable.** Login account identifiers are trimmed, NFC-normalized, and lowercased before rate-limit keying, matching lockout behavior and preventing case/Unicode bypass. The memory store retains each key for its configured window instead of dropping all counters after one hour.
- **URL coercion and middleware paths are canonicalized safely.** Query/path numerics accept only decimal notation—empty, hex, exponent, signed-plus, and non-finite forms remain strings for validation to reject. Route and plugin-middleware matching now share slash canonicalization, so double/trailing slashes cannot reach an endpoint while bypassing path-scoped controls.
- **OAuth signing-key lookup now uses SQL `IS NULL`.** Repeated OIDC id-token issuance reuses the active RS256 key instead of generating a new keypair on every lookup under SQL adapters.
- **Microsoft social login now fails closed on an absent `email_verified` claim (security).** The Microsoft provider previously mapped a missing `email_verified` to `true`, so a Microsoft login could auto-link by email to an existing account with no verified-email signal — an account-takeover vector, since Graph `/me` and most Entra id_tokens omit the claim. It now matches the other providers: absent ⇒ unverified ⇒ no by-email auto-link (the account is JIT-provisioned instead). Tenants that trust their directory can opt back in via a custom `mapProfile`.
- **All documented subpaths now resolve for npm consumers.** `package.json` `"exports"` covered only 9 of the 29 subpaths declared in `jsr.json`, so `@bajustone/fortress/express`, `@bajustone/fortress/drizzle/pg`, and every `@bajustone/fortress/plugins/*` returned a bare module-not-found on npm even though they resolved on JSR. Added the 20 missing `exports` entries (and the matching `tsup` build entries for `drizzle/pg` + all `plugins/*`) so the build emits each artifact, plus a `check:exports` guard (run in CI and before publish) that fails if `jsr.json`, `package.json`, and `tsup.config.ts` ever drift again.

### Changed (breaking)
- **The adapter conformance suite now enforces the full frozen database contract.** It runtime-checks string IDs, every core comparison/null operator, ascending and descending sorting, update return values, multi-row update/delete behavior, boolean round-trips, unknown-operator rejection, portable raw-query placeholders, and typed duplicate conflicts on both SQLite and PostgreSQL. Node consumers of `@bajustone/fortress/testing` must install the newly declared optional peer `better-sqlite3`; the built testing artifact now loads through pure Node ESM.
- **Auth and post-auth verification now share one frozen result contract.** `AuthResponse*`/wire names are replaced by `AuthResult`, `AuthSuccess`, `AuthPending`, and `AuthImpersonation`; a pending result has a required `{ reason, continuationToken }` challenge and no token properties, while success includes `method`. Two-factor completion is `verify(continuationToken, code, meta?)`, setup activation is `confirmSetup(userId, code)`, and magic-link completion is `verify(token, meta?)`. Core HTTP now exposes `POST /auth/2fa/verify` and `POST /auth/magic-link/verify`, both returning `AuthResult` and setting cookies only on success.
- **Password and cookie defaults are now freeze-ready.** New passwords default to a 15-character minimum (existing hashes and logins are unaffected). HIBP checks now use a bounded LRU cache (`breachedCacheMaxEntries`, default 1000) and support `breachedFailureMode: 'open' | 'closed'` (default `'open'`); every upstream outage logs and emits `PASSWORD_BREACH_CHECK_DEGRADED`. `isPasswordBreached` now accepts an options object as its second argument. Cookie configuration now fails at startup when `SameSite=None` is combined with `Secure: false` or caller-supplied `__Host-`/`__Secure-` names violate their required attributes.
- **Webhook plugin API replaced and frozen (v1).** Event names are now dot-cased (`auth.login.success`, `auth.user.registered`, … — was the `LOGIN_SUCCESS`/`REGISTER` enum). `registerEndpoint(url, events, secret)` → `registerEndpoint(url, events, opts?)` (secret is generated when omitted). The `deliver` config option is replaced by `delivery.fetch` (a fetcher `FetchFn`). `processRetries()` is removed — retries are the queue's job now. New `webhook_endpoint` columns (`deactivated_reason`, `consecutive_failures`) and `webhook_delivery` columns (`idempotency_key`, `response_body`, `error_kind`) plus a unique index on `webhook_delivery (endpoint_id, idempotency_key)`. The frozen breaker defaults are `maxConsecutiveFailures=15`, `permanentStatuses=[404,410,421]`, and `timeoutMs=10000`; exported `WebhookErrorKind` is `'http' | 'network'` and `WebhookDeactivatedReason` is `permanent_${number} | too_many_failures`. The plugin had not shipped a stable release, so there is no migration path. See [docs/plugins/webhook.md](docs/plugins/webhook.md).
- **SvelteKit adapter contracts now match the real peer runtime.** Public handle/action types are anchored to `@sveltejs/kit` and compile under strict mode against `Handle`, `Action`, and `RequestHandler`. `redirectTo` now throws SvelteKit's recognized `Redirect` and failures use real `ActionFailure`s instead of raw lookalikes. Action success is discriminated as `{ pending: false }` or `{ pending: true, challenge }`. Silent SSR refreshes are single-flighted per refresh token and forward IP/user-agent `RequestMeta`, preventing concurrent family revocation and hard fingerprint mismatches.
- **Express host-route middleware is complete and OAuth form bodies are preserved.** `@bajustone/fortress/express` now exports `createCsrfMiddleware` and the factory returns `csrfMiddleware`, with configurable custom header, safe methods, segment-safe skip paths, and cross-site rejection. Express requests parsed by `express.urlencoded()` are re-encoded as form data—not JSON—before OAuth token/introspection/revocation dispatch. The standalone Hono CSRF middleware now also matches skips at segment boundaries (`/foo` covers `/foo/bar`, never `/foobar`; trailing `/*` is supported).
- **Plugin middleware now receives one cross-adapter request contract.** Core, Hono, and Express all pass the exported `PluginRequestContext` (`{ request: Request, fortressSubject?, fortressUserId?, fortressClaims?, fortressScopes? }`) to `MiddlewareDefinition.handler`. Framework-native Hono `Context` / Express `Request` objects are no longer passed directly. This fixes path-bound plugin middleware silently failing under adapters—notably generic rate-limit `paths` bindings, which require the web-standard `request` field.
- **Route-map RBAC can now fail closed.** The Express and Hono `createRbacMiddleware` still default to treating an unmapped user route as public, but you can now opt into fail-closed enforcement: `unmappedRoutes: 'deny'` (Express) / `defaultDeny: true` (Hono) refuses any non-skipped route without a `routeMap`/`mapRequest` entry with a 403, so a forgotten mapping can't silently expose a route. Genuinely public routes go in `skipPaths`. Express matches `routeMap` against `originalUrl`, so mounting middleware under `app.use('/api', ...)` no longer strips the prefix and silently misses full-path mappings. Fortress-managed routes are unaffected—they are protected inside `fortress.handleRequest`.
- **Policy/resource loaders now validate frozen shapes and destructive intent.** `fortress.resources.json` is canonically a map keyed by resource name; legacy arrays and malformed actions/descriptions are rejected, and CLI `init`/`sync:types` use that same map. `loadPolicy` validates all collection/item primitives, effects, and duplicate names. `diffPolicy(..., { prune: true })` refuses an empty policy unless `allowEmptyPrune: true` explicitly acknowledges deleting all managed IAM state.
- **Policy apply/diff now converges through authoritative IAM state.** `applyPolicyPlan` applies resource operations directly without `node:fs`; `IamService.pushResources` exposes the in-memory path. Service-account role diffs use `listRoleBindingsForSubject` rows instead of permission heuristics, covering shared permissions and zero-permission roles. Role descriptions can clear to `null`, and prune ordering unbinds retained service accounts before deleting roles. The legacy `applyResourceOps` path argument remains accepted but no file is written. `loadPolicy` and `resolvePolicyPath` are now async so their `node:fs`/`node:path` dependencies can be dynamically loaded only when file helpers run; callers must `await` them.
- **Tenancy responses and default switching now match their frozen contract.** `getMyTenants` and `GET /tenancy/tenants/mine` return `{ tenants: [...] }` as declared by OpenAPI (rather than a bare array). `switchTenant` serializes per user and performs a two-phase clear/set inside one transaction; migration `0004_tenant_default_unique` deterministically repairs duplicate historical defaults and adds a partial unique index enforcing at most one default membership per user.
- **Core host dispatch and collision behavior are now fail-fast.** Top-level `routes` are explicitly metadata-only (`manifest.mounted: false`), so framework adapters fall through to host handlers and direct `handleRequest()` returns 404 instead of fabricating `{ok:true}`. Duplicate plugin method/path declarations and duplicate `fortress.call` keys now fail at startup; intentional plugin-over-core overrides remain supported.
- **Core logout and permission-only routes have consistent wire behavior.** Successful `POST /auth/logout` expires both configured auth cookies. An endpoint with `meta.permission` now attempts normal JWT authentication even when it omits redundant `security:['bearer']`, so valid callers reach RBAC instead of receiving a credential-dependent 401.
- **DatabaseAdapter contract hardened for freeze.** `DrizzleDialect` is now `'sqlite' | 'pg'` — `mysql` is dropped (it was only smoke-tested and had no constraint-error mapping or CI lane; it can be re-added once there's a real consumer). `update`, `delete`, and `findOne` now **throw** on an empty `where` clause instead of silently matching every row (a full-table wipe footgun); unfiltered `findMany`/`count` reads are still allowed. The Drizzle adapter now maps **SQLite** constraint errors to typed `FortressError`s the same way it already did for Postgres (`UNIQUE`/`PRIMARYKEY` → `CONFLICT/409`, `FOREIGN KEY` → `UNPROCESSABLE_ENTITY/422`, `NOT NULL` → `BAD_REQUEST/400`), and the exported helper `rethrowPgError` is renamed `rethrowDbError(err, dialect)`. The `rawQuery` contract now uses portable `?` positional placeholders on every dialect (the adapter translates to driver syntax), and the conformance suite asserts placeholder behavior, empty-`where` rejection, and unique-violation mapping.

### Changed (breaking)
- **Validation migration window and dependency are frozen for the next release.** `@bajustone/fetcher` is pinned exactly to `1.0.0`; consumers must migrate issue-path readers from `[{key}]` to bare property keys and replace exclusive `oneOf` assumptions with `discriminatedUnion()` before upgrading. No dual-shape compatibility shim is provided during the 0.x breaking-change window.
- **Request/response validation now runs on `@bajustone/fetcher`'s `fromJSONSchema`.** Fortress's hand-rolled `validateJsonSchema` (`src/core/json-schema-validator.ts`) is deleted; `FortressSchema` objects keep `vendor: 'fortress'` and stay plain JSON Schema objects, but their `~standard.validate()` delegates to fetcher's compiled validator. Consequences:
  - The `422 VALIDATION_ERROR` body's issue `path` segments are now fetcher's bare `PropertyKey`s (e.g. `["email"]`) instead of fortress's `{ key }` objects (e.g. `[{ key: "email" }]`). The `location`/`message`/`code` envelope is unchanged.
  - `oneOf` now validates as "matches at least one" (union) rather than "matches exactly one". Use `discriminatedUnion()` for tagged variants.
  - More keywords are now actually enforced (`minimum`/`maximum`, `const`, `allOf`, `additionalProperties: false`, `discriminator`) — schemas that emitted these previously passed them through unchecked.
  - `$ref` fields in request bodies remain present-but-unconstrained at validation time (compiled in isolation without the components map), preserving prior behavior; full ref resolution is a follow-up.
- **Node `>=20.19.0` is now required** (matches `@bajustone/fetcher`'s engine floor), declared in `package.json#engines`.

### Changed (breaking)
- **Subject identifiers are strings everywhere.** `FortressUser.id`, `TokenClaims.sub`, `Session.userId`, every IAM `id`/`*Id` field (`Role`, `Group`, `Permission`, `RoleBinding`, `LoginIdentifier`, `ServiceAccount`, `Subject`), every plugin `id` field (`api-key.id`, `webhook.id`, `webauthn.userId`, audit `actorId`/`targetId`, etc.), and every HTTP endpoint path-param `:id` are now typed `string` at the fortress API surface. Closes the lock-in identified in the 2026-06-13 audit: `TokenClaims.sub: number` plus the `Number()`/`String()` round-trip in `verifyAccessToken` made string/UUID/ULID-keyed adapters structurally impossible. This was the only lock-in blocking UUID adapters that fortress couldn't lift later without a second breaking change.

  **Why string and not `string | number`.** RFC 7519 §4.1.2 already mandates `sub` is a string on the wire; the only reason the round-trip existed was that the internal type disagreed with the wire type. A union pushed the coercion hazard to every consumer. Making the internal type match the wire type deletes the round-trip and the bug class in one cut. (See the rejected-options note under the [lock-in audit memory](memory/project_lockin_audit.md).)

  **What didn't change.** The Drizzle adapter still uses `bigserial`/`integer` PKs by default — the new `stringifyIds` helper at the adapter boundary transparently translates rows on read. No migrations are required for existing numeric-keyed installations. JWTs signed by v0.2.x verify unchanged because `String(1)` already produced `"1"` on the wire.

  **What you have to change.** Every place your code held a fortress id as `number` is now `string`. The mechanical migration:
  - `FortressUser['id']`, `TokenClaims['sub']`, `Subject['id']`, all role/group/permission/session/identifier `id` fields: `number → string`.
  - HTTP path params: `Number(params.id) → params.id`. Zod schemas: `z.coerce.number() → z.string().min(1)`.
  - Custom adapters returning `id: number`: stringify on read at the adapter boundary (`row.id.toString()`), parse on write if the column is numeric.
  - Comparisons: `userId === 1 → userId === '1'`. Set/Map type params: `Set<number> → Set<string>`.
  - Schema builder: new `id(description?)` helper exports a string-typed id schema. Path-param `:id` declarations should use it instead of `int()`.

  **Files touched in this commit (for grep):** `src/core/types.ts`, `src/core/internal-adapter.ts`, `src/core/auth/jwt.ts` (round-trip removed), `src/core/auth/auth-service.ts`, `src/core/iam/iam-service.ts`, `src/core/iam/explain.ts`, `src/core/iam/permission-sync.ts`, `src/core/http/dispatch.ts`, `src/core/http/handle-request.ts`, `src/core/http/protect.ts`, `src/core/policy/apply.ts`, `src/core/policy/diff.ts`, `src/core/schema-builder.ts` (new `id()` helper), `src/drizzle/adapter.ts` (new `stringifyIds` boundary helper), every plugin (`admin`, `api-key`, `audit-log`, `email-verification`, `magic-link`, `oauth`, `rate-limit`, `social-login`, `tenancy`, `two-factor`, `webauthn`, `webhook`), and every framework binding (`hono`, `express`, `sveltekit`).

### Fixed (security)
- **Phase 1 security hotfixes.** Hardened social login with verified OIDC ID tokens (JWKS signature plus issuer/audience/expiry/nonce, both checked unconditionally), timing-safe OAuth state validation, verified-email-only account linking, active-user guards, transactional provisioning/linking, unique social-account constraints, and opt-in AES-256-GCM provider-token storage. **`persistTokens` now defaults to `false`** (was `true` in the initial draft of this patch) so existing `socialLogin()` configs keep working without a key; opting in to server-side provider-token access requires `persistTokens: true` *and* a 32-byte `tokenEncryptionKey`, otherwise the plugin throws at construction. `getAuthorizationUrl()` now returns `{ url, state, codeVerifier, nonce }`; `handleCallback()` now requires returned/stored state and stored nonce; `ProviderProfile` includes `emailVerified`; `getProviderTokens()` decrypts stored provider tokens.
- **Webhook SSRF guard scoped to the built-in transport.** `defaultDeliver` resolves the host and pins the outbound `https.request` to that exact IP (closing the DNS-rebind TOCTOU) and rejects loopback / RFC1918 / link-local / multicast targets including IPv4-mapped IPv6 forms like `::ffff:169.254.169.254`. Custom `config.deliver` transports are no longer wrapped in a redundant `dns.lookup` — they are responsible for their own outbound safety, which un-breaks offline/CI consumers using injected transports. The guard is exported as `assertSafeWebhookUrl(url)` for custom transports that want to reuse it.
- **Two-factor PG migration parity.** The bundled `migrations/pg/0002_initial_schema.sql` adds `fortress_two_factor_secret.last_used_counter INTEGER` and the missing `UNIQUE (provider, provider_account_id)` on `fortress_social_account`, matching the SQLite migration and the in-process `migrations.ts` definitions. Without this, fresh PG databases installed from the bundled SQL files broke 2FA verification outright (not just replay-vulnerable) and silently lacked the social-account uniqueness constraint.
- **Admin bootstrap is no longer ambient.** Removed `adminUserIds`; `/iam/admin/bootstrap` is opt-in via `admin({ bootstrap: { enabled, secret } })`, requires the one-time secret, and only succeeds while no `fortress-admin` bindings exist.
- **Fortress OpenAPI Hono auto-mounts now delegate to `fortress.handleRequest`.** Auto-mounted IAM/admin routes get the same principal resolution, CSRF, validation, and RBAC enforcement as all other Fortress-managed routes.
- **Session, 2FA, webhook, lockout, data-isolation, and tenancy hardening.** Password changes revoke active refresh tokens; TOTP counters are single-use; webhooks are out-of-band with timeout and SSRF protections; lockout identifiers are normalized and window expiry self-recovers; scoped creates force resolved scope and scoped-field updates are rejected; tenant-less permission checks match only tenant-less bindings.

- **Login timing-oracle defense is now actually a defense.** The "user not found / no password" branch of `auth.login()` previously called `hasher.verify()` with a hard-coded, malformed Argon2 PHC string (`$argon2id$...$dummy`). `hash-wasm`'s parser threw before running the KDF, so the branch completed in ~0.3ms while a real password verify took ~50–200ms — a ~300× timing gap usable for user enumeration over the network. The dummy is now a lazily computed, well-formed Argon2id hash produced by the configured `PasswordHasher`, so the not-found branch performs a *real* verify at the same cost as a hit. Regression test in `src/core/auth/login-timing.test.ts`.

### Changed (breaking)
- **`FortressConfig.jwt.secret` renamed to `FortressConfig.jwt.key`.** The field now accepts the new exported `JwtKeyMaterial` type (currently `string | string[]`, intentionally narrow so the runtime helpers don't lie about supported inputs). The alias exists so the public signature stays stable when fortress expands to asymmetric algorithms (RS256 / EdDSA) and JWKS-backed verification — the doc comment on `JwtKeyMaterial` in `core/auth/jwt.ts` shows the planned widening (`CryptoKey | KeyObject | JWK | Uint8Array | …` plus a `JwtVerifyKeyMaterial` variant for `JWTVerifyGetKey`). `signAccessToken` / `verifyAccessToken` parameter renamed `secret` → `key` to match. Codemod: `jwt: { secret: ... }` → `jwt: { key: ... }`.

## [0.2.5] - 2026-06-10

### Changed
- **`ctx.body` is now non-optional when a body schema is declared.** `protect()` / `protectedRoute()` only invoke the handler after the declared body passes Standard Schema validation, so `ProtectedRouteContext['body']` narrows to `T` (not `T | undefined`) for endpoints with a `.body(...)` schema — use `ctx.body` directly without `!` or `ctx.input`. Endpoints with no declared body schema keep the loose `unknown`. Types-only change; runtime is identical.

## [0.2.4] - 2026-06-09

### Fixed
- Stabilized the SvelteKit auto-refresh test by using a deliberately expired access token instead of a 1-second token plus sleep. Slow CI runners could expire the freshly refreshed 1-second access token before locals were populated.

## [0.2.3] - 2026-06-09

### Added
- **Programmatic OpenAPI emission** — new standalone `toOpenAPI(endpoints, options)` helper plus `fortress.toOpenAPI(options)`. The standalone helper is env/DB-free for build scripts and client codegen; the instance method defaults to the endpoint definitions Fortress knows about: core auth/IAM routes, plugin routes, and top-level host `routes`. Supports `title`, `version`, `description`, `servers`, top-level `tags`, custom `schemas`, explicit endpoint override, and `operationId` strategy. Defaults `operationId` to endpoint `handler` names for host-app codegen use cases. This replaces hand-rolled builders like `reb-edit/apps/api/src/openapi.ts`. (Wishlist #2.)
- **OpenAPI builder hardening.** Schema objects are deep-cleaned before embedding in OpenAPI: `~standard` validators, functions, and `undefined` values are stripped recursively so Fortress schemas and external Standard Schema adapters serialize cleanly. The OpenAPI plugin now also sees top-level `createFortress({ routes })` host endpoints, not just plugin routes and `additionalEndpoints`.
- **`fortress.migrate()`** — single entrypoint that runs Fortress migrations and an optional app-supplied callback in the correct order. Eliminates the two-step `migrate(db, '...') + migrateUp(adapter)` footgun where forgetting the second call silently leaves auth tables unmigrated. Accepts `{ migrateApp?: () => Promise<void>, dialect?, targetVersion? }`; returns `{ fortress: MigrationApplyResult, appRan: boolean }`. (Wishlist #8.)
- **`fortress.syncPermissionsFromManifest()`** — walks `fortress.endpoints`, deduplicates `(resource, action)` pairs from `meta.permission`, and seeds them via `iam.createPermission`. Optional `defaultRoles: { admin: '*', member: ['school:read', ...] }` binds the discovered permissions to named roles (`'*'` = bind every permission discovered from the supplied endpoint manifest, not unrelated DB rows). Idempotent: re-running only grants, never revokes. `roles[role].bound` reports newly-added bindings for this run, not already-existing bindings. Replaces the seed script every consumer used to write. (Wishlist #7.)
- **`ctx.respond(status, body)`** on `ProtectedRouteContext` — typed JSON-response builder for non-2xx returns. When `protect()` is given a typed `EndpointDefinition`, `status` narrows to the response codes the endpoint declares and `body` narrows to the matching response schema. String-target endpoints fall back to `(number, unknown)`. Replaces hand-rolled `new Response(JSON.stringify(...), { status })` calls. (Wishlist #4.)
- **Top-level `routes` on `FortressConfig`.** Host applications can register their own `EndpointDefinition` map directly on `createFortress({ routes: ... })` instead of authoring a one-field `FortressPlugin`. Fortress synthesizes the plugin internally under the reserved name `__host`; declaring a user plugin named `__host` alongside `routes` is now a configuration error. (Wishlist #1.)
- **`ErrorEnvelope` schema + `.errorResponse()` builder shorthand.** Exported from the root entry: a canonical fortress schema matching the wire shape `FortressError.toJSON()` emits (`{ code, message, statusCode, details? }`). `EndpointBuilder.errorResponse(status, description)` is a one-liner that wires it into a status declaration so host APIs document the same error contract Fortress's own routes produce. (Wishlist #6.)
- **Drizzle Postgres SQLSTATE → `FortressError` mapping.** The Fortress Drizzle adapter's `create` / `update` / `delete` methods now translate Postgres constraint and concurrency states into the matching `FortressError` so `protect()` can serialize them as the right HTTP status. The same mapper is exported from `@bajustone/fortress/drizzle` as `findSqlstate` / `rethrowPgError` for host routes that use raw Drizzle directly. Mapped: `23505 → CONFLICT/409`, `23503 → UNPROCESSABLE_ENTITY/422`, `23502 → BAD_REQUEST/400`, `23514 → UNPROCESSABLE_ENTITY/422`, `40001` and `40P01 → CONFLICT/409`, `57014 → SERVICE_UNAVAILABLE/503`. No-op for non-`pg` dialects. (Wishlist #5.)
- `Errors.unprocessable()` and `Errors.serviceUnavailable()` factory functions for the new `UNPROCESSABLE_ENTITY` and `SERVICE_UNAVAILABLE` codes.

### Changed
- **`FortressErrorCode` widened** with `'UNPROCESSABLE_ENTITY'` (422) and `'SERVICE_UNAVAILABLE'` (503). `Errors.conflict()` now accepts an optional `{ cause, details }` options bag so it can be threaded through error wrappers without losing the original.
- **`statusToErrorCode` fallback** now maps 422 → `UNPROCESSABLE_ENTITY` (was `VALIDATION_ERROR`) and 503 → `SERVICE_UNAVAILABLE`. Bodies that carry an explicit `code` field still round-trip unchanged via `Errors.fromHttpResponse`; this only affects bodies whose `code` cannot be parsed.
- **Typing (breaking, types-only):** `protect()` and the Hono / Express / SvelteKit `protectedRoute()` wrappers are now generic over the `EndpointDefinition` you point them at. Passing a typed endpoint (the value produced by `endpoint(...).build()`) flows its phantom `<TBody, TQuery, TParams, TResponses>` generics into `ctx.body` / `ctx.query` / `ctx.params` / `ctx.input` — no more `unknown` / `Record<string, unknown>` at the call boundary, and no more local casts in host apps. Passing a string `handler` name keeps the previous loose typing. The runtime is identical; this is a `.d.ts`-only change.
- Hono `protectedRoute()` renames its environment type parameter from `E` to `HEnv` so it no longer collides with the new endpoint generic. Callers who relied on positional type-argument inference are unaffected; callers that passed the env explicitly should rename the slot.

## [0.2.0] - 2026-06-08

### Added
- SQL-first initial-schema migration baseline with deep drift detection.
- CI matrix coverage and audit export pipeline.
- Phase 0 + Phase 1 + most of Phase 2 work from the library plan (see commit 8b94985 for scope).

### Changed
- Tenancy plugin hardened: claim-based resolution and atomic schema isolation.
- Repo hygiene: ephemeral planning/review docs moved to `scratch/` and untracked.

## [0.1.2] - 2026-06-06

### Security
- Remediation pass for the 2026-06-05 independent review (tenancy plugin skeleton findings remain deferred/unmounted):
  - SQLite adapter transactions are serialized and use `BEGIN IMMEDIATE`, restoring atomic CAS semantics for refresh rotation and OAuth code exchange.
  - OAuth authorization codes are now atomically single-use under concurrency; public-client PKCE is enforced at exchange; per-client `grantTypes` are enforced for `authorization_code` and `refresh_token`.
  - OAuth consent flows are bound to a user and deny cross-user get/approve/deny with 404.
  - Pipeline CSRF protection is now enabled by default for unsafe, cookie-authenticated Fortress routes. Bearer/API-key requests are skipped; configure via `FortressConfig.csrf`.
  - Data-isolation bypass windows now use `AsyncLocalStorage` and no longer leak across concurrent requests.
  - JWT verification pins HS256 and configured issuer; reserved JWT claims (`sub`, `act`, `groups`, etc.) are stripped from custom claims.
  - Disabled-account login returns the same generic invalid-credentials path and still verifies the password hash to reduce enumeration/timing signals.
  - Impersonation token TTL is clamped (default max 3600s) and emits an auth observer event.
  - Follow-up gap closure from the implementation review:
    - Public-client PKCE is now also enforced at code-issuance time (`createAuthorizationCode`), so a binding-less code is never minted — not only rejected at exchange.
    - `findOrCreatePermission`, `ensureResource`, and the role/permission/group binding idempotency helpers are race-safe: a lost create race re-reads the winner's row instead of surfacing a raw unique-constraint error.
    - CSRF detection recognizes refresh-only cookie sessions (expired access cookie), closing a bypass where a refresh-only request skipped the check.
    - The SvelteKit adapter's silent token refresh is restricted to safe HTTP methods, so a cross-site unsafe request can no longer trigger a refresh-token rotation.

### Changed
- Auth cookie extraction now prefers an explicit `Authorization: Bearer` header over the access cookie (cookie-shadow hardening).
- Cookies default to `Secure` / `__Host-` names regardless of `NODE_ENV`; local HTTP development must opt out with `cookies: { secure: false }`.
- Schema migration required for OAuth pending flows (`user_id`) and permission uniqueness partial indexes.

## [0.1.1] - 2026-05-07

### Fixed
- fix(oauth): honor security: ['bearer'] on /oauth/* routes via bearerKind

## [0.1.0] - 2026-05-07

### Added
- oauth: full RFC + OIDC compliance pass

## [0.0.42] - 2026-04-29

### Added
- oauth2

## [Unreleased]

### Security
- Hardened the tenancy plugin: tenant schema names now use numeric ids, tenant context comes from verified JWT custom claims instead of `X-Tenant-Code`, PostgreSQL `search_path` is transaction-pinned with a bound parameter, invalid tenant claims are rejected, and missing tenant context fails closed.

### Fixed
- **`security: ['bearer']` on `/oauth/*` routes is now honoured.** Previously the dispatcher had a path-based `startsWith('/oauth/')` short-circuit that skipped the plugin principal chain, the JWT bearer check, AND RBAC enforcement for *every* `/oauth/*` route, including the consent-flow endpoints (`/oauth/flows/:flowId{,/approve,/deny}`) added in 0.0.42 — leaving them silently unauthenticated despite their `security: ['bearer']` declaration. Host apps had to ship a workaround shim that re-implemented the routes on their own router; TDMP discovered this regression on the 0.0.42 → 0.1.0 upgrade after retiring the shim under the impression that the new `security` declarations were enforced. The fix introduces a per-route opt-in: `EndpointMeta.bearerKind` is a new field with two values — `'jwt'` (default) and `'oauth'`. When the field is absent or `'jwt'`, the dispatcher runs the normal auth pipeline (plugin principals → JWT verification → RBAC → body parse + validation) regardless of path. When set to `'oauth'`, the route is treated as a self-managed OAuth-protocol endpoint (handler parses the bearer itself, body is form-encoded) and the entire pipeline is skipped — same behaviour the path-based check used to provide. The seven OAuth-protocol routes (`/oauth/{authorize, token, introspect, revoke, userinfo, .well-known/openid-configuration, .well-known/jwks.json}`) now declare `bearerKind: 'oauth'` explicitly. Consent-flow routes inherit the JWT default and run through fortress's full auth pipeline, so `/oauth/flows/:flowId/approve` correctly receives `auth.userId` from the host app's session JWT and no host-app shim is needed. Three regression tests added under `core/http/handle-request.test.ts › bearerKind: 'jwt' default for /oauth/* routes`.

### Added
- Route-security manifest: `fortress.manifest`, `buildRouteManifest()`, manifest drift-check helpers, `fortress manifest`, and `fortress manifest:check`. Hono, Express, and SvelteKit adapters now consume the manifest when deciding which routes to intercept.
- Host-owned route protection helpers: core `protect()` plus Hono/Express/SvelteKit `protectedRoute()` wrappers apply plugin middleware, CSRF, auth, RBAC, validation, and auth-cookie attachment from endpoint metadata.
- Migration tooling foundation: `fortress_schema_version` Drizzle table, bundled `migrations/{sqlite,pg}/0001_schema_version.sql`, migration runner/status/drift helpers, and `fortress migrate:*` catalog commands.
- Migration drift checker now reports missing Fortress tables via `FORTRESS_TABLES`, not only version-table state; new upgrade fixture proves bundled migrations apply end-to-end against a bare database. Workflow documented in `docs/migrations/upgrade-guide.md`.
- Production deployment guide (`docs/deployment.md`) covering JWT rotation, cookies behind reverse proxies, CSRF opt-outs, CORS recipes, HTTPS requirements, PostgreSQL vs SQLite tradeoffs, OAuth/OIDC RP setup, API-key/service-account ops, migration runbook, observability, and a release checklist.
- Typed adapter helpers (P1-6): `FortressEnv<TAppEnv>` is now generic so host Hono apps compose their own `Variables` / `Bindings` with Fortress's without `Context<AppEnv>` ↔ `Context<FortressEnv>` casts. `getSubject`/`getUserId`/`getClaims`/`getDb`/`getScopedDb` are generic in the env type; `getClaims<TCustomClaims>(c)` narrows `customClaims` to plugin-augmented shapes (e.g. tenancy's `tenantId`/`tenantCode`). Express exports `FortressExpressFields` for declaration-merging into `express-serve-static-core.Request`. SvelteKit's `FortressLocals` is already merge-friendly. Type-level tests under `src/hono/middleware/auth.types.test.ts`; full reference in `docs/adapter-typed-helpers.md`.
- CI / test utility package (P1-10): `@bajustone/fortress/testing` now ships `checkRouteManifestDrift`, `checkPublicRoutes`, `checkMigrationDrift`, `smokeTestAuth`, and the `runFortressChecks` aggregator so consumer apps can gate deploys on Fortress's own drift detectors. New `fortress check:routes`, `check:public-routes`, and `check:migrations` CLI commands; a drop-in GitHub Actions workflow at `docs/ci/github-actions.yml`. Full reference in `docs/ci.md`.
- Policy-as-code (P1-7): declarative `fortress.policy.json` (with optional `fortress.policy.<env>.json` override) covers resources, roles, groups, and service-account role bindings. New exports: `loadPolicy`, `diffPolicy`, `applyPolicyPlan`, `applyResourceOps`, `resolvePolicyPath`. CLI: `fortress policy:summary` (offline), `policy:diff`/`apply`/`check` (how-to printers). New `IamService.removePermissionFromRole(...)` underpins narrow-role diffs. Full reference in `docs/policy-as-code.md`; sample file at `examples/policy/fortress.policy.json`.
- Permission-debugging helper (P1-8): `explainPermission(db, iam, subject, resource, action)` returns the full attribution graph — every grant source (direct user / direct group / service account / role), group memberships, role bindings, and the final DENY-wins decision — powering admin "why does X have permission Y?" workflows. Recipes for admin/operator console workflows in `docs/admin-recipes.md`.
- Observability event + alert catalog (P2-13): expanded `docs/observability.md` with the full Auth/IAM event catalog (every `eventType` Fortress emits), recommended dashboards (auth, IAM, OAuth, database), starting-point alert thresholds, and audit-log integration recipe.
- Compatibility matrix (P2-11): `docs/compatibility.md` documenting the tested runtime/framework/database matrix and what's intentionally out of scope.
- Hardening guide (P2-14): `docs/hardening.md` — prescriptive production hardening checklist covering identity/credentials, authorization, transport/edge, data isolation, audit/logging, crypto, and deployment hygiene. Linked from `SECURITY.md`.
- Full initial-schema migration (P0-1): new bundled `0002_initial_schema` migration (SQLite + PostgreSQL) creates every Fortress-owned table, index, and constraint, so `migrateUp` now provisions a brand-new database end-to-end through the adapter's `rawQuery` — no Drizzle/`drizzle-kit` dependency at runtime. The migrations are the SQL-first source of truth: `createTestAdapter()` derives its schema from them via `getMigrationUpSql()`, so the test adapter and a production `migrateUp` can no longer drift. Per-release guide at `docs/migrations/0002-initial-schema.md`.
- Deep migration drift detection: `detectMigrationDrift` now reports `missingColumns` — tables that exist but are missing a column the bundled DDL defines (partial/stale schema). Expected columns are parsed straight from the migration SQL, so the check stays adapter-agnostic. Surfaced by `checkMigrationDrift` and `fortress migrate:check`.
- PostgreSQL migration upgrade fixture (testcontainers): provisions a bare real Postgres from the bundled migrations and asserts zero drift, catching dialect-specific issues (SERIAL, partial unique indexes, JSONB, FK drop ordering) the SQLite fixture can't.
- Audit-log export: `auditLog.exportEntries(format?, options?)` serializes entries to JSON or RFC 4180 CSV for compliance/retention, honouring the same `AuditLogQueryOptions` filters as `getAuditLog`. Docs in `docs/plugins/audit-log.md`.
- Public CI matrix: `.github/workflows/ci.yml` now runs the unit suite across Bun + Node 20 + Node 22, plus a PostgreSQL/testcontainers `integration` job (pg dialect, tenancy isolation, migration fixture, framework adapters) on PRs/main and a nightly cron.

### Changed
- The migration version row is now stamped solely by the runner (`migrateUp`/`migrateDown`); the `0001_schema_version` forward SQL no longer self-inserts a version row, giving a single source of version truth.
- Examples scenario index (P2-12): `examples/README.md` maps the six plan-specified scenarios (cookie+CSRF, bearer-only API, API-key + service account, OAuth/OIDC provider, admin bootstrap + policy sync, tenancy) to the existing reference apps and recipe docs.
- Formal security-review packet and threat model docs covering OAuth/OIDC, refresh rotation, CSRF/cookies, IAM/RBAC, API-key/service-account flows, tenancy isolation, and drift controls.
- Tenancy: `deleteTenant`, `getMyTenants`, opt-in `/tenancy/*` routes, `onSchemaCreated`, and `dropSchemaOnDelete`.
- **OAuth 2 / OIDC compliance pass.** Brings `@bajustone/fortress/plugins/oauth` from "OAuth 2 + OIDC userinfo veneer" to a full RFC-conformant authorization server suitable for strict OIDC RPs (Moodle, openid-client, Keycloak federation, Spring Security). Closes the eleven gaps in the TDMP audit (`docs/oauth-compliance-plan.html`); every audit row now reads PASS. Headline changes:
  - **OIDC userinfo (§4.1, OIDC Core §5.3)** — `/oauth/userinfo` now returns the OIDC-shaped JSON object (`sub` as string, `email`, `email_verified`, `name`, `preferred_username`, `updated_at`) instead of leaking the raw `FortressUser` row. Claims are scope-gated per OIDC §5.4 (`email` / `profile`); the legacy permissive baseline is kept for non-OIDC tokens. New `OAuthConfig.userinfoClaims` hook for per-deployment claim extension. Exported `toOidcUserinfo(user, scope)` for host-app composition.
  - **id_token issuance (§4.2, OIDC Core §3.1.3.7)** — New `src/plugins/oauth/jwks.ts` + `id-token.ts` modules. The `/token` endpoint now issues a signed RS256 id_token alongside the access token whenever the request used `scope=openid`. New endpoint `GET /oauth/.well-known/jwks.json` exposes the verification JWKS (RFC 7517). `nonce` and `auth_time` are persisted on the auth code and echoed into the id_token (§3.1.2.1 / §2). New `oauth_signing_key` model holds the active RS256 keypair (kid = RFC 7638 thumbprint).
  - **Refresh token grant + rotation (§4.3, RFC 6749 §6 + RFC 9700 §2.2.2)** — New `oauth_refresh_token` model with `familyId` rotation tracking. `exchangeCode` now returns a refresh token alongside the access token; `grant_type=refresh_token` is supported on `/token`. Reuse of an already-rotated token is treated as an attack and revokes the entire family (replay detection). Configurable via `OAuthConfig.refreshTokenExpirySeconds` (default 30 d, set to 0 to disable). Revoking a refresh token (RFC 7009) sweeps the whole family.
  - **Constant-time secret compare (§4.4)** — New `src/core/auth/timing-safe.ts` (`timingSafeEqualHex`); replaces all `===` hash comparisons in OAuth (client secret check, code hash, refresh-token hash). Mitigates the hypothetical timing oracle even on uniform SHA-256 outputs.
  - **Mandatory PKCE on `/oauth/authorize` (§4.5, RFC 9700 §2.1.1)** — Authorize requests without `code_challenge` now return `error=invalid_request`. Plain method is rejected. Escape hatch: `OAuthConfig.allowNonPkceConfidentialClients` for legacy server-side RPs (defaults `false`, discouraged).
  - **RFC 9207 issuer identification (§4.6)** — Every authorize redirect (success and error) now carries `iss=<issuerUrl>`. Discovery declares `authorization_response_iss_parameter_supported: true`. Mitigates RFC 9700 §4.4 mix-up attacks.
  - **Discovery completeness (§4.7)** — Adds `jwks_uri`, `id_token_signing_alg_values_supported`, `scopes_supported`, `claims_supported`, `response_modes_supported`, `authorization_response_iss_parameter_supported`, `'none'` in `token_endpoint_auth_methods_supported`, `'refresh_token'` in `grant_types_supported`. Strict autoconfig (openid-client) now succeeds with no manual config.
  - **Public-client + RFC 8252 loopback (§4.8)** — New `tokenEndpointAuthMethod` per-client field (`'client_secret_basic'` | `'client_secret_post'` | `'none'`). Public clients (SPAs / native apps) authenticate via PKCE alone; presenting a client_secret is rejected per RFC 6749 §2.3.1; `client_credentials` is denied. Exported `matchRedirectUri(registered, inbound)` honours the loopback exception: registered `http://127.0.0.1/cb` matches any-port at runtime. `localhost` (DNS) is NOT widened (RFC 8252 §8.3 DNS-rebinding guidance).
  - **Per-client scope allow-list (§4.9, RFC 6749 §3.3 + RFC 9700 §2.2.1)** — New `allowedScopes` field on `oauth_client`. Requested scope is intersected against the allow-list at authorize and `client_credentials` time; empty intersection returns `error=invalid_scope`. Refresh-token grant rejects scope widening, accepts narrowing. Legacy clients with no allow-list pass through unchanged.
  - **RFC 6749 §5.2 / §4.1.2.1 error codes (§4.10)** — New `OAuthErrorCode` union (`invalid_request`, `invalid_client`, `invalid_grant`, `unauthorized_client`, `unsupported_grant_type`, `invalid_scope`, `access_denied`, `unsupported_response_type`, `server_error`, `temporarily_unavailable`) + `Errors.oauth(code, description)` factory. The HTTP error mapper detects `oauthError` and emits the spec-required `{ error, error_description, error_uri? }` body shape on the token endpoint instead of the default fortress `{ code, message }` envelope.
  - **HTTPS issuer assertion (§4.11, RFC 8414 §2)** — Production startup (`NODE_ENV=production`) refuses to register the OAuth plugin if `issuerUrl` is non-HTTPS. Dev / test (localhost over HTTP) is unaffected.

### Changed
- **BREAKING tenancy:** removed `headerName` / `X-Tenant-Code` tenant selection; schemas are now named `tenant_<id>` instead of `tenant_<taxId>` (no in-place migration — rename existing schemas manually); `switchTenant` and `getMyTenants` now take `(input, routeCtx?)`.
- `OAuthMethods.handleUserInfoRequest` return type: `Promise<FortressUser | null>` → `Promise<Record<string, unknown>>` (OIDC claims, throws 401 on bad token).
- `OAuthMethods.exchangeCode` now also returns an optional `refreshToken` and `idToken`. Existing callers ignoring those fields are unaffected.
- `createClient` now accepts optional `tokenEndpointAuthMethod` and `allowedScopes`; returns `clientSecret: string | null` (null for public clients).

### Docs
- New compliance plan: `docs/oauth-compliance-plan.html` (companion to TDMP's audit). Maps each finding to spec clause → observable behaviour → code shape → definition of done.

- **OAuth: SPA-friendly authorization flow (Pattern B).** The OAuth plugin can now drive a consent flow where the host app owns the login + consent UI and Fortress owns the state machine — no HTML ever leaves Fortress, the framework-agnostic stance stays intact.
  - New `OAuthConfig` fields: `enableAuthorizeEndpoint`, `enableConsentApi`, `loginUrl`, `consentUrl`. Both endpoint groups default to off so existing setups are unaffected.
  - New endpoints (opt-in): `GET /oauth/authorize` (front door, 302s to `loginUrl?flow=<id>` if no session, `consentUrl?flow=<id>` if authenticated), `GET /oauth/flows/:flowId` (consent metadata: client name, requested scopes, redirect URI — PKCE fields stripped), `POST /oauth/flows/:flowId/approve` (issues auth code, returns `{ redirectUrl }`), `POST /oauth/flows/:flowId/deny` (returns `access_denied` redirect URL).
  - New plugin methods: `handleAuthorizeRequest`, `handleGetFlow`, `handleApproveFlow`, `handleDenyFlow`. All transport-agnostic; safe to call from `fortress.call.*` or directly.
  - New method `getPendingFlow(flowId)` for non-destructive reads of pending flows. Existing `resumePendingFlow` (single-use consume) is unchanged.

## [0.0.41] - 2026-04-22

### Fixed
- fix input schemas

## [0.0.40] - 2026-04-16

### Fixed
- fix

## [0.0.39] - 2026-04-16

### Changed
- rate-limit: `login` and `register` are now **always on with defaults** when the plugin is registered — reverts the 0.0.37 opt-in change, which risked silent loss of auth DoS protection on upgrade. To turn either off explicitly, pass `login: { disabled: true }` / `register: { disabled: true }`. Other endpoint blocks (`refresh`, `oauthToken`, `apiKeyIssue`) remain opt-in.

### Docs
- Clarify `paths` config vs the per-framework wrappers (`honoRateLimit` / `expressRateLimit` / `svelteKitRateLimit`). Both target the same store; the wrapper is for framework-mounted routes, `paths` is for serverless / declarative-only setups. Don't stack both on the same path — each match increments the counter, halving the effective limit.
- Spell out that `fortress.call.*` runs the full middleware pipeline — plugin middleware, rate limits, principal resolution, RBAC, validation, auth/IAM observers, OTel spans. Tests that need to bypass those should call the service layer directly (`fortress.auth.*`, `fortress.iam.*`).

## [0.0.38] - 2026-04-16

### Fixed
- fix(jsr)!: explicit types on `authEndpoints` / `iamEndpoints` / their component registries so JSR fast-check passes without `--allow-slow-types`. v0.0.36 and v0.0.37 silently failed `publish-jsr` (latest on the JSR registry was 0.0.35) — this release is the first since 0.0.35 to actually reach JSR. Removed `--allow-slow-types` from `publish:dry`, `jsr-check`, and `publish-jsr` so the regression can't recur.

### Added
- `AuthEndpointsMap` and `IamEndpointsMap` exported interfaces listing each core endpoint's `EndpointDefinition<TBody, TQuery, TParams, TResponses>` generics. Used to constrain `authEndpoints` / `iamEndpoints` at declaration — `fortress.call.*` per-handler inference is fully preserved.
- Wire-format shape exports (`UserWire`, `AuthResponseWire`, `AuthTokenPairWire`, `ErrorResponseWire`, `SessionInfoWire`, `LoginIdentifierWire`, `CreateUserInputWire`, `OkResponseWire` in auth; `RoleWire`, `GroupWire`, `PermissionWire`, `PermissionInputWire`, `ServiceAccountWire` in iam). These mirror `src/core/types.ts` with `Date` fields widened to `string` (ISO 8601) — the shapes consumers actually see after JSON serialization.

## [0.0.37] - 2026-04-16

### Added
- feat(rate-limit)!: whole-app coverage via check() + framework wrappers

## Unreleased

### Fixed
- `extractJsonSchema` now recognizes Standard Schema implementations that are themselves JSON Schema objects (e.g. `@bajustone/fetcher`), not just fortress. Previously only schemas with `vendor: 'fortress'` or a `~standard.jsonSchema.input()` adapter (Zod, Valibot, ArkType) survived — fetcher schemas fell through to `{}` and bodies/queries/params disappeared from generated OpenAPI specs. Detection uses structural JSON Schema props (`type` matching a spec type, or `$ref`/`oneOf`/`anyOf`/`allOf`), so Zod-style wrappers whose `type` is an internal kind string (`'ZodObject'`) still route through the adapter path.

### Added
- feat(rate-limit): extend coverage to `refresh` (`beforeTokenRefresh` hook), OAuth `/oauth/token`, and API-key issuance (`POST /api-key/keys`) via path-bound plugin middleware.
- feat(rate-limit): **named rules** (`config.rules`) referenced from a new programmatic `fortress.plugins['rate-limit'].check(ruleName, { ip, userId })` surface.
- feat(rate-limit): per-framework wrappers — `honoRateLimit`, `expressRateLimit`, `svelteKitRateLimit` — published as sub-path exports `./plugins/rate-limit/{hono,express,sveltekit}`. Rate-limit any user-owned route in one line.
- feat(rate-limit): `paths` config accepts arbitrary path-glob bindings to a rule + optional method filter, for any Fortress-handled route without a built-in block.

### Changed (breaking)
- `RateLimitConfig.login` / `register` are now fully opt-in — omitting a block disables that hook (previously both were always enabled with defaults if the plugin was registered). Pass an empty object (`login: {}`) to enable defaults.
- Rate-limit store key format changed from `login:ip:<ip>` / `login:account:<email>` to `<rule>:ip:<ip>` / `<rule>:user:<value>` for consistency across all rule types. Clears automatically with in-memory store; external stores on v0.0.x may need a flush.

## [0.0.36] - 2026-04-16

### Added
- feat(endpoints): typed in-process client via fortress.call.*
- feat(observability): outer request span, token-verify histogram, DB spans

## [0.0.36] - 2026-04-15

### Added
- feat(endpoints): typed in-process client — `fortress.call.<handler>(input)` infers body/query/params from the endpoint's declared schemas and returns the 2xx response body typed. Non-2xx throws a structured `FortressError`.
- feat(schema-builder): `defineComponents({...})` returns a typed `ref` bound to a component map so `$ref`s carry their TS type through to endpoint responses. The old `ref(name)` still works; a new 2-arg overload `ref(name, schema)` preserves type for self-references inside a components literal.
- feat(endpoint): `EndpointDefinition` + `EndpointBuilder` are now generic in body/query/params/responses. Added `InferEndpointBody`, `InferEndpointQuery`, `InferEndpointParams`, `InferEndpointResponses`, `InferEndpointSuccessResponse`, `InferEndpointCallInput` helpers.
- feat(errors): `Errors.fromHttpResponse(status, body)` reconstructs a `FortressError` from a JSON error body — the inverse of `errorToResponse`.

### Changed (breaking)
- `authEndpoints` / `iamEndpoints` changed shape from `EndpointDefinition[]` to keyed records (`Record<string, EndpointDefinition<...>>`). Preserves per-handler generic types for the new typed call surface. Consumers that iterated the arrays should now use `Object.values(authEndpoints)`.
- `FortressPlugin.routes` changed from `EndpointDefinition[]` to `Record<string, EndpointDefinition>` — keyed by handler name. All built-in plugins with routes (admin, api-key, oauth, openapi, webauthn) migrated. The `RouteDefinition` alias has been removed.
- `Fortress` interface grew a second generic parameter `TCall` and a new `call` field.

## [0.0.35] - 2026-04-15

### Added
- feat(observability): pluggable logger, auth/permission observers, optional OTel adapter

## [0.0.34] - 2026-04-14

### Added
- more tests

### Fixed
- fix(validation): coerce URL-sourced query/params to their declared types

## [0.0.33] - 2026-04-14

### Added
- feat(admin): HTTP endpoints to mint api keys for any subject

## [0.0.32] - 2026-04-14

### Added
- docs: polish documentation
- feat(iam)!: promote SERVICE_ACCOUNT to first-class citizen
- feat(api-key,admin)!: opt-in HTTP routes for self-service + admin management
- feat(admin): HTTP endpoints to mint api keys for any subject (closes the SERVICE_ACCOUNT bootstrap gap — `POST /admin/users/:userId/api-keys` and `POST /admin/service-accounts/:id/api-keys`, plus GET/DELETE for service accounts)
- feat(webauthn)!: require ctx.userId for registration, drop body userId
- feat(plugins)!: pass PluginRouteContext to plugin route handlers

## [0.0.31] - 2026-04-10

### Added
- feat(openapi): emit per-resource discriminated unions for Permission schemas

## [0.0.30] - 2026-04-09

### Added
- feat!: validate consumer routes (hono/sveltekit/express) at runtime

### Fixed
- fix jsr

## [0.0.29] - 2026-04-09

### Changed
- refactor(adapters)!: delete deprecated dispatch APIs, delegate fully to fortress.handleRequest
- refactor

## [Unreleased]

### Added
- **Pluggable logger via `FortressConfig.logger`.** Accepts any object
  structurally compatible with `FortressLogger` — a `pino()` instance,
  Fastify's `app.log`, or a hand-rolled `console` wrapper. Default is
  `SILENT_LOGGER` so Fortress never writes to stderr unless the caller
  opts in. Replaces the five hardcoded `console.warn`/`console.error`
  call sites in `plugin-runner.ts`, `auth-service.ts`,
  `http/error-response.ts`, and `express/middleware.ts`.
- **`AuthEvent` + `AuthService.addAuthObserver`.** Mirrors the existing
  `addIamObserver` pattern. Emits `LOGIN_SUCCESS`, `LOGIN_FAILURE`,
  `LOGOUT`, `REGISTER`, `TOKEN_REFRESH`, `TOKEN_REUSE_DETECTED`, and
  `TOKEN_FINGERPRINT_MISMATCH` with optional actor, IP, user-agent,
  method, and outcome metadata. Observers can subscribe at init time
  from any plugin's `methods(ctx)` factory without re-implementing
  every auth hook.
- **`PermissionCheckEvent` + `IamService.addPermissionCheckObserver`.**
  Synchronous high-frequency listener for `checkPermission`, carrying
  `cached` / `durationSeconds` / `allowed` / `subjectType` /
  `subjectId` / `resource` / `action`. Separate from `IamEvent` so
  audit-log (which subscribes to IAM mutations) isn't spammed with
  per-check traffic. Listener signature is intentionally `void`, not
  `Promise<void>`, to discourage awaiting expensive work on the hot path.
- **Unsubscribe functions on every observer adder.** `addAuthObserver`,
  `addIamObserver`, and `addPermissionCheckObserver` all return a
  `() => void` unsubscribe callback. Existing callers of
  `addIamObserver` that ignored the `void` return type still compile
  unchanged.
- **Observer error routing.** Observer failures are now logged at
  `error` level via the configured `FortressLogger` instead of being
  silently swallowed. Auth/IAM operations still never throw from an
  observer bug.
- **`FortressConfig.observability` + OpenTelemetry adapter sub-path.**
  New opt-in `@bajustone/fortress/otel` sub-path export with a single
  `createOtelTelemetry({ name })` factory. The core package never
  statically imports `@opentelemetry/api` — the adapter uses
  `await import('@opentelemetry/api')` for true dynamic loading, so
  runtimes that don't opt in (Cloudflare Workers, Deno without OTel)
  never resolve the peer dep. `@opentelemetry/api` is declared as an
  optional peer dependency with `peerDependenciesMeta.optional: true`.
- **Built-in metrics via the telemetry provider.** When a non-noop
  `observability` provider is wired, Fortress emits:
  - `fortress.auth.events.total` counter (attrs: `event`, `outcome`, `method`)
  - `fortress.iam.events.total` counter (attrs: `event`)
  - `fortress.iam.permission_check.duration` histogram in seconds
    (attrs: `subject_type`, `result`, `cached`)
  - `fortress.iam.permission_check.cache.hits` + `.cache.misses` counters
  - `db.client.operation.duration` histogram in seconds — **the stable
    OpenTelemetry semantic-convention metric name**, not a
    Fortress-specific name — with `db.system.name`, `db.operation.name`,
    and `db.collection.name` attributes. Every Fortress-internal DB
    operation (and plugin queries going through the wrapped adapter)
    flows into it.
  - Plus a `fortress.iam.permission_check.deny` span emitted only on
    denied checks (security-interesting). Allowed checks are metric
    fodder — no span emitted, keeping the hot path cheap.
- **`fortress.logger` and `fortress.telemetry` exposed on the instance.**
  Adapters and plugins can read them after construction.

### Fixed
- **`resolvePrincipal` now fires on user-owned routes, not just
  Fortress-managed ones.** Previously, only requests dispatched through
  `fortress.handleRequest` (`/auth/*`, `/iam/*`, plugin routes, OAuth,
  OpenAPI) walked the `resolvePrincipal` plugin chain — so
  `Authorization: ApiKey ...` / `X-API-Key: ...` headers authenticated
  Fortress routes but silently 401'd on any custom route protected by the
  Hono / Express / SvelteKit auth middleware. API keys, and every future
  credential plugin, now work uniformly on both surfaces.
  - New `fortress.resolvePrincipal(request)` method on the Fortress
    instance — plugin chain + non-throwing JWT fallback. Exposed publicly
    alongside `fortress.extractAccessToken`, so third-party adapters can
    delegate to it in ~3 lines.
  - New `src/core/http/principal.ts` with `tryPluginPrincipal` (plugin
    chain only, used by `handle-request`) and `resolveRequestPrincipal`
    (chain + JWT, used by adapter user-route middleware).

### Changed
- **Adapter request context is now subject-based, not USER-only.** All
  three adapters now expose `fortressSubject: Subject` as the
  authoritative principal field, with `fortressUserId` demoted to a
  convenience alias populated only when `subject.type === 'USER'`. This
  unblocks service-account principals resolved via api-key from using
  *any* user-owned route, not just Fortress routes.
  - **Hono**: `FortressEnv.Variables.fortressSubject: Subject`;
    `fortressUserId` now optional. User-route RBAC middleware checks
    `fortress.iam.checkPermission(subject, ...)` instead of hardcoding
    `{ type: 'USER', id }`. New `getSubject(c)` helper.
  - **Express**: `req.fortressSubject?: Subject`; `req.fortressUserId`
    now populated only for USER subjects. New `getSubject(req)` helper.
  - **SvelteKit**: `event.locals.fortress.subject?: Subject`;
    `locals.fortress.userId` populated only for USER subjects. New
    `getSubject(event)` helper. Auto-refresh on expired JWTs still
    works, but plugin resolvers run first so api-key requests skip the
    refresh path entirely.
  - **Breaking**: `getUserId` / `getClaims` now throw 401 for
    non-USER principals and for api-key-authenticated requests
    (respectively). Code that accepts any principal should call
    `getSubject` instead and branch on `subject.type`. Per the "no
    compat burden" rule for v0.0.x, no shims are provided.
- **`PluginRequestContext` now carries `fortressSubject`** in addition to
  `fortressUserId` / `fortressClaims`. All three adapters pass it through
  to the `before-auth` / `after-auth` / `after-rbac` plugin middleware
  slots; plugin middleware wanting subject-level identity (non-USER
  principals) can read it instead of relying on the USER-only alias.

### Added
- **`SERVICE_ACCOUNT` is now a first-class core IAM citizen.** Previously
  `SERVICE_ACCOUNT` existed only as a `SubjectType` enum value and any role
  binding to one was silently dropped at permission-check time. Service
  accounts are now a fully-supported IAM entity with CRUD endpoints, role
  bindings, direct permission bindings, and api-key authentication. Typical
  use: CI/CD, M2M communication, mobile devices, or any machine principal
  that should hold scoped permissions without being tied to a human user.
  - **New table: `fortress_service_account`**. Columns: `id`, `name`
    (unique machine identifier, immutable after creation), `displayName`,
    `description`, `isActive`, `createdAt`, `updatedAt`. Service accounts
    are globally scoped at the table level — tenant scoping happens via
    `role_binding.tenantId`, the same mechanism users use.
  - **New `IamService` methods**: `createServiceAccount`,
    `getServiceAccount`, `listServiceAccounts`, `updateServiceAccount`
    (rejects `name` changes), `deleteServiceAccount` (hard delete with
    cascade cleanup of bindings + api keys), plus
    `bindRoleToServiceAccount`, `unbindRoleFromServiceAccount`,
    `bindPermissionToServiceAccount`, `unbindPermissionFromServiceAccount`.
  - **New HTTP endpoints** under `/iam/service-accounts/*`: create, list,
    get, patch, delete, `GET /iam/service-accounts/:id/permissions`,
    `POST/DELETE /iam/roles/:id/bind/service-account`, and
    `POST/DELETE /iam/permissions/bind/service-account`. All require the
    new `fortress:createServiceAccount` / `fortress:viewServiceAccounts` /
    `fortress:manageServiceAccount` permissions.
  - **api-key plugin authenticates service accounts.** Keys can now belong
    to either a USER or a SERVICE_ACCOUNT. The plugin implements the new
    `resolvePrincipal` plugin capability (see below) so incoming requests
    with `Authorization: ApiKey <key>` or `X-API-Key: <key>` headers
    resolve to a subject principal end-to-end through RBAC. Deleting a
    service account hard-deletes its api keys via the new multi-listener
    IAM observer (no revocation step — the keys are gone).
  - **The permission-resolution bug is fixed.** The legacy
    `internal-adapter.getUserPermissions` hardcoded
    `subject_type IN ('USER', 'GROUP')` in both the rawQuery and fallback
    paths, silently dropping any `SERVICE_ACCOUNT` role binding. The new
    `getSubjectPermissions(subject, tenantId?)` resolves permissions for
    any subject type — users still walk their group memberships, service
    accounts and other non-user subjects don't (they can't be group
    members). The `direct_permission_binding` schema comment was also
    updated from `'USER' | 'GROUP'` to
    `'USER' | 'GROUP' | 'SERVICE_ACCOUNT'`.
  - **Inactive service accounts authenticate to nothing.** Both
    `resolveApiKey` and `getSubjectPermissions` short-circuit when
    `service_account.isActive = false`, so deactivating a service account
    immediately stops its keys from authenticating and drops any cached
    permissions on the next check.
- **New plugin capability: `resolvePrincipal`.** Plugins can now attach
  non-JWT credential mechanisms to the request pipeline:
  ```ts
  resolvePrincipal?: (
    request: Request,
    ctx: PluginContext,
  ) => Promise<{ subject: Subject; claims?: TokenClaims } | null>;
  ```
  Resolvers are tried in registration order; the first non-null return
  wins. If none resolve, the JWT fallback runs as before. The api-key
  plugin implements this; future credential plugins (OAuth client
  credentials, mTLS, signed JWT assertions) can implement it the same way
  without core changes.
- **New `Subject` type.** `{ type: SubjectType; id: number }` —
  discriminated principal shape threaded through
  `IamService.checkPermission`, `enforceFortressPermission`,
  `DispatchAuth`, and `PluginRouteContext`. Enables a single abstraction
  across users, service accounts, and any future subject kinds.
- **New `TokenClaims.subjectType` field.** JWTs now carry the subject type
  alongside `sub`. Verifier defaults missing `subjectType` to `'USER'` so
  tokens minted before this change keep verifying until they expire.
- **`IamService.addIamObserver`** replaces `setIamObserver` (single-slot →
  multi-listener). Enables plugins to coexist — the audit-log plugin keeps
  its listener, and the api-key plugin attaches a cascade listener for
  `SERVICE_ACCOUNT_DELETED`. Old `setIamObserver` is removed.
- **Audit event types `SERVICE_ACCOUNT_CREATED`, `SERVICE_ACCOUNT_UPDATED`,
  `SERVICE_ACCOUNT_DELETED`** added to the audit-log plugin's
  `AuditEventType` union.
- **`api-key` plugin now ships self-service HTTP routes — opt-in.** Pass
  `apiKey({ routes: true })` to mount four endpoints under `/api-key/keys/*`:
  `POST /api-key/keys` (create), `GET /api-key/keys` (list), `DELETE
  /api-key/keys/:id` (revoke), `POST /api-key/keys/:id/rotate` (rotate). All
  require a bearer token; the authenticated caller can only manage their own
  keys — a body-supplied `userId` is ignored in favor of `ctx.userId` so
  clients cannot forge keys for other users. The programmatic API on
  `fortress.plugins['api-key']` is always available regardless of the flag.
- **`admin` plugin now exposes admin-side api-key management routes —
  opt-in.** Pass `admin({ apiKeyRoutes: true })` alongside `apiKey()` to
  mount `GET /admin/users/:userId/api-keys` and `DELETE
  /admin/users/:userId/api-keys/:id`. Both are guarded by the
  `apiKey:manage` permission, which bootstrap auto-discovers into the
  `fortress-admin` role when the routes are mounted. Typical use:
  responding to leaked keys or auditing a user's active surface.
- **Design convention: plugins that ship HTTP routes are moving to
  opt-in.** New HTTP-ish surfaces (starting with `api-key` and the new
  `admin` api-key routes) gate route mounting behind a boolean config
  flag that defaults to `false`. The programmatic methods on
  `fortress.plugins[name]` stay always-on, so consumers keep the library
  behavior they had before and can explicitly opt in to the URL
  namespace. Existing plugins (`webauthn`, `two-factor`, `oauth`,
  `email-verification`, `magic-link`, `webhook`, `social-login`,
  `openapi`) will migrate in a follow-up PR.
- **Plugin HTTP route handlers now receive a `PluginRouteContext`** as a
  second argument: `(input, ctx) => ...`. `ctx` carries the verified
  caller (`userId`, `claims`), request metadata (`meta` with `ipAddress`
  / `userAgent`), and the raw `Request` — the data the dispatcher already
  had but was dropping before calling plugin methods. Plugin handlers
  that need to know who is calling them no longer have to trust a
  client-supplied body field or re-verify the JWT themselves.
  - The new `PluginRouteContext` type is exported from
    `@bajustone/fortress` (re-exported from `src/core/plugin.ts`).
  - Existing handlers that ignore the second argument still work — the
    new argument is additive.
  - `admin.bootstrap` now uses `ctx.userId` as the default target. Only
    superadmins (configured via `adminUserIds`) may pass `body.userId`
    to bootstrap another user. Programmatic callers
    (`fortress.plugins.admin.bootstrap({ userId })`) are unaffected —
    when `ctx` is absent the handler still trusts `body.userId`.
  - The `POST /iam/admin/bootstrap` body schema no longer marks `userId`
    as required.

### Migration summary (SERVICE_ACCOUNT / Subject release)

If you're upgrading from the previous release, the minimum set of edits:

```ts
// 1. Permission checks: wrap userId in a Subject
- fortress.iam.checkPermission(userId, 'post', 'read');
+ fortress.iam.checkPermission({ type: 'USER', id: userId }, 'post', 'read');

// 2. getUserPermissions → getPermissionsForSubject
- fortress.iam.getUserPermissions(userId, tenantId);
+ fortress.iam.getPermissionsForSubject({ type: 'USER', id: userId }, tenantId);

// 3. api-key plugin: userId → subject
- fortress.plugins['api-key'].createKey({ userId, name });
+ fortress.plugins['api-key'].createKey({ subject: { type: 'USER', id: userId }, name });
// Same shape change for listKeys/revokeKey/rotateKey.

// 4. api-key plugin config
- apiKey({ maxKeysPerUser: 5 });
+ apiKey({ maxKeysPerSubject: 5 });

// 5. resolveKey return shape
- const { userId } = await fortress.plugins['api-key'].resolveKey(raw);
+ const { subject } = await fortress.plugins['api-key'].resolveKey(raw);

// 6. IAM observer registration
- fortress.iam.setIamObserver(listener);
+ fortress.iam.addIamObserver(listener);
```

And one schema migration for installs that manage DDL manually:

```sql
-- api_key: polymorphic ownership (USER | SERVICE_ACCOUNT)
ALTER TABLE fortress_api_key ADD COLUMN subject_type varchar(20) NOT NULL DEFAULT 'USER';
ALTER TABLE fortress_api_key RENAME COLUMN user_id TO subject_id;
ALTER TABLE fortress_api_key DROP CONSTRAINT IF EXISTS fortress_api_key_user_id_fkey;
CREATE INDEX api_key_subject_idx ON fortress_api_key (subject_type, subject_id);

-- new service_accounts table (Postgres; adjust types for SQLite/MySQL)
CREATE TABLE fortress_service_account (
  id serial PRIMARY KEY,
  name varchar(100) NOT NULL UNIQUE,
  display_name varchar(255),
  description text,
  is_active boolean NOT NULL DEFAULT true,
  created_at timestamp NOT NULL DEFAULT NOW(),
  updated_at timestamp NOT NULL DEFAULT NOW()
);
```

Full per-field details below.

### Changed (breaking)
- **`IamService.checkPermission` and `getUserPermissions` are now
  subject-aware.** The first argument is a `Subject`, not a bare `userId`.
  The old `getUserPermissions(userId, tenantId?)` is removed — use
  `getPermissionsForSubject({ type: 'USER', id: userId }, tenantId?)` for
  users or `{ type: 'SERVICE_ACCOUNT', id }` for service accounts.
  ```ts
  // Before
  fortress.iam.checkPermission(userId, 'post', 'read');
  fortress.iam.getUserPermissions(userId, tenantId);
  // After
  fortress.iam.checkPermission({ type: 'USER', id: userId }, 'post', 'read');
  fortress.iam.getPermissionsForSubject({ type: 'USER', id: userId }, tenantId);
  ```
- **`api-key` plugin method signatures now take a `subject` instead of a
  `userId`.** The polymorphic `(subject_type, subject_id)` schema mirrors
  `role_binding` / `direct_permission_binding`, and lets keys belong to
  service accounts as well as users.
  ```ts
  // Before
  await fortress.plugins['api-key'].createKey({ userId, name });
  await fortress.plugins['api-key'].listKeys({ userId });
  await fortress.plugins['api-key'].revokeKey({ userId, id });
  await fortress.plugins['api-key'].rotateKey({ userId, id });
  // After
  await fortress.plugins['api-key'].createKey({ subject: { type: 'USER', id: userId }, name });
  await fortress.plugins['api-key'].listKeys({ subject: { type: 'USER', id: userId } });
  await fortress.plugins['api-key'].revokeKey({ subject: { type: 'USER', id: userId }, id });
  await fortress.plugins['api-key'].rotateKey({ subject: { type: 'USER', id: userId }, id });
  ```
  `resolveKey(rawKey)` now returns `{ subject, scopes }` instead of
  `{ userId, scopes }`.
- **`ApiKeyConfig.maxKeysPerUser` → `maxKeysPerSubject`.** The config
  knob now counts keys per subject (either USER or SERVICE_ACCOUNT)
  rather than per user specifically.
- **`api_key` schema migration.** `user_id` is replaced by
  `(subject_type, subject_id)`. For installs that manage their own
  schema, apply the following SQL:
  ```sql
  ALTER TABLE fortress_api_key ADD COLUMN subject_type varchar(20) NOT NULL DEFAULT 'USER';
  ALTER TABLE fortress_api_key RENAME COLUMN user_id TO subject_id;
  ALTER TABLE fortress_api_key DROP CONSTRAINT IF EXISTS fortress_api_key_user_id_fkey;
  CREATE INDEX api_key_subject_idx ON fortress_api_key (subject_type, subject_id);
  ```
- **`IamService.setIamObserver` → `addIamObserver`.** Semantics change
  from single-slot overwrite to append-only. Multiple plugins (audit log,
  api-key cascade, etc.) can now attach listeners without clobbering
  each other.
- **`enforceFortressPermission` takes a `Subject`** instead of
  `userId: number | undefined`. `PermissionEnforcement.checkPermission`
  signature changes likewise. Custom adapters that call these directly
  need to pass a `Subject`.
- **`DispatchAuth.subject`** is the canonical principal field.
  `DispatchAuth.userId` remains as a convenience alias (`subject.id` when
  `subject.type === 'USER'`, otherwise `undefined`) so most existing
  handlers keep working.
- **`POST /iam/check` body shape accepts `{ subject, resource, action }`**
  in addition to the legacy `{ userId, resource, action }`. The dispatcher
  prefers `subject` when present; the userId form is kept for backwards
  compatibility until the next major and will be removed.
- **`POST /webauthn/register/options` and `POST /webauthn/register/verify`
  no longer accept `userId` in the request body.** The passkey is always
  registered against the authenticated caller (`ctx.userId`). Clients
  passing a different `userId` in the body were enabling a
  privilege-escalation bug — any bearer-authenticated user could register
  a credential on another user's account. Programmatic callers of
  `fortress.plugins.webauthn.generateRegistrationOptions` /
  `verifyRegistration` must now supply a `PluginRouteContext` as the
  second argument instead of `{ userId }` in the first.
  Before:
  ```ts
  await fortress.plugins.webauthn.generateRegistrationOptions({ userId });
  ```
  After:
  ```ts
  await fortress.plugins.webauthn.generateRegistrationOptions(
    {},
    { userId, request: new Request('http://localhost') },
  );
  ```

### Added
- **`validateRequest` is now a public export** from `@bajustone/fortress`.
  Framework-agnostic validation primitive that walks an `EndpointInput`,
  aggregates body+query+params issues, and throws
  `FortressError('VALIDATION_ERROR', 422)`. Use it from any runtime — Next.js
  route handlers, SvelteKit `+server.ts`, Bun.serve, Deno, edge functions, or
  custom middleware — to validate consumer-defined routes with the exact
  shape fortress's own dispatch uses internally.
- **`vBody` / `vParam` / `vQuery` for SvelteKit**
  (`@bajustone/fortress/sveltekit`). Take a `RequestEvent`, validate against
  a Standard Schema, return the parsed value or throw
  `FortressError('VALIDATION_ERROR', 422)`. Drop-in for `+server.ts` handlers.
- **`vBody` / `vParam` / `vQuery` for Express**
  (`@bajustone/fortress/express`). Take a structurally typed Express
  `Request`, validate against a Standard Schema, return the parsed value or
  throw `FortressError('VALIDATION_ERROR', 422)`. The Express
  `createErrorHandler` already maps the thrown error to a 422 JSON response.
- **SvelteKit adapter** at `@bajustone/fortress/sveltekit`. Single
  `createSvelteKitHandle(fortress)` hook for `hooks.server.ts`. Intercepts
  Fortress paths and delegates to `fortress.handleRequest`. Auto-refreshes
  expired access tokens during SSR loads. Populates `event.locals.fortress`
  for user routes. Form-action helpers (`fortressActions.login` /
  `logout` / `register` / `refresh`). Optional catch-all `+server.ts`
  escape hatch via `toSvelteKitHandler(fortress)`.
- **`fortress.handleRequest(request: Request): Promise<Response>`** —
  framework-agnostic HTTP entry point on every Fortress instance. Composes
  plugin middleware → token verification → fortress-managed RBAC →
  validation → endpoint dispatch → cookie attachment. All adapters delegate
  to it; future runtimes (Cloudflare Workers, Deno Deploy, etc.) only need a
  ~10-line wrapper.
- **`FortressConfig.cookies`** — `__Host-` prefixed access/refresh cookie
  names with `HttpOnly`, `Secure`, `SameSite=Lax`, `Path=/` defaults in
  production. Auto-relaxes (drops `__Host-` and `Secure`) in
  `NODE_ENV !== 'production'` so localhost over HTTP works.
- **`fortress.runPluginMiddleware`**, **`fortress.extractAccessToken`**,
  **`fortress.serializeAuthCookies`**, **`fortress.cookies`** — auxiliary
  HTTP helpers exposed on the Fortress instance for adapters that compose
  custom flows on user-owned routes.
- **`mountFortress(app, fortress)`** in the Hono and Express adapters — new
  modern entry point that delegates Fortress-managed paths to
  `fortress.handleRequest` via a single middleware. Replaces the old split
  surface (`createHonoMiddleware` + `mountPluginRoutes`).

### Changed
- **BREAKING: Hono `vBody` / `vParam` / `vQuery` now validate at runtime.**
  Previously they were type-only — the schema parameter was used purely for
  TypeScript inference and the deleted `createValidationMiddleware` did the
  actual validation upstream. With that middleware gone, the helpers now
  call `schema['~standard'].validate()` themselves and throw
  `FortressError('VALIDATION_ERROR', 422)` on failure (the same shape every
  fortress-managed endpoint produces). **`vParam` and `vQuery` are now
  `async`** — Standard Schema's `validate()` may return a promise, so all
  three helpers had to align. Migration: add `await` to any sync
  destructuring call sites (`const { id } = vParam(c, P)` →
  `const { id } = await vParam(c, P)`).
- The Hono `createErrorHandler` now delegates to the framework-agnostic
  `errorToResponse` from core so the FortressError → HTTP mapping
  (`Retry-After`, sanitized 500s, etc.) stays in one place.
- The Hono `createAuthMiddleware` and Express `createAuthMiddleware` now
  use `fortress.extractAccessToken` (cookie-first, `Authorization: Bearer`
  fallback), so the same adapter serves both browsers and API clients.
- The Hono and Express RBAC middleware are simplified — they only handle
  user-route `routeMap` lookups now. The default-deny logic for
  Fortress-managed paths moved into core (`src/core/http/fortress-rbac.ts`)
  and runs inside `fortress.handleRequest`.

### Removed (breaking)
- **Deleted `mountPluginRoutes`** from the Hono adapter
  (`src/hono/plugin-routes.ts`). Replaced by `mountFortress`, which
  delegates to `fortress.handleRequest` and handles plugin routes
  (OAuth, OpenAPI, etc.) automatically.
- **Deleted `createValidationMiddleware`** from the Hono and Express
  adapters (`src/hono/validation-middleware.ts`,
  `src/express/validation-middleware.ts`). Validation now runs
  automatically inside `fortress.handleRequest` for every Fortress-managed
  endpoint. For custom user routes, use the new runtime-validating
  `vBody` / `vParam` / `vQuery` helpers (Hono / SvelteKit / Express) or
  the framework-agnostic `validateRequest` export — see the Unreleased
  section above.
- **Deleted `mountFortressRoutes` and `mountPluginRoutes`** from the
  Express adapter (`src/express/routes.ts`). Same migration: use
  `mountFortress(app, fortress)` from `@bajustone/fortress/express`.
- **Removed `RbacOptions.allowUnmappedFortressPaths`** from the Hono and
  Express adapters. The fortress-path default-deny now lives in core, so
  the adapter-side opt-out is gone. Core's default-deny is non-negotiable
  (it's part of the security contract).
- **Migration**: replace
  `mountPluginRoutes(app, fortress)` → `mountFortress(app, fortress)`,
  delete any `createValidationMiddleware(...)` calls, and rely on the
  automatic validation inside `fortress.handleRequest`.

## [0.0.28] - 2026-04-09

### Fixed
- fix jsr

## [0.0.27] - 2026-04-09

### Fixed
- fix jsr

## [0.0.26] - 2026-04-09

### Fixed
- fix jsr

## [0.0.25] - 2026-04-09

### Changed
- chore(jsr): eliminate all 62 slow-type errors by typing `fortressSchema` /
  `fortressPgSchema` as `Record<string, AnySQLiteTable>` /
  `Record<string, AnyPgTable>`. The drizzle adapter is unaffected (it already
  accesses tables generically), but consumers who relied on column-level
  inference from `fortressSchema.users.email` style access will now see the
  loose `AnySQLiteTable`/`AnyPgTable` type. Workaround: declare your own
  typed Drizzle tables and pass them via `createDrizzleAdapter(db, { tables })`.
- chore(jsr): drop `--allow-slow-types` from `publish:dry` and the publish
  workflow so future regressions fail loudly. JSR will now ship proper
  `.d.ts` files for Node consumers.
- docs: add `@module` JSDoc to every JSR entrypoint (22 files) and document
  every re-export in `src/index.ts`.

### Added
- chore(jsr): add `description`, `runtimeCompat` (node/deno/bun/workerd), and
  `publish.exclude` to `jsr.json`. The published tarball no longer bundles
  test files, vitest/tsup configs, `.github`, `examples`, `docs`, `scripts`,
  or local tooling files.

## [0.0.24] - 2026-04-07

### Fixed
- fix: prevent Zod schemas from being misidentified as FortressSchema

## [0.0.23] - 2026-04-07

### Added
- feat(hono): add typed validation helpers and unmatched route warnings

## [0.0.23] - 2026-04-08

### Added
- feat: add typed validation helpers (`vBody`, `vParam`, `vQuery`) to Hono adapter — zero-cost type-safe request extraction using Standard Schema V1 inference, works with Zod, Valibot, ArkType, or fortress built-in schemas
- feat: export `InferOutput` utility type from `@bajustone/fortress/hono`

## [0.0.22] - 2026-04-07

### Fixed
- fix: use relative URL in openapi plugin Scalar UI for prefix compatibility

## [0.0.21] - 2026-04-07

### Added
- docs: sync documentation with source code

## [Unreleased]

### Fixed
- docs: sync README, SECURITY.md, docs/security.md, and architecture.md with source code
  - WebAuthn plugin is fully implemented, not a stub — updated README, CLAUDE.md
  - Fixed plugin count from 12 to 15 in architecture.md
  - Fixed `breachedCacheTtlMs` default from 300000 to 86400000 in docs/security.md
  - Fixed account lockout config names (`maxFailedAttempts`, `lockoutDurationSeconds`, `maxLockoutSeconds`) in docs/security.md
  - Fixed rate limit config shape (`maxPerIp`, `maxPerAccount`, `windowSeconds`) in docs/security.md
  - Fixed CSRF middleware import (`createCsrfMiddleware`) in docs/security.md
  - Fixed supported version from 0.1.x to 0.0.x in SECURITY.md
  - Synced jsr.json version to 0.0.20

## [0.0.20] - 2026-04-07

### Added
- feat: complete admin plugin with all IAM endpoints, type safety, and bug fixes

## [0.0.20] - 2026-04-07

### Added
- Admin plugin now mounts all 16 core IAM endpoints (roles CRUD, role/group bindings, permission bindings, getUserPermissions, checkPermission)
- `POST /auth/users` — admin-initiated user creation with `fortress:manageUsers` permission
- `POST /iam/sync` — push/pull resource sync endpoint
- `safeInt()` / `requireInt()` helpers for safe numeric input coercion in admin plugin
- `updateUser` now supports `password` field — hashed via configured `PasswordHasher` with password policy validation

### Changed
- `PluginContext.auth` and `.iam` now typed as `AuthService` and `IamService` (was `Record<string, Function>`)
- Removed `as any` casts throughout admin plugin — all service calls are now type-checked
- All `Number(body.id)` calls replaced with `requireInt()` to prevent NaN propagation to database queries
- Endpoint deduplication in `fortress.ts` — plugin routes take priority over core definitions by `method+path`

### Fixed
- `mountPluginRoutes` now returns HTML with `c.html()` instead of `c.json()` for plugin methods returning HTML strings (fixes broken Scalar UI)
- CHANGELOG formatting errors in v0.0.19 and v0.0.16 entries

## [0.0.19] - 2026-04-07

### Added
- fix: pass path params to plugin route handlers in Hono adapter

## [0.0.18] - 2026-04-07

### Added
- feat: Standard Schema V1 support with typed schemas and runtime validation
- feat: add admin CRUD endpoints for users, roles, groups, and permissions

## [0.0.17] - 2026-04-07

### Added
- feat: security-aware default deny and endpoint permission declarations

## [0.0.16] - 2026-04-07

### Added
- feat: add admin plugin, plugin middleware wiring, and default deny for fortress routes
- feat(openapi): add additionalEndpoints and convertRoutes for unified spec generation

## [Unreleased]

### Added
- **Admin CRUD endpoints** — 15 new endpoints in the admin plugin for managing users, roles, groups, and permissions
  - Auth admin: `GET /auth/users`, `GET /auth/users/:id`, `PUT /auth/users/:id`, `DELETE /auth/users/:id`
  - IAM admin: `GET /iam/roles/:id`, `PUT /iam/roles/:id`, `GET /iam/groups`, `GET /iam/groups/:id`, `PUT /iam/groups/:id`, `DELETE /iam/groups/:id`, `GET /iam/groups/:id/users`, `GET /iam/permissions`, `POST /iam/permissions`, `DELETE /iam/permissions/:id`, `POST /iam/roles/:id/permissions`
- **Auth service admin methods** — `listUsers`, `getUserById`, `updateUser`, `deleteUser` on `AuthService`
- **IAM service admin methods** — `getRole`, `updateRole`, `listGroups`, `getGroup`, `updateGroup`, `deleteGroup`, `getGroupUsers`, `listPermissions`, `createPermission`, `deletePermission`, `addPermissionToRole` on `IamService`
- `iam` property on `PluginContext` — plugins can now access the IAM service via `ctx.iam`
- `like` operator support in Drizzle adapter
- **Standard Schema V1 support** — `obj()`, `str()`, `int()`, etc. now implement Standard Schema, providing runtime validation + TypeScript type inference + JSON Schema for OpenAPI from a single definition
- `FortressSchema<T>`, `Infer<T>`, `StandardSchemaV1.InferOutput` types for type extraction
- Built-in JSON Schema validator for fortress schemas' `~standard.validate()`
- New schema helpers: `nullType()`, `record()`, `recordOf()`
- `isStandardSchema()`, `isFortressSchema()`, `extractJsonSchema()` utilities
- `endpoint().body()`, `.query()`, `.params()` accept both `FortressSchema` and external Standard Schema (Zod, Valibot, ArkType)
- `/auth/users` added to `FORTRESS_AUTH_PROTECTED` for default-deny

### Changed
- Plugin route dispatch now merges path params into body, enabling plugin routes with `:id` params
- GET request handlers now receive query params (previously `undefined`) in both Hono and Express adapters
- Admin plugin superadmin middleware now covers `/auth/users/*` in addition to `/iam/*`

### Previously Released

- **Admin plugin** (`@bajustone/fortress/plugins/admin`) — protects IAM routes with `fortress:*` permissions, provides bootstrap endpoint to assign first admin, and lists available resources/roles
- **Plugin middleware wiring** — `MiddlewareDefinition` from plugins is now executed in the request pipeline via `pluginMiddleware.beforeAuth`, `pluginMiddleware.afterAuth`, and `pluginMiddleware.afterRbac`
- **Endpoint permission declarations** — `EndpointMeta.permission` field and `.permission(resource, action)` builder method allow endpoints to declare IAM requirements
- `GET /iam/resources` endpoint — lists all available resources and their actions
- `GET /iam/roles` endpoint — lists all roles
- `POST /iam/admin/bootstrap` endpoint — auto-discovers all declared permissions from endpoint definitions and creates fortress-admin role
- `getResources()` and `getRoles()` methods on `IamService`
- `createPluginMiddleware()` for Hono adapter
- `createExpressPluginMiddleware()` for Express adapter
- **Security-aware default deny** — RBAC middleware respects endpoint security metadata
- **Default deny for fortress-owned routes** — RBAC middleware denies unmapped `/iam/*`, `/auth/impersonate`, and plugin-owned routes by default

## [0.0.15] - 2026-04-07

### Added
- add version lifecycle script
- `additionalEndpoints` option for OpenAPI plugin — consumers can merge app-specific routes into a single unified spec
- `convertRoutes` utility in Hono adapter — schema-agnostic converter from `createRoute`-style objects to `EndpointDefinition[]`

## [0.0.14] - 2026-04-07

### Added
- v0.0.14
- feat: webauthn plugin
- openapi
- support openapi via JSONSchema
- examples

### Changed
- update doc/architecture.md
- improve tests

### Fixed
- fix read me

## [0.0.13] - 2026-04-07

### Added
- Core auth: JWT (jose), Argon2id password hashing, refresh token rotation with family tracking
- Core IAM: resource+action permissions, conditions, deny rules, groups, roles
- LRU permission cache with TTL and invalidation
- Plugin system: 8 capabilities (models, hooks, methods, routes, middleware, wrapAdapter, enrichTokenClaims, scopeRules)
- Plugins: email-verification, api-key, two-factor, social-login, data-isolation, tenancy, oauth, rate-limit, account-lockout, audit-log, webhook, magic-link, openapi, webauthn (stub)
- Declarative endpoint definitions with OpenAPI metadata
- JSON Schema builder DSL for fluent schema construction
- Drizzle adapter: PostgreSQL, MySQL, SQLite
- Hono middleware: auth, RBAC, CSRF, error handler, OpenAPI integration
- Express middleware: auth, RBAC, error handler, route mounting
- In-memory SQLite testing adapter
- Password policy with NIST 800-63B defaults and HIBP breach checking
- Session management: list, revoke, revoke all
- Token fingerprinting on refresh
- Admin impersonation with RFC 8693 `act` claim
- Security documentation
