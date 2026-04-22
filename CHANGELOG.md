# Changelog

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
