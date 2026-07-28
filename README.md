# Fortress

Authentication, sessions, IAM, and security plugins for TypeScript.

- Web-standard core: `Request → Response`
- Hono, Express, and SvelteKit adapters
- PostgreSQL and SQLite through Drizzle
- JWT access tokens and rotating refresh-token families
- Roles, groups, direct permissions, conditions, and service accounts
- Typed endpoint schemas, in-process calls, OpenAPI, migrations, and CI checks
- 15 optional plugins

Fortress runs on Bun, Deno, Node.js 20.19+, and edge runtimes. File-based helpers and the Bun CLI require a filesystem runtime.

## Install

```bash
# JSR library (Node package manager, Bun, or Deno)
npx jsr add @bajustone/fortress
bunx jsr add @bajustone/fortress
deno add jsr:@bajustone/fortress

# npm registry package (includes the Bun `fortress` executable)
bun add @bajustone/fortress
# or: npm install @bajustone/fortress
```

JSR publishes the runtime library but not an executable `bin`; install the npm
registry package when using the `fortress` CLI.

Install the integrations you use:

```bash
bun add drizzle-orm hono                 # Hono + Drizzle
bun add drizzle-orm express              # Express + Drizzle
bun add drizzle-orm @sveltejs/kit        # SvelteKit + Drizzle
```

## Start with Hono and SQLite

```typescript
import { Hono } from 'hono';
import { drizzle } from 'drizzle-orm/bun-sqlite';
import { createFortress } from '@bajustone/fortress';
import { createSqliteDrizzleAdapter } from '@bajustone/fortress/drizzle';
import { mountFortress } from '@bajustone/fortress/hono';

const database = createSqliteDrizzleAdapter(drizzle('app.db'));
const fortress = createFortress({
  database,
  jwt: {
    key: process.env.FORTRESS_JWT_SECRET!, // at least 32 UTF-8 bytes
    issuer: 'my-app',
  },
  // Required only for plain-HTTP local development.
  cookies: { secure: false },
});

await fortress.migrate();

const app = new Hono();
mountFortress(app, fortress);

export default app;
```

`mountFortress()` serves core auth, IAM, and registered plugin routes. Login and refresh responses set access and refresh cookies.

Generate a key (npm registry installation):

```bash
fortress generate-secret
```

The `fortress` CLI uses Bun and is shipped by the npm registry package. JSR
consumers use the programmatic APIs. Live migrations can explicitly load your
configured adapter as described below.

## Use the service API

Direct service calls are useful in jobs, tests, scripts, and application services. They run auth/IAM hooks and observers but skip the HTTP middleware, CSRF, route RBAC, and request-validation pipeline.

### Register and sign in

```typescript
const user = await fortress.auth.createUser({
  email: 'alice@example.com',
  name: 'Alice',
  password: 'correct-horse-battery-staple',
});

const result = await fortress.auth.login(
  'alice@example.com',
  'correct-horse-battery-staple',
  {
    ipAddress: requestIp,
    userAgent: request.headers.get('user-agent') ?? undefined,
    deviceName: 'Alice laptop',
  },
);

if (result.status === 'success') {
  result.user;
  result.accessToken;
  result.refreshToken;
}

if (result.status === 'pending') {
  // Complete the factor through the plugin that requested it. Two-factor:
  const completed = await fortress.plugins['two-factor'].verify(
    result.pending.continuationToken,
    code,
  );
}
```

`AuthResult` has three variants:

```typescript
switch (result.status) {
  case 'success':
    result.refreshToken; // string
    break;
  case 'pending':
    result.pending.reason;
    result.pending.continuationToken;
    break;
  case 'impersonation':
    result.refreshToken; // null
    break;
}
```

### Rotate and revoke sessions

```typescript
const next = await fortress.auth.refresh(refreshToken, {
  ipAddress: requestIp,
  userAgent: request.headers.get('user-agent') ?? undefined,
});

await fortress.auth.logout(next.refreshToken);

const sessions = await fortress.auth.listSessions(user.id);
await fortress.auth.revokeSession(user.id, sessions[0].id);
await fortress.auth.revokeAllOtherSessions(user.id, currentSessionId);
```

Every refresh rotates the token. Reuse of a revoked token invalidates its family. Configure retry grace, inactivity limits, absolute lifetime, and per-user caps under `jwt.session`.

Add phone or username sign-in without replacing the primary email:

```typescript
await fortress.auth.addLoginIdentifier(user.id, 'phone', '+15551234567');
await fortress.auth.addLoginIdentifier(user.id, 'username', 'alice');
await fortress.auth.login('alice', password);
```

Issue a short-lived, access-only impersonation token. The caller must hold `fortress:impersonate`:

```typescript
const impersonation = await fortress.auth.impersonate(admin.id, user.id, {
  reason: 'Support case 1234',
  expirySeconds: 5 * 60,
});
// impersonation.status === 'impersonation'
// JWT `sub` is user.id; `act.sub` is admin.id; refreshToken is null.
```

### Grant and check permissions

```typescript
const editor = await fortress.iam.createRole('editor', [
  { resource: 'post', action: 'read' },
  { resource: 'post', action: 'update' },
]);

await fortress.iam.bindRoleToUser(user.id, editor.id);

const allowed = await fortress.iam.checkPermission(
  { type: 'USER', id: user.id },
  'post',
  'update',
  { resource: { ownerId: user.id } },
);
```

Permissions can come from roles, groups, or direct bindings:

```typescript
const team = await fortress.iam.createGroup('engineering');
await fortress.iam.addUserToGroup(team.id, user.id);
await fortress.iam.bindRoleToGroup(team.id, editor.id);

await fortress.iam.bindPermissionToUser(user.id, {
  resource: 'report',
  action: 'export',
});
```

Use `deny-overrides` to enforce explicit denies:

```typescript
const fortress = createFortress({
  database,
  jwt: { key },
  rbac: { evaluationMode: 'deny-overrides' },
});
```

Add ABAC conditions to permissions:

```typescript
await fortress.iam.createRole('owner', [{
  resource: 'post',
  action: 'update',
  conditions: [{
    field: 'resource.ownerId',
    operator: 'eq',
    value: { ref: 'user.id' },
  }],
}]);
```

Credential scopes only narrow IAM access. An empty `credentialScopes` array denies every permission:

```typescript
await fortress.iam.checkPermission(subject, 'post', 'read', {
  credentialScopes: ['post:read'],
});
```

### Use service accounts

```typescript
const ci = await fortress.iam.createServiceAccount({
  name: 'ci-deploy',
  displayName: 'CI deployer',
});

await fortress.iam.bindRoleToServiceAccount(ci.id, editor.id);
```

Register the API-key plugin to authenticate the account:

```typescript
import { apiKey } from '@bajustone/fortress/plugins/api-key';

const fortress = createFortress({
  database,
  jwt: { key },
  plugins: [apiKey()] as const,
});

const credential = await fortress.plugins['api-key'].createKey({
  subject: { type: 'SERVICE_ACCOUNT', id: ci.id },
  name: 'production',
  scopes: ['post:read'],
});

console.log(credential.key); // returned once; only its hash is stored
```

Clients send `Authorization: ApiKey <key>` or `X-API-Key: <key>`.

## Call routes in process

`fortress.call` is a namespaced tree — core auth callables under `call.auth`, IAM callables under `call.iam`, and plugin routes under `call.plugins.<name>` — with request and success-response types inferred from endpoint definitions. It enters the same HTTP pipeline as a network request.

```typescript
const login = await fortress.call.auth.login({
  identifier: 'alice@example.com',
  password: 'correct-horse-battery-staple',
});

await fortress.call.auth.revokeSession(
  { id: sessionId },
  { headers: { authorization: `Bearer ${login.accessToken}` } },
);
```

Non-2xx responses throw `FortressError`:

```typescript
import { FortressError } from '@bajustone/fortress';

try {
  await fortress.call.auth.login({ identifier: 'alice@example.com', password: 'wrong' });
}
catch (error) {
  if (error instanceof FortressError && error.code === 'UNAUTHORIZED') {
    // Return your application's login error.
  }
}
```

## Mount a framework adapter

### Hono

```typescript
import { Hono } from 'hono';
import {
  createHonoMiddleware,
  getSubject,
  mountFortress,
} from '@bajustone/fortress/hono';

const app = new Hono();
mountFortress(app, fortress, { prefix: '/api' });

const { authMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, {
  routeMap: {
    'GET /posts': { resource: 'post', action: 'read' },
    'POST /posts': { resource: 'post', action: 'create' },
  },
  defaultDeny: true,
  skipPaths: ['/health'],
});

app.onError(errorHandler);
app.use('/posts/*', authMiddleware, rbacMiddleware);
app.get('/posts', (c) => c.json({ subject: getSubject(c) }));
```

Set HSTS, CSP, frame, content-type, referrer, and cross-domain-policy headers:

```typescript
import { createSecurityHeadersMiddleware } from '@bajustone/fortress/hono';

app.use('*', createSecurityHeadersMiddleware());
```

### Express

```typescript
import express from 'express';
import {
  createExpressMiddleware,
  getSubject,
  mountFortress,
} from '@bajustone/fortress/express';

const app = express();
app.use(express.json());
app.use(express.urlencoded({ extended: false })); // OAuth form endpoints
mountFortress(app, fortress, { prefix: '/api' });

const { authMiddleware, rbacMiddleware, errorHandler } = createExpressMiddleware(fortress, {
  routeMap: { 'GET /posts': { resource: 'post', action: 'read' } },
  unmappedRoutes: 'deny',
});

app.use('/posts', authMiddleware, rbacMiddleware);
app.get('/posts', (req, res) => res.json({ subject: getSubject(req) }));
app.use(errorHandler);
```

### SvelteKit

```typescript
// src/hooks.server.ts
import { createSvelteKitHandle } from '@bajustone/fortress/sveltekit';
import { fortress } from '$lib/server/fortress';

export const handle = createSvelteKitHandle(fortress, { basePath: '/api' });
```

```typescript
// src/app.d.ts
import type { FortressLocals } from '@bajustone/fortress/sveltekit';

declare global {
  namespace App {
    interface Locals extends FortressLocals {}
  }
}

export {};
```

```typescript
// src/routes/login/+page.server.ts
import { fortressActions } from '@bajustone/fortress/sveltekit';
import { fortress } from '$lib/server/fortress';

export const actions = {
  default: fortressActions.login(fortress, { redirectTo: '/dashboard' }),
};
```

The handle hook mounts Fortress routes, resolves `event.locals.fortress`, and refreshes expired access cookies on safe requests.

### Any `Request`/`Response` runtime

```typescript
export default {
  fetch(request: Request) {
    return fortress.handleRequest(request);
  },
};
```

## Protect application-owned routes

Define route metadata once, then use the adapter-specific `protectedRoute()` wrapper. The metadata drives authentication, CSRF, RBAC, validation, the route manifest, and OpenAPI.

```typescript
import { endpoint, obj, str } from '@bajustone/fortress';
import { protectedRoute } from '@bajustone/fortress/hono';

const createPost = endpoint('POST', '/posts')
  .security('bearer')
  .permission('post', 'create')
  .body(obj({ title: str({ min: 1 }) }, 'title'))
  .response(201, 'Created', obj({ id: str() }, 'id'))
  .handler('createPost')
  .build();

const fortress = createFortress({
  database,
  jwt: { key },
  routes: { createPost }, // manifest/OpenAPI metadata; host router owns dispatch
});

app.post('/posts', protectedRoute(fortress, createPost, async (_c, ctx) => {
  const post = await savePost(ctx.body.title, ctx.subject!);
  return ctx.respond(201, { id: post.id });
}));
```

See [Host-owned routes](docs/host-owned-routes.md).

## Validate custom handlers

Fortress schemas provide JSON Schema, Standard Schema V1 validation, and inferred TypeScript types:

```typescript
import { email, int, obj, strict, type Infer } from '@bajustone/fortress';

const CreateUser = strict(obj({
  email: email(),
  age: int({ min: 18 }),
}, 'email', 'age'));

type CreateUser = Infer<typeof CreateUser>;
```

Use `vBody`, `vParam`, and `vQuery` in framework-owned handlers:

```typescript
import { vBody } from '@bajustone/fortress/hono';

app.post('/users', async (c) => {
  const input = await vBody(c, CreateUser);
  return c.json(await createUser(input), 201);
});
```

For other runtimes, validate all endpoint inputs at once:

```typescript
import { validateRequest } from '@bajustone/fortress';

await validateRequest(endpoint.input, {
  body: await request.json(),
  query: Object.fromEntries(new URL(request.url).searchParams),
  params,
});

// Continue with the original data after validation.
```

`endpoint()` accepts any Standard Schema V1 implementation, including Zod, Valibot, and ArkType. Fetcher's richer schema builder is available at `@bajustone/fortress/fetcher`.

## Configure Fortress

```typescript
const fortress = createFortress({
  database,
  jwt: {
    key: [currentSecret, previousSecret], // first signs; all verify
    issuer: 'my-app',
    audience: 'my-api',
    accessTokenExpirySeconds: 15 * 60,
    refreshTokenExpirySeconds: 7 * 24 * 60 * 60,
    validateRefreshFingerprint: 'warn', // false | 'warn' | true
    session: {
      refreshGraceSeconds: 5,
      idleTimeoutSeconds: 7 * 24 * 60 * 60,
      absoluteTimeoutSeconds: 30 * 24 * 60 * 60,
      maxSessionsPerUser: 10,
    },
  },
  rbac: {
    evaluationMode: 'deny-overrides',
    resourceFile: './fortress.resources.json',
    cache: { ttlSeconds: 30, maxEntries: 1000 }, // opt in
  },
  passwordPolicy: {
    minLength: 15,
    maxLength: 128,
    checkBreached: true,
    breachedFailureMode: 'open',
  },
  impersonation: { maxTtlSeconds: 15 * 60 },
  cookies: {
    secure: true,
    sameSite: 'lax',
    path: '/',
  },
  csrf: {
    enabled: true,
    skipPaths: ['/webhooks/incoming'],
  },
  plugins: [],
  routes: {},
  logger,
  observability,
});
```

Defaults:

- JWT issuer: `fortress`
- Access token: 15 minutes
- Refresh token: 7 days
- Permission evaluation: `allow-only`
- Permission cache: disabled until `rbac.cache` is supplied
- Password length: 15–128 characters; breach lookup disabled
- Cookies: `Secure`, `HttpOnly`, `SameSite=Lax`, `Path=/`, with `__Host-` names when possible
- CSRF: enabled for unsafe browser requests; cookie-authenticated requests require `X-Fortress-CSRF`
- Logger and telemetry: silent/no-op

Set `cookies: { secure: false }` only for plain-HTTP local development. `SameSite=None` requires `Secure`.

### Replace password hashing

The default hasher is Argon2id through WASM. Supply a native implementation when needed:

```typescript
import type { PasswordHasher } from '@bajustone/fortress';

const passwordHasher: PasswordHasher = {
  hash: password => Bun.password.hash(password, { algorithm: 'argon2id' }),
  verify: (hash, password) => Bun.password.verify(password, hash),
};
```

## Add plugins

```typescript
import { accountLockout } from '@bajustone/fortress/plugins/account-lockout';
import { auditLog } from '@bajustone/fortress/plugins/audit-log';
import { rateLimit } from '@bajustone/fortress/plugins/rate-limit';

const fortress = createFortress({
  database,
  jwt: { key },
  plugins: [
    rateLimit(),
    accountLockout(),
    auditLog({ hashChain: true }),
  ] as const,
});

await fortress.plugins['account-lockout'].resetLockout('alice@example.com');
const events = await fortress.plugins['audit-log'].getAuditLog({ userId: user.id });
```

Hooks run in registration order. Put rejection/gate plugins before side-effect plugins. A failing `afterLogin`, `afterRegister`, or `afterTokenRefresh` side-effect is logged and does not invalidate an already committed auth result. Use `beforeLogin` or `postAuthGate` to block token issuance.

| Need | Plugin | Guide |
|---|---|---|
| Protected admin CRUD and first-admin bootstrap | `admin` | [Admin](docs/plugins/admin.md) |
| API keys for users and service accounts | `api-key` | [API key](docs/plugins/api-key.md) |
| Progressive login lockouts | `account-lockout` | [Account lockout](docs/plugins/account-lockout.md) |
| Sliding-window limits for auth and app routes | `rate-limit` | [Rate limit](docs/plugins/rate-limit.md) |
| Verify email before issuing a session | `email-verification` | [Email verification](docs/plugins/email-verification.md) |
| TOTP, backup codes, and trusted devices | `two-factor` | [Two-factor](docs/plugins/two-factor.md) |
| Passkeys or WebAuthn as a second factor | `webauthn` | [WebAuthn](docs/plugins/webauthn.md) |
| Passwordless email login | `magic-link` | [Magic link](docs/plugins/magic-link.md) |
| Google, GitHub, Apple, Microsoft, Discord, or OIDC login | `social-login` | [Social login](docs/plugins/social-login.md) |
| OAuth 2.0/OIDC authorization server | `oauth` | [OAuth server](docs/plugins/oauth.md) |
| PostgreSQL schema-per-tenant isolation | `tenancy` | [Tenancy](docs/plugins/tenancy.md) |
| Database-independent row-level scoping | `data-isolation` | [Data isolation](docs/plugins/data-isolation.md) |
| Queryable or hash-chained audit events | `audit-log` | [Audit log](docs/plugins/audit-log.md) |
| Signed, queued outbound events | `webhook` | [Webhook](docs/plugins/webhook.md) |
| OpenAPI 3.1 JSON and Scalar UI | `openapi` | [OpenAPI](docs/plugins/openapi.md) |

## Migrate and bootstrap

```typescript
await fortress.migrate({
  migrateApp: () => migrate(appDb, { migrationsFolder: './drizzle' }),
});

await fortress.syncPermissionsFromManifest({
  defaultRoles: {
    admin: '*',
    member: ['post:read'],
  },
});
```

Fortress migrations run before `migrateApp`. Permission sync is idempotent and only adds missing manifest permissions and bindings.

For a one-shot deploy job, export the configured instance from a trusted module:

```typescript
// src/fortress.ts
export const fortress = createFortress({ database, jwt, plugins });
export async function migrateApp() { /* optional application migration */ }
export async function dispose() { /* optional pool/connection cleanup */ }
```

```bash
fortress migrate:up --module ./src/fortress.ts
fortress migrate:up --module ./src/fortress.ts --target-version 10
```

The module path is resolved from the current directory and loaded explicitly by
Bun. Importing it executes trusted application code with that process's database
credentials. The live dialect always comes from the configured adapter; the CLI
rejects a separate `--dialect` override.

Check live schema drift:

```typescript
import { detectMigrationDrift, hasMigrationDrift } from '@bajustone/fortress';

const drift = await detectMigrationDrift(database);
if (hasMigrationDrift(drift))
  throw new Error(JSON.stringify(drift));
```

See the [migration upgrade guide](docs/migrations/upgrade-guide.md).

## Use PostgreSQL

```typescript
import { drizzle } from 'drizzle-orm/node-postgres';
import { createPostgresDrizzleAdapter } from '@bajustone/fortress/drizzle';
import { fortressPgSchema } from '@bajustone/fortress/drizzle/pg';

const drizzleDb = drizzle(connectionString, { schema: fortressPgSchema });
const database = createPostgresDrizzleAdapter(drizzleDb);
```

`@bajustone/fortress/drizzle/pg` exports the schema. Import `createPostgresDrizzleAdapter` from `@bajustone/fortress/drizzle`.

To use another datastore, implement `DatabaseAdapter`:

```typescript
import type { DatabaseAdapter } from '@bajustone/fortress';

const database: DatabaseAdapter = {
  create: async ({ model, data }) => insert(model, data),
  findOne: async ({ model, where }) => findOne(model, where),
  findMany: async ({ model, where, limit, offset, sortBy }) => findMany(model, { where, limit, offset, sortBy }),
  update: async ({ model, where, data }) => update(model, where, data),
  delete: async ({ model, where }) => remove(model, where),
  count: async ({ model, where }) => count(model, where),
  transaction: async fn => runTransaction(fn),
  rawQuery: async (sql, params) => query(sql, params), // optional for ordinary operations
  dialect: 'pg',                                      // optional for ordinary operations
};
```

To run Fortress-managed migrations with a custom datastore, implement
`MigratableDatabaseAdapter`. It requires both `rawQuery` and a literal
`dialect`, and its transaction callback must receive the same migration
capability. Drizzle users get this contract from the dialect-specific factories.

## Generate OpenAPI

```typescript
const spec = fortress.toOpenAPI({
  title: 'My API',
  version: '1.0.0',
  servers: [{ url: 'https://api.example.com' }],
});

await Bun.write('openapi.json', JSON.stringify(spec, null, 2));
```

Or mount the plugin:

```typescript
import { openapi } from '@bajustone/fortress/plugins/openapi';

const fortress = createFortress({
  database,
  jwt: { key },
  plugins: [openapi({ title: 'My API', version: '1.0.0' })] as const,
});
// GET /openapi.json
// GET /openapi
```

## Test and check drift

```bash
# Node tests need the optional SQLite driver.
npm install --save-dev better-sqlite3
```

```typescript
import { createFortress } from '@bajustone/fortress';
import { createTestAdapter, runFortressChecks } from '@bajustone/fortress/testing';

const fortress = createFortress({
  database: createTestAdapter(),
  jwt: { key: 'test-secret-that-is-at-least-32-bytes' },
  plugins,
});

const result = await runFortressChecks({ fortress });
if (!result.ok)
  throw new Error(result.messages.join('\n'));
```

The testing entrypoint also exports `smokeTestAuth`, `checkMigrationDrift`, `checkRouteManifestDrift`, and `checkPublicRoutes`. See [CI checks](docs/ci.md).

## Observe auth and IAM

```typescript
const stopAuth = fortress.auth.addAuthObserver(async (event) => {
  await securityEvents.write(event);
});

const stopIam = fortress.iam.addIamObserver(async (event) => {
  await audit.write(event);
});

const stopChecks = fortress.iam.addPermissionCheckObserver((event) => {
  permissionLatency.record(event.durationSeconds);
});
```

Auth and IAM observers may return promises; failures are logged and contained. Permission-check observers are synchronous and run on the authorization hot path.

Use OpenTelemetry through the optional entrypoint:

```typescript
import { createOtelTelemetry } from '@bajustone/fortress/otel';

const observability = await createOtelTelemetry({ name: 'my-app' });
const fortress = createFortress({ database, jwt: { key }, observability });
```

See [Observability](docs/observability.md).

## CLI

```bash
fortress init
fortress generate-secret
fortress sync:types
fortress openapi --module ./fortress.config.ts --out openapi.json
fortress schemas --module ./fortress.config.ts --format json-schema --out schemas.json
fortress manifest --module ./fortress.config.ts --out route-manifest.json
fortress manifest:check --module ./fortress.config.ts
fortress check:public-routes --module ./fortress.config.ts
fortress migrate:status --dialect pg       # bundled catalog status
fortress migrate:check --dialect pg        # bundled catalog validation
fortress migrate:up --module ./fortress.migrate.ts   # needs a real instance
fortress migrate:export --dialect pg --direction up --out fortress-pg.sql
fortress policy:summary
```

`openapi`, `schemas`, `manifest`, `manifest:check` (alias `check:routes`), and
`check:public-routes` take `--module <path>`, pointing at a module that exports
your configuration as `export const config`. That is what makes them cover your
plugin and host-owned routes. The route surface is derived from the config
without calling `createFortress()`, so no Fortress instance is created and no
plugin's `methods()` factory runs — relevant because plugins do real work in
that factory (the webhook queue runs a startup recovery sweep there). Keep such a
module free of side effects at import time. A configured instance exported as
`export const fortress` is also accepted, at the cost of constructing your app.
Export `componentSchemas` to add your own reusable schemas to `openapi` and
`schemas` output.

**Omit `--module` and they only cover Fortress's own auth and IAM routes** —
useful for checking Fortress itself, but a pass says nothing about your routes.
Every one of them prints its scope. `fortress init` scaffolds a
`fortress.config.ts` in the shape these commands expect.

`migrate:up` is the live migration command and needs a real instance, so it
requires an explicit trusted module with a named `fortress` export. `migrate:export` emits deterministic SQL
for review or external tooling; it does not run JavaScript data steps and is not
a substitute for the live command. `migrate:down` remains a deprecated alias
for down-SQL export, not a live rollback command. Live drift checks use
`detectMigrationDrift()` / `checkMigrationDrift()` against your adapter.

## Guides

- [Examples](examples/README.md)
- [Host-owned routes](docs/host-owned-routes.md)
- [Typed framework helpers](docs/adapter-typed-helpers.md)
- [Policy as code](docs/policy-as-code.md)
- [Admin recipes](docs/admin-recipes.md)
- [Deployment](docs/deployment.md)
- [Security](docs/security.md) and [hardening](docs/hardening.md)
- [Threat model](docs/threat-model.md)
- [Observability](docs/observability.md)
- [Route manifest](docs/route-manifest.md)
- [CI checks](docs/ci.md)
- [Compatibility](docs/compatibility.md)
- [npm/JSR publication policy](docs/publication.md)
- [Architecture and plugin authoring](docs/architecture.md)

## License

MIT
