# Architecture and plugin authoring

## Request pipeline

Every framework adapter delegates Fortress-owned routes to:

```typescript
const response = await fortress.handleRequest(request);
```

The pipeline runs in this order:

1. `before-auth` plugin middleware
2. CSRF for unsafe cookie-authenticated requests
3. route matching
4. plugin principal resolvers, then JWT fallback
5. `after-auth` plugin middleware
6. endpoint permission check
7. `after-rbac` plugin middleware
8. body, query, and parameter validation
9. endpoint dispatch
10. auth-cookie serialization

Use the same pipeline without an HTTP server:

```typescript
const result = await fortress.call.login({
  identifier: 'alice@example.com',
  password: 'correct-horse-battery-staple',
});
```

Direct service calls skip HTTP middleware, CSRF, route permissions, and request schemas:

```typescript
await fortress.auth.login(identifier, password);
await fortress.iam.checkPermission(subject, 'post', 'read');
```

Auth and IAM service hooks and observers still run.

## Instance composition

`createFortress()`:

1. validates JWT keys and session options;
2. wraps the database with observability;
3. creates auth and IAM services;
4. registers plugin methods, hooks, middleware, routes, and principal resolvers;
5. merges core, plugin, and host endpoint metadata;
6. builds `manifest`, `handleRequest`, and `call`.

```typescript
const fortress = createFortress({ database, jwt: { key }, plugins });

fortress.auth;
fortress.iam;
fortress.plugins;
fortress.call;
fortress.endpoints;
fortress.manifest;
fortress.handleRequest;
fortress.migrate;
fortress.syncPermissionsFromManifest;
fortress.toOpenAPI;
```

Startup rejects:

- JWT keys shorter than 32 UTF-8 bytes;
- non-positive `jwt.session` values;
- duplicate plugin names;
- duplicate routes or call keys between plugins;
- `security: ['none']` combined with a permission;
- use of the reserved `__host` plugin name when top-level `routes` are set.

A plugin may intentionally replace a core route. Two plugins cannot own the same route.

## Endpoint metadata

An endpoint definition supplies request schemas, response schemas, security, IAM permission, OpenAPI metadata, and a handler name:

```typescript
import { endpoint, obj, str } from '@bajustone/fortress';

const createPost = endpoint('POST', '/posts')
  .summary('Create a post')
  .security('bearer')
  .permission('post', 'create')
  .body(obj({ title: str() }, 'title'))
  .response(201, 'Created', obj({ id: str() }, 'id'))
  .handler('createPost')
  .build();
```

Register application-owned metadata at the top level:

```typescript
const fortress = createFortress({
  database,
  jwt: { key },
  routes: { createPost },
});
```

Top-level routes appear in `fortress.endpoints`, the manifest, OpenAPI, and protection helpers. The host router still dispatches them. They do not create `fortress.call` methods.

To create a mounted and callable endpoint, define a plugin with matching `routes` and `methods` keys.

## Write a route plugin

```typescript
import {
  endpoint,
  obj,
  str,
  type FortressPlugin,
} from '@bajustone/fortress';

const greetingEndpoint = endpoint('POST', '/greetings')
  .security('bearer')
  .permission('greeting', 'create')
  .body(obj({ name: str() }, 'name'))
  .response(200, 'Greeting', obj({ message: str() }, 'message'))
  .handler('createGreeting')
  .build();

export function greetings() {
  return {
    name: 'greetings',
    routes: { createGreeting: greetingEndpoint },
    methods: () => ({
      async createGreeting(input: { name: string }) {
        return { message: `Hello ${input.name}` };
      },
    }),
  } as const satisfies FortressPlugin;
}
```

```typescript
const fortress = createFortress({
  database,
  jwt: { key },
  plugins: [greetings()] as const,
});

await fortress.call.createGreeting(
  { name: 'Alice' },
  { headers: { authorization: `Bearer ${token}` } },
);
```

The route record key, endpoint handler, and method key must match.

## Add lifecycle hooks

```typescript
export function loginPolicy(): FortressPlugin {
  return {
    name: 'login-policy',
    hooks: {
      async beforeLogin(ctx) {
        if (await isBlocked(ctx.email)) {
          return {
            stop: true,
            response: { error: 'ACCOUNT_BLOCKED' },
          };
        }
      },
      async onLoginFailure(ctx) {
        await recordFailure(ctx.identifier);
      },
      async afterLogin(ctx, result) {
        await recordSuccess(result.user.id);
        ctx.responseHeaders.set('X-Auth-Method', result.method);
        return result;
      },
    },
  };
}
```

Hooks run in plugin registration order.

Use these before token issuance:

- `beforeLogin`
- `beforeRegister`
- `beforeTokenRefresh`
- `postAuthGate`

Use these for committed side effects:

- `afterLogin`
- `afterRegister`
- `afterTokenRefresh`
- `onLoginFailure`

A thrown `afterLogin`, `afterRegister`, or `afterTokenRefresh` hook is logged and skipped. It cannot roll back an issued session or created user. A plugin that must deny authentication belongs before token issuance.

## Add a pending authentication gate

```typescript
import { Errors, type FortressPlugin } from '@bajustone/fortress';

export function securityQuestion(): FortressPlugin {
  return {
    name: 'security-question',
    hooks: {
      postAuthGate: {
        reason: 'two-factor',
        maxAttempts: 5,
        cooldownSeconds: 60,
        async evaluate({ user }) {
          if (await requiresQuestion(user.id))
            return { pluginData: { prompt: 'First school?' } };
        },
        async verify({ user }, completion) {
          if (!await checkAnswer(user.id, completion))
            throw Errors.unauthorized('Invalid answer');
        },
      },
    },
  };
}
```

A gate returns a pending auth result before tokens exist:

```typescript
const result = await fortress.auth.login(email, password);

if (result.status === 'pending') {
  const completed = await fortress.auth.completePendingAuth(
    result.pending.continuationToken,
    answer,
  );
}
```

Use an existing `PendingReason` or add a new reason to the core union before publishing a plugin.

## Resolve a custom credential

Principal resolvers run in plugin order before JWT verification. Return `null` when the credential is absent so the next resolver can try.

```typescript
export function signedRequest(): FortressPlugin {
  return {
    name: 'signed-request',
    async resolvePrincipal(request) {
      const signature = request.headers.get('X-Signature');
      if (!signature)
        return null;

      const serviceAccountId = await verifySignature(signature, request);
      return {
        subject: { type: 'SERVICE_ACCOUNT', id: serviceAccountId },
        scopes: ['orders:write'],
      };
    },
  };
}
```

Scopes narrow the subject's IAM permissions. They never grant a permission the subject does not already have.

## Add request middleware

```typescript
export function requestAudit(): FortressPlugin {
  return {
    name: 'request-audit',
    middleware: [{
      path: '/orders/*',
      position: 'after-rbac',
      async handler(_plugin, context, next) {
        await audit(
          context.fortressSubject,
          new URL(context.request.url).pathname,
        );
        await next();
      },
    }],
  };
}
```

Positions:

| Position | Identity | Permission result | Use |
|---|---:|---:|---|
| `before-auth` | no | no | rate limits, request normalization |
| `after-auth` | yes | no | account state, identity-aware controls |
| `after-rbac` | yes | yes | authorized audit and request context |

## Extend JWT claims

```typescript
export function tenantClaims(): FortressPlugin {
  return {
    name: 'tenant-claims',
    async enrichTokenClaims(userId, { db }) {
      const membership = await findMembership(db, userId);
      return {
        tenantId: membership.id,
        tenantCode: membership.code,
      };
    },
  };
}
```

Claims are shallow-merged in plugin order. Later plugins overwrite duplicate keys and emit a development warning.

## Scope database access

`scopeRules` adds model filters. `wrapAdapter` replaces the request-scoped adapter when a plugin needs transaction or schema behavior.

```typescript
export function organizationScope(): FortressPlugin {
  return {
    name: 'organization-scope',
    async scopeRules(userId, model) {
      if (model !== 'post')
        return null;

      const organizationId = await organizationFor(userId);
      return {
        filters: [{ field: 'organizationId', operator: '=', value: organizationId }],
        defaults: { organizationId },
      };
    },
  };
}
```

Read the scoped adapter from framework context:

```typescript
const db = await getScopedDb(c, 'post');
const posts = await db.findMany({ model: 'post' });
```

Use the bundled [data-isolation plugin](plugins/data-isolation.md) for row-level filtering and [tenancy plugin](plugins/tenancy.md) for PostgreSQL schema isolation.

## Database contract

Plugins use the same adapter as core:

```typescript
interface DatabaseAdapter {
  create(args): Promise<unknown>;
  findOne(args): Promise<unknown | null>;
  findMany(args): Promise<unknown[]>;
  update(args): Promise<unknown | null>;
  delete(args): Promise<void>;
  count(args): Promise<number>;
  transaction<T>(fn: (tx: DatabaseAdapter) => Promise<T>): Promise<T>;
  rawQuery?<T>(sql: string, params?: unknown[]): Promise<T[]>;
  dialect?: 'sqlite' | 'pg';
}
```

Portable `rawQuery` SQL uses `?` placeholders. The adapter translates them for its driver.

Core operators:

```typescript
'=' | '!=' | 'in' | 'gt' | 'lt' | 'gte' | 'lte' | 'isNull'
```

Adapters may support additional operators. The Drizzle adapter also supports `like`.

## Auth data flow

### Login

1. Run `beforeLogin` hooks.
2. Resolve the login identifier.
3. verify user state and password with timing-safe miss behavior.
4. run post-auth gates.
5. enrich claims.
6. create the access token and refresh-token family.
7. run failure-contained after hooks.
8. emit auth observers.

### Refresh

1. hash and find the refresh token;
2. reject expiry, inactivity, absolute lifetime, or fingerprint policy failures;
3. detect reuse and revoke the family;
4. rotate the token in the same family;
5. refresh claims and session metadata;
6. run failure-contained after hooks;
7. return the new pair.

The database stores refresh-token hashes, not raw tokens.

## IAM data flow

```typescript
await fortress.iam.checkPermission(subject, resource, action, context);
```

The check:

1. verifies that a user subject still exists and is active;
2. loads global permissions from the optional cache or tenant permissions from the database;
3. collects role, group, and direct grants;
4. narrows with credential scopes;
5. evaluates resource/action wildcards and conditions;
6. applies `allow-only` or `deny-overrides`;
7. emits a synchronous permission-check event.

Tenant checks bypass the global permission cache. User activation is checked before cached grants, so deactivation denies immediately.

## Package boundaries

| Entry point | Purpose |
|---|---|
| `@bajustone/fortress` | core, schemas, endpoints, policy, migrations |
| `@bajustone/fortress/hono` | Hono mount, middleware, validation, protection |
| `@bajustone/fortress/express` | Express mount, middleware, validation, protection |
| `@bajustone/fortress/sveltekit` | handle hook, actions, locals, validation, protection |
| `@bajustone/fortress/drizzle` | adapter, SQLite/PG schemas, DB error mapping |
| `@bajustone/fortress/drizzle/pg` | PostgreSQL schema only |
| `@bajustone/fortress/testing` | in-memory adapter and drift checks |
| `@bajustone/fortress/otel` | OpenTelemetry provider adapter |
| `@bajustone/fortress/fetcher` | outbound client and schema tooling |
| `@bajustone/fortress/plugins/*` | optional plugins |

Core does not import framework adapters. Framework adapters only translate their request/response APIs to the web-standard core.
