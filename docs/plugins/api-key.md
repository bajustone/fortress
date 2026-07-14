# API Key Plugin

## Overview

The `api-key` plugin adds scoped API key management to Fortress. It is designed for service accounts, CI/CD pipelines, mobile devices, and any scenario where long-lived bearer tokens are preferable to short-lived JWTs.

Keys are generated with a configurable prefix, hashed with SHA-256 before storage, and can be scoped to limit what actions a key is allowed to perform.

**Polymorphic ownership.** Keys are owned by a `Subject` — either a `USER` or a `SERVICE_ACCOUNT`. The api-key schema stores `(subject_type, subject_id)` instead of a hard FK to `users.id`, mirroring `role_binding` and `direct_permission_binding`. Authentication flows support both subject types transparently.

**Automatic request principal resolution.** The plugin implements Fortress's `resolvePrincipal` capability: when a request arrives with an `Authorization: ApiKey <key>` or `X-API-Key: <key>` header, the plugin resolves the key to its owning subject and that subject becomes the request principal for RBAC. No middleware setup required — just register the plugin.

## Installation

Import the `apiKey` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { apiKey } from '@bajustone/fortress/plugins/api-key';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    apiKey({
      prefix: 'myapp',
      defaultExpirySeconds: 90 * 24 * 60 * 60, // 90 days
      maxKeysPerSubject: 5,
    }),
  ],
});
```

Once registered, methods are available at `fortress.plugins['api-key']` with full type safety.

## Configuration

All fields on `ApiKeyConfig` are optional:

| Option | Type | Default | Description |
|---|---|---|---|
| `prefix` | `string` | `'fortress'` | Prefix prepended to generated keys. Keys are formatted as `{prefix}_sk_{hex}`. |
| `defaultExpirySeconds` | `number \| null` | `null` | Default time-to-live for new keys, in seconds. `null` means keys never expire unless an explicit `expiresAt` is provided at creation time. |
| `maxKeysPerSubject` | `number` | `10` | Maximum number of active (non-revoked) keys a single subject (user or service account) can hold. Revoked keys do not count toward this limit. |
| `routes` | `boolean` | `false` | Mount self-service HTTP routes under `/api-key/keys/*`. The programmatic methods on `fortress.plugins['api-key']` are always available regardless of this flag. |

## Usage

### Creating a key

```ts
// For a user
const { key, id } = await fortress.plugins['api-key'].createKey({
  subject: { type: 'USER', id: userId },
  name: 'CI deploy token',
});

// For a service account (see IAM docs for createServiceAccount)
const { key: saKey } = await fortress.plugins['api-key'].createKey({
  subject: { type: 'SERVICE_ACCOUNT', id: serviceAccountId },
  name: 'ci-deploy-key',
});

// key = "myapp_sk_a1b2c3d4..." (the raw secret -- only returned once)
// id  = 42 (database record ID)
```

Store or display the raw `key` immediately. Fortress stores only the SHA-256 hash; the plaintext cannot be retrieved later.

You can set an explicit expiry:

```ts
const { key } = await fortress.plugins['api-key'].createKey({
  subject: { type: 'USER', id: userId },
  name: 'Temp key',
  expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
});
```

If neither `expiresAt` nor `defaultExpirySeconds` is set, the key never expires.

### Listing keys

```ts
const keys = await fortress.plugins['api-key'].listKeys({
  subject: { type: 'USER', id: userId },
});

for (const k of keys) {
  console.log(k.id, k.name, k.keyPrefix, k.scopes, k.expiresAt, k.lastUsedAt);
}
```

Returns only active (non-revoked) keys scoped to the given subject. Each entry includes a short `keyPrefix` (first 12 characters) for identification but never exposes the full key or its hash.

### Revoking a key

```ts
await fortress.plugins['api-key'].revokeKey({
  subject: { type: 'USER', id: userId },
  id: keyId,
});
```

Marks the key as revoked. Revoked keys cannot be resolved and do not count toward the per-subject limit. The `subject` parameter is checked against the key's owner — attempting to revoke a key that belongs to a different subject throws a `NotFound` error.

### Rotating a key

```ts
const { key: newKey, id: newId } = await fortress.plugins['api-key'].rotateKey({
  subject: { type: 'USER', id: userId },
  id: keyId,
});
```

Rotation is a single atomic operation that:

1. Revokes the existing key.
2. Creates a new key with the same `name`, `scopes`, and `expiresAt` as the original.

The old key stops working immediately. The new raw key is returned and must be stored by the caller.

### Resolving a key for authentication

```ts
const result = await fortress.plugins['api-key'].resolveKey(rawKey);

if (!result) {
  // Key is invalid, revoked, expired, or owned by a disabled service account.
  throw new Error('Unauthorized');
}

console.log(result.subject); // { type: 'USER' | 'SERVICE_ACCOUNT', id: string }
console.log(result.scopes);  // string[] | null
```

`resolveKey` hashes the provided raw key and looks it up in the database. It returns `null` when the key is unknown, revoked, past its `expiresAt`, or owned by a service account with `isActive: false`. On success it also updates the key's `lastUsedAt` timestamp.

### Authenticating incoming requests

You don't need to call `resolveKey` yourself — the api-key plugin implements Fortress's `resolvePrincipal` capability, so both `fortress.handleRequest` *and* the Hono / Express / SvelteKit user-route auth middleware automatically resolve requests bearing an api-key header into a subject principal. Two header formats are accepted:

```
Authorization: ApiKey myapp_sk_a1b2c3d4...
X-API-Key: myapp_sk_a1b2c3d4...
```

If neither header is present, the pipeline falls back to the JWT path. If both a JWT and an api-key are present, the api-key wins (resolvers run before the JWT fallback).

> Note: api-key authentication works uniformly on Fortress-owned routes (`/auth/*`, `/iam/*`, plugin routes) *and* your own custom routes — any route protected by the adapter's auth middleware goes through `fortress.resolvePrincipal`, which tries the plugin chain before the JWT fallback. The resolved principal is available as `fortressSubject` on the adapter request context (Hono `c.get('fortressSubject')` / Express `req.fortressSubject` / SvelteKit `event.locals.fortress.subject`).

Once resolved, the principal flows through the same RBAC machinery as a JWT-authenticated request:

```ts
// Inside a fortress-managed route or an adapter middleware RBAC check
await fortress.iam.checkPermission(
  ctx.subject,  // { type: 'USER' | 'SERVICE_ACCOUNT', id }
  'deploy',
  'run',
);
```

### Scoped keys

Scopes let you restrict what an API key is allowed to do. Pass a `scopes` array at creation time:

```ts
const { key } = await fortress.plugins['api-key'].createKey({
  subject: { type: 'USER', id: userId },
  name: 'Read-only analytics',
  scopes: ['analytics:read', 'reports:list'],
});
```

When the key is resolved, the scopes are returned so your application can enforce them:

```ts
const result = await fortress.plugins['api-key'].resolveKey(rawKey);

if (result && result.scopes && !result.scopes.includes('analytics:read')) {
  throw new Error('Forbidden: insufficient scope');
}
```

If no scopes are provided, `resolveKey` returns `scopes: null`, which you can treat as "unrestricted" or reject based on your security policy.

## API Reference

| Method | Signature | Returns |
|---|---|---|
| `createKey` | `(input: { subject?: Subject; name: string; scopes?: string[]; expiresAt?: Date }, routeCtx?: PluginRouteContext)` | `Promise<{ key: string; id: string }>` |
| `listKeys` | `(input: { subject?: Subject }, routeCtx?: PluginRouteContext)` | `Promise<ApiKeyInfo[]>` |
| `revokeKey` | `(input: { subject?: Subject; id: string \| string }, routeCtx?: PluginRouteContext)` | `Promise<{ ok: true }>` |
| `rotateKey` | `(input: { subject?: Subject; id: string \| string }, routeCtx?: PluginRouteContext)` | `Promise<{ key: string; id: string }>` |
| `resolveKey` | `(rawKey: string)` | `Promise<{ subject: Subject; scopes: string[] \| null } \| null>` |

**Dual-mode `subject`.** When called from an HTTP route handler with a `routeCtx`, the plugin uses `routeCtx.subject` and ignores any `subject` supplied in `input` — clients can't pick which subject a key is created for. When called programmatically (no `routeCtx`), the plugin uses `input.subject`; programmatic callers are trusted.

The `ApiKeyInfo` type returned by `listKeys`:

```ts
interface ApiKeyInfo {
  id: string;
  name: string;
  keyPrefix: string;        // first 12 characters of the raw key
  scopes: string[] | null;
  expiresAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
}
```

## Service account flow (end-to-end)

A complete walkthrough of setting up a CI deploy bot as a service account, granting it permissions, and authenticating its requests. Service accounts are first-class IAM principals — see the [README IAM section](../../README.md#use-service-accounts) for the conceptual overview.

### 1. Create the service account

```ts
const ci = await fortress.iam.createServiceAccount({
  name: 'ci-deploy',                       // machine identifier, immutable
  displayName: 'CI Deploy',
  description: 'Runs production deploys from GitHub Actions',
});
```

### 2. Grant it permissions

Either bind a role or a direct permission. Both work exactly as they do for users:

```ts
const deployer = await fortress.iam.createRole('deployer', [
  { resource: 'deploy', action: 'run' },
  { resource: 'deploy', action: 'rollback' },
]);
await fortress.iam.bindRoleToServiceAccount(ci.id, deployer.id);
```

### 3. Mint an API key for the service account

Programmatically:

```ts
const { key } = await fortress.plugins['api-key'].createKey({
  subject: { type: 'SERVICE_ACCOUNT', id: ci.id },
  name: 'ci-deploy-github-actions',
});
// store `key` in your CI secrets store NOW — it is never returned again
```

Or via HTTP, using the admin plugin's mint endpoint — the only supported HTTP path for bootstrapping a service account's first credential (a fresh SA has no login flow, so it can't self-mint via the `/api-key/keys` self-service route):

```bash
curl -X POST http://localhost:3000/admin/service-accounts/$SA_ID/api-keys \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"ci-deploy-github-actions"}'
```

This requires `admin({ apiKeyRoutes: true })` registered alongside `apiKey()`, and the caller must hold the `apiKey:manage` permission (auto-registered by bootstrap). See [docs/plugins/admin.md — API key management](./admin.md#api-key-management) for the full admin surface.

### 4. Authenticate requests using the key

The client sends the key in either header. Fortress's `resolvePrincipal` plugin hook — which `api-key` implements — inspects each incoming request and turns the header into a subject principal *before* RBAC runs:

```
POST /deploy/run HTTP/1.1
Authorization: ApiKey fortress_sk_a1b2c3d4...
```

or

```
POST /deploy/run HTTP/1.1
X-API-Key: fortress_sk_a1b2c3d4...
```

Inside your route, the authenticated principal is the service account:

```ts
// On a fortress-managed route, routeCtx.subject is populated
async handler(input, routeCtx) {
  // routeCtx.subject is { type: 'SERVICE_ACCOUNT', id: ci.id }
  const allowed = await fortress.iam.checkPermission(
    routeCtx.subject!,
    'deploy',
    'run',
  );
  if (!allowed) throw Errors.forbidden();
  // ... run the deploy
}
```

Fortress-managed routes (like the `/iam/service-accounts/*` admin endpoints) automatically enforce the subject's permissions via `enforceFortressPermission`.

### 5. Kill-switch: deactivate when compromised

If a key leaks, you have two layers of defense. Revoke the individual key, or deactivate the entire service account — the latter instantly stops every key the account owns from resolving, and drives `checkPermission` to return `false` for that subject:

```ts
// Option A: revoke just this key
await fortress.plugins['api-key'].revokeKey({
  subject: { type: 'SERVICE_ACCOUNT', id: ci.id },
  id: keyId,
});

// Option B: kill-switch the whole service account
await fortress.iam.updateServiceAccount(ci.id, { isActive: false });
```

### 6. Decommission: delete the service account

`deleteServiceAccount` is a hard delete with cascade — the account row, all role bindings, all direct permission bindings, and every API key owned by the account are removed in one operation.

```ts
await fortress.iam.deleteServiceAccount(ci.id);
```

---

## How It Works

1. **Key generation** -- `crypto.getRandomValues` produces 32 random bytes, hex-encoded and prepended with `{prefix}_sk_` to form the raw key.
2. **Hashed storage** -- The raw key is hashed with SHA-256 (via the same `hashToken` used for refresh tokens). Only the hash is persisted; the plaintext is returned once at creation time.
3. **Prefix-based identification** -- The first 12 characters of the raw key are stored as `keyPrefix`, allowing users and admins to identify keys in listings without exposing the secret.
4. **Resolution** -- `resolveKey` hashes the incoming raw key and performs a database lookup on `keyHash`. It rejects revoked and expired keys, and updates `lastUsedAt` on success.
5. **Scopes** -- Stored as a JSON-serialized string array in the database and parsed back to `string[]` on read. Scope enforcement is left to the application layer.
