# API Key Plugin

## Overview

The `api-key` plugin adds scoped API key management to Fortress. It is designed for service accounts, CI/CD pipelines, mobile devices, and any scenario where long-lived bearer tokens are preferable to short-lived JWTs.

Keys are generated with a configurable prefix, hashed with SHA-256 before storage, and can be scoped to limit what actions a key is allowed to perform.

## Installation

Import the `apiKey` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { apiKey } from '@bajustone/fortress/plugins/api-key';

const fortress = createFortress({
  jwt: { secret: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    apiKey({
      prefix: 'myapp',
      defaultExpirySeconds: 90 * 24 * 60 * 60, // 90 days
      maxKeysPerUser: 5,
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
| `maxKeysPerUser` | `number` | `10` | Maximum number of active (non-revoked) keys a single user can hold. Revoked keys do not count toward this limit. |

## Usage

### Creating a key

```ts
const { key, id } = await fortress.plugins['api-key'].createKey(userId, {
  name: 'CI deploy token',
});

// key = "myapp_sk_a1b2c3d4..." (the raw secret -- only returned once)
// id  = 42 (database record ID)
```

Store or display the raw `key` immediately. Fortress stores only the SHA-256 hash; the plaintext cannot be retrieved later.

You can set an explicit expiry:

```ts
const { key } = await fortress.plugins['api-key'].createKey(userId, {
  name: 'Temp key',
  expiresAt: new Date(Date.now() + 60 * 60 * 1000), // 1 hour from now
});
```

If neither `expiresAt` nor `defaultExpirySeconds` is set, the key never expires.

### Listing keys

```ts
const keys = await fortress.plugins['api-key'].listKeys(userId);

for (const k of keys) {
  console.log(k.id, k.name, k.keyPrefix, k.scopes, k.expiresAt, k.lastUsedAt);
}
```

Returns only active (non-revoked) keys. Each entry includes a short `keyPrefix` (first 12 characters) for identification but never exposes the full key or its hash.

### Revoking a key

```ts
await fortress.plugins['api-key'].revokeKey(userId, keyId);
```

Marks the key as revoked. Revoked keys cannot be resolved and do not count toward the per-user limit. The `userId` parameter is checked against the key's owner -- attempting to revoke another user's key throws a `NotFound` error.

### Rotating a key

```ts
const { key: newKey, id: newId } = await fortress.plugins['api-key'].rotateKey(userId, keyId);
```

Rotation is a single atomic operation that:

1. Revokes the existing key.
2. Creates a new key with the same `name`, `scopes`, and `expiresAt` as the original.

The old key stops working immediately. The new raw key is returned and must be stored by the caller.

### Resolving a key for authentication

```ts
const result = await fortress.plugins['api-key'].resolveKey(rawKey);

if (!result) {
  // Key is invalid, revoked, or expired
  throw new Error('Unauthorized');
}

console.log(result.userId); // owner of the key
console.log(result.scopes); // string[] | null
```

`resolveKey` hashes the provided raw key and looks it up in the database. It returns `null` when the key is unknown, revoked, or past its `expiresAt`. On success it also updates the key's `lastUsedAt` timestamp.

### Scoped keys

Scopes let you restrict what an API key is allowed to do. Pass a `scopes` array at creation time:

```ts
const { key } = await fortress.plugins['api-key'].createKey(userId, {
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
| `createKey` | `(userId: number, options: { name: string; scopes?: string[]; expiresAt?: Date })` | `Promise<{ key: string; id: number }>` |
| `listKeys` | `(userId: number)` | `Promise<ApiKeyInfo[]>` |
| `revokeKey` | `(userId: number, keyId: number)` | `Promise<void>` |
| `rotateKey` | `(userId: number, keyId: number)` | `Promise<{ key: string; id: number }>` |
| `resolveKey` | `(rawKey: string)` | `Promise<{ userId: number; scopes: string[] \| null } \| null>` |

The `ApiKeyInfo` type returned by `listKeys`:

```ts
interface ApiKeyInfo {
  id: number;
  name: string;
  keyPrefix: string;        // first 12 characters of the raw key
  scopes: string[] | null;
  expiresAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
}
```

## How It Works

1. **Key generation** -- `crypto.getRandomValues` produces 32 random bytes, hex-encoded and prepended with `{prefix}_sk_` to form the raw key.
2. **Hashed storage** -- The raw key is hashed with SHA-256 (via the same `hashToken` used for refresh tokens). Only the hash is persisted; the plaintext is returned once at creation time.
3. **Prefix-based identification** -- The first 12 characters of the raw key are stored as `keyPrefix`, allowing users and admins to identify keys in listings without exposing the secret.
4. **Resolution** -- `resolveKey` hashes the incoming raw key and performs a database lookup on `keyHash`. It rejects revoked and expired keys, and updates `lastUsedAt` on success.
5. **Scopes** -- Stored as a JSON-serialized string array in the database and parsed back to `string[]` on read. Scope enforcement is left to the application layer.
