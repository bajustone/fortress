# Rate Limit Plugin

## Overview

The `rate-limit` plugin adds sliding-window rate limiting to Fortress. It covers:

- **Built-in auth endpoints**: `/auth/login`, `/auth/register`, `/auth/refresh`, plus OAuth token issuance (`/oauth/token`) and API-key creation (`/api-key/keys`) when those plugins are mounted.
- **User-owned routes**: exposes `fortress.plugins['rate-limit'].check(ruleName, keys)` and per-framework middleware wrappers so any route in your app can be rate-limited against a shared, named rule.

Attempts are tracked by IP address, authenticated user (when keyed that way), or both. When a limit is exceeded, a `FortressError` with code `RATE_LIMITED` and a `retryAfter` value (in seconds) is thrown — adapters translate this into a 429 with a `Retry-After` header automatically.

## Installation

```ts
import { createFortress } from '@bajustone/fortress';
import { rateLimit } from '@bajustone/fortress/plugins/rate-limit';

const fortress = createFortress({
  jwt: { secret: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    rateLimit({
      // Built-in Fortress endpoint blocks — each is opt-in; omitting a block
      // disables rate-limiting for that endpoint.
      login:       { maxPerIp: 10, maxPerAccount: 5, windowSeconds: 900 },
      register:    { maxPerIp: 3,  windowSeconds: 3600 },
      refresh:     { maxPerIp: 60, windowSeconds: 60 },
      oauthToken:  { maxPerIp: 60, windowSeconds: 60 },
      apiKeyIssue: { maxPerIp: 10, maxPerUser: 10, windowSeconds: 3600 },

      // Named rules for your own routes + programmatic check() calls.
      rules: {
        api:    { maxPerIp: 200, maxPerUser: 1000, windowSeconds: 60 },
        strict: { maxPerIp: 5,   windowSeconds: 60 },
      },
    }),
  ],
});
```

## Configuration

All fields on `RateLimitConfig` are optional. Each built-in endpoint block is opt-in — omit it to disable rate-limiting for that endpoint.

### Endpoint blocks

| Block | Applied at | Default when enabled |
|---|---|---|
| `login` | `beforeLogin` hook | `{ maxPerIp: 10, maxPerAccount: 5, windowSeconds: 900 }` |
| `register` | `beforeRegister` hook | `{ maxPerIp: 3, windowSeconds: 3600 }` |
| `refresh` | `beforeTokenRefresh` hook | `{ maxPerIp: 60, maxPerUser: 60, windowSeconds: 60 }` |
| `oauthToken` | Path middleware on `POST /oauth/token` (before-auth) | `{ maxPerIp: 60, windowSeconds: 60 }` |
| `apiKeyIssue` | Path middleware on `POST /api-key/keys` (after-auth) | `{ maxPerIp: 10, maxPerUser: 10, windowSeconds: 3600 }` |

### Rule shape (`rules` + `paths`)

```ts
interface RateLimitRule {
  maxPerIp?: number;      // per-client-IP limit
  maxPerUser?: number;    // per-authenticated-user limit (no-op if no userId)
  windowSeconds: number;
  keyPrefix?: string;     // defaults to rule name
}
```

A rule with both `maxPerIp` and `maxPerUser` evaluates each key independently — whichever fills up first short-circuits with `RATE_LIMITED`.

### Path bindings (advanced)

Bind a named rule (or inline rule) to any Fortress-handled path glob. Matching uses `:param` and `*` wildcards.

```ts
rateLimit({
  rules: { webhooks: { maxPerIp: 20, windowSeconds: 60 } },
  paths: [
    { match: '/webhooks/*', methods: ['POST'], rule: 'webhooks' },
    { match: '/internal/*', position: 'after-auth',
      rule: { maxPerIp: 1000, maxPerUser: 100, windowSeconds: 60 } },
  ],
})
```

`position: 'before-auth'` (default) matches any request against the IP. `after-auth` runs after principal resolution so `maxPerUser` can apply. Path bindings only fire for routes dispatched through `fortress.handleRequest` — use the programmatic `check()` or a framework wrapper for your own routes.

## Rate-limiting your own routes

The plugin exposes a `check(ruleName, keys)` method and ready-made middleware wrappers for Hono, Express, and SvelteKit.

### Programmatic API

```ts
// Works from any context — route handlers, jobs, WebSocket messages, etc.
await fortress.plugins['rate-limit'].check('api', {
  ip: request.ip,
  userId: session.userId,
});
// throws FortressError(RATE_LIMITED) when the limit is exceeded.
```

### Hono

```ts
import { honoRateLimit } from '@bajustone/fortress/plugins/rate-limit/hono';

app.use('/api/*', honoRateLimit(fortress, 'api'));
// Extracts IP from X-Forwarded-For / X-Real-IP and fortressUserId from the
// Hono context (populated by the fortress auth middleware). Pair with the
// fortress Hono errorHandler so 429 responses carry Retry-After.
```

### Express

```ts
import { expressRateLimit } from '@bajustone/fortress/plugins/rate-limit/express';

app.use('/api', expressRateLimit(fortress, 'api'));
// Uses req.ip / forwarding headers and req.fortressUserId set by the
// fortress Express auth middleware. Errors flow through next(err) into the
// standard fortress error handler.
```

### SvelteKit

```ts
// hooks.server.ts
import { svelteKitRateLimit } from '@bajustone/fortress/plugins/rate-limit/sveltekit';

export const handle = async ({ event, resolve }) => {
  if (event.url.pathname.startsWith('/api/')) {
    await svelteKitRateLimit(fortress, 'api', event);
  }
  return resolve(event);
};
```

## Methods-only plugins (magic-link, 2FA, email-verification)

These plugins expose methods rather than HTTP routes — you wire them into your own endpoints. Rate-limit them the same way you'd rate-limit any app route: call `check()` (or the per-framework wrapper) in your handler before invoking the plugin method.

```ts
app.post('/auth/magic-link/send', async (c) => {
  await fortress.plugins['rate-limit'].check('strict', {
    ip: c.req.header('x-forwarded-for'),
  });
  const { email } = await c.req.json();
  return c.json(await fortress.plugins['magic-link'].sendMagicLink(email));
});
```

## How It Works

### IPv6 normalization

IPv6 addresses are normalized to their `/64` prefix to prevent bypass via address rotation within an allocated block. IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) are stripped to the IPv4 form. IPv4 addresses are used as-is. Missing IPs fall through as `unknown` — still counted against the `unknown` bucket so smuggling via a stripped header doesn't get a free pass.

### Sliding window algorithm

The default in-memory store records a timestamp for each request. On each check, timestamps older than the window are pruned, and the remaining count is compared to the limit. A background cleanup runs every 60 seconds to prune stale entries.

### Key format

Keys are namespaced by rule name:
- `<rule>:ip:<normalized-ip>` for per-IP counters
- `<rule>:user:<userId>` for per-user counters

Set `keyPrefix` on a rule to override the namespace (useful when sharing a store with other tooling).

## Custom Store

Provide a custom `RateLimitStore` for distributed deployments (e.g., Redis):

```ts
interface RateLimitStore {
  increment: (key: string, windowMs: number) => Promise<{ count: number; resetAt: number }>;
  get: (key: string) => Promise<{ count: number; resetAt: number } | null>;
}
```

| Method | Description |
|---|---|
| `increment(key, windowMs)` | Increment the counter for `key` within a sliding window of `windowMs` milliseconds. Returns the current count and the timestamp (ms) when the oldest entry in the window expires. |
| `get(key)` | Return the current counter for `key`, or `null` if no record exists. |

```ts
rateLimit({
  login: { maxPerIp: 10, maxPerAccount: 5, windowSeconds: 900 },
  store: myRedisStore, // implements RateLimitStore
});
```

## Example: handling the error

```ts
import { FortressError } from '@bajustone/fortress';

try {
  await fortress.auth.login('alice@example.com', 'wrong-password');
} catch (err) {
  if (err instanceof FortressError && err.code === 'RATE_LIMITED') {
    console.log(`Try again in ${err.retryAfter} seconds`);
  }
}
```
