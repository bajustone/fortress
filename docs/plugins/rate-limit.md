# Rate Limit Plugin

## Overview

The `rate-limit` plugin adds sliding-window rate limiting to Fortress login and registration endpoints. It tracks attempts by both IP address and account identifier to prevent distributed attacks while allowing legitimate use.

This is a hook-only plugin -- it works automatically with no methods to call. When a rate limit is exceeded, a `FortressError` with code `RATE_LIMITED` and a `retryAfter` value (in seconds) is thrown.

## Installation

Import the `rateLimit` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { rateLimit } from '@bajustone/fortress/plugins/rate-limit';

const fortress = createFortress({
  jwt: { secret: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    rateLimit({
      login: {
        maxPerIp: 10,
        maxPerAccount: 5,
        windowSeconds: 900,
      },
      register: {
        maxPerIp: 3,
        windowSeconds: 3600,
      },
    }),
  ],
});
```

## Configuration

All fields on `RateLimitConfig` are optional:

| Option | Type | Default | Description |
|---|---|---|---|
| `login.maxPerIp` | `number` | `10` | Maximum login attempts per IP within the sliding window. |
| `login.maxPerAccount` | `number` | `5` | Maximum login attempts per account identifier within the sliding window. |
| `login.windowSeconds` | `number` | `900` (15 min) | Sliding window duration for login limits, in seconds. |
| `register.maxPerIp` | `number` | `3` | Maximum registration attempts per IP within the sliding window. |
| `register.windowSeconds` | `number` | `3600` (1 hour) | Sliding window duration for registration limits, in seconds. |
| `store` | `RateLimitStore` | In-memory | Custom store for rate limit counters (see below). |

## How It Works

The plugin uses two lifecycle hooks:

1. **`beforeLogin`** -- Checks both per-IP and per-account counters. If either exceeds its limit, a `RATE_LIMITED` error is thrown with a `retryAfter` value indicating when the window resets.
2. **`beforeRegister`** -- Checks the per-IP counter for registrations.

### IPv6 normalization

IPv6 addresses are normalized to their `/64` prefix to prevent bypass via address rotation within an allocated block. IPv4-mapped IPv6 addresses (`::ffff:1.2.3.4`) are stripped to the IPv4 form. IPv4 addresses are used as-is.

### Sliding window algorithm

The default in-memory store records a timestamp for each request. On each check, timestamps older than the window are pruned, and the remaining count is compared to the limit. A background cleanup runs every 60 seconds to prune stale entries.

## Custom Store

You can provide a custom `RateLimitStore` for distributed deployments (e.g., Redis):

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
import { rateLimit } from '@bajustone/fortress/plugins/rate-limit';

rateLimit({
  store: myRedisStore, // implements RateLimitStore
});
```

## Example

```ts
import { createFortress, FortressError } from '@bajustone/fortress';
import { rateLimit } from '@bajustone/fortress/plugins/rate-limit';

const fortress = createFortress({
  jwt: { secret: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    rateLimit({
      login: { maxPerIp: 20, maxPerAccount: 5, windowSeconds: 600 },
      register: { maxPerIp: 5, windowSeconds: 3600 },
    }),
  ],
});

try {
  await fortress.auth.login('alice@example.com', 'wrong-password');
} catch (err) {
  if (err instanceof FortressError && err.code === 'RATE_LIMITED') {
    console.log(`Try again in ${err.retryAfter} seconds`);
  }
}
```
