# Webhook Plugin

## Overview

The `webhook` plugin delivers webhook events following the [Standard Webhooks](https://www.standardwebhooks.com) specification. Events are signed with HMAC-SHA256 and delivered with exponential retry backoff on failure.

The plugin automatically dispatches webhooks for authentication lifecycle events (login, logout, registration, token refresh) via hooks. You manage webhook endpoints and process retries via the plugin methods.

## Installation

Import the `webhook` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { webhook } from '@bajustone/fortress/plugins/webhook';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    webhook({
      events: ['LOGIN_SUCCESS', 'REGISTER'],
      maxRetries: 5,
    }),
  ],
});
```

Once registered, methods are available at `fortress.plugins['webhook']` with full type safety.

## Configuration

All fields on `WebhookConfig` are optional:

| Option | Type | Default | Description |
|---|---|---|---|
| `events` | `WebhookEventType[]` | All events | Restrict which event types are delivered. When omitted, all event types are eligible. |
| `maxRetries` | `number` | `5` | Maximum number of delivery retries before a delivery is marked as `failed`. |
| `deliver` | `(url: string, payload: string, headers: Record<string, string>) => Promise<boolean>` | `fetch`-based | Custom delivery function. Return `true` for success, `false` for failure. Useful for testing or custom transports. |

### Event Types

| Event | Triggered by |
|---|---|
| `LOGIN_SUCCESS` | Successful login |
| `LOGIN_FAILURE` | Failed login attempt |
| `LOGOUT` | User logout |
| `REGISTER` | New user registration |
| `TOKEN_REFRESH` | Access token refresh |

## How It Works

The plugin uses lifecycle hooks to dispatch events:

1. **`afterLogin`** -- Dispatches `LOGIN_SUCCESS` with `userId`, `email`, `timestamp`, and `ip`.
2. **`onLoginFailure`** -- Dispatches `LOGIN_FAILURE` with `identifier`, `error`, and `timestamp`.
3. **`beforeLogout`** -- Dispatches `LOGOUT` with `timestamp` and `ip`.
4. **`afterRegister`** -- Dispatches `REGISTER` with `userId`, `email`, `timestamp`, and `ip`.
5. **`afterTokenRefresh`** -- Dispatches `TOKEN_REFRESH` with `timestamp` and `ip`.

For each event, the plugin looks up all active webhook endpoints subscribed to that event type, creates a delivery record, and attempts delivery.

### Signing

Payloads are signed per the Standard Webhooks spec. Each delivery includes three headers:

```
webhook-id: wh_<unique-id>
webhook-timestamp: 1234567890
webhook-signature: v1,<base64-hmac-sha256>
```

The signature is computed as `HMAC-SHA256(secret, "{webhookId}.{timestamp}.{body}")`.

### Retry Backoff

Failed deliveries are retried with increasing intervals:

| Attempt | Retry after |
|---|---|
| 1st retry | 5 seconds |
| 2nd retry | 5 minutes |
| 3rd retry | 30 minutes |
| 4th retry | 2 hours |
| 5th retry | 5 hours |

After `maxRetries` attempts, the delivery is marked as `failed`.

## API Reference

| Method | Signature | Returns |
|---|---|---|
| `registerEndpoint` | `(url: string, events: WebhookEventType[], secret: string)` | `Promise<WebhookEndpoint>` |
| `listEndpoints` | `()` | `Promise<WebhookEndpoint[]>` |
| `removeEndpoint` | `(id: string)` | `Promise<void>` |
| `processRetries` | `()` | `Promise<void>` |

### registerEndpoint

Registers a new webhook endpoint:

```ts
const endpoint = await fortress.plugins['webhook'].registerEndpoint(
  'https://myapp.com/webhooks',
  ['LOGIN_SUCCESS', 'REGISTER'],
  'whsec_my-webhook-secret',
);
// endpoint.id, endpoint.url, endpoint.events, endpoint.isActive
```

### listEndpoints

Returns all active webhook endpoints:

```ts
const endpoints = await fortress.plugins['webhook'].listEndpoints();
```

### removeEndpoint

Removes an endpoint and all its delivery records:

```ts
await fortress.plugins['webhook'].removeEndpoint(endpointId);
```

### processRetries

Processes all pending deliveries whose `nextRetryAt` has passed. Call this periodically (e.g., via a cron job):

```ts
await fortress.plugins['webhook'].processRetries();
```

## Types

The `WebhookEndpoint` type:

```ts
interface WebhookEndpoint {
  id: string;
  url: string;
  events: string;        // JSON array of event types
  secret: string;
  isActive: boolean;
  createdAt: Date;
}
```

The `WebhookDelivery` type:

```ts
interface WebhookDelivery {
  id: string;
  endpointId: string;
  eventType: string;
  payload: string;                 // JSON
  status: 'pending' | 'success' | 'failed';
  attempts: number;
  lastAttemptAt: Date | null;
  nextRetryAt: Date | null;
  responseStatus: number | null;
  createdAt: Date;
}
```

## Example

```ts
import { createFortress } from '@bajustone/fortress';
import { webhook } from '@bajustone/fortress/plugins/webhook';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    webhook({ maxRetries: 3 }),
  ],
});

// Register an endpoint
await fortress.plugins['webhook'].registerEndpoint(
  'https://hooks.myapp.com/auth',
  ['LOGIN_SUCCESS', 'LOGIN_FAILURE', 'REGISTER'],
  'whsec_s3cr3t',
);

// Events are dispatched automatically on login, register, etc.

// Set up a cron job to process retries
setInterval(async () => {
  await fortress.plugins['webhook'].processRetries();
}, 60_000); // every minute
```
