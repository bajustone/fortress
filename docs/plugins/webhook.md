# Webhook Plugin

## Overview

The `webhook` plugin delivers events to consumer-registered HTTPS endpoints following the [Standard Webhooks](https://www.standardwebhooks.com) specification (HMAC-SHA256 signing, `webhook-id`/`webhook-timestamp`/`webhook-signature` headers).

Highlights:

- **Custom events** — declare and `emit()` your own events through the same path the built-in auth events use.
- **Bring-Your-Own-Queue (BYOQ)** — delivery is always queued; plug in any backend (in-memory, database, BullMQ, SQS, Cloudflare Queues, …) via a small interface. Defaults to a dev-only in-memory queue.
- **SSRF-safe delivery** — webhook URLs are consumer-supplied, so delivery resolves + validates the target, blocks private/loopback/link-local/CGNAT/NAT64 addresses, and **pins the connection to the resolved IP** (closing the DNS-rebinding window).
- **Resilience** — failure classification, jittered exponential backoff, a per-endpoint circuit breaker, and DLQ/alert callbacks.
- **Per-delivery idempotency** — a stable `webhook-id` so receivers can dedup retries, plus an `idempotencyKey` so `emit()` is safe to call more than once.

Built-in auth events are dispatched automatically via lifecycle hooks; custom events you `emit()` yourself.

## Installation

```ts
import { createFortress } from '@bajustone/fortress';
import { webhook } from '@bajustone/fortress/plugins/webhook';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [webhook()], // defaults: all built-in events, in-memory queue
});
```

Methods are available at `fortress.plugins.webhook`. The plugin is method-only — it ships **no** HTTP routes (mount your own management endpoints, as the example app does).

## Events

Built-in and custom events share one declaration shape (`WebhookEventDeclaration`) and one emit path. The built-ins:

| Event | Source hook |
|---|---|
| `auth.login.success` | `afterLogin` |
| `auth.login.failure` | `onLoginFailure` |
| `auth.logout` | `beforeLogout` |
| `auth.user.registered` | `afterRegister` |
| `auth.token.refreshed` | `afterTokenRefresh` |

Pass `events` to declare custom events (and optionally exclude built-ins). Each event may carry a Standard Schema validator (`schema`) — the payload is validated at `emit()` time.

```ts
import { builtinEvents, webhook } from '@bajustone/fortress/plugins/webhook';
import { obj, str } from '@bajustone/fortress';

webhook({
  events: [
    ...builtinEvents({ exclude: ['auth.logout'] }), // keep the built-ins you want
    { name: 'order.paid', schema: obj({ orderId: str(), amount: str() }, 'orderId', 'amount') },
    { name: 'order.refunded' },
  ],
});
```

Emit a custom event from your code:

```ts
await fortress.plugins.webhook.emit('order.paid', { orderId: 'o_123', amount: '49.00' });
```

`emit()` throws a `WebhookEmitError` (with `code: 'unknown_event' | 'invalid_payload' | 'payload_too_large'`) so you can branch on the failure.

## Queue (Bring-Your-Own-Queue)

Delivery is always queued. Bundled queues (zero extra deps):

- **`inMemoryQueue()`** — the **default**. `setTimeout`-driven, single process. **Dev-only**: scheduled retries live in in-process timers, so a restart loses every pending retry until the next process runs its startup recovery sweep. Jobs are processed sequentially.
- **`databaseQueue({ pollMs })`** — the crash-safe bundled option. Polls `webhook_delivery` for due rows; the table itself is the transactional outbox, so it survives restarts. Single-worker (run one poller per deployment, or use a real broker for multi-worker).

```ts
import { databaseQueue, webhook } from '@bajustone/fortress/plugins/webhook';

webhook({ queue: databaseQueue({ pollMs: 10_000 }) });
```

Implement `WebhookQueue` to use any external broker. Set `handlesRetries: true` and `delivery.retry: 'queue'` to let the broker own retries (the plugin re-throws on failure so the broker re-delivers).

The queue worker starts automatically the first time the plugin methods are accessed; call `await fortress.plugins.webhook.stop()` on shutdown to tear down timers/pollers.

## Configuration

All fields on `WebhookConfig` are optional:

| Option | Type | Default | Description |
|---|---|---|---|
| `events` | `WebhookEventDeclaration[]` | `builtinEvents()` | The event registry (built-in + custom). |
| `queue` | `WebhookQueue` | `inMemoryQueue()` | Delivery queue backend. |
| `maxRetries` | `number` | `5` | Attempts before a delivery is marked `failed`. |
| `maxPayloadBytes` | `number` | `262144` (256 KB) | `emit()` rejects larger payloads. |
| `delivery.timeoutMs` | `number` | `10000` | Per-attempt request timeout. |
| `delivery.retry` | `'pluginScheduled' \| 'inProcess' \| 'queue'` | `'pluginScheduled'` | Who owns retries (see below). |
| `delivery.permanentStatuses` | `number[]` | `[404, 410, 421]` | Statuses that permanently deactivate an endpoint. |
| `delivery.maxConsecutiveFailures` | `number` | `15` | Circuit breaker — deactivate after this many consecutive failures. |
| `delivery.onDeliveryFailed` | `(d: WebhookDelivery) => void \| Promise<void>` | — | Terminal-failure hook (the DLQ/alert seam). |
| `delivery.onEndpointDeactivated` | `(e: WebhookEndpoint, reason: string) => void \| Promise<void>` | — | Fired on auto-deactivation. |
| `delivery.fetch` | `FetchFn` | `ssrfSafeFetch()` | Override the transport (custom transport or tests). **Bypasses the SSRF guard** — only override when you control the targets. |

### Retry modes

| Mode | Behavior |
|---|---|
| `'pluginScheduled'` (default) | One attempt per job. On a retriable failure the plugin schedules `nextRetryAt` with jittered backoff and re-enqueues. Works with any queue. |
| `'inProcess'` | The fetcher transport retries within a single attempt (POST opted in). The queue sees one job per logical delivery. |
| `'queue'` | The plugin re-throws on a retriable failure so the queue re-delivers. Requires a queue with `handlesRetries: true`. |

### Failure classification (plugin-scheduled)

| Result | Action |
|---|---|
| 2xx | success (resets the failure counter) |
| `404 / 410 / 421` | `failed` + **deactivate** the endpoint (`permanent_<status>`) |
| `408 / 425 / 429` | retry (transient) |
| other `4xx` | `failed`, **no retry** (permanent client error) |
| `5xx` / network / timeout | retry with jittered exponential backoff |

Backoff ladder (jittered ±25%): **5s → 5min → 30min → 2h → 5h**. Independently, the circuit breaker deactivates an endpoint after `maxConsecutiveFailures` consecutive failures (`reason: 'too_many_failures'`).

## Endpoint management

| Method | Signature |
|---|---|
| `emit` | `(name: string, payload: object, opts?: { idempotencyKey?: string }) => Promise<void>` |
| `registerEndpoint` | `(url: string, events: string[], opts?: { secret?: string }) => Promise<WebhookEndpoint>` |
| `updateEndpoint` | `(id: string, patch: { url?, events?, isActive? }) => Promise<RedactedWebhookEndpoint \| null>` |
| `rotateSecret` | `(id: string) => Promise<{ id: string; secret: string }>` |
| `listEndpoints` | `() => Promise<RedactedWebhookEndpoint[]>` |
| `removeEndpoint` | `(id: string) => Promise<void>` |
| `listEventTypes` | `() => { name: string; description?: string }[]` |
| `stop` | `() => Promise<void>` |

```ts
const wh = fortress.plugins.webhook;

// A CSPRNG secret is generated when omitted — returned ONCE on the result.
const endpoint = await wh.registerEndpoint('https://hooks.myapp.com/auth', ['auth.login.success', 'order.paid']);
console.log(endpoint.secret); // whsec_… — store it now; it is never returned again

await wh.updateEndpoint(endpoint.id, { events: ['order.paid'], isActive: true });
const { secret } = await wh.rotateSecret(endpoint.id); // new secret, returned once

const endpoints = await wh.listEndpoints(); // secret REDACTED
await wh.removeEndpoint(endpoint.id);
```

> **Secrets are returned only at `registerEndpoint` and `rotateSecret`.** `listEndpoints()` and `updateEndpoint()` omit the `secret` field.

## Signing

Each attempt sends:

```
webhook-id: msg_<deliveryId>          # STABLE across retries — use it as your idempotency key
webhook-timestamp: 1234567890         # changes per attempt
webhook-signature: v1,<base64-hmac-sha256>
```

The signature is `HMAC-SHA256(secret, "{webhook-id}.{webhook-timestamp}.{body}")`. Because `webhook-id` is stable per delivery, a receiver that dedups on it ignores retries automatically.

## Idempotency

Pass `emit(name, payload, { idempotencyKey })` to make a logical event safe to emit more than once: a second `emit` with the same `(endpoint, idempotencyKey)` is a no-op, enforced by a unique index on `webhook_delivery (endpoint_id, idempotency_key)` (so it holds even under concurrent emits).

## Types

```ts
interface WebhookEndpoint {
  id: string;
  url: string;
  events: string;              // JSON array of event names
  secret: string;              // redacted in listEndpoints()/updateEndpoint()
  isActive: boolean;
  deactivatedReason: string | null;
  consecutiveFailures: number;
  createdAt: Date;
}

interface WebhookDelivery {
  id: string;
  endpointId: string;
  eventType: string;
  payload: string;             // JSON
  status: 'pending' | 'success' | 'failed';
  attempts: number;
  idempotencyKey: string | null;
  lastAttemptAt: Date | null;
  nextRetryAt: Date | null;
  responseStatus: number | null;
  responseBody: string | null; // first ~2 KB, for debugging
  errorKind: string | null;
  createdAt: Date;
}
```

## Security

- **SSRF.** Built-in delivery resolves the host, rejects non-https and private/loopback/link-local/CGNAT targets (IPv4, IPv6, `::ffff:`-mapped, and `64:ff9b::/96` NAT64 forms), and pins the connection to the validated IP. Overriding `delivery.fetch` bypasses this guard — only do so for targets you control. `assertSafeWebhookUrl(url)` is exported if a custom transport wants to reuse the guard.
- **Secrets.** Generated with a CSPRNG, returned only at creation/rotation, and redacted from list/update. Rotate with `rotateSecret`.
- **Payloads.** Signed but **not encrypted** — never put secrets/PII in a webhook payload you wouldn't want a receiver (or a misconfigured endpoint) to see.

## Example

```ts
import { createFortress, obj, str } from '@bajustone/fortress';
import { builtinEvents, databaseQueue, webhook } from '@bajustone/fortress/plugins/webhook';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    webhook({
      events: [
        ...builtinEvents(),
        { name: 'order.paid', schema: obj({ orderId: str() }, 'orderId') },
      ],
      queue: databaseQueue({ pollMs: 10_000 }), // crash-safe
      delivery: {
        maxConsecutiveFailures: 10,
        onEndpointDeactivated: (e, reason) => log.warn('webhook endpoint disabled', { id: e.id, reason }),
        onDeliveryFailed: d => deadLetter.push(d),
      },
    }),
  ],
});

const wh = fortress.plugins.webhook;

// Built-in auth events deliver automatically on login/register/etc.
await wh.registerEndpoint('https://hooks.myapp.com/auth', ['auth.login.success', 'order.paid']);

// Emit a custom event
await fortress.plugins.webhook.emit('order.paid', { orderId: 'o_123' }, { idempotencyKey: 'o_123' });

// On shutdown
await wh.stop();
```
