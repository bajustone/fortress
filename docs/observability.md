# Observability

Fortress has three layered observability surfaces. All three are zero-default — Fortress never writes to stderr, never imports `@opentelemetry/api`, and never allocates metric objects unless you explicitly opt in.

## 1. Pluggable Logger (`config.logger`)

The `FortressLogger` interface is structurally compatible with `pino`'s `BaseLogger` and Fastify's `FastifyBaseLogger`, so a `pino()` instance or `fastify.log` drops in directly with zero adapter code.

```typescript
export interface FortressLogger {
  level: LogLevel | 'silent' | string;
  fatal: LogFn;
  error: LogFn;
  warn: LogFn;
  info: LogFn;
  debug: LogFn;
  trace: LogFn;
  silent: LogFn;
  child?: (bindings: Record<string, unknown>) => FortressLogger;
  isLevelEnabled?: (level: LogLevel) => boolean;
}
```

Where `LogFn` accepts any of three shapes:
```typescript
logger.info('a string');
logger.info({ key: 'value' }, 'string with meta');
logger.info('format %s', 'arg');
```

### Default: `SILENT_LOGGER`

If you don't pass `config.logger`, Fortress uses a no-op logger where every method is a shared arrow function. Zero allocation per call.

### Pino example

```typescript
import pino from 'pino';
import { createFortress } from '@bajustone/fortress';

const fortress = createFortress({
  jwt: { secret: process.env.JWT_SECRET! },
  database: db,
  logger: pino({ level: 'info' }),
});
```

### Fastify example

```typescript
import Fastify from 'fastify';
import { createFortress } from '@bajustone/fortress';

const app = Fastify({ logger: { level: 'info' } });
const fortress = createFortress({
  jwt: { secret: process.env.JWT_SECRET! },
  database: db,
  logger: app.log,
});
```

### Console wrapper

```typescript
const consoleLogger = {
  level: 'info',
  fatal: (...a) => console.error('[fatal]', ...a),
  error: (...a) => console.error('[error]', ...a),
  warn:  (...a) => console.warn('[warn]',  ...a),
  info:  (...a) => console.info('[info]',  ...a),
  debug: (...a) => console.debug('[debug]', ...a),
  trace: (...a) => console.debug('[trace]', ...a),
  silent: () => {},
};

const fortress = createFortress({
  jwt: { secret: process.env.JWT_SECRET! },
  database: db,
  logger: consoleLogger,
});
```

### What Fortress logs

- **Plugin token-claim overwrite** (dev only, `warn` level) — when one plugin's `enrichTokenClaims` overwrites a claim set by an earlier plugin.
- **Refresh token fingerprint mismatch** (`warn` level) — when `config.jwt.validateRefreshFingerprint === 'warn'` detects a UA change on refresh without rejecting.
- **Unhandled errors in `fortress.handleRequest`** (`error` level) — anything that reaches the outer catch that isn't a `FortressError`.
- **Unhandled errors in the Express error handler** (`error` level) — same, for the Express adapter.
- **Observer failures** (`error` level) — when an auth/IAM/permission-check listener throws or rejects.

Fortress does **not** call `logger.debug` or `logger.info` on hot paths like `checkPermission`. Hot-path observability goes through metrics and the sync `PermissionCheckEvent` observer, both of which are bounded and allocation-free when nobody subscribes. If you want per-check logs, attach a permission-check observer and call your logger explicitly — you'll pay the cost you opt into.

## 2. Observer Lists

Three independent listener lists on the `Fortress` instance. Each `add…Observer` call returns an `() => void` unsubscribe function. Listener exceptions are routed to `logger.error` and the remaining listeners continue.

### `auth.addAuthObserver`

Async, cold-path. Fires on every auth lifecycle event.

```typescript
import type { AuthEvent } from '@bajustone/fortress';

const off = fortress.auth.addAuthObserver(async (event: AuthEvent) => {
  switch (event.eventType) {
    case 'LOGIN_SUCCESS':
      // actor, identifier, ipAddress, userAgent available
      break;
    case 'LOGIN_FAILURE':
      // identifier + error.code + error.message available
      break;
    case 'TOKEN_REUSE_DETECTED':
      // metadata.tokenFamily available; send security alert
      break;
    // LOGOUT | REGISTER | TOKEN_REFRESH | TOKEN_FINGERPRINT_MISMATCH
  }
});

// Later...
off(); // unsubscribe
```

### `iam.addIamObserver`

Async, cold-path. Fires on IAM mutation events (`ROLE_CREATED`, `ROLE_BOUND`, `PERMISSION_CHANGED`, `GROUP_MEMBER_ADDED`, etc.). Used by the audit-log plugin and the api-key plugin for cascade deletes.

```typescript
fortress.iam.addIamObserver(async (event) => {
  if (event.eventType === 'ROLE_BOUND') {
    await notifySlack(`Role ${event.targetId} bound to subject ${event.metadata?.subjectId}`);
  }
});
```

### `iam.addPermissionCheckObserver`

**Synchronous, hot-path.** Fires on every `checkPermission` call with latency and cache-hit information.

```typescript
fortress.iam.addPermissionCheckObserver((event) => {
  // This runs on the hot path — keep it bounded.
  if (!event.allowed) {
    metrics.increment('auth.denies', { resource: event.resource });
  }
});
```

**Why synchronous?** The listener signature returns `void`, not `Promise<void>`, to make it impossible to accidentally await expensive work inline. If you need async work, fire-and-forget: `void asyncWork()`.

**Why separate from `addIamObserver`?** Permission checks fire thousands of times per minute in a busy app. Mixing them with mutation events would spam the audit-log plugin.

### Error-routing gotcha (async observers only)

The auth and IAM observer lists route listener failures to `logger.error` so one bad listener can't break the caller. But the safety net only engages when the listener **returns** the promise. Consider the two shapes:

```typescript
// ✅ Routed — the listener returns the promise, the list attaches .catch
fortress.auth.addAuthObserver(async (event) => {
  await siem.log(event); // a rejection here ends up at logger.error
});

// ✅ Routed — equivalent; the async function returns an implicit promise
fortress.auth.addAuthObserver(event => siem.log(event));

// ❌ Not routed — the listener returns `undefined`, the list has no handle
//   on the inflight promise, and a rejection escapes to the runtime's
//   unhandled-rejection handler.
fortress.auth.addAuthObserver((event) => {
  void siem.log(event);
});
```

`void asyncWork()` is an explicit opt-out of the safety net. It's sometimes what you want — you accept the risk because you don't want the listener to wait on a cross-network call — but if you want rejections surfaced in your logger, return the promise. Fortress does not install a process-level `unhandledRejection` handler on your behalf.

The permission-check observer is synchronous (returns `void`, not `Promise<void>`), so this gotcha doesn't apply to it — there's no async work to lose track of.

## 3. OpenTelemetry Adapter (opt-in)

The `@bajustone/fortress/otel` sub-path ships a single factory: `createOtelTelemetry()`. It's the **only file in the repository that imports `@opentelemetry/api`**, and the import is dynamic (`await import('@opentelemetry/api')`). Runtimes that don't import the `/otel` sub-path never resolve the peer dep.

### Install

```bash
bun add @opentelemetry/api
# Plus the SDK you want (this example uses Node SDK with OTLP):
bun add @opentelemetry/sdk-node \
        @opentelemetry/exporter-trace-otlp-http \
        @opentelemetry/exporter-metrics-otlp-http
```

`@opentelemetry/api` is declared as an **optional peer dependency** on the Fortress `package.json`, so it's not installed automatically — you explicitly add it when you opt in.

### Wire it up

```typescript
import { createFortress } from '@bajustone/fortress';
import { createOtelTelemetry } from '@bajustone/fortress/otel';
import { NodeSDK } from '@opentelemetry/sdk-node';
import { OTLPMetricExporter } from '@opentelemetry/exporter-metrics-otlp-http';
import { PeriodicExportingMetricReader } from '@opentelemetry/sdk-metrics';

// 1. Start an OTel SDK (registers global Tracer/Meter providers).
const sdk = new NodeSDK({
  metricReader: new PeriodicExportingMetricReader({
    exporter: new OTLPMetricExporter({ url: process.env.OTEL_ENDPOINT! }),
  }),
});
sdk.start();

// 2. Wire the Fortress adapter.
const observability = await createOtelTelemetry({ name: 'my-app-auth' });
const fortress = createFortress({
  jwt: { secret: process.env.JWT_SECRET! },
  database: db,
  observability,
});
```

### Metric catalog

| Metric | Type | Unit | Attributes |
|---|---|---|---|
| `fortress.auth.events.total` | counter | — | `event`, `outcome`, `method` |
| `fortress.iam.events.total` | counter | — | `event` |
| `fortress.iam.permission_check.duration` | histogram | s | `subject_type`, `result`, `cached` |
| `fortress.iam.permission_check.cache.hits` | counter | — | — |
| `fortress.iam.permission_check.cache.misses` | counter | — | — |
| `db.client.operation.duration` | histogram | s | `db.system.name`, `db.operation.name`, `db.collection.name` |

**Histogram bucket boundaries:**

- `fortress.iam.permission_check.duration`: `[0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1]`
- `db.client.operation.duration`: `[0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10]` (OTel advisory default for DB clients)

### Span catalog

- `fortress.iam.permission_check.deny` — fired only on denied permission checks. Attributes: `subject.type`, `subject.id`, `resource`, `action`, `cached`. Allowed checks are metric-only — no span — to keep the hot path cheap.

### Cardinality rules (important)

Fortress **never** places user IDs, emails, tenant IDs, session IDs, or raw resource IDs on metric attributes. Those would cause cardinality explosions — every monitoring vendor charges you for high-cardinality metrics, and Prometheus will eat itself.

Allowed metric attributes: `result`, `method`, `outcome`, `event`, `subject_type`, `cached`, and the three standard `db.*` semconv attributes. Everything else goes on spans (pivotable per trace) or logs (grep-able).

### What Fortress does **not** emit

- **`http.server.request.duration`** — that's the host framework's job via `@opentelemetry/instrumentation-http`, `@opentelemetry/instrumentation-hono`, `@opentelemetry/instrumentation-express`, etc. Emitting it here would double-count.
- **Structured logs via `@opentelemetry/api-logs`** — that package is explicitly not for library authors and is alpha. Fortress uses its own `FortressLogger` contract, which is pino-compatible.

## Provider contract (advanced)

If you want to plug a non-OTel metric backend (custom Prometheus client, DataDog StatsD client, etc.), you can implement the `TelemetryProvider` interface directly instead of using the `/otel` adapter:

```typescript
import type { TelemetryProvider } from '@bajustone/fortress';

const customTelemetry: TelemetryProvider = {
  tracer: { startSpan: (name, attrs) => ({ /* ... */ }) },
  meter: {
    createCounter: (name, opts) => ({ add: (v, a) => myBackend.counter(name).add(v, a) }),
    createHistogram: (name, opts) => ({ record: (v, a) => myBackend.histogram(name).observe(v, a) }),
  },
};

createFortress({ /* ... */ observability: customTelemetry });
```

This is the escape hatch — most users should stick with `createOtelTelemetry()` because the OpenTelemetry SDK ecosystem already has exporters for every major backend.
