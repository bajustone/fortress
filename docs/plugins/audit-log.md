# Audit Log Plugin

## Overview

The audit-log plugin provides a tamper-evident audit trail for all authentication events. Every login, logout, registration, token refresh, and failed login attempt is recorded with actor, timestamp, IP address, and user-agent metadata.

An optional SHA-256 hash chain links each entry to its predecessor, making retroactive tampering detectable. This is designed for organizations that need to demonstrate compliance with SOC 2, HIPAA, PCI-DSS, or similar frameworks that require immutable, verifiable logs of access events.

## Installation

```ts
import { createFortress } from '@bajustone/fortress';
import { auditLog } from '@bajustone/fortress/plugins/audit-log';

const fortress = createFortress({
  jwt: { key: process.env.JWT_SECRET! },
  database: adapter,
  plugins: [auditLog()],
});
```

The plugin automatically creates the `audit_log` model via the database adapter. No manual migration is required beyond what your adapter handles for plugin models.

## Configuration

Pass an `AuditLogConfig` object to the `auditLog()` factory:

```ts
auditLog({
  events: ['LOGIN_SUCCESS', 'LOGIN_FAILURE', 'LOGOUT'],
  hashChain: true,
})
```

| Option | Type | Default | Description |
|---|---|---|---|
| `events` | `AuditEventType[]` | `undefined` (all events) | Restrict which events are captured. When omitted, all event types are logged. |
| `hashChain` | `boolean` | `false` | Enable SHA-256 hash chain linking each entry to its predecessor for tamper detection. |

### Event Types

| Event | Trigger | Actor |
|---|---|---|
| `LOGIN_SUCCESS` | Successful `auth.login()` call | The authenticated user |
| `LOGIN_FAILURE` | Failed `auth.login()` call (wrong password, unknown user) | Anonymous (actorId is null) |
| `LOGOUT` | `auth.logout()` call | User (resolved from token context) |
| `REGISTER` | `auth.createUser()` call | The newly created user |
| `TOKEN_REFRESH` | `auth.refresh()` call | User (from refresh token context) |
| `TOKEN_REUSE` | Refresh token replay detected | Reserved for future hook support |

## Usage

### Automatic Event Capture

Once the plugin is registered, events are captured automatically through Fortress lifecycle hooks. No additional code is needed for logging -- every `auth.login()`, `auth.createUser()`, `auth.logout()`, and `auth.refresh()` call writes an audit entry.

```ts
// These calls automatically produce audit log entries:
const user = await fortress.auth.createUser({
  email: 'alice@example.com',
  name: 'Alice',
  password: 'secure-password-123',
});
// -> REGISTER entry logged

const { accessToken, refreshToken } = await fortress.auth.login(
  'alice@example.com',
  'secure-password-123',
);
// -> LOGIN_SUCCESS entry logged

await fortress.auth.refresh(refreshToken);
// -> TOKEN_REFRESH entry logged

await fortress.auth.logout(refreshToken);
// -> LOGOUT entry logged
```

Failed logins are also captured. The entry includes the attempted identifier and error message in the `metadata` field as JSON:

```ts
await fortress.auth.login('alice@example.com', 'wrong-password').catch(() => {});
// -> LOGIN_FAILURE entry logged with metadata: {"identifier":"alice@example.com","error":"..."}
```

### Passing Request Metadata

To capture IP address and user-agent in audit entries, pass `RequestMeta` through the auth methods that support it. If you are using the Hono adapter, this is handled automatically. Otherwise, pass `meta` through your hook context.

### Querying the Audit Log

Use the type-safe plugin access to retrieve entries:

```ts
const entries = await fortress.plugins['audit-log'].getAuditLog();
```

The `getAuditLog` method accepts an `AuditLogQueryOptions` object for filtering and pagination:

```ts
// All login failures in the last 24 hours
const failures = await fortress.plugins['audit-log'].getAuditLog({
  eventType: 'LOGIN_FAILURE',
  from: new Date(Date.now() - 24 * 60 * 60 * 1000),
});

// All events for a specific user, paginated
const userHistory = await fortress.plugins['audit-log'].getAuditLog({
  userId: 42,
  limit: 50,
  offset: 0,
});

// Events within a date range
const report = await fortress.plugins['audit-log'].getAuditLog({
  from: new Date('2026-01-01'),
  to: new Date('2026-03-31'),
  limit: 1000,
});
```

Results are returned in reverse chronological order (`timestamp DESC`).

#### Query Options

| Option | Type | Description |
|---|---|---|
| `userId` | `number` | Filter by `actorId` |
| `eventType` | `AuditEventType` | Filter by event type |
| `from` | `Date` | Entries on or after this timestamp |
| `to` | `Date` | Entries on or before this timestamp |
| `limit` | `number` | Maximum entries to return |
| `offset` | `number` | Number of entries to skip (for pagination) |

### Hash Chain for Tamper Detection

When `hashChain: true` is set, each audit entry includes a `previousHash` field containing the SHA-256 hash of the preceding entry. The hash is computed from the previous entry's `id`, `timestamp`, `eventType`, and `actorId`.

The first entry in the chain has `previousHash: null`. Every subsequent entry references the one before it, forming a verifiable chain.

```ts
const fortress = createFortress({
  jwt: { key: process.env.JWT_SECRET! },
  database: adapter,
  plugins: [auditLog({ hashChain: true })],
});

// After several auth events...
const entries = await fortress.plugins['audit-log'].getAuditLog();

// Verify chain integrity
const sorted = [...entries].sort((a, b) => a.id - b.id);

// First entry: no predecessor
console.log(sorted[0].previousHash); // null

// Subsequent entries: 64-character SHA-256 hex string
console.log(sorted[1].previousHash); // "a3f2b8c1..."
```

If a row is deleted or altered, the hash chain breaks. Auditors can walk the chain to confirm log integrity without trusting the application layer.

**Note:** The hash chain adds one read query per write (to fetch the last entry). For high-throughput systems where write latency matters more than tamper evidence, leave it disabled and rely on your database's own integrity guarantees.

### Exporting for compliance

`exportEntries` serializes audit entries to a string for retention,
hand-off to a SIEM, or a compliance request. It accepts the same
`AuditLogQueryOptions` as `getAuditLog`, so you can scope the export by
user, event type, or time window.

```ts
const audit = fortress.plugins['audit-log'];

// Full JSON export (default format)
const json = await audit.exportEntries();

// CSV export of one user's last quarter, for a data-subject request
const csv = await audit.exportEntries('csv', {
  userId: 42,
  from: new Date('2026-01-01'),
  to: new Date('2026-03-31'),
});
```

The CSV output is RFC 4180-compliant: a fixed header row, one row per
entry, with cells containing commas, quotes, or newlines quoted and their
embedded quotes doubled. `Date` columns are emitted as ISO 8601 strings.
Both formats stream the rows in the same order as `getAuditLog` (newest
first).

## API Reference

### Factory

| Function | Signature | Description |
|---|---|---|
| `auditLog` | `(config?: AuditLogConfig) => FortressPlugin` | Creates the audit-log plugin instance |

### Methods (via `fortress.plugins['audit-log']`)

| Method | Signature | Description |
|---|---|---|
| `getAuditLog` | `(options?: AuditLogQueryOptions) => Promise<AuditLogEntry[]>` | Query audit log entries with optional filters |
| `logCustomEvent` | `(event: CustomAuditEvent) => Promise<void>` | Append an application-defined event |
| `verifyChain` | `() => Promise<ChainVerificationResult>` | Walk the hash chain and report broken links |
| `exportEntries` | `(format?: 'json' \| 'csv', options?: AuditLogQueryOptions) => Promise<string>` | Serialize entries for compliance export (defaults to `json`) |

### Types

**`AuditLogEntry`** -- a single audit log record:

| Field | Type | Description |
|---|---|---|
| `id` | `number` | Auto-incremented entry ID |
| `timestamp` | `string` | ISO 8601 timestamp of the event |
| `eventType` | `AuditEventType` | One of the six event types |
| `actorId` | `number \| null` | User ID of the actor, or null for anonymous events |
| `actorType` | `string` | `"user"` or `"anonymous"` |
| `targetId` | `number \| null` | ID of the affected resource (e.g., the new user on REGISTER) |
| `targetType` | `string \| null` | Type of the affected resource (e.g., `"user"`) |
| `ipAddress` | `string \| null` | Client IP if available via `RequestMeta` |
| `userAgent` | `string \| null` | Client user-agent if available via `RequestMeta` |
| `outcome` | `string` | `"success"` or `"failure"` |
| `metadata` | `string \| null` | JSON string with event-specific details (e.g., error message on failure) |
| `previousHash` | `string \| null` | SHA-256 hash of the preceding entry (only when `hashChain` is enabled) |
| `createdAt` | `string` | ISO 8601 creation timestamp |

## How It Works

The plugin uses Fortress's hook system to intercept auth lifecycle events without modifying core code.

**Hooks registered:**

| Hook | Event Logged |
|---|---|
| `afterLogin` | `LOGIN_SUCCESS` |
| `onLoginFailure` | `LOGIN_FAILURE` |
| `beforeLogout` | `LOGOUT` |
| `afterRegister` | `REGISTER` |
| `afterTokenRefresh` | `TOKEN_REFRESH` |

Each hook writes a row to the `audit_log` model via the database adapter. When hash chaining is enabled, the hook first reads the most recent entry (`ORDER BY id DESC LIMIT 1`), computes `SHA-256(id + timestamp + eventType + actorId)`, and stores the result as `previousHash` on the new entry.

The `getAuditLog` method builds `WhereClause` filters from the query options and delegates to `db.findMany`, keeping the plugin fully database-agnostic.

All hooks are non-blocking with respect to the auth flow -- they run inline but do not alter the auth response (except to pass it through). A logging failure will propagate as an error rather than silently swallow it, which is the correct behavior for compliance-critical audit trails.
