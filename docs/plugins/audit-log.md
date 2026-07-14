# Audit Log Plugin

## Overview

The audit-log plugin provides a hash-chain integrity trail for authentication events. Every login, logout, registration, token refresh, and failed login attempt is recorded with actor, timestamp, IP address, and user-agent metadata.

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

The bundled Fortress migrations create `fortress_audit_log`; run `fortress.migrate()` before enabling the plugin.

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
  userId: '42',
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
| `userId` | `string` | Filter by `actorId` |
| `eventType` | `AuditEventType` | Filter by event type |
| `from` | `Date` | Entries on or after this timestamp |
| `to` | `Date` | Entries on or before this timestamp |
| `limit` | `number` | Maximum entries to return |
| `offset` | `number` | Number of entries to skip (for pagination) |

### Hash Chain for Tamper Detection

When `hashChain: true` is set, each audit entry includes a `previousHash` field containing the SHA-256 hash of the preceding entry. The digest uses an unambiguous serialization of all 13 stored fields, including the predecessor's own `previousHash`, so changes to actor, target, request, outcome, metadata, or timestamp fields break verification. This is an unkeyed integrity check, not proof against an attacker who can rewrite the complete database: such an attacker can recompute the chain and reset its in-database anchor. Use external attestation or a keyed/external anchor when database-write attackers are in scope.

The first entry has `previousHash: null`. Every subsequent entry references the one before it. A permanent singleton `fortress_audit_chain_state` anchor starts at `{ lastHash: null, entryCount: 0 }` and stores the expected terminal hash/count after each append, making deletion or mutation of the final row—or deletion of the entire chain—detectable as well. Each append reads this anchor, inserts the new row using `anchor.lastHash`, and advances the anchor in the same serialized transaction, so append work remains constant as the log grows. A zero anchor performs one bounded (`LIMIT 1`) existence probe to reject an untransformed legacy log safely; no history is hashed or traversed. SQLite transactions are queued per adapter instance to accommodate synchronous drivers; PostgreSQL uses a transaction-scoped advisory lock across application instances and is not placed on an in-process/global queue. `verifyChain()` performs the separate full historical scan.

```ts
const fortress = createFortress({
  jwt: { key: process.env.JWT_SECRET! },
  database: adapter,
  plugins: [auditLog({ hashChain: true })],
});

// After several auth events...
const entries = await fortress.plugins['audit-log'].getAuditLog();

// Verify chain integrity without relying on identifier ordering
const verification = await fortress.plugins['audit-log'].verifyChain();
if (!verification.valid)
  throw new Error(`Broken audit chain: ${JSON.stringify(verification.brokenLinks)}`);
```

If a row is deleted or altered, either an internal link or the persisted terminal anchor breaks. Auditors can verify both the chain graph and its expected terminal state through `verifyChain()`. Appends intentionally do not rescan history; schedule `verifyChain()` independently and alert on an invalid result.

### Enabling hash chaining on an existing log

A non-empty log written with `hashChain: false` must be explicitly transitioned before normal auth traffic starts using `hashChain: true`. Archive and externally attest the legacy rows first: rebaselining links the stored rows from that point forward but cannot prove that their earlier history was untampered.

```ts
const audit = fortress.plugins['audit-log'];
const result = await audit.rebaselineChain();
if (!result.valid)
  throw new Error('Audit rebaseline failed');
```

`rebaselineChain()` runs under the same transaction/advisory lock as append, accepts only the migration-seeded zero anchor plus rows whose `previousHash` values are all null, orders those rows by `createdAt` and then string `id`, rewrites their links, advances the anchor, and verifies the result before commit. It rejects an already or partially chained log, so it cannot be used as a general-purpose way to erase evidence of detected tampering. Run it once during a maintenance window after migrations, before exposing login/register/refresh/logout traffic on the hash-chain-enabled instance.

Automatic audit hook writes are best-effort after auth state changes: an audit storage/anchor failure is sent to the configured logger and does not turn a committed login, registration, refresh, or logout into a reported auth failure. Direct `logCustomEvent()` and maintenance methods still reject on errors, allowing operators to monitor and fail their own workflows explicitly.

**Performance note:** Chain-enabled append is O(1) with respect to historical row count. `verifyChain()` and the one-time `rebaselineChain()` are O(n) maintenance operations and hold the chain lock while they run.

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
  userId: '42',
  from: new Date('2026-01-01'),
  to: new Date('2026-03-31'),
});
```

The CSV output is RFC 4180-compliant: a fixed header row, one row per
entry, with cells containing commas, quotes, or newlines quoted and their
embedded quotes doubled. Cells beginning with `=`, `+`, `-`, `@`, tab, or
carriage return are prefixed with an apostrophe to prevent spreadsheet-formula
injection. `Date` columns are emitted as ISO 8601 strings.
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
| `rebaselineChain` | `() => Promise<ChainVerificationResult>` | One-time transactional conversion of an unchained legacy log |
| `exportEntries` | `(format?: 'json' \| 'csv', options?: AuditLogQueryOptions) => Promise<string>` | Serialize entries for compliance export (defaults to `json`) |

### Types

**`AuditLogEntry`** -- a single audit log record:

| Field | Type | Description |
|---|---|---|
| `id` | `string` | Adapter-generated entry ID |
| `timestamp` | `Date` | Event timestamp |
| `eventType` | `AuditEventType` | One of the six event types |
| `actorId` | `string \| null` | User ID of the actor, or null for anonymous events |
| `actorType` | `string` | `"user"` or `"anonymous"` |
| `targetId` | `string \| null` | ID of the affected resource (e.g., the new user on REGISTER) |
| `targetType` | `string \| null` | Type of the affected resource (e.g., `"user"`) |
| `ipAddress` | `string \| null` | Client IP if available via `RequestMeta` |
| `userAgent` | `string \| null` | Client user-agent if available via `RequestMeta` |
| `outcome` | `string` | `"success"` or `"failure"` |
| `metadata` | `string \| null` | JSON string with event-specific details (e.g., error message on failure) |
| `previousHash` | `string \| null` | SHA-256 hash of the preceding entry (only when `hashChain` is enabled) |
| `createdAt` | `Date` | Creation timestamp |

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

Each hook writes a row to the `audit_log` model via the database adapter. When hash chaining is enabled, Fortress reads the persisted terminal anchor, stores its `lastHash` as the new entry's `previousHash`, hashes the inserted entry, and advances the anchor in the same serialized transaction. Full graph traversal and all-field digest verification are reserved for `verifyChain()`.

The `getAuditLog` method builds `WhereClause` filters from the query options and delegates to `db.findMany`, keeping the plugin fully database-agnostic.

All hooks run inline with the auth flow. Audit-plugin write failures are logged and contained so they cannot report a committed auth state change as failed. Failures from other plugins are unaffected, and explicit audit method calls continue to reject on storage or chain-maintenance errors.
