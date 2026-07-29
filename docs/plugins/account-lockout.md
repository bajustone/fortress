# Account Lockout Plugin

## Overview

The `account-lockout` plugin adds progressive account lockout to Fortress. After a configurable number of failed login attempts, the account is temporarily locked. With escalation enabled, each successive lockout doubles the duration up to a configurable cap.

Lockout sequence with defaults:
- 1st lockout: 15 minutes
- 2nd lockout: 30 minutes
- 3rd lockout: 60 minutes (capped at `maxLockoutSeconds`)

On successful login the failed attempt counter resets to zero.

## Installation

Import the `accountLockout` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { accountLockout } from '@bajustone/fortress/plugins/account-lockout';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!!' },
  database: adapter,
  plugins: [
    accountLockout({
      maxFailedAttempts: 5,
      lockoutDurationSeconds: 900,
      escalation: true,
      maxLockoutSeconds: 3600,
    }),
  ],
});
```

Once registered, methods are available at `fortress.plugins['account-lockout']` with full type safety.

## Configuration

All fields on `AccountLockoutConfig` are optional:

| Option | Type | Default | Description |
|---|---|---|---|
| `maxFailedAttempts` | `number` | `5` | Number of consecutive failed login attempts before the account is locked. |
| `lockoutDurationSeconds` | `number` | `900` (15 min) | Duration of the first lockout in seconds. |
| `escalation` | `boolean` | `true` | When `true`, each successive lockout doubles the duration (exponential backoff). |
| `maxLockoutSeconds` | `number` | `3600` (1 hour) | Maximum lockout duration in seconds. Escalation never exceeds this cap. |

## How It Works

The plugin uses three lifecycle hooks -- no manual calls are needed for the lockout logic itself:

1. **`beforeLogin`** -- Checks if the identifier (email) is currently locked. If `lockedUntil` is in the future, a `FortressError` with code `UNAUTHORIZED` and message "Account temporarily locked. Try again later." is thrown.
2. **`onLoginFailure`** -- Increments the failed attempt counter. When the counter reaches `maxFailedAttempts`, the account is locked for the calculated duration and `lockoutCount` is incremented.
3. **`afterLogin`** -- Resets the failed attempt counter and clears the lock on successful login.

## API Reference

| Method | Signature | Returns |
|---|---|---|
| `getLockoutStatus` | `(identifier: string)` | `Promise<LockoutStatus>` |
| `resetLockout` | `(identifier: string)` | `Promise<void>` |

### getLockoutStatus

Returns the current lockout status for an identifier (typically the user's email):

```ts
const status = await fortress.plugins['account-lockout'].getLockoutStatus('alice@example.com');

console.log(status.isLocked);        // boolean
console.log(status.failedAttempts);   // number
console.log(status.lockoutCount);     // number
console.log(status.lockedUntil);      // Date | null
console.log(status.lastFailedAt);     // Date | null
```

The `LockoutStatus` type:

```ts
interface LockoutStatus {
  identifier: string;
  failedAttempts: number;
  lockoutCount: number;
  lockedUntil: Date | null;
  lastFailedAt: Date | null;
  isLocked: boolean;
}
```

If no lockout record exists for the identifier, all counters are `0` and `isLocked` is `false`.

### resetLockout

Manually resets all lockout state for an identifier. Useful for admin-initiated unlocks:

```ts
await fortress.plugins['account-lockout'].resetLockout('alice@example.com');
```

This clears `failedAttempts`, `lockedUntil`, `lockoutCount`, and `lastFailedAt`.

## Example

```ts
import { createFortress } from '@bajustone/fortress';
import { accountLockout } from '@bajustone/fortress/plugins/account-lockout';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!!' },
  database: adapter,
  plugins: [
    accountLockout({
      maxFailedAttempts: 3,
      lockoutDurationSeconds: 60,
      escalation: true,
      maxLockoutSeconds: 600,
    }),
  ],
});

// After 3 failed logins, the account is locked for 60 seconds.
// If the user fails again after unlock, the next lockout is 120 seconds.
// The maximum lockout is capped at 600 seconds (10 minutes).

// Admin can check status or manually unlock:
const status = await fortress.plugins['account-lockout'].getLockoutStatus('alice@example.com');
if (status.isLocked) {
  await fortress.plugins['account-lockout'].resetLockout('alice@example.com');
}
```
