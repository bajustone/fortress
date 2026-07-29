# Magic Link Plugin

## Overview

The `magic-link` plugin adds passwordless authentication via one-time email tokens to Fortress. Users receive a time-limited link that logs them in without a password. If no account exists for the given email, one is created automatically (JIT provisioning).

Tokens are generated using cryptographically secure random bytes and hashed with SHA-256 before storage. Each token is single-use.

## Installation

Import the `magicLink` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { magicLink } from '@bajustone/fortress/plugins/magic-link';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!!' },
  database: adapter,
  plugins: [
    magicLink({
      tokenExpirySeconds: 600,
      onSendMagicLink: async (email, token) => {
        await sendEmail(email, `Login: https://myapp.com/auth/magic?token=${token}`);
      },
    }),
  ],
});
```

Once registered, methods are available at `fortress.plugins['magic-link']` with full type safety.

## Configuration

All fields on `MagicLinkConfig` are optional:

| Option | Type | Default | Description |
|---|---|---|---|
| `tokenExpirySeconds` | `number` | `600` (10 minutes) | How long a magic link token remains valid, in seconds. |
| `onSendMagicLink` | `(email: string, token: string) => Promise<void>` | `undefined` | Callback invoked when a magic link token is created. Use this to send the email containing the link. |

## API Reference

| Method | Signature | Returns |
|---|---|---|
| `sendMagicLink` | `(email: string)` | `Promise<{ sent: true }>` |
| `verify` | `(rawToken: string, meta?: RequestMeta)` | `Promise<AuthResult>` |

### sendMagicLink

Generates a magic link token and delivers it via the `onSendMagicLink` callback:

```ts
await fortress.plugins['magic-link'].sendMagicLink('alice@example.com');
```

The user does not need to exist in the database. If they do not exist, the account is created when the link is verified.

### verify

Atomically consumes a magic-link token and returns the unified auth result:

```ts
const result = await fortress.plugins['magic-link'].verify(rawToken);

if (result.status === 'success') {
  console.log(result.user.id);
  console.log(result.user.email);
  console.log(result.accessToken, result.refreshToken);
}
else if (result.status === 'pending') {
  // Another configured post-auth gate must complete first.
  console.log(result.pending.reason, result.pending.continuationToken);
}
```

The equivalent HTTP endpoint is `POST /auth/magic-link/verify` with `{ token }`.

This method:
1. Hashes the raw token and looks it up in the database.
2. Checks that the token has not been used and has not expired.
3. Marks the token as used (`usedAt` timestamp).
4. Finds the user by email, or creates a new account if none exists (JIT provisioning).
5. Runs every configured post-auth gate and issues an access/refresh session only when they all pass.

Throws:
- `NotFound` -- Invalid or unknown token.
- `BadRequest` -- Token already used.
- `BadRequest` -- Token expired.

## Example

```ts
import { createFortress } from '@bajustone/fortress';
import { magicLink } from '@bajustone/fortress/plugins/magic-link';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!!' },
  database: adapter,
  plugins: [
    magicLink({
      tokenExpirySeconds: 300, // 5 minutes
      onSendMagicLink: async (email, token) => {
        await mailer.send({
          to: email,
          subject: 'Your login link',
          html: `<a href="https://myapp.com/auth/magic?token=${token}">Click to sign in</a>`,
        });
      },
    }),
  ],
});

// Step 1: User requests a magic link
await fortress.plugins['magic-link'].sendMagicLink('alice@example.com');

// Step 2: User clicks the link -- your handler calls verify
const result = await fortress.plugins['magic-link'].verify(tokenFromUrl);

if (result.status === 'success') {
  // The user is authenticated with result.accessToken/result.refreshToken.
}
```
