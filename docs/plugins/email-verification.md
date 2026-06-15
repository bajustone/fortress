# Email Verification Plugin

## Overview

The `email-verification` plugin adds token-based email verification to Fortress. It automatically sends a verification token when a user registers and can optionally block login until the email is verified.

Tokens are generated using the same SHA-256 hashing used for refresh tokens -- only the hash is stored in the database.

## Installation

Import the `emailVerification` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { emailVerification } from '@bajustone/fortress/plugins/email-verification';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    emailVerification({
      tokenExpirySeconds: 86400,
      requireVerification: true,
      onSendVerification: async (email, token, userId) => {
        await sendEmail(email, `Verify: https://myapp.com/verify?token=${token}`);
      },
    }),
  ],
});
```

Once registered, methods are available at `fortress.plugins['email-verification']` with full type safety.

## Configuration

All fields on `EmailVerificationConfig` are optional:

| Option | Type | Default | Description |
|---|---|---|---|
| `tokenExpirySeconds` | `number` | `86400` (24 hours) | How long a verification token remains valid, in seconds. |
| `requireVerification` | `boolean` | `true` | When `true`, unverified users receive an error response on login with `error: 'EMAIL_NOT_VERIFIED'`. |
| `onSendVerification` | `(email: string, token: string, userId: string) => Promise<void>` | `undefined` | Callback invoked when a verification token is created. Use this to send the verification email. |

## How It Works

The plugin uses two lifecycle hooks:

1. **`afterRegister`** -- Automatically generates a verification token and calls `onSendVerification` (if provided) with the raw token.
2. **`beforeLogin`** -- When `requireVerification` is `true`, checks if the user's `emailVerified` field is set. If not, it falls back to checking whether any verification token has been used. Unverified users receive a `{ error: 'EMAIL_NOT_VERIFIED', message: 'Please verify your email before logging in' }` response.

## API Reference

| Method | Signature | Returns |
|---|---|---|
| `sendVerification` | `(userId: string, email?: string)` | `Promise<{ token: string }>` |
| `verify` | `(rawToken: string)` | `Promise<{ userId: string; email: string }>` |

### sendVerification

Generates and sends a new verification token. Use this to resend verification emails or to verify a different email address:

```ts
// Resend to the user's current email
const { token } = await fortress.plugins['email-verification'].sendVerification(userId);

// Send to a different email (e.g., email change flow)
const { token } = await fortress.plugins['email-verification'].sendVerification(userId, 'newemail@example.com');
```

The raw token is returned for cases where you need programmatic access. In production, the `onSendVerification` callback delivers it to the user via email.

Throws `NotFound` if the user does not exist.

### verify

Validates a verification token and marks the user as email-verified:

```ts
const { userId, email } = await fortress.plugins['email-verification'].verify(rawToken);
```

This method:
1. Hashes the raw token and looks it up in the database.
2. Checks that the token has not been used and has not expired.
3. Marks the token as used (`usedAt` timestamp).
4. Sets `emailVerified = true` on the user record.

Throws:
- `NotFound` -- Invalid or unknown token.
- `BadRequest` -- Token already used.
- `BadRequest` -- Token expired.

## Example

```ts
import { createFortress } from '@bajustone/fortress';
import { emailVerification } from '@bajustone/fortress/plugins/email-verification';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    emailVerification({
      tokenExpirySeconds: 3600, // 1 hour
      requireVerification: true,
      onSendVerification: async (email, token, userId) => {
        await mailer.send({
          to: email,
          subject: 'Verify your email',
          html: `<a href="https://myapp.com/verify?token=${token}">Click to verify</a>`,
        });
      },
    }),
  ],
});

// Registration automatically triggers onSendVerification
const user = await fortress.auth.createUser({
  email: 'alice@example.com',
  name: 'Alice',
  password: 'correct-horse-battery-staple',
});

// User clicks the link in the email
const { userId, email } = await fortress.plugins['email-verification'].verify(tokenFromUrl);

// Now login works
const result = await fortress.auth.login('alice@example.com', 'correct-horse-battery-staple');
```
