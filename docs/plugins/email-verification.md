# Email verification

Register the plugin and deliver raw verification tokens through your mail provider:

```typescript
import { emailVerification } from '@bajustone/fortress/plugins/email-verification';

const fortress = createFortress({
  database,
  jwt: { key },
  plugins: [emailVerification({
    tokenExpirySeconds: 24 * 60 * 60,
    requireVerification: true,
    onSendVerification: async (email, token) => {
      const url = `https://app.example.com/verify?token=${encodeURIComponent(token)}`;
      await mailer.send({ to: email, text: url });
    },
  })] as const,
});
```

| Option | Default | Use |
|---|---:|---|
| `tokenExpirySeconds` | `86400` | Token lifetime |
| `requireVerification` | `true` | Hold login before session issuance |
| `onSendVerification` | — | Deliver the raw token |

Fortress stores only the SHA-256 token hash.

## Registration

Creating a user creates and sends a token:

```typescript
await fortress.auth.createUser({
  email: 'alice@example.com',
  name: 'Alice',
  password: 'correct-horse-battery-staple',
});
```

`afterRegister` is a committed side-effect hook. If token creation or delivery throws, Fortress logs the failure and keeps the created user. Retry delivery with `sendVerification`:

```typescript
await fortress.plugins['email-verification'].sendVerification(userId);
```

Send a changed-address token without changing the account immediately:

```typescript
await fortress.plugins['email-verification'].sendVerification(
  userId,
  'new-address@example.com',
);
```

The new address is adopted only after that token is verified.

## Complete a pending login

With `requireVerification: true`, correct primary credentials return `pending` instead of issuing tokens:

```typescript
const login = await fortress.auth.login(email, password);

if (login.status === 'pending' && login.pending.reason === 'email-verification') {
  const result = await fortress.plugins['email-verification'].completeVerification(
    login.pending.continuationToken,
    tokenFromEmail,
    { ipAddress, userAgent },
  );

  if (result.status === 'success') {
    result.accessToken;
    result.refreshToken;
  }
}
```

`completeVerification` consumes both the single-use continuation and the email token, then reruns any remaining post-auth gates before issuing a session.

## Verify outside login

Use `verify` for a standalone verification page:

```typescript
const verified = await fortress.plugins['email-verification'].verify(tokenFromUrl);
// { userId, email }
```

A token is accepted only when it:

- matches a stored hash;
- has not been used;
- has not expired;
- belongs to the pending user when completing login.

Consumption and the user update run transactionally. Invalid, used, expired, or mismatched tokens throw `NOT_FOUND` without revealing which check failed.

## Methods

```typescript
interface EmailVerificationMethods {
  sendVerification(
    userId: string,
    email?: string,
  ): Promise<{ sent: true }>;

  verify(
    rawToken: string,
  ): Promise<{ userId: string; email: string }>;

  completeVerification(
    continuationToken: string,
    verificationToken: string,
    meta?: RequestMeta,
  ): Promise<AuthResult>;
}
```

The plugin owns no HTTP routes. Use its methods in host routes. The core auth pipeline owns pending-auth continuation behavior.
