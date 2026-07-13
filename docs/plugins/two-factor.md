# Two-Factor Authentication Plugin

TOTP-based two-factor authentication with backup codes and trusted devices.

## Installation

```ts
import { createFortress } from '@bajustone/fortress';
import { twoFactor } from '@bajustone/fortress/plugins/two-factor';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes-long' },
  database: yourAdapter,
  plugins: [
    twoFactor({
      totp: { issuer: 'MyApp' },
    }),
  ],
} as const);
```

The plugin registers three database models automatically: `two_factor_secret`, `backup_code`, and `trusted_device`.

## Configuration

All options are optional. Pass a `TwoFactorConfig` object to `twoFactor()`.

| Option | Type | Default | Description |
|---|---|---|---|
| `totp.issuer` | `string` | `'Fortress'` | Issuer name displayed in authenticator apps (Google Authenticator, Authy, etc.) |
| `totp.period` | `number` | `30` | TOTP time step in seconds |
| `totp.digits` | `number` | `6` | Number of digits in the TOTP code |
| `backupCodes.count` | `number` | `10` | Number of backup codes generated on enable |
| `trustedDeviceDays` | `number` | `30` | Days a device stays trusted after successful 2FA verification |

```ts
twoFactor({
  totp: {
    issuer: 'MyApp',
    period: 30,
    digits: 6,
  },
  backupCodes: { count: 10 },
  trustedDeviceDays: 30,
})
```

## Usage

Access the plugin methods via the type-safe `fortress.plugins['two-factor']` accessor.

```ts
const tf = fortress.plugins['two-factor'];
```

### Enable 2FA

Call `enable` to generate a TOTP secret and backup codes. The user must verify a code before 2FA is activated -- the secret is stored but `isEnabled` stays `false` until the first successful `verify`.

```ts
const setup = await fortress.plugins['two-factor'].enable(userId);

// setup.secret     — base32-encoded TOTP secret (store nowhere; show once)
// setup.otpauthUrl — otpauth:// URI for QR code generation
// setup.backupCodes — array of one-time backup codes (show once, user saves them)
```

Show the QR code to the user using any QR library:

```ts
import QRCode from 'qrcode';

const qrDataUrl = await QRCode.toDataURL(setup.otpauthUrl);
// Render qrDataUrl as an <img> for the user to scan with their authenticator app
```

Display the backup codes and instruct the user to store them securely. These are the only time the raw codes are available.

### Confirm setup and complete challenges

After `enable`, activate the secret with `confirmSetup(userId, code)`. This setup-only method returns `{ verified: true }` and does not issue a session.

```ts
await fortress.plugins['two-factor'].confirmSetup(userId, '123456');
```

During login, call `verify` with the pending continuation token and a TOTP or backup code. It returns the unified `AuthResult` and issues tokens only when every configured gate is complete.

```ts
const result = await fortress.plugins['two-factor'].verify(
  loginResult.pending.continuationToken,
  code,
  { userAgent: request.headers.get('user-agent') ?? undefined },
);
```

The equivalent HTTP endpoint is `POST /auth/2fa/verify` with `{ continuationToken, code }`.

### Disable 2FA

Removes the TOTP secret, all backup codes, and all trusted devices for the user.

```ts
await fortress.plugins['two-factor'].disable(userId);
```

After disabling, the user can call `enable` again to set up fresh 2FA.

### Login flow with the post-auth gate

When a user with enabled 2FA logs in, Fortress checks trusted-device state before token issuance. An untrusted login returns an `AuthPending` with a required challenge and **no token fields**.

```ts
const loginResult = await fortress.auth.login(email, password, {
  userAgent: request.headers.get('user-agent') ?? undefined,
});

if (loginResult.status === 'pending' && loginResult.pending.reason === 'two-factor') {
  const completed = await fortress.plugins['two-factor'].verify(
    loginResult.pending.continuationToken,
    codeFromUser,
    { userAgent: request.headers.get('user-agent') ?? undefined },
  );

  if (completed.status === 'success') {
    // completed.accessToken and completed.refreshToken are the issued session.
  }
}
```

### Trusted Devices

When `verify` is called with a `RequestMeta` containing a `userAgent`, the plugin automatically creates a trusted device record. On subsequent logins with the same `userAgent`, the `postAuthGate` hook skips the 2FA challenge.

- Device identity is a SHA-256 hash of `userId:userAgent`.
- Trust expires after `trustedDeviceDays` (default 30).
- The `lastUsedAt` timestamp is updated each time a trusted device is recognized during login.
- Calling `disable` removes all trusted devices for the user.

## API Reference

All methods are accessed via `fortress.plugins['two-factor']`.

| Method | Signature | Description |
|---|---|---|
| `enable` | `(userId: string) => Promise<{ secret: string; otpauthUrl: string; backupCodes: string[] }>` | Generate an unconfirmed TOTP secret and backup codes. Throws if 2FA is already enabled. |
| `confirmSetup` | `(userId: string, code: string, meta?: RequestMeta) => Promise<{ verified: true }>` | Verify the first TOTP code and activate setup. |
| `verify` | `(continuationToken: string, code: string, meta?: RequestMeta) => Promise<AuthResult>` | Complete a pending login with TOTP or a single-use backup code, rerun remaining gates, and issue the session on success. |
| `disable` | `(userId: string) => Promise<void>` | Remove all 2FA data (secret, backup codes, trusted devices) for the user. |

The plugin also installs a `postAuthGate` hook. This is not called directly -- it runs automatically on every `fortress.auth.login()` call.

## How It Works

### TOTP (RFC 6238)

The implementation follows RFC 6238 (TOTP) built on RFC 4226 (HOTP):

1. A 20-byte random secret is generated and base32-encoded.
2. The current Unix timestamp is divided by the `period` (default 30s) to produce a counter.
3. The counter is HMAC-SHA1 signed with the secret.
4. Dynamic truncation extracts a 6-digit code from the HMAC result.
5. Verification checks the current time window plus one window before and after (+-30s) to tolerate clock drift.

The `otpauthUrl` is a standard `otpauth://totp/` URI that authenticator apps (Google Authenticator, Authy, 1Password, etc.) can scan via QR code.

### Backup Codes

- Generated as 8-character hex strings (4 random bytes each).
- Only SHA-256 hashes are stored in the database; raw codes are returned once from `enable`.
- Each backup code can be used exactly once. After use, the record is marked `isUsed: true`.
- All backup codes are deleted when 2FA is disabled.

### Trusted Device Hashing

- The device fingerprint is `SHA-256(userId + ":" + userAgent)`.
- This is a convenience mechanism, not a strong device binding. User-Agent strings can be spoofed.
- Expired trusted device records are not automatically cleaned up. They are simply ignored when their `expiresAt` is in the past.
