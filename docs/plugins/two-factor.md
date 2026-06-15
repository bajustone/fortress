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

### Verify (activate and complete 2FA challenges)

Call `verify` with a 6-digit TOTP code from the authenticator app, or one of the backup codes.

```ts
// TOTP code from authenticator app
const result = await fortress.plugins['two-factor'].verify(userId, '123456');
// result.verified === true

// Or use a backup code (each code works once)
const result = await fortress.plugins['two-factor'].verify(userId, backupCode);
```

The first successful `verify` call activates 2FA (`isEnabled` becomes `true`). This is the confirmation step after `enable`.

Pass `RequestMeta` as the third argument to automatically trust the device (see Trusted Devices below):

```ts
await fortress.plugins['two-factor'].verify(userId, code, {
  userAgent: request.headers.get('user-agent') ?? undefined,
});
```

### Disable 2FA

Removes the TOTP secret, all backup codes, and all trusted devices for the user.

```ts
await fortress.plugins['two-factor'].disable(userId);
```

After disabling, the user can call `enable` again to set up fresh 2FA.

### Login Flow with 2FA (`afterLogin` Hook)

The plugin hooks into `afterLogin` automatically. When a user with enabled 2FA logs in:

1. Fortress checks if the user has an active `two_factor_secret` record.
2. If a `userAgent` is present in the request meta, it checks for a matching trusted device that has not expired.
3. If the device is trusted, login proceeds normally with tokens.
4. If not trusted, the response returns `accessToken: null`, `refreshToken: null`, and `pluginData: { requires2FA: true }`.

Your application checks for this and prompts for a 2FA code:

```ts
const loginResult = await fortress.auth.login(email, password, {
  userAgent: request.headers.get('user-agent') ?? undefined,
});

if (loginResult.pluginData?.requires2FA) {
  // Show 2FA input form to the user
  // After user submits code:
  const verified = await fortress.plugins['two-factor'].verify(
    loginResult.user.id,
    codeFromUser,
    { userAgent: request.headers.get('user-agent') ?? undefined },
  );

  if (verified) {
    // Issue tokens manually or re-login (device is now trusted)
    const tokens = await fortress.auth.login(email, password, {
      userAgent: request.headers.get('user-agent') ?? undefined,
    });
  }
}
```

### Trusted Devices

When `verify` is called with a `RequestMeta` containing a `userAgent`, the plugin automatically creates a trusted device record. On subsequent logins with the same `userAgent`, the `afterLogin` hook skips the 2FA challenge.

- Device identity is a SHA-256 hash of `userId:userAgent`.
- Trust expires after `trustedDeviceDays` (default 30).
- The `lastUsedAt` timestamp is updated each time a trusted device is recognized during login.
- Calling `disable` removes all trusted devices for the user.

## API Reference

All methods are accessed via `fortress.plugins['two-factor']`.

| Method | Signature | Description |
|---|---|---|
| `enable` | `(userId: string) => Promise<{ secret: string; otpauthUrl: string; backupCodes: string[] }>` | Generate TOTP secret and backup codes. Throws if 2FA is already enabled. |
| `verify` | `(userId: string, code: string, meta?: RequestMeta) => Promise<{ verified: boolean }>` | Verify a TOTP or backup code. Activates 2FA on first success. Trusts device if `meta.userAgent` is provided. Throws `'Invalid two-factor code'` on failure. |
| `disable` | `(userId: string) => Promise<void>` | Remove all 2FA data (secret, backup codes, trusted devices) for the user. |

The plugin also installs an `afterLogin` hook. This is not called directly -- it runs automatically on every `fortress.auth.login()` call.

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
