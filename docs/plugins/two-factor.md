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
      secretEncryptionKey: process.env.FORTRESS_TOTP_ENCRYPTION_KEY!,
      totp: { issuer: 'MyApp' },
    }),
  ],
} as const);
```

The plugin registers three database models automatically: `two_factor_secret`, `backup_code`, and `trusted_device`.

## Configuration

Pass a `TwoFactorConfig` object to `twoFactor()`. `secretEncryptionKey` is required; all other options are optional.

| Option | Type | Default | Description |
|---|---|---|---|
| `secretEncryptionKey` | `string` | required | Exactly 32 bytes (raw UTF-8, hex, base64, or base64url) used for AES-256-GCM encryption of TOTP seeds |
| `totp.issuer` | `string` | `'Fortress'` | Issuer name displayed in authenticator apps (Google Authenticator, Authy, etc.) |
| `totp.period` | `number` | `30` | TOTP time step in seconds |
| `totp.digits` | `number` | `6` | Number of digits in the TOTP code |
| `backupCodes.count` | `number` | `10` | Number of backup codes generated on enable |
| `trustedDeviceDays` | `number` | `30` | Days a device stays trusted after successful 2FA verification |

```ts
twoFactor({
  secretEncryptionKey: process.env.FORTRESS_TOTP_ENCRYPTION_KEY!,
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

Call `enable` to generate a TOTP secret and backup codes. The user must verify a code before 2FA is activated. Only an AES-256-GCM ciphertext is stored; `isEnabled` stays `false` until the first successful `verify`.

Keep the encryption key in a secrets manager, separate from the database, and back it up. Losing or changing it makes existing seeds undecryptable and requires re-enrolment. Migration `0009_encrypt_totp_secrets` deletes legacy plaintext enrolments and associated recovery/trusted-device records so an upgrade cannot leave usable plaintext seeds behind.

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

After `enable`, activate the secret with `confirmSetup(userId, code)`. This setup-only method returns `{ verified: true, trustedDeviceToken? }` and does not issue a session. Device enrollment is explicit:

```ts
const confirmation = await fortress.plugins['two-factor'].confirmSetup(
  userId,
  '123456',
  { rememberDevice: true },
);
// If present, put confirmation.trustedDeviceToken in a host-managed
// Secure, HttpOnly, SameSite cookie. Fortress stores only its hash.
```

During login, call `verify` with the pending continuation token and a TOTP or backup code. It returns the unified `AuthResult` and issues tokens only when every configured gate is complete.

```ts
const result = await fortress.plugins['two-factor'].verify(
  loginResult.pending.continuationToken,
  code,
  { rememberDevice: true },
);
```

The equivalent HTTP endpoint is `POST /auth/2fa/verify` with `{ continuationToken, code, rememberDevice?: boolean }`. A successful opted-in response carries the raw token once in `pluginData.trustedDeviceToken`.

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
  trustedDeviceToken: readTrustedDeviceCookie(request),
});

if (loginResult.status === 'pending' && loginResult.pending.reason === 'two-factor') {
  const completed = await fortress.plugins['two-factor'].verify(
    loginResult.pending.continuationToken,
    codeFromUser,
    { rememberDevice: shouldRememberDevice },
  );

  if (completed.status === 'success') {
    // completed.accessToken and completed.refreshToken are the issued session.
  }
}
```

### Trusted Devices

Trusted-device enrollment occurs only when `rememberDevice: true` is supplied to `confirmSetup` or `verify`. Fortress generates a high-entropy opaque token, returns it once, and stores only its SHA-256 hash. User-Agent is metadata only and is never a trust credential.

The host must store the raw token in a `Secure`, `HttpOnly`, appropriately scoped `SameSite` cookie and pass it as `RequestMeta.trustedDeviceToken` on later programmatic logins. The HTTP login endpoint accepts the same opaque value as optional `trustedDeviceToken`; the host adapter is responsible for copying its cookie into that field.

- Trust expires after `trustedDeviceDays` (default 30).
- `lastUsedAt` is updated whenever a valid token is recognized.
- Calling `disable` removes all trusted devices for the user.
- Never expose the token to JavaScript-readable storage.

## API Reference

All methods are accessed via `fortress.plugins['two-factor']`.

| Method | Signature | Description |
|---|---|---|
| `enable` | `(userId: string) => Promise<{ secret: string; otpauthUrl: string; backupCodes: string[] }>` | Generate an unconfirmed TOTP secret and backup codes. Throws if 2FA is already enabled. |
| `confirmSetup` | `(userId: string, code: string, meta?: RequestMeta) => Promise<{ verified: true; trustedDeviceToken?: string }>` | Verify the first TOTP code, activate setup, and optionally enroll a trusted device. |
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
