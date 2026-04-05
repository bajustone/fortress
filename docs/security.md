# Security Guide

## JWT Secret Requirements

Fortress uses `jose` with HS256 by default. The secret must be at least 32 bytes.

Generate a secret:

```bash
node -e "console.log(require('crypto').randomBytes(64).toString('hex'))"
```

### Secret Rotation

Pass an array to rotate secrets with zero downtime. Fortress signs with the first secret and verifies against all:

```typescript
const fortress = createFortress({
  jwt: {
    secret: ['new-secret-abc', 'old-secret-xyz'],
  },
});
```

1. Deploy with `['new', 'old']`
2. Wait for all existing access tokens to expire (default 15 min)
3. Remove the old secret: `secret: 'new'`

## Password Hashing

Default: Argon2id via WASM (`hash-wasm`).

| Parameter | Value |
|-----------|-------|
| Memory    | 64 MB |
| Iterations | 3 |
| Parallelism | 1 |
| Output length | 32 bytes |

### Swapping the Hasher

For better performance outside edge runtimes, swap to a native implementation:

```typescript
import { createFortress } from '@bajustone/fortress';

const fortress = createFortress({
  passwordHasher: {
    hash: async (password) => Bun.password.hash(password, 'argon2id'),
    verify: async (password, hash) => Bun.password.verify(password, hash),
  },
});
```

Or with `@node-rs/argon2`:

```typescript
import { hash, verify } from '@node-rs/argon2';

const fortress = createFortress({
  passwordHasher: {
    hash: async (password) => hash(password),
    verify: async (password, h) => verify(h, password),
  },
});
```

## Password Policy

Configured via `passwordPolicy` in config. Defaults follow NIST 800-63B:

| Option | Default | Description |
|--------|---------|-------------|
| `minLength` | 8 | Minimum password length |
| `maxLength` | 128 | Maximum password length |
| `checkBreached` | `false` | Check against HIBP breached passwords |
| `breachedCacheTtlMs` | 300000 | Cache TTL for HIBP results (5 min) |

### Breach Checking (HIBP)

When `checkBreached: true`, Fortress checks passwords against the Have I Been Pwned API using k-anonymity. Only the first 5 characters of the SHA-1 hash are sent to the API -- the full password never leaves the server.

Breach checking **fails open** on network errors: if the HIBP API is unreachable, the password is accepted. This prevents authentication outages from a third-party dependency.

## Rate Limiting

The `rate-limit` plugin provides sliding-window rate limiting with dual-key support (per-IP and per-account).

```typescript
import { rateLimit } from '@bajustone/fortress/plugins/rate-limit';

const fortress = createFortress({
  plugins: [
    rateLimit({
      login: { maxAttempts: 10, windowMs: 900_000 },  // 10 per 15 min
      register: { maxAttempts: 5, windowMs: 3600_000 }, // 5 per hour
    }),
  ],
});
```

### Custom Store

The default store is in-memory. For distributed deployments, provide a custom store:

```typescript
rateLimit({
  store: myRedisRateLimitStore, // implements RateLimitStore interface
})
```

### IPv6 Normalization

IPv6 addresses are normalized to /64 prefixes to prevent attackers from rotating through a /64 block to bypass per-IP limits.

## Account Lockout

The `account-lockout` plugin uses progressive delays with exponential backoff instead of hard lockout.

| Option | Default | Description |
|--------|---------|-------------|
| `maxAttempts` | 5 | Attempts before lockout triggers |
| `lockoutDurationMs` | 900000 | Initial lockout (15 min) |
| `escalation` | `true` | Enable exponential backoff |
| `maxLockoutMs` | 3600000 | Maximum lockout (1 hour) |

Lockout is tracked by login identifier (email/username), not userId. This correctly handles attempts against non-existent accounts.

## Token Storage

### Refresh Tokens

Store in **httpOnly, Secure, SameSite=Lax** cookies. Never store in localStorage or sessionStorage.

Why: XSS attacks can read localStorage but cannot access httpOnly cookies. A compromised script can still make requests with cookies attached, but that is mitigated by CSRF protection (see below).

### Access Tokens

Keep in memory only (JavaScript variable). Do not persist to localStorage, sessionStorage, or cookies.

Access tokens are short-lived (default 15 min) and re-issued via the refresh token. On page reload, the client calls the refresh endpoint to get a new access token.

## CSRF Protection

Fortress provides a custom-header CSRF middleware for Hono:

```typescript
import { createHonoMiddleware } from '@bajustone/fortress/hono';

const { csrf } = createHonoMiddleware(fortress);
app.use('/api/*', csrf());
```

This requires API clients to send `X-Fortress-CSRF: 1` on all mutating requests (POST, PUT, PATCH, DELETE). Browsers will not attach this header on cross-origin requests unless the server explicitly allows it via CORS, which blocks CSRF.

### Defense Layers

1. **SameSite=Lax cookies** -- baseline protection, prevents cookies from being sent on cross-origin POST
2. **Custom header check** -- `X-Fortress-CSRF: 1` required on mutating requests
3. **Fetch Metadata** -- checks `Sec-Fetch-Site` header when present (modern browsers only)

## Refresh Token Security

### Family-Based Rotation

Every refresh token belongs to a token family. When a refresh token is used:

1. The old token is invalidated
2. A new token in the same family is issued

If a previously-used token is presented (reuse detection), the entire token family is invalidated. This protects against token theft: if an attacker steals a refresh token and uses it, the legitimate user's next refresh attempt triggers family-wide revocation.

### Token Fingerprinting

When `jwt.validateRefreshFingerprint` is enabled, Fortress stores a SHA-256 hash of the User-Agent with each refresh token.

| Value | Behavior |
|-------|----------|
| `true` | Fingerprint mismatch invalidates the entire token family |
| `'warn'` | Mismatch is logged but the refresh proceeds |
| `false` / unset | No fingerprint validation |

## HTTPS Requirements

Always use HTTPS in production.

- Set the `Secure` flag on all cookies so they are only sent over HTTPS
- Enable HTTP Strict Transport Security (HSTS) at the reverse proxy or application level
- Fortress does not enforce HTTPS at the library level -- this is a deployment concern

## Audit Logging

The `audit-log` plugin records auth events as append-only entries:

- `LOGIN_SUCCESS`, `LOGIN_FAILURE`
- `LOGOUT`
- `REGISTER`
- `TOKEN_REFRESH`, `TOKEN_REUSE`

### Hash Chain

When enabled, each audit entry includes a SHA-256 hash of the previous entry, creating a tamper-evident chain. If any entry is modified or deleted, the chain breaks and the tampering is detectable.

### Compliance

| Standard | Relevant Requirement |
|----------|---------------------|
| SOC 2 | Access logging and monitoring (CC6.1, CC7.2) |
| HIPAA | Audit controls (164.312(b)) |
| PCI-DSS | Log retention of 1 year, 3 months immediately accessible (10.7) |

Configure retention in your application. Fortress writes events; your infrastructure handles retention and archival.

## Admin Impersonation

Fortress supports admin impersonation via RFC 8693 token exchange semantics.

```typescript
const result = await fortress.auth.impersonate(adminUserId, targetUserId, {
  reason: 'Support ticket #1234',
});
```

The resulting access token includes an `act` (actor) claim identifying the admin:

```json
{
  "sub": "target-user-id",
  "act": { "sub": "admin-user-id" },
  "exp": 1712345678
}
```

Security constraints:

- Default expiry: 60 minutes
- Non-renewable: no refresh token is issued
- The caller must verify that the admin has the `fortress:impersonate` permission before calling `impersonate()`
- The impersonation reason is stored in plugin data for audit purposes
