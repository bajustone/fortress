# Fortress

Framework-agnostic, adapter-based authentication and authorization for TypeScript.

## Features

- **JWT auth** with access/refresh token pairs (jose, Web Crypto API)
- **Password hashing** with Argon2id (WASM default, swappable for native)
- **Refresh token rotation** with family tracking and reuse detection
- **IAM** with resource+action permissions, conditions, deny rules, groups, and roles
- **Plugin system** for extending auth without touching core
- **Database-agnostic** via a generic CRUD adapter interface
- **Framework-agnostic** with first-class Hono middleware
- **Runs everywhere** -- Bun, Deno, Node.js, edge runtimes

## Quick Start

```bash
# npm
npm install @bajustone/fortress

# bun
bun add @bajustone/fortress
```

```typescript
import { createFortress } from '@bajustone/fortress';
import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';

const db = createDrizzleAdapter(drizzle);

const fortress = createFortress({
  adapter: db,
  jwt: {
    secret: process.env.JWT_SECRET!, // min 32 bytes for HS256
    issuer: 'my-app',
    accessTokenTtl: 900,   // 15 minutes
    refreshTokenTtl: 604800, // 7 days
  },
});

// Register a user
const user = await fortress.auth.createUser({
  email: 'alice@example.com',
  name: 'Alice',
  password: 'correct-horse-battery-staple',
});

// Login
const result = await fortress.auth.login('alice@example.com', 'correct-horse-battery-staple');
// result.user, result.accessToken, result.refreshToken

// Check permissions
const allowed = await fortress.iam.checkPermission({
  userId: user.id,
  resource: 'post',
  action: 'update',
});
```

## Plugins

| Plugin | Description |
|--------|-------------|
| `two-factor` | TOTP, backup codes, trusted devices |
| `email-verification` | Token-based email verification |
| `api-key` | Scoped API keys for service accounts and devices |
| `social-login` | OAuth/OIDC consumer (Google, GitHub, Microsoft, Apple, Discord) |
| `oauth` | OAuth 2.0 server with auth code + PKCE and client credentials |
| `tenancy` | Schema-per-tenant isolation (PostgreSQL) |
| `data-isolation` | Row-level data isolation (any database) |
| `rate-limit` | Sliding window rate limiting with dual-key support |
| `account-lockout` | Progressive lockout with exponential backoff |
| `audit-log` | Append-only event logging with optional hash chain |
| `webhook` | Standard Webhooks spec with HMAC-SHA256 signing |
| `webauthn` | WebAuthn/Passkey support (stub) |

```typescript
import { createFortress } from '@bajustone/fortress';
import { twoFactor } from '@bajustone/fortress/plugins/two-factor';
import { auditLog } from '@bajustone/fortress/plugins/audit-log';

const fortress = createFortress({
  adapter: db,
  jwt: { secret: process.env.JWT_SECRET!, issuer: 'my-app' },
  plugins: [twoFactor(), auditLog()],
});
```

## Framework Integration

### Hono

```typescript
import { Hono } from 'hono';
import { createHonoMiddleware } from '@bajustone/fortress/hono';

const app = new Hono();
const { auth, rbac, errorHandler } = createHonoMiddleware(fortress);

app.onError(errorHandler);
app.use('/api/*', auth());
app.get('/api/posts', rbac('post', 'read'), (c) => { /* ... */ });
```

## Database Support

| Database   | Adapter | Status |
|------------|---------|--------|
| PostgreSQL | Drizzle | Supported |
| MySQL      | Drizzle | Supported |
| SQLite     | Drizzle | Supported |

The `DatabaseAdapter` interface is generic -- you can implement your own adapter for any database.

## Documentation

- [Architecture](docs/architecture.md) -- full technical design
- [Security](docs/security.md) -- JWT, password hashing, token storage, CSRF, audit logging
- [Watch-outs](docs/watch-outs.md) -- known gaps and design decisions

## License

[MIT](LICENSE)
