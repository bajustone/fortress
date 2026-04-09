# Security Policy

## Reporting a Vulnerability

If you discover a security vulnerability in Fortress, please report it responsibly.

**Do NOT open a public GitHub issue for security vulnerabilities.**

Instead, email: security@bajustone.dev

Include:
- Description of the vulnerability
- Steps to reproduce
- Potential impact
- Suggested fix (if any)

We will acknowledge receipt within 48 hours and aim to release a fix within 7 days for critical issues.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.0.x   | Yes       |

## Security Best Practices

See [docs/security.md](docs/security.md) for comprehensive security guidance.

## Cookie posture (SvelteKit / `fortress.handleRequest`)

When using `fortress.handleRequest` directly or the SvelteKit adapter, auth
tokens are written to two `httpOnly` cookies. Defaults from
`FortressConfig.cookies`:

| Environment | Access cookie | Refresh cookie | Attributes |
|---|---|---|---|
| Production (`NODE_ENV=production`) | `__Host-fortress_access` | `__Host-fortress_refresh` | `HttpOnly; Secure; SameSite=Lax; Path=/` |
| Development | `fortress_access` | `fortress_refresh` | `HttpOnly; SameSite=Lax; Path=/` |

The `__Host-` prefix binds the cookie to the exact origin (no `Domain`, no
subpath, must be `Secure`) — the strongest browser-enforced isolation.
It's automatically dropped in non-production because `Secure` is required
for the prefix and would break localhost HTTP.

Override via `FortressConfig.cookies` if you need a `Domain`, `Path`,
custom names, or `SameSite=strict`. Note: `SameSite=strict` blocks
top-level cross-site navigation cookies, which breaks magic-link email
flows and OAuth callbacks. Stick with `lax` unless you know you don't need
them.

## CSRF posture (SvelteKit)

The SvelteKit adapter splits CSRF protection across two paths:

- **Fortress-managed routes** (`/auth/*`, `/iam/*`, plugin paths) are
  intercepted in `hooks.server.ts` *before* SvelteKit's `resolve()` runs,
  which means they bypass SvelteKit's built-in `csrf.checkOrigin`. They
  rely on `SameSite=Lax` cookies and (for OAuth) PKCE for cross-site
  protection.
- **Form actions** (`<form action="?/login">`) DO go through `resolve()`
  and ARE subject to SvelteKit's `checkOrigin`. This is the right default
  — keep it on. To accept logins from a separate frontend origin, add the
  origin to `csrf.allowedOrigins` in `svelte.config.js`.

## SSR auto-refresh race

The SvelteKit handle hook auto-refreshes an expired access cookie when a
valid refresh cookie is present. Opening N tabs simultaneously triggers N
parallel refresh attempts; Fortress's refresh-token family rotation will
succeed for one and fail for the others (with `TOKEN_REUSE`). This is a
fundamental trade-off of the JWT + family-rotation model. If your UX
requires zero-friction multi-tab opens, consider:

- Adding a short grace window on rotation (`refreshTokenExpirySeconds`
  overlap)
- Storing the refresh attempt in a per-user lock (custom plugin)
- Falling back to a server-side session table for the refresh side
