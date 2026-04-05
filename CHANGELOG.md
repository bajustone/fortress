# Changelog

## [0.1.0] - 2026-04-06

### Added
- Core auth: JWT (jose), Argon2id password hashing, refresh token rotation with family tracking
- Core IAM: resource+action permissions, conditions, deny rules, groups, roles
- Plugin system: 8 capabilities (models, hooks, methods, routes, middleware, wrapAdapter, enrichTokenClaims, scopeRules)
- Plugins: email-verification, api-key, two-factor, social-login, data-isolation, tenancy, oauth, rate-limit, account-lockout, audit-log, webhook, webauthn (stub)
- Drizzle adapter: PostgreSQL, MySQL, SQLite
- Hono middleware: auth, RBAC, CSRF, error handler
- Password policy with NIST 800-63B defaults and HIBP breach checking
- Session management: list, revoke, revoke all
- Token fingerprinting on refresh
- Admin impersonation with RFC 8693 `act` claim
- Security documentation
