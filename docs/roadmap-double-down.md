# Roadmap: Double Down on Strengths

*Strategy: Widen the moat on Fortress's unique advantages rather than chase Better Auth's breadth.*

*Created: 2026-04-06*

---

## TIER 1: Widen the Moat (Weeks 1-3)

### 1A. Wildcard Permissions + Permission Caching
- Support `post:*`, `*:read`, `*:*` in `matchesResourceAction()`
- Per-request permission cache with configurable TTL (default 30s)
- **Files**: `src/core/iam/permission-evaluator.ts`, `src/core/internal-adapter.ts`, `src/core/config.ts`

### 1B. Inline Permissions (user→permission without roles)
- New `direct_permission_binding` model
- `bindPermissionToUser()`, `bindPermissionToGroup()` methods
- **Files**: `src/core/iam/iam-service.ts`, `src/core/internal-adapter.ts`, `src/core/types.ts`

### 1C. Audit Log: IAM Events + Chain Verification
- New events: ROLE_CREATED, ROLE_BOUND, PERMISSION_CHANGED, etc.
- `auditLog.logCustomEvent(event)` for app-level events
- `auditLog.verifyChain(options)` — walks chain, reports hash mismatches (compliance demo killer feature)
- **Files**: `src/plugins/audit-log/index.ts`, `src/core/iam/iam-service.ts`

### 1D. Tenant-Scoped IAM
- Optional `tenantId` on role bindings
- User can be "Admin" in Tenant A, "Viewer" in Tenant B
- **Files**: `src/core/iam/iam-service.ts`, `src/core/internal-adapter.ts`, `src/core/types.ts`

---

## TIER 2: Fix Critical DX Gaps (Weeks 3-5)

### 2A. Type-Safe Plugin Methods
- Generic plugin registry or declaration merging
- Each plugin exports typed methods: `fortress.plugin<TwoFactorMethods>('two-factor').setup(userId)`
- **Files**: `src/core/plugin.ts`, each plugin's index.ts

### 2B. Working Example App
- Uncomment and implement `examples/hono-app/index.ts`
- Registration, login, token refresh, RBAC routes, 2FA, audit log
- Must be runnable with `bun run dev`

### 2C. Plugin Usage Guides
- `docs/plugins/` with one guide per plugin
- Priority: two-factor, social-login, audit-log, api-key, oauth

### 2D. OAuth Server HTTP Endpoints
- Standard endpoints: `POST /oauth/token`, `GET /oauth/authorize`, `POST /oauth/introspect`, `POST /oauth/revoke`
- `GET /oauth/.well-known/openid-configuration` discovery
- Scope-to-IAM-permission mapping (bridges OAuth + IAM — unique differentiator)
- **Files**: `src/plugins/oauth/index.ts`

---

## TIER 3: Minimal Breadth for Adoption (Week 6)

### 3A. Express Adapter
- ~100 lines of glue — core is already transport-agnostic
- Export as `@bajustone/fortress/express`
- **Files**: New `src/express/middleware.ts`, update `jsr.json`

### 3B. Security Headers Middleware
- HSTS, X-Content-Type-Options, X-Frame-Options, CSP with configurable defaults
- ~60 lines, high signal for security-first positioning
- **Files**: New `src/hono/middleware/security-headers.ts`

---

## TIER 4: Positioning (Continuous)

### 4A. README Rewrite
- Lead with: "Enterprise-grade auth + IAM. Not just login."
- Comparison table vs Better Auth / Auth.js
- "When to use Fortress" + "When NOT to use Fortress"

### 4B. SaaS Starter Example
- `examples/saas-starter/` — multi-tenant app with IAM, audit, OAuth server, rate limiting

### 4C. Compliance Documentation
- `docs/compliance.md` — maps features to SOC2, HIPAA, PCI-DSS controls

---

## What NOT to Do

- Don't add more social providers (5 + generic OIDC is enough)
- Don't build a dashboard UI (separate product)
- Don't add stateful sessions (JWT + refresh is the right call)
- Don't chase MySQL/SQLite schema tenancy (Pg-only, data-isolation covers others)
- Don't add SCIM yet (no demand signal)
- Don't build a client SDK yet (server-side strength is the differentiator)

---

## Key Files for Implementation

| File | Changes |
|---|---|
| `src/core/iam/permission-evaluator.ts` | Wildcard permissions |
| `src/core/internal-adapter.ts` | Caching, inline perms, tenant scoping |
| `src/core/iam/iam-service.ts` | Inline perms, tenant scoping, audit observer |
| `src/plugins/audit-log/index.ts` | IAM events, chain verification |
| `src/plugins/oauth/index.ts` | HTTP endpoints, scope-to-IAM mapping |
| `src/core/plugin.ts` | Type-safe plugin registry |
| `examples/hono-app/index.ts` | Working example |

## Verification

- `bun run test` after each tier
- `bun run typecheck` after type-safety changes
- `bun run publish:dry` before version bumps
- Manual: example app runs E2E with `bun run dev`
