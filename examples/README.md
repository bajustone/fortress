# Fortress examples

This directory hosts runnable examples of Fortress. Each app exercises a
different framework adapter; the `hono-app` is the kitchen-sink
reference that demonstrates every plugin.

| Example | Framework | Highlights |
|---|---|---|
| [`hono-app/`](./hono-app) | Hono | full plugin matrix, OpenAPI, OAuth provider, admin bootstrap, tenancy, audit log |
| [`express-app/`](./express-app) | Express | minimal Fortress-on-Express boot with admin + IAM |
| [`sveltekit-app/`](./sveltekit-app) | SvelteKit | adapter handle + form actions, declaration-merged `App.Locals` |
| [`policy/`](./policy) | _file-only_ | sample `fortress.policy.json` for policy-as-code |

## Scenario index (P2-12)

The library plan asks for examples covering six specific recipes. They
all live inside the existing apps — this index points at the exact
file + line range for each so you can copy what you need.

### 1. Cookie + CSRF Hono

- Base wiring: [`hono-app/index.ts`](./hono-app/index.ts) — `mountFortress` plus `createCsrfMiddleware`. Auth cookies are emitted automatically by `/auth/login` and `/auth/refresh`.
- Client-side: any unsafe-method request must include the `X-Fortress-CSRF` header. The pipeline rejects cross-site cookie POSTs without it; see [docs/security.md](../docs/security.md#csrf-posture).
- Skip-list pattern for callbacks that must accept third-party POSTs (OAuth, webhooks): pass `csrf: { skipPaths: [...] }` in `FortressConfig`.

### 2. Bearer-token API (no cookies)

- Disable the pipeline CSRF check entirely (no ambient credentials):
  ```ts
  createFortress({ /* ... */, csrf: { enabled: false } })
  ```
- Mount adapter middleware that resolves bearer-only:
  - Hono: `createAuthMiddleware(fortress)` accepts `Authorization: Bearer <jwt>`.
  - Express: same in `@bajustone/fortress/express`.
- See [docs/deployment.md §3](../docs/deployment.md#3-csrf-opt-out-rules-and-recipes) for the "pure API" recipe.

### 3. API-key + service-account flows

- Bind the plugin in `hono-app`: search for `apiKey({ prefix: 'fortress'...})` in [`hono-app/index.ts`](./hono-app/index.ts).
- Self-service routes: `POST/GET/DELETE /api-key/keys` (gated behind `routes: true`).
- Admin-side rotation: `POST /admin/users/:id/api-keys`, `POST /admin/service-accounts/:id/api-keys` (from the `admin` plugin when `apiKeyRoutes: true`).
- Service-account creation: `fortress.iam.createServiceAccount({ name: 'ci-bot' })`; bind a role via `fortress.iam.bindRoleToServiceAccount(saId, roleId)`.
- Auth pipeline picks up `Authorization: ApiKey <key>` and `X-API-Key: <key>` headers automatically once the plugin is registered.
- Recipe walkthrough: [docs/admin-recipes.md](../docs/admin-recipes.md#service-accounts-and-api-keys).

### 4. OAuth 2 / OIDC provider

- Plugin: `oauth({ issuerUrl, loginUrl, consentUrl })` mounted in `hono-app`.
- Endpoints exposed automatically: `/oauth/authorize`, `/oauth/token`, `/oauth/userinfo`, `/oauth/.well-known/openid-configuration`, `/oauth/.well-known/jwks.json`, plus consent-flow `/oauth/flows/:flowId/{approve,deny}`.
- SPA-driven consent flow: read the docs section on `enableAuthorizeEndpoint` / `enableConsentApi` in [src/plugins/oauth/index.ts](../src/plugins/oauth/index.ts).
- RP setup checklist: [docs/deployment.md §7](../docs/deployment.md#7-oauth--oidc-rp-setup).

### 5. Admin bootstrap + policy sync

- Bootstrap: `POST /iam/admin/bootstrap` (mounted by the `admin` plugin). Creates `fortress-admin` role and binds it to the calling user.
- Sample policy file: [`policy/fortress.policy.json`](./policy/fortress.policy.json).
- Apply from a script (see [docs/policy-as-code.md](../docs/policy-as-code.md) for the full pattern):
  ```ts
  import { loadPolicy, diffPolicy, applyPolicyPlan } from '@bajustone/fortress';
  const { policy } = await loadPolicy();
  const plan = await diffPolicy(policy, fortress.iam);
  if (!plan.inSync) await applyPolicyPlan(plan, fortress.iam);
  ```
- CI gate: `fortress policy:summary` for the offline file check; `runFortressChecks({ fortress })` from a test (see [docs/ci.md](../docs/ci.md)).

### 6. Tenancy (schema-per-tenant PostgreSQL)

- Plugin: `tenancy({ schemaPrefix: 'tenant_', routes: true, onSchemaCreated })`.
- Create tenant: `await fortress.plugins.tenancy.createTenant({ name: 'Acme', taxId: 'acme-001' })` — the plugin creates `tenant_<id>` schema and runs your `onSchemaCreated` hook.
- Add user to tenant: `await fortress.plugins.tenancy.addUserToTenant(userId, tenantId)`. Triggers `enrichTokenClaims` so future JWTs carry `customClaims.tenantId`.
- Switch tenant: `POST /tenancy/switch` (when `routes: true`).
- Adapter pin: PostgreSQL connections inside any DB operation run `set_config('search_path', ?, true)` for the resolved tenant before the operation, so the schema selection and query share one connection.
- Full guide: [docs/plugins/tenancy.md](../docs/plugins/tenancy.md). Migration notes from pre-hardening tenants: same doc, "Migration notes" section.

## Adding your own example

The bar for a useful example: it should boot end-to-end with one
command, exercise the smallest possible plugin set to make the point,
and ship a README that explains what it shows in two paragraphs.

Add new examples as a sub-folder here and extend the table at the top
of this file. Don't duplicate the `hono-app` reference — if the example
is "the same thing with one knob flipped", a section in this README is
enough.
