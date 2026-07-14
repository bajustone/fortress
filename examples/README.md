# Examples

| Example | Shows | Run |
|---|---|---|
| [`hono-app`](./hono-app/index.ts) | Hono, plugin composition, host routes, validation, OpenAPI | `bun run dev` |
| [`express-app`](./express-app/index.ts) | Express-compatible middleware, plugins, validation | `bun run examples/express-app/index.ts` |
| [`sveltekit-app`](./sveltekit-app/README.md) | Handle hook, locals, form actions, OAuth consent | See its README |
| [`policy`](./policy/fortress.policy.json) | Policy-as-code input | `fortress policy:summary --file examples/policy/fortress.policy.json` |

## Cookie login with Hono

```typescript
import { Hono } from 'hono';
import { createFortress } from '@bajustone/fortress';
import { mountFortress } from '@bajustone/fortress/hono';

const fortress = createFortress({
  database,
  jwt: { key: process.env.FORTRESS_JWT_SECRET! },
  cookies: { secure: false }, // local HTTP only
});

const app = new Hono();
mountFortress(app, fortress);
```

Unsafe cookie-authenticated requests send the CSRF header:

```typescript
await fetch('/auth/logout', {
  method: 'POST',
  headers: { 'X-Fortress-CSRF': '1' },
});
```

See [Security](../docs/security.md#csrf-protection).

## Bearer-only API

```typescript
const fortress = createFortress({
  database,
  jwt: { key },
  csrf: { enabled: false }, // only when cookies are never accepted
});

const { authMiddleware } = createHonoMiddleware(fortress);
app.use('/api/*', authMiddleware);
```

```http
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

## Service account with a scoped API key

```typescript
const account = await fortress.iam.createServiceAccount({
  name: 'ci-bot',
  displayName: 'CI',
});

await fortress.iam.bindRoleToServiceAccount(account.id, deployerRole.id);

const credential = await fortress.plugins['api-key'].createKey({
  subject: { type: 'SERVICE_ACCOUNT', id: account.id },
  name: 'deploy',
  scopes: ['deploy:run'],
});
```

```http
Authorization: ApiKey fortress_sk_...
```

## Apply a policy

```typescript
import {
  applyPolicyPlan,
  diffPolicy,
  loadPolicy,
} from '@bajustone/fortress';

const { policy } = await loadPolicy();
const plan = await diffPolicy(policy, fortress.iam);
const result = await applyPolicyPlan(plan, fortress.iam);

if (result.errors.length)
  throw new Error(JSON.stringify(result.errors));
```

See [Policy as code](../docs/policy-as-code.md).

## PostgreSQL schema tenancy

```typescript
import { tenancy } from '@bajustone/fortress/plugins/tenancy';

const fortress = createFortress({
  database: postgresAdapter,
  jwt: { key },
  plugins: [tenancy({
    routes: true,
    onSchemaCreated: async (schema, rawQuery) => {
      await rawQuery(`CREATE TABLE "${schema}".widgets (id BIGSERIAL PRIMARY KEY)`);
    },
  })] as const,
});

const tenant = await fortress.plugins.tenancy.createTenant({
  name: 'Acme',
  taxId: 'acme',
});

await fortress.plugins.tenancy.addUserToTenant(user.id, tenant.id);
```

See [Tenancy](../docs/plugins/tenancy.md).
