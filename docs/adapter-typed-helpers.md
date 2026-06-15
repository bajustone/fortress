# Typed adapter helpers (P1-6)

Fortress's framework adapters (Hono, Express, SvelteKit) attach
request-scoped state (`fortressSubject`, `fortressUserId`,
`fortressClaims`, `fortressDb`, `fortressGetScopedDb`,
`fortressScopes`). This page covers how to read that state from your own
handlers with **no casts**, while keeping your own env/locals/request
augmentations intact.

The plugin-method surface (`fortress.plugins.<name>.method(...)`) is
already typed via `InferPlugins<T>` — the const generic plugin list
passed to `createFortress` carries each plugin's method-shape through to
`fortress.plugins`. Nothing extra to do.

---

## Hono — `FortressEnv<TAppEnv>`

The Hono adapter exports a generic env type that composes your own
`Variables` and `Bindings` with Fortress's. Use the default
`FortressEnv` for Fortress-only apps; parameterize it with your env for
apps that already declare their own variables.

```ts
import { Hono } from 'hono';
import {
  FortressEnv,
  createHonoMiddleware,
  getClaims,
  getSubject,
  getUserId,
} from '@bajustone/fortress/hono';

interface MyEnv {
  Variables: { requestId: string };
  Bindings: { DB: D1Database };
}

const app = new Hono<FortressEnv<MyEnv>>();
const { authMiddleware, errorHandler } = createHonoMiddleware(fortress);
app.use(authMiddleware);
app.onError(errorHandler);

app.get('/me', (c) => {
  const requestId = c.get('requestId');  // string  (host-defined)
  const subject = getSubject(c);          // Subject (fortress-defined)
  const userId = getUserId(c);            // number  (USER-only)
  return c.json({ requestId, subject, userId });
});
```

### Typed custom JWT claims

`getClaims<TCustomClaims>(c)` narrows the `customClaims` slot to your
deployment's plugin-augmented shape. The tenancy plugin, for example,
adds `tenantId` / `tenantCode`:

```ts
interface MyClaims {
  tenantId: string;
  tenantCode: string;
}

app.get('/iam/whoami', (c) => {
  const claims = getClaims<MyClaims>(c);
  const tenantCode = claims.customClaims?.tenantCode; // string | undefined
  return c.json({ sub: claims.sub, tenantCode });
});
```

### Exports

| Export | Kind | Purpose |
|---|---|---|
| `FortressEnv<TAppEnv>` | type | Generic env composing your env with Fortress's variables |
| `FortressVariables` | type | The bare Fortress `Variables` slot — useful for `Hono<{ Variables: FortressVariables & MyVars }>` |
| `FortressContext<E>` | type | Sugar for `Context<E>` typed handlers |
| `getSubject<E>(c)` | function | Returns `Subject`; throws 401 if unauthenticated |
| `getUserId<E>(c)` | function | Returns `number`; throws 401 if subject is not a `USER` |
| `getClaims<T, E>(c)` | function | Returns `TokenClaims & { customClaims?: T }` |
| `getDb<E>(c)` | function | Per-request `DatabaseAdapter` with plugin `wrapAdapter` applied |
| `getScopedDb<E>(c, model)` | function | Adds `scopeRules` for `model` on top of `getDb` |

All helpers are generic in the env type so they accept any
`Context<E>` whose `Variables` include `FortressVariables`.

---

## Express — `FortressExpressFields`

The Express adapter exports the Fortress-specific fields it attaches to
the `Request` object so you can **declaration-merge** them into express's
native `Request` type. Once merged, your route handlers see the typed
fields with no casts.

```ts
// src/types/express.d.ts
import type { FortressExpressFields } from '@bajustone/fortress/express';

declare module 'express-serve-static-core' {
  interface Request extends FortressExpressFields {}
}
```

```ts
// src/routes/me.ts
import { Router } from 'express';
import { createAuthMiddleware } from '@bajustone/fortress/express';

const router = Router();
router.use(createAuthMiddleware(fortress));

router.get('/me', (req, res) => {
  const subject = req.fortressSubject;       // Subject | undefined  (typed)
  const userId = req.fortressUserId;          // number   | undefined
  const claims = req.fortressClaims;          // TokenClaims | undefined
  res.json({ subject, userId, claims });
});
```

`@bajustone/fortress/express` also exports the helper functions
(`getSubject(req)`, `getUserId(req)`, `getClaims(req)`, `getDb(req)`,
`getScopedDb(req, model)`) — they're equivalent to reading the fields
directly, but throw a typed 401 when the field is missing instead of
returning `undefined`.

---

## SvelteKit — `FortressLocals`

The SvelteKit adapter exposes `event.locals.fortress` (subject, userId,
claims, scopes, db, getScopedDb). Augment SvelteKit's `App.Locals` once
and your `+server.ts` / `+page.server.ts` handlers see the typed shape
everywhere.

```ts
// src/app.d.ts
import type { FortressLocals } from '@bajustone/fortress/sveltekit';

declare global {
  namespace App {
    interface Locals extends FortressLocals {}
  }
}
```

```ts
// src/routes/api/me/+server.ts
import { json } from '@sveltejs/kit';
import { getSubject } from '@bajustone/fortress/sveltekit';

export const GET = ({ locals }) => {
  const subject = locals.fortress?.subject;  // Subject | undefined  (typed)
  return json({ subject });
};
```

`FortressLocals` already extends Fortress's variables under the
`fortress` key, so multiple library augmentations of `App.Locals` (e.g.
your own session library + Fortress) coexist without colliding.

---

## Typed plugin methods

`fortress.plugins.<name>` is automatically typed from the plugin's
`methods` return type, propagated through the const generic plugin
list:

```ts
import { createFortress } from '@bajustone/fortress';
import { tenancy } from '@bajustone/fortress/plugins/tenancy';
import { apiKey } from '@bajustone/fortress/plugins/api-key';

const fortress = createFortress({
  database: db,
  jwt: { key: secret },
  plugins: [tenancy(), apiKey({ prefix: 'fortress' })] as const,
});

// All typed; no casts.
await fortress.plugins.tenancy.createTenant({ name: 'Acme', taxId: 'acme-001' });
await fortress.plugins['api-key'].createKey({ name: 'CI', scopes: ['*'] }, ctx);
```

For dynamic plugin lookup (e.g. a plugin loaded by name at runtime),
use `getPluginMethods<T>(fortress, name)` to attach a known interface
without casting.

---

## Type-level tests

The Hono helpers ship with type-level tests under
`src/hono/middleware/auth.types.test.ts` using `expectTypeOf`. They
assert:

- `FortressEnv<MyEnv>['Variables']` keeps host-defined variables and
  adds Fortress's.
- `getSubject` / `getUserId` work on a parameterized
  `Hono<FortressEnv<MyEnv>>` with no casts.
- `getClaims<T>` narrows `customClaims` to `T`.
- The unparameterized `FortressEnv` default still works for existing
  callers.

Run with `bunx vitest run src/hono/middleware/auth.types.test.ts`.
