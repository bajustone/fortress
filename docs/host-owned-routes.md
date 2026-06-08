# Host-owned routes

Fortress has two HTTP surfaces:

1. **Fortress-managed routes** — endpoints registered in `fortress.endpoints` and served through `fortress.handleRequest()` by `mountFortress()` / `createSvelteKitHandle()`.
2. **Host-owned routes** — routes your app registers in Hono, Express, SvelteKit, `Bun.serve`, etc. These often call `fortress.auth.*`, `fortress.iam.*`, or plugin methods directly.

Use `protect()` / `protectedRoute()` when a host-owned route should receive the same security controls as a Fortress-managed route.

## What `protect()` runs

Given an endpoint definition (or handler name) present in the route manifest, Fortress applies:

- plugin middleware: `before-auth`, `after-auth`, `after-rbac`;
- pipeline CSRF protection for unsafe cookie-authenticated requests;
- principal resolution via plugin credentials first, then Fortress JWT bearer/cookie;
- default-deny RBAC from `endpoint.meta.permission`;
- request validation from endpoint body/query/params schemas;
- auth-cookie attachment when the handler returns `{ accessToken, refreshToken? }`.

The route's endpoint metadata remains the source of truth. Do not duplicate permissions in a separate route map unless you intentionally want a different policy.

## Core API

```ts
import { protect } from '@bajustone/fortress';

const handler = protect(fortress, endpointDefinition, async (ctx) => {
  // ctx.subject, ctx.userId, ctx.input, ctx.params, ctx.query, ctx.body
  return { ok: true };
});

const response = await handler(request);
```

`target` may be an `EndpointDefinition` or a unique endpoint `handler` name. If a handler name maps to multiple routes, pass the definition directly or set `method`.

## Hono

```ts
import { endpoint, obj, str } from '@bajustone/fortress';
import { protectedRoute } from '@bajustone/fortress/hono';

const statsEndpoint = endpoint('GET', '/api/stats')
  .summary('Stats')
  .security('bearer')
  .permission('stats', 'read')
  .response(200, 'OK', obj({ ok: str() }, 'ok'))
  .handler('stats')
  .build();

// Include the endpoint in a small metadata plugin so it appears in
// fortress.endpoints / fortress.manifest / OpenAPI.
const fortress = createFortress({
  // ...
  plugins: [{ name: 'host-routes', routes: { stats: statsEndpoint } }],
});

app.get('/api/stats', protectedRoute(fortress, statsEndpoint, async (_c, ctx) => {
  return { ok: ctx.subject?.type ?? 'unknown' };
}));
```

Register the Hono route before `mountFortress(app, fortress)` so the host handler wins over the manifest-owned fallback route.

## Express

```ts
import { protectedRoute } from '@bajustone/fortress/express';

app.get('/api/stats', protectedRoute(fortress, statsEndpoint, async (_req, _res, ctx) => {
  return { ok: ctx.subject?.type ?? 'unknown' };
}));
```

## SvelteKit

```ts
import { protectedRoute } from '@bajustone/fortress/sveltekit';

const GET = protectedRoute(fortress, statsEndpoint, async (_event, ctx) => {
  return new Response(JSON.stringify({ ok: ctx.subject?.type }), {
    headers: { 'Content-Type': 'application/json' },
  });
});

export { GET };
```

## Boundary checklist

- `fortress.handleRequest()` remains responsible for Fortress-managed routes.
- `protectedRoute()` is responsible for host-owned routes that opt in.
- Public host routes can remain unwrapped.
- If a host route is mounted at a different path than its endpoint metadata, pass `options.path` / `options.params` so plugin middleware and validation use the intended canonical route.
