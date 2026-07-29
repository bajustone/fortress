# Fortress + SvelteKit Example

A reference for wiring `@bajustone/fortress` into a SvelteKit project.

This directory holds the **Fortress-relevant** files. Drop them into a real
SvelteKit project (`npm create svelte@latest`) and they work as-is once you
adjust the imports to use SvelteKit's `$lib` / `$app` aliases.

## Files

| File | Purpose |
|---|---|
| `src/lib/server/fortress.ts` | Singleton Fortress instance (server-only). |
| `src/hooks.server.ts` | Handle hook — primary integration point. |
| `src/app.d.ts` | Augments `App.Locals` so `event.locals.fortress` is typed. |
| `src/routes/login/+page.server.ts` | Form-action login. Honors `?flow=<id>` to land back on consent. |
| `src/routes/dashboard/+page.server.ts` | Protected route reading `getUserId`. |
| `src/routes/oauth/consent/+page.server.ts` | OAuth consent flow — fetches flow metadata, posts approve/deny. |
| `src/routes/oauth/consent/+page.svelte` | Branded consent UI rendered in your app, not Fortress. |
| `src/routes/api/fortress/[...path]/+server.ts` | **Optional** catch-all escape hatch. |

## OAuth consent flow (Pattern B)

`src/lib/server/fortress.ts` registers the `oauth` plugin with
`enableAuthorizeEndpoint`/`enableConsentApi` on, and seeds a demo user
(`alice@example.com` / `correct-horse-battery-staple`) plus a demo OAuth client at startup.
The seeded `client_id` / `client_secret` are logged to the server console.

To try the flow end-to-end:

1. Start the example (`npm run dev`).
2. Copy the seeded `client_id` from the server log.
3. Hit `http://localhost:5173/api/oauth/authorize?client_id=<id>&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Foauth%2Fcallback-demo&response_type=code&state=xyz&scope=read:posts`.
4. Fortress 302s to `/login?flow=<id>` (no session). Log in as alice.
5. The login action redirects to `/oauth/consent?flow=<id>`. The page
   loads flow metadata, you click Allow, and the action redirects the
   browser to the OAuth client's `redirect_uri` with `?code=...&state=xyz`.
6. The client exchanges the code for an access token via
   `POST /api/oauth/token` (Basic auth with `client_id:client_secret`).

No HTML ever leaves Fortress — the consent screen is `+page.svelte`,
styled however you like.

## Two ways to mount Fortress

### 1. Handle hook (recommended)

```ts
// src/hooks.server.ts
import { sequence } from '@sveltejs/kit/hooks';
import { createSvelteKitHandle } from '@bajustone/fortress/sveltekit';
import { fortress } from '$lib/server/fortress';

export const handle = sequence(
  createSvelteKitHandle(fortress, { basePath: '/api' }),
);
```

This single hook:

- Intercepts `/api/auth/*`, `/api/iam/*`, plugin paths and delegates to
  `fortress.handleRequest`. The Response (with `Set-Cookie`) is returned
  directly, **bypassing SvelteKit's `csrf.checkOrigin`**.
- For user routes, populates `event.locals.fortress` from the access cookie
  (or `Authorization: Bearer` fallback). Auto-refreshes when expired.
- Runs plugin middleware at `before-auth` / `after-auth` / `after-rbac`.
- Auto-skips during `vite build` prerender via `building`.

Zero route files. No `+server.ts` for `/auth/login` etc.

### 2. Catch-all `+server.ts` (escape hatch)

```ts
// src/routes/api/fortress/[...path]/+server.ts
import { toSvelteKitHandler } from '@bajustone/fortress/sveltekit';
import { fortress } from '$lib/server/fortress';

export const { GET, POST, PUT, DELETE, PATCH } = toSvelteKitHandler(fortress);
```

Use this when you want Fortress routes colocated under your normal routes
tree. Works alongside the handle hook — there is no conflict because the
handle hook intercepts paths the file handler would have served anyway.

## Cookie defaults

Fortress defaults to secure, `__Host-`-prefixed cookies in every environment;
it does not infer cookie security from `NODE_ENV`:

```
Set-Cookie: __Host-fortress_access=...; HttpOnly; Secure; SameSite=Lax; Path=/
Set-Cookie: __Host-fortress_refresh=...; HttpOnly; Secure; SameSite=Lax; Path=/
```

Because this example runs on plain HTTP, its configuration explicitly sets
`cookies: { secure: false }`, producing local-only cookies without `Secure` or
the `__Host-` prefix:

```
Set-Cookie: fortress_access=...; HttpOnly; SameSite=Lax; Path=/
Set-Cookie: fortress_refresh=...; HttpOnly; SameSite=Lax; Path=/
```

Remove that override when deploying behind HTTPS. Override other
`FortressConfig.cookies` fields only when you need different names, a `Domain`,
or `SameSite=strict`.

## CSRF posture

- **Fortress-managed routes** (`/api/auth/*`, etc.) are intercepted *before*
  `resolve()` runs, so SvelteKit's built-in `csrf.checkOrigin` does NOT
  apply. They rely on `SameSite=Lax` cookies and (for OAuth) PKCE.
- **Form actions** (`?/login`) DO go through `resolve()` and ARE subject to
  SvelteKit's CSRF check. This is good — the check is the right default
  for form-based logins.

## Auto-refresh during SSR

When a user opens a protected page with an expired access cookie but a
valid refresh cookie, the handle hook silently refreshes both tokens and
sets the new cookies before `resolve(event)`. The render proceeds as if
the access token was never expired.

**Caveat**: opening N tabs simultaneously triggers N parallel refresh
attempts. Fortress's refresh-token family rotation will succeed for one and
fail (with `TOKEN_REUSE`) for the rest. This is a known JWT+rotation
trade-off — out of scope for this adapter.
