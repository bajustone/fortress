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
| `src/routes/login/+page.server.ts` | Form-action login (`fortressActions.login`). |
| `src/routes/dashboard/+page.server.ts` | Protected route reading `getUserId`. |
| `src/routes/api/fortress/[...path]/+server.ts` | **Optional** catch-all escape hatch. |

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

In production (`NODE_ENV === 'production'`):

```
Set-Cookie: __Host-fortress_access=...; HttpOnly; Secure; SameSite=Lax; Path=/
Set-Cookie: __Host-fortress_refresh=...; HttpOnly; Secure; SameSite=Lax; Path=/
```

In development:

```
Set-Cookie: fortress_access=...; HttpOnly; SameSite=Lax; Path=/
Set-Cookie: fortress_refresh=...; HttpOnly; SameSite=Lax; Path=/
```

(`__Host-` prefix requires `Secure`, which breaks localhost over HTTP.)

Override via `FortressConfig.cookies` if you need different names, a
`Domain`, or `SameSite=strict`.

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
