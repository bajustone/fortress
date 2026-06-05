/**
 * `createSvelteKitHandle(fortress, options)` — primary entrypoint for the
 * SvelteKit adapter.
 *
 * Returns a SvelteKit `Handle` hook that:
 *
 * 1. Short-circuits during `vite build` prerender (caller passes
 *    `building` to opt out).
 * 2. Intercepts Fortress-managed paths (`/auth/*`, `/iam/*`, plugin paths)
 *    by calling `fortress.handleRequest(event.request)` and returning the
 *    `Response` directly — bypassing SvelteKit's router AND its built-in
 *    CSRF check (which only runs inside `resolve(event)`).
 * 3. For user routes, runs plugin `before-auth` middleware, extracts the
 *    access token (cookie-first, Bearer fallback), verifies it,
 *    auto-refreshes when expired, populates `event.locals.fortress`, runs
 *    plugin `after-auth` and (when a route map matches) RBAC, then
 *    delegates to `resolve(event)`.
 *
 * Compose with `sequence()` from `@sveltejs/kit/hooks` if you have other
 * handles.
 *
 * @example
 * ```ts
 * // src/hooks.server.ts
 * import { sequence } from '@sveltejs/kit/hooks';
 * import { createSvelteKitHandle } from '@bajustone/fortress/sveltekit';
 * import { fortress } from '$lib/server/fortress';
 *
 * export const handle = sequence(
 *   createSvelteKitHandle(fortress, { basePath: '/api' }),
 * );
 * ```
 */

import type { DatabaseAdapter } from '../adapters/database';
import type { Fortress } from '../core/fortress';
import type { PluginContext } from '../core/plugin';
import type { Subject, TokenClaims } from '../core/types';
import type {
  FortressLocals,
  SvelteKitAdapterOptions,
  SvelteKitHandle,
  SvelteKitRequestEvent,
} from './types';
import { Errors, FortressError } from '../core/errors';
import { errorToResponse } from '../core/http/error-response';
import { buildRouteTable, matchRoute } from '../core/http/match';
import { tryPluginPrincipal } from '../core/http/principal';
import {
  chainAdapterWrappers,
  collectScopeRules,
  wrapAdapterWithScopeRules,
} from '../core/plugin-runner';
import { replayCookies, setAuthCookies } from './cookies';

/** Build the SvelteKit `handle` hook for a Fortress instance. */
export function createSvelteKitHandle(
  fortress: Fortress,
  options: SvelteKitAdapterOptions = {},
): SvelteKitHandle {
  const basePath = options.basePath ?? '';
  // Pre-build the route table at startup so the handle hook can quickly
  // detect whether a path is a Fortress endpoint without re-parsing.
  const routeTable = buildRouteTable(fortress.endpoints);
  const skipPatterns = (options.skipPaths ?? []).map(p => pathToRegex(p));
  const routeMap = options.routeMap ?? {};

  return async ({ event, resolve }) => {
    try {
      // 1. Strip basePath if provided. Paths outside the prefix are user-owned.
      const fullPath = event.url.pathname;
      const innerPath = stripPrefix(fullPath, basePath);

      // 2. Fortress-managed path → delegate to core, return Response directly.
      //    The handle hook returns BEFORE resolve() so SvelteKit's CSRF check
      //    is bypassed for these routes (login, refresh, etc.). We detect
      //    fortress paths by matching the canonical endpoint table — this
      //    catches /auth/login, /iam/*, plugin routes, OAuth, OpenAPI, etc.
      if (innerPath !== null && matchRoute(routeTable, event.request.method, innerPath)) {
        const rewritten = rewriteRequest(event.request, event.url, innerPath);
        const response = await fortress.handleRequest(rewritten);
        // Mirror Set-Cookie headers into event.cookies so anything else in this
        // request cycle (e.g. a sequence() handle running after this one) sees
        // them via event.cookies.get(). The browser still sees the originals
        // on the returned Response.
        replayCookies(response, event);
        return response;
      }

      // 3. User route — run plugin `before-auth` middleware.
      await fortress.runPluginMiddleware('before-auth', { request: event.request });

      // 4. Resolve the request principal. Plugin `resolvePrincipal` hooks
      //    (api-key, future OAuth client_credentials, mTLS) run first so
      //    non-JWT credentials authenticate uniformly on user routes. If
      //    no plugin claims the request, fall back to the JWT bearer token
      //    (cookie-first, Authorization: Bearer second) — and if the JWT
      //    is expired, try a silent refresh using the refresh cookie so
      //    SSR loads stay logged in across token lifetimes.
      let subject: Subject | undefined;
      let userId: number | undefined;
      let claims: TokenClaims | undefined;
      let scopes: string[] | null | undefined;

      const pluginResolved = await tryPluginPrincipal(fortress, event.request);
      if (pluginResolved) {
        subject = pluginResolved.subject;
        claims = pluginResolved.claims;
        scopes = pluginResolved.scopes;
      }
      else {
        const token = fortress.extractAccessToken(event.request);
        if (token) {
          try {
            claims = await fortress.auth.verifyToken(token);
            subject = { type: claims.subjectType, id: claims.sub };
          }
          catch {
            // Token invalid or expired — try silent refresh.
            const refreshToken = event.cookies.get(fortress.cookies.refreshName);
            if (refreshToken) {
              try {
                const refreshed = await fortress.auth.refresh(refreshToken);
                setAuthCookies(event, fortress, refreshed);
                claims = await fortress.auth.verifyToken(refreshed.accessToken);
                subject = { type: claims.subjectType, id: claims.sub };
              }
              catch {
                // Refresh failed too — leave locals empty; loaders decide.
              }
            }
          }
        }
      }

      if (subject?.type === 'USER')
        userId = subject.id;

      if (subject) {
        populateLocals(
          event as unknown as SvelteKitRequestEvent<FortressLocals>,
          fortress,
          subject,
          claims,
          scopes,
        );
      }
      else {
        // Always set the namespace so consumer code can call `event.locals.fortress?.userId`
        // without optional chaining gymnastics on the namespace itself.
        const locals = event.locals as unknown as FortressLocals;
        locals.fortress ??= {};
      }

      // 5. Plugin `after-auth` middleware on user routes.
      await fortress.runPluginMiddleware('after-auth', {
        request: event.request,
        fortressSubject: subject,
        fortressUserId: userId,
        fortressClaims: claims,
        fortressScopes: scopes,
      });

      // 6. User-route RBAC via routeMap (skip-patterns filtered out first).
      if (!skipPatterns.some(p => p.test(fullPath))) {
        const mapping = matchRouteMap(routeMap, event.request.method, fullPath);
        if (mapping) {
          if (!subject)
            throw Errors.unauthorized('Not authenticated');
          const allowed = await fortress.iam.checkPermission(subject, mapping.resource, mapping.action, {
            credentialScopes: scopes,
          });
          if (!allowed)
            throw Errors.forbidden('Insufficient permissions');
        }
      }

      // 7. Plugin `after-rbac` middleware.
      await fortress.runPluginMiddleware('after-rbac', {
        request: event.request,
        fortressSubject: subject,
        fortressUserId: userId,
        fortressClaims: claims,
        fortressScopes: scopes,
      });

      // 8. Hand off to SvelteKit's normal route resolution.
      return await resolve(event);
    }
    catch (err) {
      return errorToResponse(err);
    }
  };
}

// ── helpers ─────────────────────────────────────────────────────────

/**
 * Populate `event.locals.fortress` with the request-scoped DB adapter and
 * scope-aware accessor. Builds the same chain that core does for
 * fortress-managed routes (`chainAdapterWrappers` + `collectScopeRules`).
 */
function populateLocals(
  event: SvelteKitRequestEvent<FortressLocals>,
  fortress: Fortress,
  subject: Subject,
  claims: TokenClaims | undefined,
  scopes: string[] | null | undefined,
): void {
  const plugins = fortress.config.plugins ?? [];
  const requestContext: Record<string, unknown> = {
    tenantCode: event.request.headers.get('x-tenant-code') ?? undefined,
    ipAddress:
      event.request.headers.get('x-forwarded-for')
      ?? event.request.headers.get('x-real-ip')
      ?? undefined,
    userAgent: event.request.headers.get('user-agent') ?? undefined,
  };
  const wrapped = chainAdapterWrappers(plugins, fortress.config.database, requestContext);
  const pluginCtx: PluginContext = { db: wrapped, config: fortress.config };

  event.locals.fortress = {
    subject,
    userId: subject.type === 'USER' ? subject.id : undefined,
    claims,
    scopes,
    db: wrapped,
    getScopedDb: async (model: string): Promise<DatabaseAdapter> => {
      const rule = await collectScopeRules(plugins, subject.id, model, pluginCtx);
      if (!rule)
        return wrapped;
      return wrapAdapterWithScopeRules(wrapped, rule);
    },
  };
}

/**
 * Strip an optional path prefix. Returns `null` if a prefix was configured
 * but the path doesn't start with it (signal to fall through to user routes).
 */
function stripPrefix(pathname: string, prefix: string): string | null {
  if (!prefix)
    return pathname;
  if (!pathname.startsWith(prefix))
    return null;
  return pathname.slice(prefix.length) || '/';
}

/**
 * Build a new `Request` with the same method/headers/body as the original
 * but with the path rewritten to drop the basePath. Used so core's route
 * matcher sees the canonical `/auth/*` paths regardless of mount prefix.
 */
function rewriteRequest(original: Request, url: URL, innerPath: string): Request {
  const newUrl = `${url.origin}${innerPath}${url.search}`;
  return new Request(newUrl, original);
}

/** Convert a simple path pattern (`:param` and `*`) to a regex. */
function pathToRegex(pattern: string): RegExp {
  const regexStr = pattern
    .replace(/:[^/]+/g, '[^/]+')
    .replace(/\*/g, '.*')
    .replace(/\//g, '\\/');
  return new RegExp(`^${regexStr}$`);
}

/** Look up a `(resource, action)` mapping for `METHOD path`. */
function matchRouteMap(
  map: Record<string, { resource: string; action: string }>,
  method: string,
  path: string,
): { resource: string; action: string } | null {
  const exact = map[`${method} ${path}`];
  if (exact)
    return exact;
  for (const [pattern, mapping] of Object.entries(map)) {
    const [m, p] = pattern.split(' ', 2);
    if (m !== method)
      continue;
    if (pathToRegex(p).test(path))
      return mapping;
  }
  return null;
}

// Re-export FortressError so the consumer of this module catches it correctly.
export { FortressError };
