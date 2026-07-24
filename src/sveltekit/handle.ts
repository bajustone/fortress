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
 *    `Response` directly. This bypasses SvelteKit's built-in CSRF check
 *    (which only runs inside `resolve(event)`), but `handleRequest` runs
 *    Fortress's own pipeline CSRF check (H5) in its place.
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
import type { FortressAuthRuntime, FortressHttpRuntime, FortressPluginRuntime } from '../core/capabilities';
import type { PluginContext } from '../core/plugin';
import type { AuthTokenPair, RequestMeta, Subject, TokenClaims } from '../core/types';
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

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

type SvelteKitHandleRuntime
  = & Pick<FortressHttpRuntime, 'manifest' | 'handleRequest'>
    & Pick<FortressAuthRuntime, 'auth' | 'iam' | 'config' | 'extractAccessToken' | 'cookies'>
    & Pick<FortressPluginRuntime, 'runPluginMiddleware'>;

/** Build the SvelteKit `handle` hook for a Fortress instance. */
export function createSvelteKitHandle(
  fortress: SvelteKitHandleRuntime,
  options: SvelteKitAdapterOptions = {},
): SvelteKitHandle {
  const basePath = options.basePath ?? '';
  // Pre-build the route table at startup so the handle hook can quickly
  // detect whether a path is a Fortress endpoint without re-parsing.
  const routeTable = buildRouteTable(fortress.manifest.filter(route => route.mounted));
  const skipPatterns = (options.skipPaths ?? []).map(p => pathToRegex(p));
  const routeMap = options.routeMap ?? {};
  const unmappedRoutes = options.unmappedRoutes ?? 'allow';
  // Coalesce overlapping SSR requests that arrive with the same expired
  // cookie pair. Entries remain until every request that joined has finished
  // its full handle/resolve lifecycle—not merely until refresh() settles—so a
  // stale-cookie request still in the same SSR wave receives the successor
  // instead of replaying the predecessor. User agent is part of the key so a
  // mismatched fingerprint can never piggyback on another request's check.
  interface RefreshFlight {
    consumers: number;
    promise: Promise<AuthTokenPair>;
  }
  const refreshFlights = new Map<string, RefreshFlight>();
  const refreshFlightKey = (refreshToken: string, meta: RequestMeta): string =>
    `${refreshToken}\u0000${meta.userAgent ?? ''}`;
  const acquireRefreshFlight = (
    refreshToken: string,
    meta: RequestMeta,
  ): { key: string; promise: Promise<AuthTokenPair> } => {
    const key = refreshFlightKey(refreshToken, meta);
    const existing = refreshFlights.get(key);
    if (existing) {
      existing.consumers++;
      return { key, promise: existing.promise };
    }
    const promise = fortress.auth.refresh(refreshToken, meta);
    refreshFlights.set(key, { consumers: 1, promise });
    return { key, promise };
  };
  const releaseRefreshFlight = (key: string): void => {
    const flight = refreshFlights.get(key);
    if (!flight)
      return;
    flight.consumers--;
    if (flight.consumers === 0)
      refreshFlights.delete(key);
  };

  return async ({ event, resolve }) => {
    let acquiredRefreshKey: string | undefined;
    try {
      // 1. Strip basePath if provided. Paths outside the prefix are user-owned.
      const fullPath = event.url.pathname;
      const innerPath = stripPrefix(fullPath, basePath);

      // 2. Fortress-managed path → delegate to core, return Response directly.
      //    The handle hook returns BEFORE resolve(), so SvelteKit's own CSRF
      //    check is skipped — but handleRequest runs Fortress's pipeline CSRF
      //    check (enforceCsrf) for these routes (login, refresh, etc.). We
      //    detect fortress paths by matching the canonical endpoint table —
      //    this catches /auth/login, /iam/*, plugin routes, OAuth, OpenAPI.
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
      let userId: string | undefined;
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
            // Token invalid or expired — try silent refresh. Restricted to
            // safe methods (SSR page loads are GETs): a silent refresh rotates
            // the refresh token, so allowing it on unsafe cross-site requests
            // would be a CSRF-triggered state change. Unsafe requests fall
            // through with no subject; the client re-auths via the
            // CSRF-protected POST /auth/refresh endpoint.
            const refreshToken = SAFE_METHODS.has(event.request.method.toUpperCase())
              ? event.cookies.get(fortress.cookies.refreshName)
              : undefined;
            if (refreshToken) {
              try {
                const flight = acquireRefreshFlight(refreshToken, requestMeta(event.request));
                acquiredRefreshKey = flight.key;
                const refreshed = await flight.promise;
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
        if (!mapping && unmappedRoutes === 'deny')
          throw Errors.forbidden('No permission mapping for this route');
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
    finally {
      if (acquiredRefreshKey)
        releaseRefreshFlight(acquiredRefreshKey);
    }
  };
}

// ── helpers ─────────────────────────────────────────────────────────

function requestMeta(request: Request): RequestMeta {
  return {
    ipAddress:
      request.headers.get('x-forwarded-for')
      ?? request.headers.get('x-real-ip')
      ?? undefined,
    userAgent: request.headers.get('user-agent') ?? undefined,
  };
}

/**
 * Populate `event.locals.fortress` with the request-scoped DB adapter and
 * scope-aware accessor. Builds the same chain that core does for
 * fortress-managed routes (`chainAdapterWrappers` + `collectScopeRules`).
 */
function populateLocals(
  event: SvelteKitRequestEvent<FortressLocals>,
  fortress: Pick<FortressAuthRuntime, 'config'>,
  subject: Subject,
  claims: TokenClaims | undefined,
  scopes: string[] | null | undefined,
): void {
  const plugins = fortress.config.plugins ?? [];
  // Tenant comes from the verified JWT claim, never a client header.
  const requestContext: Record<string, unknown> = {
    tenantId: claims?.customClaims?.tenantId,
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
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/:[^/]+/g, '[^/]+')
    .replace(/\\\*/g, '.*')
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
