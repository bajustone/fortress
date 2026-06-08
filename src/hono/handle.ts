/**
 * Primary entry point for the Hono adapter: register a single fortress
 * middleware that detects Fortress-managed paths and delegates to
 * `fortress.handleRequest`. Custom user routes registered *before*
 * `mountFortress` keep working — Hono's first-match routing means user
 * handlers win over the catch-all.
 *
 * @example
 * ```ts
 * import { Hono } from 'hono';
 * import { mountFortress } from '@bajustone/fortress/hono';
 *
 * const app = new Hono();
 * mountFortress(app, fortress);
 * // POST /auth/login, POST /auth/refresh, GET /auth/me, /iam/*, /oauth/* …
 * // are all handled automatically. Cookies for login/refresh are set on
 * // the response without any extra wiring.
 * ```
 */

import type { Env, Hono } from 'hono';
import type { Fortress } from '../core/fortress';
import { buildRouteTable, matchRoute } from '../core/http/match';

/** Options for {@link mountFortress}. */
export interface MountFortressOptions {
  /**
   * Optional path prefix to mount Fortress under (e.g. `/api`). When set,
   * a request to `/api/auth/login` is internally rewritten to `/auth/login`
   * before being passed to `fortress.handleRequest`.
   */
  prefix?: string;
}

/**
 * Mount a single Hono middleware that delegates Fortress-managed paths to
 * `fortress.handleRequest` and otherwise calls `next()` so user-route
 * handlers run normally.
 *
 * Cookies emitted by login/refresh/impersonate are honored automatically:
 * the `Response` returned by `fortress.handleRequest` already carries the
 * `Set-Cookie` headers built by core, and Hono returns it verbatim.
 */
export function mountFortress<E extends Env = Env>(
  app: Hono<E>,
  fortress: Fortress,
  options: MountFortressOptions = {},
): void {
  const prefix = options.prefix ?? '';
  // Pre-build the route table once at startup. The middleware uses this to
  // detect whether a request belongs to Fortress before delegating to core.
  // Matching against the table catches every endpoint (auth, iam, plugin
  // routes including OpenAPI's flat `/openapi.json` and `/openapi`) without
  // needing per-prefix heuristics.
  const routeTable = buildRouteTable(fortress.manifest.filter(route => route.mounted));

  app.use('*', async (c, next) => {
    const url = new URL(c.req.url);
    let pathname = url.pathname;
    if (prefix && pathname.startsWith(prefix)) {
      pathname = pathname.slice(prefix.length) || '/';
    }
    else if (prefix) {
      // Path doesn't live under our prefix — leave it for user routes.
      await next();
      return;
    }

    if (!matchRoute(routeTable, c.req.method, pathname)) {
      await next();
      return;
    }

    // Build a fresh Request with the (possibly rewritten) path so core
    // matches the canonical /auth/* / /iam/* paths regardless of mount prefix.
    const rewritten = new Request(`${url.origin}${pathname}${url.search}`, c.req.raw);
    return fortress.handleRequest(rewritten);
  });
}
