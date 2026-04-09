/**
 * Modern entry point for the Hono adapter: register a single fortress
 * middleware that detects Fortress-managed paths and delegates to
 * `fortress.handleRequest`.
 *
 * Replaces the older split surface (`createHonoMiddleware` +
 * `mountPluginRoutes`) for greenfield projects. Custom user routes
 * registered before `mountFortress` keep working — Hono's first-match
 * routing means user handlers win over the catch-all.
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

import type { Hono } from 'hono';
import type { Fortress } from '../core/fortress';
import {
  getPluginPathPrefixes,
  isFortressPath,
} from '../core/http/fortress-rbac';

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
export function mountFortress(
  app: Hono,
  fortress: Fortress,
  options: MountFortressOptions = {},
): void {
  const prefix = options.prefix ?? '';
  const plugins = fortress.config.plugins ?? [];
  const pluginPathPrefixes = getPluginPathPrefixes(plugins);

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

    if (!isFortressPath(pathname, pluginPathPrefixes)) {
      await next();
      return;
    }

    // Build a fresh Request with the (possibly rewritten) path so core
    // matches the canonical /auth/* / /iam/* paths regardless of mount prefix.
    const rewritten = new Request(`${url.origin}${pathname}${url.search}`, c.req.raw);
    return fortress.handleRequest(rewritten);
  });
}
