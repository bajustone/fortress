import type { MiddlewareHandler } from 'hono';
import type { Fortress } from '../../core/fortress';
import type { PluginRequestContext } from '../../core/http/plugin-middleware';
import type { MiddlewareDefinition } from '../../core/plugin';
import type { FortressEnv } from './auth';
import { executePluginMiddleware } from '../../core/plugin-runner';

/**
 * Hono middleware that executes plugin-defined middleware for a given position.
 *
 * Normalizes Hono's context to the shared {@link PluginRequestContext}, so
 * plugin middleware receives the same web-standard Request and resolved auth
 * fields under core, Hono, and Express.
 */
export function createPluginMiddleware(
  fortress: Fortress,
  position: MiddlewareDefinition['position'],
): MiddlewareHandler<FortressEnv> {
  const plugins = fortress.config.plugins ?? [];

  return async (c, next) => {
    const path = c.req.path;
    const ctx = { db: fortress.config.database, config: fortress.config };
    const requestContext: PluginRequestContext = {
      request: c.req.raw,
      fortressSubject: c.get('fortressSubject'),
      fortressUserId: c.get('fortressUserId'),
      fortressClaims: c.get('fortressClaims'),
      fortressScopes: c.get('fortressScopes'),
    };

    await executePluginMiddleware(plugins, position, path, ctx, requestContext);
    await next();
  };
}
