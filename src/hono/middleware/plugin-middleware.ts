import type { MiddlewareHandler } from 'hono';
import type { Fortress } from '../../core/fortress';
import type { MiddlewareDefinition } from '../../core/plugin';
import type { FortressEnv } from './auth';
import { executePluginMiddleware } from '../../core/plugin-runner';

/**
 * Hono middleware that executes plugin-defined middleware for a given position.
 *
 * Wraps `executePluginMiddleware()` as a Hono `MiddlewareHandler`.
 * Passes the Hono context as the `request` parameter so plugin middleware
 * can access request data in a framework-agnostic way.
 */
export function createPluginMiddleware(
  fortress: Fortress,
  position: MiddlewareDefinition['position'],
): MiddlewareHandler<FortressEnv> {
  const plugins = fortress.config.plugins ?? [];

  return async (c, next) => {
    const path = c.req.path;
    const ctx = { db: fortress.config.database, config: fortress.config };

    await executePluginMiddleware(plugins, position, path, ctx, c);
    await next();
  };
}
