/**
 * Framework-agnostic plugin middleware execution for `fortress.handleRequest`
 * and adapter handles.
 *
 * Wraps {@link executePluginMiddleware} from `plugin-runner.ts` so the
 * caller can hand it a {@link PluginRequestContext} (a duck-typed object with
 * `fortressUserId` and friends) instead of a framework-specific Hono context
 * or Express request.
 *
 * Plugins that short-circuit do so by throwing a {@link FortressError}; the
 * caller is expected to wrap this in a try/catch and translate via
 * `errorToResponse`.
 */

import type { FortressConfig } from '../config';
import type { FortressPlugin, MiddlewareDefinition, PluginContext } from '../plugin';
import type { TokenClaims } from '../types';
import { executePluginMiddleware } from '../plugin-runner';

/**
 * Object passed to plugin middleware as the "request" argument when running
 * inside `fortress.handleRequest` or any framework adapter that delegates to
 * core. Carries the web-standard `Request` plus the resolved auth context.
 *
 * The shape is intentionally compatible with the existing admin-plugin
 * `extractUserId` helper, which checks `'fortressUserId' in request`.
 */
export interface PluginRequestContext {
  request: Request;
  fortressUserId?: number;
  fortressClaims?: TokenClaims;
}

/**
 * Run all plugin middleware for the given phase against a request path.
 *
 * The path is extracted from `ctx.request.url.pathname` so plugins can
 * filter by path pattern. Errors thrown by plugin handlers propagate to the
 * caller.
 */
export async function runPluginMiddleware(
  plugins: readonly FortressPlugin[],
  config: FortressConfig,
  phase: MiddlewareDefinition['position'],
  ctx: PluginRequestContext,
): Promise<void> {
  if (plugins.length === 0)
    return;

  const pluginCtx: PluginContext = { db: config.database, config };
  const path = new URL(ctx.request.url).pathname;
  await executePluginMiddleware(plugins, phase, path, pluginCtx, ctx);
}
