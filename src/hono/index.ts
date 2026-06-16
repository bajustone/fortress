/**
 * Hono adapter for fortress.
 *
 * Provides {@link mountFortress}, the modern entry point that delegates to
 * `fortress.handleRequest`, plus the lower-level middleware factories
 * (`createHonoMiddleware`, `createAuthMiddleware`, `createRbacMiddleware`,
 * `createCsrfMiddleware`, `createSecurityHeadersMiddleware`, etc.) for
 * user-owned routes. Also exports `vBody` / `vParam` / `vQuery` typed
 * extraction helpers for custom routes.
 *
 * @example
 * ```ts
 * import { Hono } from 'hono';
 * import { mountFortress, createHonoMiddleware } from '@bajustone/fortress/hono';
 *
 * const app = new Hono();
 *
 * // One-line mount: handles all Fortress routes (auth, IAM, plugins, OAuth, OpenAPI).
 * mountFortress(app, fortress);
 *
 * // Optional: protect your own routes with the IAM middleware.
 * const { authMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, {
 *   routeMap: { 'GET /api/users': { resource: 'user', action: 'list' } },
 * });
 * app.use('/api/*', authMiddleware, rbacMiddleware);
 * app.onError(errorHandler);
 * ```
 *
 * @module
 */

import type { Fortress } from '../core/fortress';
import type { RbacOptions } from './middleware/rbac';
import { createAuthMiddleware } from './middleware/auth';
import { createErrorHandler } from './middleware/error-handler';
import { createPluginMiddleware } from './middleware/plugin-middleware';
import { createRbacMiddleware } from './middleware/rbac';

export { convertRoutes } from './convert-routes';
export type { ConvertRoutesOptions, ExternalRoute, ToJSONSchemaConverter } from './convert-routes';
export { fetcherSchemaConverter, identitySchemaConverter, toJSONSchemaConverter } from './converters';
export { mountFortress } from './handle';
export type { MountFortressOptions } from './handle';
export { getClaims, getDb, getScopedDb, getSubject, getUserId } from './helpers';
export type { FortressContext, FortressEnv, FortressVariables } from './middleware/auth';
export { createCsrfMiddleware } from './middleware/csrf';
export type { CsrfConfig } from './middleware/csrf';
export { createPluginMiddleware } from './middleware/plugin-middleware';
export type { RbacOptions, RouteMapping } from './middleware/rbac';
export { createSecurityHeadersMiddleware } from './middleware/security-headers';
export type { SecurityHeadersConfig } from './middleware/security-headers';
export { buildRouteDefinition, getFortressRoutes, mountFortressOpenAPI } from './openapi';
export type { SchemaConverter } from './openapi';
export { protectedRoute } from './protect';
export type { HonoProtectedRouteHandler, ProtectedRouteContext, ProtectedRouteHandler, ProtectedRouteTarget, ProtectOptions } from './protect';
export { vBody, vParam, vQuery } from './validated';
export type { InferOutput } from './validated';

/**
 * Options for {@link createHonoMiddleware}. Currently extends {@link RbacOptions}
 * so callers can override which IAM resource/action a route maps to.
 */
export interface HonoAdapterOptions extends RbacOptions {}

/**
 * Create Hono middleware from a Fortress instance.
 *
 * Usage:
 *   const { authMiddleware, pluginMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, {
 *     routeMap: { 'POST /api/users': { resource: 'user', action: 'create' } },
 *     skipPaths: ['/health', '/auth/*'],
 *   });
 *
 *   app.onError(errorHandler);
 *   app.use('/api/*', pluginMiddleware.beforeAuth);
 *   app.use('/api/*', authMiddleware);
 *   app.use('/api/*', pluginMiddleware.afterAuth);
 *   app.use('/api/*', rbacMiddleware);
 *   app.use('/api/*', pluginMiddleware.afterRbac);
 */
export function createHonoMiddleware(fortress: Fortress, options?: HonoAdapterOptions): {
  authMiddleware: ReturnType<typeof createAuthMiddleware>;
  rbacMiddleware: ReturnType<typeof createRbacMiddleware>;
  errorHandler: ReturnType<typeof createErrorHandler>;
  pluginMiddleware: {
    beforeAuth: ReturnType<typeof createPluginMiddleware>;
    afterAuth: ReturnType<typeof createPluginMiddleware>;
    afterRbac: ReturnType<typeof createPluginMiddleware>;
  };
} {
  return {
    authMiddleware: createAuthMiddleware(fortress),
    rbacMiddleware: createRbacMiddleware(fortress, options),
    errorHandler: createErrorHandler(),
    pluginMiddleware: {
      beforeAuth: createPluginMiddleware(fortress, 'before-auth'),
      afterAuth: createPluginMiddleware(fortress, 'after-auth'),
      afterRbac: createPluginMiddleware(fortress, 'after-rbac'),
    },
  };
}
