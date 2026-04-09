/**
 * Hono adapter for fortress.
 *
 * Provides the {@link createHonoMiddleware} entrypoint plus auth, RBAC, CSRF,
 * security-headers, and error-handler middleware. Mounts core auth and IAM
 * routes (and any plugin routes) on a Hono app, integrates with the OpenAPI
 * plugin, and exposes typed validation helpers for endpoint definitions.
 *
 * @example
 * ```ts
 * import { Hono } from 'hono';
 * import { createHonoMiddleware } from '@bajustone/fortress/hono';
 *
 * const app = new Hono();
 * createHonoMiddleware(app, fortress);
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
export { getClaims, getDb, getScopedDb, getUserId } from './helpers';
export type { FortressEnv } from './middleware/auth';
export { createCsrfMiddleware } from './middleware/csrf';
export type { CsrfConfig } from './middleware/csrf';
export { createPluginMiddleware } from './middleware/plugin-middleware';
export type { RbacOptions, RouteMapping } from './middleware/rbac';
export { createSecurityHeadersMiddleware } from './middleware/security-headers';
export type { SecurityHeadersConfig } from './middleware/security-headers';
export { buildRouteDefinition, getFortressRoutes, mountFortressOpenAPI } from './openapi';
export type { SchemaConverter } from './openapi';
export { mountPluginRoutes } from './plugin-routes';
export { vBody, vParam, vQuery } from './validated';
export type { InferOutput } from './validated';
export { createValidationMiddleware } from './validation-middleware';
export type { ValidationMiddlewareOptions } from './validation-middleware';

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
