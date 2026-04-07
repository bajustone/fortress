import type { Fortress } from '../core/fortress';
import type { RbacOptions } from './middleware/rbac';
import { createAuthMiddleware } from './middleware/auth';
import { createErrorHandler } from './middleware/error-handler';
import { createRbacMiddleware } from './middleware/rbac';

export { getClaims, getDb, getScopedDb, getUserId } from './helpers';
export type { FortressEnv } from './middleware/auth';
export { createCsrfMiddleware } from './middleware/csrf';
export type { CsrfConfig } from './middleware/csrf';
export type { RbacOptions, RouteMapping } from './middleware/rbac';
export { createSecurityHeadersMiddleware } from './middleware/security-headers';
export type { SecurityHeadersConfig } from './middleware/security-headers';
export { buildRouteDefinition, getFortressRoutes, mountFortressOpenAPI } from './openapi';
export type { SchemaConverter } from './openapi';
export { mountPluginRoutes } from './plugin-routes';

export interface HonoAdapterOptions extends RbacOptions {}

/**
 * Create Hono middleware from a Fortress instance.
 *
 * Usage:
 *   const { authMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, {
 *     routeMap: { 'POST /api/users': { resource: 'user', action: 'create' } },
 *     skipPaths: ['/health', '/auth/*'],
 *   });
 *
 *   app.onError(errorHandler);
 *   app.use('/api/*', authMiddleware);
 *   app.use('/api/*', rbacMiddleware);
 */
export function createHonoMiddleware(fortress: Fortress, options?: HonoAdapterOptions): {
  authMiddleware: ReturnType<typeof createAuthMiddleware>;
  rbacMiddleware: ReturnType<typeof createRbacMiddleware>;
  errorHandler: ReturnType<typeof createErrorHandler>;
} {
  return {
    authMiddleware: createAuthMiddleware(fortress),
    rbacMiddleware: createRbacMiddleware(fortress, options),
    errorHandler: createErrorHandler(),
  };
}
