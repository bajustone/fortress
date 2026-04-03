import type { Fortress } from '../core/fortress';
import type { RbacOptions } from './middleware/rbac';
import { createAuthMiddleware } from './middleware/auth';
import { createErrorHandler } from './middleware/error-handler';
import { createRbacMiddleware } from './middleware/rbac';

export { getClaims, getUserId } from './helpers';
export type { FortressEnv } from './middleware/auth';
export type { RbacOptions, RouteMapping } from './middleware/rbac';

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
