/**
 * Express adapter for fortress.
 *
 * Provides {@link createExpressMiddleware}, RBAC and plugin middleware,
 * route mounting helpers, and validation middleware for Express apps.
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { createExpressMiddleware, mountFortressRoutes } from '@bajustone/fortress/express';
 *
 * const app = express();
 * app.use(createExpressMiddleware(fortress));
 * mountFortressRoutes(app, fortress);
 * ```
 *
 * @module
 */

export { convertRoutes } from '../hono/convert-routes';
export type { ConvertRoutesOptions, ExternalRoute, ToJSONSchemaConverter } from '../hono/convert-routes';
export { mountFortress } from './handle';
export type { MountFortressOptions } from './handle';
export {
  createAuthMiddleware,
  createErrorHandler,
  createExpressMiddleware,
  createExpressPluginMiddleware,
  createRbacMiddleware,
  getClaims,
  getDb,
  getScopedDb,
  getUserId,
} from './middleware';
export type {
  ExpressAdapterOptions,
  ExpressMiddleware,
  ExpressNextFunction,
  ExpressRequest,
  ExpressResponse,
  RbacOptions,
  RouteMapping,
} from './middleware';
/** @deprecated Prefer {@link mountFortress}, which delegates to `fortress.handleRequest` and handles plugin routes for free. */
export { mountFortressRoutes, mountPluginRoutes } from './routes';
/** @deprecated Validation now happens inside `fortress.handleRequest`. Use {@link mountFortress} instead. */
export { createValidationMiddleware } from './validation-middleware';
