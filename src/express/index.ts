/**
 * Express adapter for fortress.
 *
 * Provides {@link mountFortress}, the modern entry point that delegates to
 * `fortress.handleRequest`, plus the lower-level middleware factories
 * (`createAuthMiddleware`, `createRbacMiddleware`, `createErrorHandler`,
 * `createExpressPluginMiddleware`) for user-owned routes.
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { createExpressMiddleware, mountFortress } from '@bajustone/fortress/express';
 *
 * const app = express();
 * app.use(express.json());
 *
 * // One-line mount: handles all Fortress routes (auth, IAM, plugins, OAuth, OpenAPI).
 * mountFortress(app, fortress);
 *
 * // Optional: protect your own routes with the IAM middleware.
 * const { authMiddleware, rbacMiddleware, errorHandler } = createExpressMiddleware(fortress, {
 *   routeMap: { 'GET /api/users': { resource: 'user', action: 'list' } },
 * });
 * app.use('/api', authMiddleware, rbacMiddleware);
 * app.use(errorHandler);
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
  getSubject,
  getUserId,
} from './middleware';
export type {
  ExpressAdapterOptions,
  ExpressMiddleware,
  ExpressNextFunction,
  ExpressRequest,
  ExpressResponse,
  FortressExpressFields,
  RbacOptions,
  RouteMapping,
} from './middleware';
export { protectedRoute } from './protect';
export type { ExpressProtectedRouteHandler, ProtectedRouteContext, ProtectedRouteTarget, ProtectOptions } from './protect';
export { vBody, vParam, vQuery } from './validated';
export type { ExpressRequestLike, InferOutput } from './validated';
