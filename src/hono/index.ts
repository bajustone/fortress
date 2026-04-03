// TODO: Implement createHonoMiddleware(fortress, options?)
// - authMiddleware: Bearer token extraction + JWT verify
// - rbacMiddleware: resource+action permission check via routeMap
// - errorHandler: FortressError → HTTP response (with Retry-After for 429)
// - mountPlugins(app): auto-discover and mount plugin routes/middleware
//
// Usage:
//   import { createHonoMiddleware } from '@bajustone/fortress/hono';
//   const { authMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, { routeMap: { ... } });

export {};
