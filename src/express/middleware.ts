import type { DatabaseAdapter } from '../adapters/database';
import type { EndpointDefinition } from '../core/endpoint';
import type { Fortress } from '../core/fortress';
import type { MiddlewareDefinition, PluginContext } from '../core/plugin';
import type { TokenClaims } from '../core/types';
import { FortressError } from '../core/errors';
import {
  chainAdapterWrappers,
  collectScopeRules,
  executePluginMiddleware,
  wrapAdapterWithScopeRules,
} from '../core/plugin-runner';

// Minimal Express-compatible types so users bring their own express version
/** Minimal Express request shape fortress reads from. Compatible with any modern Express version. */
export interface ExpressRequest {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  path: string;
  fortressUserId?: number;
  fortressClaims?: TokenClaims;
  fortressDb?: DatabaseAdapter;
  fortressGetScopedDb?: (model: string) => Promise<DatabaseAdapter>;
}

/** Minimal Express response shape fortress writes to. */
export interface ExpressResponse {
  status: (code: number) => ExpressResponse;
  json: (body: unknown) => void;
  setHeader: (name: string, value: string) => void;
}

/** The `next(err?)` callback Express middleware signs off with. */
export type ExpressNextFunction = (err?: unknown) => void;
/** Express middleware signature fortress's adapter exports use. */
export type ExpressMiddleware = (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => void;

// --- Route mapping (same as Hono adapter) ---

/** A `(resource, action)` IAM mapping for an HTTP route. */
export interface RouteMapping {
  resource: string;
  action: string;
}

/** Options accepted by {@link createRbacMiddleware} (and the express adapter factory). */
export interface RbacOptions {
  routeMap?: Record<string, RouteMapping>;
  mapRequest?: (method: string, path: string) => RouteMapping | null;
  skipPaths?: string[];
  /** Disable default-deny for fortress-owned routes (not recommended) */
  allowUnmappedFortressPaths?: boolean;
}

// --- Auth middleware ---

/**
 * Build the Express auth middleware. Verifies the bearer token, attaches
 * `fortressUserId` / `fortressClaims` / `fortressDb` to the request, and
 * exposes the per-request scoped database accessor.
 */
export function createAuthMiddleware(fortress: Fortress): ExpressMiddleware {
  return async (req, _res, next) => {
    try {
      const header = typeof req.headers.authorization === 'string'
        ? req.headers.authorization
        : undefined;
      const bearerPrefix = 'Bearer ';
      if (!header?.startsWith(bearerPrefix)) {
        throw new FortressError('UNAUTHORIZED', 'Missing or invalid Authorization header', 401);
      }

      const token = header.slice(bearerPrefix.length);
      const claims = await fortress.auth.verifyToken(token);

      req.fortressUserId = claims.sub;
      req.fortressClaims = claims;

      const plugins = fortress.config.plugins ?? [];
      const requestContext: Record<string, unknown> = {
        tenantCode: req.headers['x-tenant-code'],
        ipAddress: req.headers['x-forwarded-for'] ?? req.headers['x-real-ip'],
        userAgent: req.headers['user-agent'],
      };

      const wrappedAdapter = chainAdapterWrappers(plugins, fortress.config.database, requestContext);
      req.fortressDb = wrappedAdapter;

      const pluginCtx: PluginContext = { db: wrappedAdapter, config: fortress.config };
      req.fortressGetScopedDb = async (model: string): Promise<DatabaseAdapter> => {
        const scopeRule = await collectScopeRules(plugins, claims.sub, model, pluginCtx);
        if (!scopeRule)
          return wrappedAdapter;
        return wrapAdapterWithScopeRules(wrappedAdapter, scopeRule);
      };

      next();
    }
    catch (err) {
      next(err);
    }
  };
}

// --- RBAC middleware ---

/** Known fortress core path prefixes that are always protected */
const FORTRESS_CORE_PREFIXES = ['/iam/'];

/** Sensitive auth endpoints that require admin protection */
const FORTRESS_AUTH_PROTECTED = ['/auth/impersonate', '/auth/users'];

/**
 * Check if a path belongs to a fortress-owned route (core or plugin).
 * Fortress-owned routes are denied by default when no permission mapping exists.
 */
function isFortressPath(path: string, pluginPathPrefixes: string[]): boolean {
  if (FORTRESS_CORE_PREFIXES.some(prefix => path.startsWith(prefix)))
    return true;
  if (FORTRESS_AUTH_PROTECTED.some(p => path === p || path.startsWith(`${p}/`)))
    return true;
  if (pluginPathPrefixes.some(prefix => path.startsWith(prefix)))
    return true;
  return false;
}

/** Extracts first path segment: '/oauth/token' → '/oauth/' */
const PLUGIN_PREFIX_REGEX = /^(\/[^/]+\/)/;

/**
 * Extract unique path prefixes from plugin routes.
 */
function getPluginPathPrefixes(fortress: Fortress): string[] {
  const plugins = fortress.config.plugins ?? [];
  const prefixes = new Set<string>();
  for (const plugin of plugins) {
    if (!plugin.routes)
      continue;
    for (const route of plugin.routes) {
      const match = route.path.match(PLUGIN_PREFIX_REGEX);
      if (match)
        prefixes.add(match[1]);
    }
  }
  return [...prefixes];
}

/**
 * Build the Express RBAC middleware. Resolves a `(resource, action)` mapping
 * for the request, applies fortress's default-deny policy to fortress-owned
 * routes, and enforces the IAM permission check.
 */
export function createRbacMiddleware(fortress: Fortress, options?: RbacOptions): ExpressMiddleware {
  const routeMap = options?.routeMap ?? {};
  const skipPaths = options?.skipPaths ?? [];
  const skipPatterns = skipPaths.map(p => pathToRegex(p));
  const pluginPathPrefixes = getPluginPathPrefixes(fortress);

  return async (req, _res, next) => {
    try {
      const path = req.path;
      const method = req.method;

      if (skipPatterns.some(pattern => pattern.test(path))) {
        next();
        return;
      }

      const key = `${method} ${path}`;
      let mapping: RouteMapping | null = routeMap[key] ?? null;

      if (!mapping) {
        mapping = findRouteMapMatch(method, path, routeMap);
      }

      if (!mapping && options?.mapRequest) {
        mapping = options.mapRequest(method, path);
      }

      // No mapping found — smart default deny for fortress-owned paths
      if (!mapping) {
        if (!options?.allowUnmappedFortressPaths && isFortressPath(path, pluginPathPrefixes)) {
          const ep = findEndpoint(fortress.endpoints, method, path);

          // Public or self-authenticated routes pass through
          if (ep?.meta?.security?.includes('none') || ep?.meta?.security?.includes('basic')) {
            next();
            return;
          }

          // Routes with declared permissions — enforce via IAM
          if (ep?.meta?.permission) {
            if (!req.fortressUserId) {
              throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
            }
            const allowed = await fortress.iam.checkPermission(req.fortressUserId, ep.meta.permission.resource, ep.meta.permission.action);
            if (!allowed) {
              throw new FortressError('FORBIDDEN', 'Insufficient permissions', 403);
            }
            next();
            return;
          }

          // Bearer-only routes without permission — require auth but no IAM check
          if (ep?.meta?.security?.includes('bearer')) {
            if (!req.fortressUserId) {
              throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
            }
            next();
            return;
          }

          // Unknown / no security metadata — deny
          throw new FortressError('FORBIDDEN', 'No permission mapping for this route', 403);
        }
        next();
        return;
      }

      if (!req.fortressUserId) {
        throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
      }

      const allowed = await fortress.iam.checkPermission(req.fortressUserId, mapping.resource, mapping.action);
      if (!allowed) {
        throw new FortressError('FORBIDDEN', 'Insufficient permissions', 403);
      }

      next();
    }
    catch (err) {
      next(err);
    }
  };
}

// --- Error handler ---

/**
 * Build the Express error handler. Translates {@link FortressError} into the
 * appropriate HTTP response with `Retry-After` for rate-limited responses,
 * and returns a generic 500 for everything else.
 *
 * Stays synchronous so it composes naturally with Express's `(err, req,
 * res, next)` signature. Shares the response *shape* with core's
 * `errorToResponse` via {@link FortressError.toJSON}.
 */
export function createErrorHandler(): (err: unknown, req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => void {
  return (err, _req, res, _next) => {
    if (err instanceof FortressError) {
      if (err.code === 'RATE_LIMITED' && err.retryAfter) {
        res.setHeader('Retry-After', String(err.retryAfter));
      }
      res.status(err.statusCode).json(err.toJSON());
      return;
    }

    console.error('Unhandled error:', err instanceof Error ? err.message : 'Unknown error');
    res.status(500).json({ code: 'INTERNAL_ERROR', message: 'Internal server error', statusCode: 500 });
  };
}

// --- Plugin middleware ---

/**
 * Express middleware that executes plugin-defined middleware for a given
 * position (`before-auth`, `after-auth`, `after-rbac`). Used internally by
 * {@link createExpressMiddleware}; expose if you want to mount the plugin
 * middleware slots manually.
 */
export function createExpressPluginMiddleware(
  fortress: Fortress,
  position: MiddlewareDefinition['position'],
): ExpressMiddleware {
  const plugins = fortress.config.plugins ?? [];

  return async (req, _res, next) => {
    try {
      const ctx: PluginContext = { db: fortress.config.database, config: fortress.config };
      await executePluginMiddleware(plugins, position, req.path, ctx, req);
      next();
    }
    catch (err) {
      next(err);
    }
  };
}

// --- Factory ---

/** Options for {@link createExpressMiddleware}. Extends {@link RbacOptions}. */
export interface ExpressAdapterOptions extends RbacOptions {}

/**
 * Build the full set of fortress Express middleware: auth, RBAC, error
 * handler, and the three plugin middleware slots (`beforeAuth`, `afterAuth`,
 * `afterRbac`). Mount each in the corresponding place in your Express app.
 */
export function createExpressMiddleware(fortress: Fortress, options?: ExpressAdapterOptions): {
  authMiddleware: ExpressMiddleware;
  rbacMiddleware: ExpressMiddleware;
  errorHandler: ReturnType<typeof createErrorHandler>;
  pluginMiddleware: {
    beforeAuth: ExpressMiddleware;
    afterAuth: ExpressMiddleware;
    afterRbac: ExpressMiddleware;
  };
} {
  return {
    authMiddleware: createAuthMiddleware(fortress),
    rbacMiddleware: createRbacMiddleware(fortress, options),
    errorHandler: createErrorHandler(),
    pluginMiddleware: {
      beforeAuth: createExpressPluginMiddleware(fortress, 'before-auth'),
      afterAuth: createExpressPluginMiddleware(fortress, 'after-auth'),
      afterRbac: createExpressPluginMiddleware(fortress, 'after-rbac'),
    },
  };
}

// --- Helpers ---

/** Read the authenticated user ID from an Express request. Throws if the auth middleware did not run or rejected the token. */
export function getUserId(req: ExpressRequest): number {
  if (!req.fortressUserId) {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return req.fortressUserId;
}

/** Read the verified JWT claims from an Express request. */
export function getClaims(req: ExpressRequest): TokenClaims {
  if (!req.fortressClaims) {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return req.fortressClaims;
}

/** Read the per-request fortress database adapter (with plugin wrappers applied). */
export function getDb(req: ExpressRequest): DatabaseAdapter {
  if (!req.fortressDb) {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return req.fortressDb;
}

/** Read the per-request fortress database adapter scoped to a specific model (applies any active row-level scope rules). */
export function getScopedDb(req: ExpressRequest, model: string): Promise<DatabaseAdapter> {
  if (!req.fortressGetScopedDb) {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return req.fortressGetScopedDb(model);
}

// --- Internal route matching (shared with Hono) ---

function findRouteMapMatch(method: string, path: string, routeMap: Record<string, RouteMapping>): RouteMapping | null {
  for (const [pattern, mapping] of Object.entries(routeMap)) {
    const [patternMethod, patternPath] = pattern.split(' ', 2);
    if (patternMethod !== method)
      continue;
    if (pathToRegex(patternPath).test(path))
      return mapping;
  }
  return null;
}

function pathToRegex(pattern: string): RegExp {
  const regexStr = pattern
    .replace(/:[^/]+/g, '[^/]+')
    .replace(/\*/g, '.*')
    .replace(/\//g, '\\/');
  return new RegExp(`^${regexStr}$`);
}

/**
 * Find an endpoint definition matching the given method and path.
 */
function findEndpoint(endpoints: EndpointDefinition[], method: string, path: string): EndpointDefinition | undefined {
  return endpoints.find((ep) => {
    if (ep.method !== method)
      return false;
    if (ep.path === path)
      return true;
    return pathToRegex(ep.path).test(path);
  });
}
