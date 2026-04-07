import type { DatabaseAdapter } from '../adapters/database';
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
export interface ExpressRequest {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  path: string;
  fortressUserId?: number;
  fortressClaims?: TokenClaims;
  fortressDb?: DatabaseAdapter;
  fortressGetScopedDb?: (model: string) => Promise<DatabaseAdapter>;
}

export interface ExpressResponse {
  status: (code: number) => ExpressResponse;
  json: (body: unknown) => void;
  setHeader: (name: string, value: string) => void;
}

export type ExpressNextFunction = (err?: unknown) => void;
export type ExpressMiddleware = (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => void;

// --- Route mapping (same as Hono adapter) ---

export interface RouteMapping {
  resource: string;
  action: string;
}

export interface RbacOptions {
  routeMap?: Record<string, RouteMapping>;
  mapRequest?: (method: string, path: string) => RouteMapping | null;
  skipPaths?: string[];
  /** Disable default-deny for fortress-owned routes (not recommended) */
  allowUnmappedFortressPaths?: boolean;
}

// --- Auth middleware ---

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
const FORTRESS_AUTH_PROTECTED = ['/auth/impersonate'];

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

      // No mapping found — default deny for fortress-owned paths
      if (!mapping) {
        if (!options?.allowUnmappedFortressPaths && isFortressPath(path, pluginPathPrefixes)) {
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
 * Express middleware that executes plugin-defined middleware for a given position.
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

export interface ExpressAdapterOptions extends RbacOptions {}

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

export function getUserId(req: ExpressRequest): number {
  if (!req.fortressUserId) {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return req.fortressUserId;
}

export function getClaims(req: ExpressRequest): TokenClaims {
  if (!req.fortressClaims) {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return req.fortressClaims;
}

export function getDb(req: ExpressRequest): DatabaseAdapter {
  if (!req.fortressDb) {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return req.fortressDb;
}

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
