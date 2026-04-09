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

// --- Route mapping ---

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
}

// --- Auth middleware ---

/**
 * Build the Express auth middleware. Extracts the access token via
 * `fortress.extractAccessToken` (cookie-first, `Authorization: Bearer`
 * fallback), verifies it, and attaches `fortressUserId` / `fortressClaims`
 * / `fortressDb` / `fortressGetScopedDb` to the request for downstream
 * user-route handlers.
 */
export function createAuthMiddleware(fortress: Fortress): ExpressMiddleware {
  return async (req, _res, next) => {
    try {
      // Adapter the Express request into a minimal web Request just for
      // header reading — fortress.extractAccessToken takes a real Request.
      const headerJar = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (Array.isArray(v)) {
          for (const item of v) headerJar.append(k, item);
        }
        else if (typeof v === 'string') {
          headerJar.set(k, v);
        }
      }
      const probe = new Request('http://localhost/', { headers: headerJar });
      const token = fortress.extractAccessToken(probe);
      if (!token) {
        throw new FortressError('UNAUTHORIZED', 'Missing or invalid access token', 401);
      }

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

// --- RBAC middleware (user routes only) ---

/**
 * Build the Express RBAC middleware for **user-owned routes**. Resolves a
 * `(resource, action)` mapping via `routeMap` / `mapRequest` and enforces
 * the IAM permission check. Fortress-managed routes (`/auth/*`, `/iam/*`,
 * plugin paths) are protected automatically inside `fortress.handleRequest`
 * — this middleware only handles routes the caller registered themselves.
 */
export function createRbacMiddleware(fortress: Fortress, options?: RbacOptions): ExpressMiddleware {
  const routeMap = options?.routeMap ?? {};
  const skipPaths = options?.skipPaths ?? [];
  const skipPatterns = skipPaths.map(p => pathToRegex(p));

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

      if (!mapping) {
        // No declarative mapping — caller treats this as a public route.
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

// --- Internal route matching ---

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
