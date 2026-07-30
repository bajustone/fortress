import type { DatabaseAdapter } from '../adapters/database';
import type { FortressAuthRuntime, FortressObservabilityRuntime, FortressPluginRuntime } from '../core/capabilities';
import type { PluginRequestContext } from '../core/http/plugin-middleware';
import type { MiddlewareDefinition, PluginContext } from '../core/plugin';
import type { Subject, TokenClaims } from '../core/types';
import { FortressError } from '../core/errors';
import {
  chainAdapterWrappers,
  collectScopeRules,
  executePluginMiddleware,
  wrapAdapterWithScopeRules,
} from '../core/plugin-runner';

// Minimal Express-compatible types so users bring their own express version

/**
 * Fortress-specific fields attached to the Express `Request` by
 * {@link createAuthMiddleware}. Exported so host apps can declaration-merge
 * them into express's native `Request` type for typed access without casts.
 *
 * @example
 * ```ts
 * // src/types/express.d.ts
 * import type { FortressExpressFields } from '@bajustone/fortress/express';
 *
 * declare module 'express-serve-static-core' {
 *   interface Request extends FortressExpressFields {}
 * }
 * ```
 */
export interface FortressExpressFields {
  /**
   * The resolved principal — set for every authenticated request regardless
   * of credential type (JWT, api-key, future OAuth client_credentials, mTLS).
   */
  fortressSubject?: Subject;
  /**
   * Convenience alias — populated **only** when the subject is a `USER`.
   * Non-USER subjects (e.g. `SERVICE_ACCOUNT` via api-key) leave this
   * undefined; fall back to {@link fortressSubject}.
   */
  fortressUserId?: string;
  fortressClaims?: TokenClaims;
  fortressScopes?: string[] | null;
  fortressDb?: DatabaseAdapter;
  fortressGetScopedDb?: (model: string) => Promise<DatabaseAdapter>;
}

/** Minimal Express request shape fortress reads from. Compatible with any modern Express version. */
export interface ExpressRequest extends FortressExpressFields {
  headers: Record<string, string | string[] | undefined>;
  method: string;
  /** Express's route path without the query string. */
  path: string;
  /** Original path including query string, when supplied by Express. */
  originalUrl?: string;
  /** Node/Express request URL fallback, usually including the query string. */
  url?: string;
  /** Resolved request protocol (`http`/`https`) when supplied by Express. */
  protocol?: string;
  /** Parsed request body, if body middleware ran before this slot. */
  body?: unknown;
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
  /**
   * Behavior when a non-skipped route matches no `routeMap`/`mapRequest`
   * entry. `'allow'` (default) treats it as public; `'deny'` fails closed
   * with a 403 so a forgotten mapping can't silently expose a user route.
   * List genuinely public routes in {@link RbacOptions.skipPaths} when using
   * `'deny'`.
   */
  unmappedRoutes?: 'allow' | 'deny';
}

// --- Auth middleware ---

/**
 * Build the Express auth middleware. Resolves the request principal via
 * `fortress.resolvePrincipal`, which tries plugin `resolvePrincipal` hooks
 * (api-key, future OAuth client_credentials, mTLS) first and then falls
 * back to the JWT bearer token (cookie-first, `Authorization: Bearer`
 * second). Populates `fortressSubject`, `fortressUserId` (USER alias),
 * `fortressClaims`, `fortressDb`, and `fortressGetScopedDb` on the request.
 */
export function createAuthMiddleware(fortress: Pick<FortressAuthRuntime, 'resolvePrincipal' | 'config'>): ExpressMiddleware {
  return async (req, _res, next) => {
    try {
      // Adapt the Express request into a minimal web Request so
      // fortress.resolvePrincipal can read headers / cookies uniformly.
      const headerJar = new Headers();
      for (const [k, v] of Object.entries(req.headers)) {
        if (Array.isArray(v)) {
          for (const item of v) headerJar.append(k, item);
        }
        else if (typeof v === 'string') {
          headerJar.set(k, v);
        }
      }
      const requestPath = expressRequestPath(req);
      const host = expressHeader(req, 'host') ?? 'localhost';
      const protocol = req.protocol ?? expressHeader(req, 'x-forwarded-proto') ?? 'http';
      const probe = new Request(`${protocol}://${host}${requestPath}`, {
        method: req.method,
        headers: headerJar,
      });

      const resolved = await fortress.resolvePrincipal(probe);
      if (!resolved) {
        throw new FortressError('UNAUTHORIZED', 'Missing or invalid credentials', 401);
      }

      const { subject, claims, scopes } = resolved;
      req.fortressSubject = subject;
      if (subject.type === 'USER')
        req.fortressUserId = subject.id;
      if (claims)
        req.fortressClaims = claims;
      if (scopes !== undefined)
        req.fortressScopes = scopes;

      const plugins = fortress.config.plugins ?? [];
      // Tenant comes from the verified JWT claim, never a client header.
      const requestContext: Record<string, unknown> = {
        tenantId: claims?.customClaims?.tenantId,
        ipAddress: req.headers['x-forwarded-for'] ?? req.headers['x-real-ip'],
        userAgent: req.headers['user-agent'],
      };

      const wrappedAdapter = chainAdapterWrappers(plugins, fortress.config.database, requestContext);
      req.fortressDb = wrappedAdapter;

      const pluginCtx: PluginContext = { db: wrappedAdapter, config: fortress.config };
      req.fortressGetScopedDb = async (model: string): Promise<DatabaseAdapter> => {
        const scopeRule = await collectScopeRules(plugins, subject.id, model, pluginCtx);
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

// --- CSRF middleware (user routes only) ---

/** Options accepted by {@link createCsrfMiddleware}. */
export interface CsrfConfig {
  /** Header name required on unsafe methods. Default: `X-Fortress-CSRF`. */
  headerName?: string;
  /** Paths/subtrees exempt from CSRF checking. A trailing `/*` is accepted. */
  skipPaths?: string[];
  /** Methods exempt from CSRF checking. Default: GET, HEAD, OPTIONS. */
  safeMethods?: string[];
}

/**
 * Build standalone Express CSRF middleware for host-owned routes. Fortress-
 * managed routes already enforce cookie-aware CSRF inside `handleRequest`.
 * This middleware uses the custom-header strategy and rejects cross-site
 * browser requests on unsafe methods.
 */
export function createCsrfMiddleware(config?: CsrfConfig): ExpressMiddleware {
  const headerName = (config?.headerName ?? 'X-Fortress-CSRF').toLowerCase();
  const skipPaths = config?.skipPaths ?? [];
  const safeMethods = new Set((config?.safeMethods ?? ['GET', 'HEAD', 'OPTIONS']).map(method => method.toUpperCase()));

  return (req, _res, next) => {
    try {
      if (safeMethods.has(req.method.toUpperCase()) || matchesCsrfSkipPath(req.path, skipPaths)) {
        next();
        return;
      }

      const fetchSite = expressHeader(req, 'sec-fetch-site');
      if (fetchSite === 'cross-site')
        throw new FortressError('FORBIDDEN', 'CSRF: cross-site request rejected', 403);
      if (!expressHeader(req, headerName))
        throw new FortressError('FORBIDDEN', `CSRF: missing ${config?.headerName ?? 'X-Fortress-CSRF'} header`, 403);

      next();
    }
    catch (error) {
      next(error);
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
export function createRbacMiddleware(fortress: Pick<FortressAuthRuntime, 'iam'>, options?: RbacOptions): ExpressMiddleware {
  // Express's default router is case-insensitive and ignores one trailing slash.
  // Canonicalize configured paths once so exact and parameterized lookups share
  // those semantics with the request path below.
  const routeMap = normalizeRouteMap(options?.routeMap ?? {});
  const skipPaths = options?.skipPaths ?? [];
  const skipPatterns = skipPaths.map(p => pathToRegex(p));
  const unmappedRoutes = options?.unmappedRoutes ?? 'allow';

  return async (req, _res, next) => {
    try {
      // Express strips an `app.use('/mount', ...)` prefix from req.path/url.
      // Match against originalUrl so route maps use the same full path as
      // Hono/SvelteKit and as the host wrote in configuration.
      const path = normalizeExpressPath(new URL(expressRequestPath(req), 'http://localhost').pathname);
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
        if (unmappedRoutes === 'deny') {
          // Fail closed: an unmapped route under deny mode is refused rather
          // than treated as public. Authenticating won't help — the route
          // needs an explicit mapping or a skipPaths entry.
          throw new FortressError('FORBIDDEN', 'No permission mapping for this route', 403);
        }
        // No declarative mapping — caller treats this as a public route.
        next();
        return;
      }

      if (!req.fortressSubject) {
        throw new FortressError('UNAUTHORIZED', 'Not authenticated', 401);
      }

      const allowed = await fortress.iam.checkPermission(req.fortressSubject, mapping.resource, mapping.action, {
        credentialScopes: req.fortressScopes,
      });
      if (!allowed) {
        throw new FortressError('FORBIDDEN', 'Insufficient permissions', 403, {
          details: { requiredPermission: `${mapping.resource}:${mapping.action}` },
        });
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
 * `errorToResponse` via {@link FortressError.toJSON}. When a `Fortress`
 * instance is provided, unhandled errors are routed to its configured
 * {@link FortressLogger}; otherwise they're silently swallowed (matching
 * the silent-by-default posture of the library).
 */
export function createErrorHandler(fortress?: Pick<FortressObservabilityRuntime, 'logger'>): (err: unknown, req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => void {
  return (err, _req, res, _next) => {
    if (err instanceof FortressError) {
      if (err.code === 'RATE_LIMITED' && err.retryAfter) {
        res.setHeader('Retry-After', String(err.retryAfter));
      }
      res.status(err.statusCode).json(err.toJSON());
      return;
    }

    fortress?.logger.error(
      { err, message: err instanceof Error ? err.message : 'Unknown error' },
      'unhandled error in express middleware',
    );
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
  fortress: Pick<FortressPluginRuntime, 'config'>,
  position: MiddlewareDefinition['position'],
): ExpressMiddleware {
  const plugins = fortress.config.plugins ?? [];

  return async (req, _res, next) => {
    try {
      const ctx: PluginContext = { db: fortress.config.database, config: fortress.config };
      const headers = new Headers();
      for (const [name, value] of Object.entries(req.headers)) {
        if (Array.isArray(value)) {
          for (const item of value) headers.append(name, item);
        }
        else if (typeof value === 'string') {
          headers.set(name, value);
        }
      }
      const requestPath = expressRequestPath(req);
      const forwardedProtocol = req.headers['x-forwarded-proto'];
      const protocol = req.protocol
        ?? (Array.isArray(forwardedProtocol) ? forwardedProtocol[0] : forwardedProtocol)
        ?? 'http';
      const hostHeader = req.headers.host;
      const host = (Array.isArray(hostHeader) ? hostHeader[0] : hostHeader) ?? 'localhost';
      const method = req.method.toUpperCase();
      let body: BodyInit | undefined;
      if (method !== 'GET' && method !== 'HEAD' && req.body !== undefined) {
        if (typeof req.body === 'string' || req.body instanceof URLSearchParams)
          body = req.body;
        else if (req.body instanceof ArrayBuffer || ArrayBuffer.isView(req.body))
          body = req.body as BodyInit;
        else if (headers.get('content-type')?.toLowerCase().startsWith('application/x-www-form-urlencoded'))
          body = new URLSearchParams(Object.entries(req.body as Record<string, unknown>).map(([key, value]) => [key, String(value)]));
        else
          body = JSON.stringify(req.body);
      }
      const requestContext: PluginRequestContext = {
        request: new Request(`${protocol}://${host}${requestPath}`, {
          method,
          headers,
          body,
        }),
        fortressSubject: req.fortressSubject,
        fortressUserId: req.fortressUserId,
        fortressClaims: req.fortressClaims,
        fortressScopes: req.fortressScopes,
      };
      await executePluginMiddleware(
        plugins,
        position,
        new URL(requestPath, 'http://localhost').pathname,
        ctx,
        requestContext,
      );
      next();
    }
    catch (err) {
      next(err);
    }
  };
}

// --- Factory ---

/** Options for {@link createExpressMiddleware}. Extends {@link RbacOptions}. */
export interface ExpressAdapterOptions extends RbacOptions {
  /** Standalone CSRF middleware options for host-owned Express routes. */
  csrf?: CsrfConfig;
}

/**
 * Build the full set of fortress Express middleware: auth, CSRF, RBAC, error
 * handler, and the three plugin middleware slots (`beforeAuth`, `afterAuth`,
 * `afterRbac`). Mount each in the corresponding place in your Express app.
 */
export function createExpressMiddleware(
  fortress: Pick<FortressAuthRuntime, 'resolvePrincipal' | 'config' | 'iam'>
    & Pick<FortressPluginRuntime, 'config'>
    & Pick<FortressObservabilityRuntime, 'logger'>,
  options?: ExpressAdapterOptions,
): {
  authMiddleware: ExpressMiddleware;
  csrfMiddleware: ExpressMiddleware;
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
    csrfMiddleware: createCsrfMiddleware(options?.csrf),
    rbacMiddleware: createRbacMiddleware(fortress, options),
    errorHandler: createErrorHandler(fortress),
    pluginMiddleware: {
      beforeAuth: createExpressPluginMiddleware(fortress, 'before-auth'),
      afterAuth: createExpressPluginMiddleware(fortress, 'after-auth'),
      afterRbac: createExpressPluginMiddleware(fortress, 'after-rbac'),
    },
  };
}

// --- Helpers ---

/**
 * Read the resolved request principal. Works for every subject kind
 * (`USER`, `SERVICE_ACCOUNT`, ...). Throws 401 if the auth middleware did
 * not run or no credential was present.
 */
export function getSubject(req: ExpressRequest): Subject {
  if (!req.fortressSubject) {
    throw new FortressError('UNAUTHORIZED', 'Not authenticated', 401);
  }
  return req.fortressSubject;
}

/**
 * Read the authenticated user ID. Throws 401 if the request was
 * authenticated by a non-USER subject (e.g. a service account via
 * api-key) — use {@link getSubject} for handlers that accept any
 * principal.
 */
export function getUserId(req: ExpressRequest): string {
  if (!req.fortressSubject || req.fortressSubject.type !== 'USER') {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return req.fortressSubject.id;
}

/**
 * Read the verified JWT claims. Only populated when the request was
 * authenticated via a JWT — api-key principals have no JWT claims and
 * this helper throws 401.
 */
export function getClaims(req: ExpressRequest): TokenClaims {
  if (!req.fortressClaims) {
    throw new FortressError('UNAUTHORIZED', 'No JWT claims on this request', 401);
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

function parseRouteMapPattern(pattern: string): { method: string; path: string } {
  const parts = pattern.split(' ');
  const [method, path] = parts;
  if (parts.length !== 2 || method === undefined || path === undefined || method === '' || !path.startsWith('/')) {
    throw new Error(`Invalid route map pattern '${pattern}': expected 'METHOD /path'`);
  }
  return { method, path };
}

function findRouteMapMatch(method: string, path: string, routeMap: Record<string, RouteMapping>): RouteMapping | null {
  for (const [pattern, mapping] of Object.entries(routeMap)) {
    const configured = parseRouteMapPattern(pattern);
    if (configured.method !== method)
      continue;
    if (pathToRegex(configured.path).test(path))
      return mapping;
  }
  return null;
}

function expressRequestPath(req: ExpressRequest): string {
  const path = req.originalUrl ?? req.url ?? req.path;
  return path.startsWith('/') ? path : `/${path}`;
}

function expressHeader(req: ExpressRequest, name: string): string | undefined {
  const target = name.toLowerCase();
  for (const [headerName, value] of Object.entries(req.headers)) {
    if (headerName.toLowerCase() !== target)
      continue;
    return Array.isArray(value) ? value[0] : value;
  }
  return undefined;
}

function matchesCsrfSkipPath(path: string, skipPaths: string[]): boolean {
  return skipPaths.some((configured) => {
    const withoutWildcard = configured.endsWith('/*') ? configured.slice(0, -2) : configured;
    const base = withoutWildcard.length > 1 && withoutWildcard.endsWith('/')
      ? withoutWildcard.slice(0, -1)
      : withoutWildcard;
    return path === base || path.startsWith(`${base}/`);
  });
}

function normalizeRouteMap(routeMap: Record<string, RouteMapping>): Record<string, RouteMapping> {
  return Object.fromEntries(Object.entries(routeMap).map(([pattern, mapping]) => {
    const configured = parseRouteMapPattern(pattern);
    return [`${configured.method} ${normalizeExpressPath(configured.path)}`, mapping];
  }));
}

function normalizeExpressPath(path: string): string {
  const lowerCased = path.toLowerCase();
  return lowerCased.length > 1 && lowerCased.endsWith('/')
    ? lowerCased.slice(0, -1)
    : lowerCased;
}

function pathToRegex(pattern: string): RegExp {
  // Escape literals first, then add back only the route syntax Fortress
  // supports. This prevents dots (and other regex metacharacters) in a
  // configured path from matching unintended requests.
  const regexStr = normalizeExpressPath(pattern)
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/:[^/]+/g, '[^/]+')
    .replace(/\\\*/g, '.*')
    .replace(/\//g, '\\/');
  return new RegExp(`^${regexStr}$`, 'i');
}
