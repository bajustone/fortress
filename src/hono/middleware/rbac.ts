import type { MiddlewareHandler } from 'hono';
import type { FortressAuthRuntime } from '../../core/capabilities';
import type { FortressEnv } from './auth';
import { FortressError } from '../../core/errors';

/** A `(resource, action)` IAM mapping for an HTTP route. */
export interface RouteMapping {
  resource: string;
  action: string;
}

/** Options accepted by {@link createRbacMiddleware} (and the Hono adapter factory). */
export interface RbacOptions {
  /** Declarative route-to-resource mapping: 'METHOD /path' → { resource, action } */
  routeMap?: Record<string, RouteMapping>;
  /** Dynamic mapping function (used if routeMap doesn't match) */
  mapRequest?: (method: string, path: string) => RouteMapping | null;
  /** Paths that skip permission checks entirely (supports * wildcards) */
  skipPaths?: string[];
  /** Behavior for non-skipped routes absent from routeMap/mapRequest. */
  unmappedRoutes?: 'allow' | 'deny';
  /** @deprecated Use `unmappedRoutes: 'deny'`. */
  defaultDeny?: boolean;
}

/**
 * Hono middleware that checks IAM permissions for **user-owned routes**
 * via a declarative route map. Fortress-managed routes (`/auth/*`,
 * `/iam/*`, plugin paths) are protected automatically inside
 * `fortress.handleRequest` — this middleware only handles routes the
 * caller registered themselves.
 *
 * Lookup order:
 * 1. {@link RbacOptions.skipPaths} — if matched, allow.
 * 2. {@link RbacOptions.routeMap} — exact `'METHOD /path'` then
 *    parameterized match.
 * 3. {@link RbacOptions.mapRequest} — dynamic resolver fallback.
 * 4. No mapping found → follow {@link RbacOptions.unmappedRoutes}; `'deny'`
 *    refuses the route with a 403 (fail closed).
 *
 * Throws {@link FortressError} on missing/insufficient permissions.
 */
export function createRbacMiddleware(
  fortress: Pick<FortressAuthRuntime, 'iam'>,
  options?: RbacOptions,
): MiddlewareHandler<FortressEnv> {
  const routeMap = options?.routeMap ?? {};
  validateRouteMap(routeMap);
  const skipPaths = options?.skipPaths ?? [];
  const skipPatterns = skipPaths.map(p => pathToRegex(p));
  const unmappedRoutes = options?.unmappedRoutes
    ?? (options?.defaultDeny ? 'deny' : 'allow');

  return async (c, next) => {
    const path = c.req.path;
    const method = c.req.method;

    if (skipPatterns.some(pattern => pattern.test(path))) {
      await next();
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
        // Fail closed: an unmapped route is refused rather than treated as
        // public. Genuinely public routes belong in skipPaths.
        throw new FortressError('FORBIDDEN', 'No permission mapping for this route', 403);
      }
      // No declarative mapping — caller treats this as a public route from
      // the adapter's perspective. (Fortress-managed paths have already
      // been caught and protected inside fortress.handleRequest.)
      await next();
      return;
    }

    const subject = c.get('fortressSubject');
    if (!subject) {
      throw new FortressError('UNAUTHORIZED', 'Not authenticated', 401);
    }

    const allowed = await fortress.iam.checkPermission(subject, mapping.resource, mapping.action, {
      credentialScopes: c.get('fortressScopes'),
    });
    if (!allowed) {
      throw new FortressError('FORBIDDEN', 'Insufficient permissions', 403, {
        details: { requiredPermission: `${mapping.resource}:${mapping.action}` },
      });
    }

    await next();
  };
}

/**
 * Match a request against parameterized route map entries.
 * 'GET /api/users/:id' matches 'GET /api/users/123'
 */
function parseRouteMapPattern(pattern: string): { method: string; path: string } {
  const parts = pattern.split(' ');
  const [method, path] = parts;
  if (parts.length !== 2 || method === undefined || path === undefined || method === '' || !path.startsWith('/')) {
    throw new Error(`Invalid route map pattern '${pattern}': expected 'METHOD /path'`);
  }
  return { method, path };
}

function validateRouteMap(routeMap: Record<string, RouteMapping>): void {
  for (const pattern of Object.keys(routeMap))
    parseRouteMapPattern(pattern);
}

function findRouteMapMatch(method: string, path: string, routeMap: Record<string, RouteMapping>): RouteMapping | null {
  for (const [pattern, mapping] of Object.entries(routeMap)) {
    const configured = parseRouteMapPattern(pattern);
    if (configured.method !== method)
      continue;

    const regex = pathToRegex(configured.path);
    if (regex.test(path))
      return mapping;
  }
  return null;
}

/**
 * Convert a route pattern to a regex.
 * :param → [^/]+
 * → .*
 */
function pathToRegex(pattern: string): RegExp {
  const regexStr = pattern
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/:[^/]+/g, '[^/]+')
    .replace(/\\\*/g, '.*')
    .replace(/\//g, '\\/');
  return new RegExp(`^${regexStr}$`);
}
