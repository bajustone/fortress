import type { MiddlewareHandler } from 'hono';
import type { Fortress } from '../../core/fortress';
import type { FortressEnv } from './auth';
import { FortressError } from '../../core/errors';

export interface RouteMapping {
  resource: string;
  action: string;
}

export interface RbacOptions {
  /** Declarative route-to-resource mapping: 'METHOD /path' → { resource, action } */
  routeMap?: Record<string, RouteMapping>;
  /** Dynamic mapping function (used if routeMap doesn't match) */
  mapRequest?: (method: string, path: string) => RouteMapping | null;
  /** Paths that skip permission checks entirely (supports * wildcards) */
  skipPaths?: string[];
}

/**
 * Hono middleware that checks permissions via resource+action mapping.
 * Uses routeMap or mapRequest to translate HTTP requests to permission checks.
 */
export function createRbacMiddleware(
  fortress: Fortress,
  options?: RbacOptions,
): MiddlewareHandler<FortressEnv> {
  const routeMap = options?.routeMap ?? {};
  const skipPaths = options?.skipPaths ?? [];
  const skipPatterns = skipPaths.map(p => pathToRegex(p));

  return async (c, next) => {
    const path = c.req.path;
    const method = c.req.method;

    // Check skip paths
    if (skipPatterns.some(pattern => pattern.test(path))) {
      await next();
      return;
    }

    // Resolve resource+action from route map
    const key = `${method} ${path}`;
    let mapping: RouteMapping | null = routeMap[key] ?? null;

    // Try pattern matching for parameterized routes (e.g., GET /api/users/:id)
    if (!mapping) {
      mapping = findRouteMapMatch(method, path, routeMap);
    }

    // Try dynamic mapper
    if (!mapping && options?.mapRequest) {
      mapping = options.mapRequest(method, path);
    }

    // No mapping found — skip RBAC (allow through)
    if (!mapping) {
      await next();
      return;
    }

    const userId = c.get('fortressUserId');
    if (!userId) {
      throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
    }

    const allowed = await fortress.iam.checkPermission(userId, mapping.resource, mapping.action);
    if (!allowed) {
      throw new FortressError('FORBIDDEN', `Permission denied: ${mapping.resource}:${mapping.action}`, 403);
    }

    await next();
  };
}

/**
 * Match a request against parameterized route map entries.
 * 'GET /api/users/:id' matches 'GET /api/users/123'
 */
function findRouteMapMatch(method: string, path: string, routeMap: Record<string, RouteMapping>): RouteMapping | null {
  for (const [pattern, mapping] of Object.entries(routeMap)) {
    const [patternMethod, patternPath] = pattern.split(' ', 2);
    if (patternMethod !== method)
      continue;

    const regex = pathToRegex(patternPath);
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
    .replace(/:[^/]+/g, '[^/]+')
    .replace(/\*/g, '.*')
    .replace(/\//g, '\\/');
  return new RegExp(`^${regexStr}$`);
}
