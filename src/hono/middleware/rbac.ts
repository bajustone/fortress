import type { MiddlewareHandler } from 'hono';
import type { EndpointDefinition } from '../../core/endpoint';
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
  /** Disable default-deny for fortress-owned routes (not recommended) */
  allowUnmappedFortressPaths?: boolean;
}

/** Known fortress core path prefixes that are always protected */
const FORTRESS_CORE_PREFIXES = ['/iam/'];

/** Sensitive auth endpoints that require admin protection */
const FORTRESS_AUTH_PROTECTED = ['/auth/impersonate'];

/**
 * Check if a path belongs to a fortress-owned route (core or plugin).
 * Fortress-owned routes are denied by default when no permission mapping exists.
 */
function isFortressPath(path: string, pluginPathPrefixes: string[]): boolean {
  // Core IAM routes
  if (FORTRESS_CORE_PREFIXES.some(prefix => path.startsWith(prefix)))
    return true;

  // Sensitive auth routes
  if (FORTRESS_AUTH_PROTECTED.some(p => path === p || path.startsWith(`${p}/`)))
    return true;

  // Plugin-owned routes
  if (pluginPathPrefixes.some(prefix => path.startsWith(prefix)))
    return true;

  return false;
}

/** Extracts first path segment: '/oauth/token' → '/oauth/' */
const PLUGIN_PREFIX_REGEX = /^(\/[^/]+\/)/;

/**
 * Extract unique path prefixes from plugin routes.
 * E.g., '/oauth/token' → '/oauth/'
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
 * Hono middleware that checks permissions via resource+action mapping.
 * Uses routeMap or mapRequest to translate HTTP requests to permission checks.
 *
 * Fortress-owned routes (`/iam/*`, plugin routes) are denied by default
 * when no permission mapping exists, unless `allowUnmappedFortressPaths` is set.
 */
export function createRbacMiddleware(
  fortress: Fortress,
  options?: RbacOptions,
): MiddlewareHandler<FortressEnv> {
  const routeMap = options?.routeMap ?? {};
  const skipPaths = options?.skipPaths ?? [];
  const skipPatterns = skipPaths.map(p => pathToRegex(p));
  const pluginPathPrefixes = getPluginPathPrefixes(fortress);

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

    // No mapping found — smart default deny for fortress-owned paths
    if (!mapping) {
      if (!options?.allowUnmappedFortressPaths && isFortressPath(path, pluginPathPrefixes)) {
        const ep = findEndpoint(fortress.endpoints, method, path);

        // Public or self-authenticated routes pass through
        if (ep?.meta?.security?.includes('none') || ep?.meta?.security?.includes('basic')) {
          await next();
          return;
        }

        // Routes with declared permissions — enforce via IAM
        if (ep?.meta?.permission) {
          const userId = c.get('fortressUserId');
          if (!userId) {
            throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
          }
          const allowed = await fortress.iam.checkPermission(userId, ep.meta.permission.resource, ep.meta.permission.action);
          if (!allowed) {
            throw new FortressError('FORBIDDEN', 'Insufficient permissions', 403);
          }
          await next();
          return;
        }

        // Bearer-only routes without permission — require auth but no IAM check
        if (ep?.meta?.security?.includes('bearer')) {
          const userId = c.get('fortressUserId');
          if (!userId) {
            throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
          }
          await next();
          return;
        }

        // Unknown / no security metadata — deny
        throw new FortressError('FORBIDDEN', 'No permission mapping for this route', 403);
      }
      await next();
      return;
    }

    const userId = c.get('fortressUserId');
    if (!userId) {
      throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
    }

    const allowed = await fortress.iam.checkPermission(userId, mapping.resource, mapping.action);
    if (!allowed) {
      throw new FortressError('FORBIDDEN', 'Insufficient permissions', 403);
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

/**
 * Find an endpoint definition matching the given method and path.
 * Handles parameterized paths (e.g., /iam/roles/:id matches /iam/roles/5).
 */
function findEndpoint(endpoints: EndpointDefinition[], method: string, path: string): EndpointDefinition | undefined {
  return endpoints.find((ep) => {
    if (ep.method !== method)
      return false;
    // Exact match
    if (ep.path === path)
      return true;
    // Parameterized match
    return pathToRegex(ep.path).test(path);
  });
}
