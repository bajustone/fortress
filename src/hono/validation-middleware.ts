/**
 * Standalone validation middleware for Hono.
 *
 * Matches incoming requests to EndpointDefinitions and validates
 * body/query/params using Standard Schema (`~standard.validate()`).
 *
 * Works with fortress schemas, Zod, Valibot, ArkType — any Standard Schema.
 */

import type { Context, Next } from 'hono';
import type { EndpointDefinition } from '../core/endpoint';
import { FortressError } from '../core/errors';
import { validateRequest } from '../core/validation';

/** Options accepted by {@link createValidationMiddleware}. */
export interface ValidationMiddlewareOptions {
  /** Log a warning when a request doesn't match any endpoint definition. Default: true in non-production. */
  warnOnUnmatched?: boolean;
}

/**
 * Create Hono middleware that validates requests against endpoint definitions.
 *
 * @example
 * ```ts
 * import { createValidationMiddleware } from '@bajustone/fortress/hono';
 *
 * const endpoints = [
 *   endpoint('POST', '/users').body(obj({ name: str() }, 'name')).handler('createUser').build(),
 * ];
 *
 * app.use('/api/*', createValidationMiddleware(endpoints));
 * ```
 */
export function createValidationMiddleware(
  endpoints: EndpointDefinition[],
  options?: ValidationMiddlewareOptions,
): (c: Context, next: Next) => Promise<void | Response> {
  // Pre-build a lookup for fast matching
  const routeMap = buildRouteMap(endpoints);
  const shouldWarn = options?.warnOnUnmatched ?? (typeof process !== 'undefined' && process.env?.NODE_ENV !== 'production');
  const warned = new Set<string>();

  return async (c: Context, next: Next): Promise<void | Response> => {
    const method = c.req.method.toUpperCase();
    const path = new URL(c.req.url).pathname;

    const match = matchEndpoint(routeMap, method, path);
    if (!match) {
      if (shouldWarn) {
        const key = `${method} ${path}`;
        if (!warned.has(key)) {
          warned.add(key);
          console.warn(`[fortress] No endpoint definition matches ${method} ${path} — request will not be validated`);
        }
      }
      await next();
      return;
    }

    const { endpoint: ep } = match;

    if (!ep.input?.bodySchema && !ep.input?.querySchema && !ep.input?.paramsSchema) {
      await next();
      return;
    }

    try {
      const body = ['POST', 'PUT', 'PATCH'].includes(method)
        ? await c.req.json().catch(() => undefined)
        : undefined;

      const query = Object.fromEntries(new URL(c.req.url).searchParams);
      const params = match.params;

      await validateRequest(ep.input, { body, query, params });
      await next();
    }
    catch (error) {
      if (error instanceof FortressError) {
        return c.json(error.toJSON(), error.statusCode as any);
      }
      throw error;
    }
  };
}

// ── Route matching ──────────────────────────────────────────────────

interface RouteEntry {
  endpoint: EndpointDefinition;
  method: string;
  segments: string[];
  paramNames: string[];
}

interface MatchResult {
  endpoint: EndpointDefinition;
  params: Record<string, string>;
}

function buildRouteMap(endpoints: EndpointDefinition[]): RouteEntry[] {
  return endpoints.map((ep) => {
    const segments = ep.path.split('/').filter(Boolean);
    const paramNames: string[] = [];
    for (const seg of segments) {
      if (seg.startsWith(':')) {
        paramNames.push(seg.slice(1));
      }
    }
    return {
      endpoint: ep,
      method: ep.method.toUpperCase(),
      segments,
      paramNames,
    };
  });
}

function matchEndpoint(
  routes: RouteEntry[],
  method: string,
  path: string,
): MatchResult | null {
  const pathSegments = path.split('/').filter(Boolean);

  for (const route of routes) {
    if (route.method !== method)
      continue;
    if (route.segments.length !== pathSegments.length)
      continue;

    const params: Record<string, string> = {};
    let matched = true;

    for (let i = 0; i < route.segments.length; i++) {
      const routeSeg = route.segments[i];
      const pathSeg = pathSegments[i];

      if (routeSeg.startsWith(':')) {
        params[routeSeg.slice(1)] = pathSeg;
      }
      else if (routeSeg !== pathSeg) {
        matched = false;
        break;
      }
    }

    if (matched) {
      return { endpoint: route.endpoint, params };
    }
  }

  return null;
}
