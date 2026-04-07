/**
 * Standalone validation middleware for Express.
 *
 * Matches incoming requests to EndpointDefinitions and validates
 * body/query/params using Standard Schema.
 */

import type { EndpointDefinition } from '../core/endpoint';
import { FortressError } from '../core/errors';
import { validateRequest } from '../core/validation';

interface ExpressReq {
  method: string;
  path: string;
  body?: unknown;
  query?: Record<string, unknown>;
  params?: Record<string, string>;
}

interface ExpressRes {
  status: (code: number) => ExpressRes;
  json: (data: unknown) => void;
}

type ExpressNext = (err?: unknown) => void;

/**
 * Create Express middleware that validates requests against endpoint definitions.
 */
export function createValidationMiddleware(
  endpoints: EndpointDefinition[],
): (req: ExpressReq, res: ExpressRes, next: ExpressNext) => Promise<void> {
  const routeMap = buildRouteMap(endpoints);

  return async (req: ExpressReq, res: ExpressRes, next: ExpressNext): Promise<void> => {
    const method = req.method.toUpperCase();
    const path = req.path;

    const match = matchEndpoint(routeMap, method, path);
    if (!match) {
      next();
      return;
    }

    const { endpoint: ep } = match;

    if (!ep.input?.bodySchema && !ep.input?.querySchema && !ep.input?.paramsSchema) {
      next();
      return;
    }

    try {
      const body = ['POST', 'PUT', 'PATCH'].includes(method) ? req.body : undefined;
      const query = req.query ?? {};
      const params = match.params;

      await validateRequest(ep.input, { body, query, params });
      next();
    }
    catch (error) {
      if (error instanceof FortressError) {
        res.status(error.statusCode).json(error.toJSON());
        return;
      }
      next(error);
    }
  };
}

// ── Route matching (same logic as Hono version) ─────────────────────

interface RouteEntry {
  endpoint: EndpointDefinition;
  method: string;
  segments: string[];
}

interface MatchResult {
  endpoint: EndpointDefinition;
  params: Record<string, string>;
}

function buildRouteMap(endpoints: EndpointDefinition[]): RouteEntry[] {
  return endpoints.map((ep) => {
    const segments = ep.path.split('/').filter(Boolean);
    return { endpoint: ep, method: ep.method.toUpperCase(), segments };
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

    if (matched)
      return { endpoint: route.endpoint, params };
  }

  return null;
}
