/**
 * Endpoint route matching shared by dispatch and fortress-RBAC.
 *
 * Builds a path-segment table from {@link EndpointDefinition}s and matches
 * incoming `(method, pathname)` pairs against it. Supports `:param` segments
 * and returns extracted path parameters alongside the matched endpoint.
 */

import type { EndpointDefinition } from '../endpoint';

/** Route table entry built from an {@link EndpointDefinition}. */
export interface RouteEntry {
  endpoint: EndpointDefinition;
  method: string;
  segments: string[];
  paramNames: string[];
}

/** Successful match: the endpoint plus extracted path parameters. */
export interface RouteMatch {
  endpoint: EndpointDefinition;
  params: Record<string, string>;
}

/**
 * Pre-build a route table from endpoint definitions. Adapters call this once
 * at startup and hand the result to {@link matchRoute} on every request.
 */
export function buildRouteTable(endpoints: readonly EndpointDefinition[]): RouteEntry[] {
  return endpoints.map((ep) => {
    const segments = ep.path.split('/').filter(Boolean);
    const paramNames: string[] = [];
    for (const seg of segments) {
      if (seg.startsWith(':'))
        paramNames.push(seg.slice(1));
    }
    return {
      endpoint: ep,
      method: ep.method.toUpperCase(),
      segments,
      paramNames,
    };
  });
}

/**
 * Find the endpoint that matches a `(method, pathname)` pair. Returns the
 * matched endpoint and any extracted `:param` values, or `null` if nothing
 * matches.
 *
 * Matching is segment-by-segment with literal segments compared verbatim
 * and `:param` segments capturing into `params`. Static segments take
 * priority because they're checked first; the iteration order follows the
 * order in which endpoints were registered.
 */
export function matchRoute(
  table: RouteEntry[],
  method: string,
  pathname: string,
): RouteMatch | null {
  const upperMethod = method.toUpperCase();
  const pathSegments = pathname.split('/').filter(Boolean);

  for (const route of table) {
    if (route.method !== upperMethod)
      continue;
    if (route.segments.length !== pathSegments.length)
      continue;

    const params: Record<string, string> = {};
    let matched = true;
    for (let i = 0; i < route.segments.length; i++) {
      const routeSeg = route.segments[i];
      const pathSeg = pathSegments[i];
      if (routeSeg.startsWith(':')) {
        params[routeSeg.slice(1)] = decodeURIComponent(pathSeg);
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
