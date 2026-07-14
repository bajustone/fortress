/**
 * Endpoint route matching shared by dispatch and fortress-RBAC.
 *
 * Builds a path-segment table from {@link EndpointDefinition}s and matches
 * incoming `(method, pathname)` pairs against it. Supports `:param` segments
 * and returns extracted path parameters alongside the matched endpoint.
 */

import type { EndpointDefinition } from '../endpoint';

/** Minimal route shape accepted by the matcher. */
export interface RouteLike {
  method: string;
  path: string;
}

/** Route table entry built from an {@link EndpointDefinition} or manifest entry. */
export interface RouteEntry<T extends RouteLike = EndpointDefinition> {
  endpoint: T;
  method: string;
  segments: string[];
  paramNames: string[];
}

/** Higher values are more specific when two routes have the same shape. */
function segmentSpecificity(segment: string): number {
  if (segment === '*')
    return 0;
  if (segment.startsWith(':'))
    return 1;
  return 2;
}

/** Successful match: the endpoint/route plus extracted path parameters. */
export interface RouteMatch<T extends RouteLike = EndpointDefinition> {
  endpoint: T;
  params: Record<string, string>;
}

/** Normalize path separators so route and middleware matching share one form. */
export function canonicalizePath(pathname: string): string {
  const segments = pathname.split('/').filter(Boolean);
  return segments.length === 0 ? '/' : `/${segments.join('/')}`;
}

/**
 * Pre-build a route table from endpoint definitions. Adapters call this once
 * at startup and hand the result to {@link matchRoute} on every request.
 */
export function buildRouteTable<T extends RouteLike>(endpoints: readonly T[]): RouteEntry<T>[] {
  const table = endpoints.map((ep) => {
    const segments = canonicalizePath(ep.path).split('/').filter(Boolean);
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

  // Match specificity lexicographically so a static segment always wins over
  // a parameter (and a parameter over a wildcard), independent of registration
  // order. Stable sorting retains registration order for duplicate patterns.
  return table
    .map((route, index) => ({ route, index }))
    .sort((a, b) => {
      const length = Math.max(a.route.segments.length, b.route.segments.length);
      for (let i = 0; i < length; i++) {
        const difference = segmentSpecificity(b.route.segments[i] ?? '')
          - segmentSpecificity(a.route.segments[i] ?? '');
        if (difference !== 0)
          return difference;
      }
      return a.index - b.index;
    })
    .map(({ route }) => route);
}

/**
 * Find the endpoint that matches a `(method, pathname)` pair. Returns the
 * matched endpoint and any extracted `:param` values, or `null` if nothing
 * matches.
 *
 * Matching is segment-by-segment with literal segments compared verbatim,
 * `:param` segments capturing into `params`, and `*` matching any one segment.
 * Static segments take priority over params, which take priority over
 * wildcards, independent of registration order.
 */
export function matchRoute<T extends RouteLike>(
  table: RouteEntry<T>[],
  method: string,
  pathname: string,
): RouteMatch<T> | null {
  const upperMethod = method.toUpperCase();
  const pathSegments = canonicalizePath(pathname).split('/').filter(Boolean);

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
      else if (routeSeg !== '*' && routeSeg !== pathSeg) {
        matched = false;
        break;
      }
    }
    if (matched)
      return { endpoint: route.endpoint, params };
  }

  return null;
}
