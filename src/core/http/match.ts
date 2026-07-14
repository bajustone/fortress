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
  return endpoints.map((ep) => {
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
