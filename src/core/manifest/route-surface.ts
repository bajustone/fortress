import type { FortressManifestRuntime } from '../capabilities';
import type { FortressConfig } from '../config';
import type { EndpointDefinition } from '../endpoint';
import type { RouteManifestEntry } from './route-manifest';
import { authEndpoints } from '../auth/auth-endpoints';
import { canonicalizeRouteShape } from '../http/match';
import { iamEndpoints } from '../iam/iam-endpoints';
import { buildRouteManifest } from './route-manifest';

/** The introspection surface, derived without constructing a Fortress instance. */
export type RouteSurface = Pick<FortressManifestRuntime, 'config' | 'endpoints' | 'manifest'>;

/**
 * Derive the route surface — every endpoint plus the generated manifest —
 * from a {@link FortressConfig} **without** calling `createFortress()`.
 *
 * Constructing a real instance invokes every plugin's `methods()` factory,
 * which is where plugins start workers and reach for the database: the
 * webhook plugin's queue, for example, runs a startup recovery sweep that
 * queries pending deliveries and can dispatch them. Route introspection —
 * manifests, OpenAPI, CI drift checks — needs none of that, so this reads
 * only the declarative inputs (core endpoints, `plugin.routes`, and
 * top-level `routes`) and never touches a plugin's runtime.
 *
 * Endpoints resolve in the same precedence order `createFortress()` uses:
 * core, then top-level host `routes`, then configured plugins in order,
 * keyed by canonical method + path shape. Construction-time validation
 * (duplicate plugin routes, undeclared core overrides, `security('none')`
 * combined with a permission) remains `createFortress()`'s job — this is a
 * description of the route surface, not a substitute for booting the app.
 */
export function describeRouteSurface(config: FortressConfig): RouteSurface {
  const byRoute = new Map<string, EndpointDefinition>();

  const declareAll = (routes: object | undefined): void => {
    for (const endpoint of Object.values(routes ?? {}) as EndpointDefinition[])
      byRoute.set(`${endpoint.method.toUpperCase()} ${canonicalizeRouteShape(endpoint.path)}`, endpoint);
  };

  declareAll(authEndpoints);
  declareAll(iamEndpoints);
  // Top-level `routes` are registered ahead of user plugins, matching the
  // synthetic `__host` plugin createFortress() prepends.
  declareAll(config.routes);
  for (const plugin of config.plugins ?? [])
    declareAll(plugin.routes);

  const endpoints = [...byRoute.values()];
  let manifest: RouteManifestEntry[] | undefined;

  return {
    endpoints,
    config,
    get manifest(): RouteManifestEntry[] {
      manifest ??= buildRouteManifest({ endpoints, config });
      return manifest;
    },
  };
}
