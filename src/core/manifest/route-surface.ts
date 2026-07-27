import type { FortressManifestRuntime } from '../capabilities';
import type { FortressConfig } from '../config';
import type { RouteManifestEntry } from './route-manifest';
import { assembleRoutes } from '../route-assembly';
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
 * Assembly and validation are shared with `createFortress()` via
 * {@link assembleRoutes}, so this throws on exactly the conflicts construction
 * throws on — duplicate plugin routes, host/core collisions, undeclared or
 * malformed core overrides, `security('none')` combined with a permission.
 * A config the CLI accepts is therefore one the app can boot, and a conflict
 * that would hide a route from an app-aware check fails here too.
 *
 * What stays with `createFortress()` is what genuinely needs an instance:
 * JWT/session and cookie resolution, database adapter instrumentation, and
 * the check that every plugin route has a matching callable method.
 */
export function describeRouteSurface(config: FortressConfig): RouteSurface {
  const { endpoints } = assembleRoutes(config);
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
