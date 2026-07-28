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
 * {@link assembleRoutes}, so this throws on the same conflicts present in the
 * declarative route inputs — duplicate plugin routes, host/core collisions,
 * undeclared or malformed core overrides, and `security('none')` combined with
 * a permission. Construction can observe additional conflicts when a plugin's
 * `methods()` factory mutates routes before final assembly.
 *
 * The guarantee is about the declared route surface only: a conflict that
 * would hide a declared route from an app-aware check fails here. It is
 * **not** a boot check. A config this accepts can still fail `createFortress()`
 * on a short or unset JWT key, a non-positive `jwt.session.*` value, a
 * contradictory `cookies` config, a missing database adapter, or a plugin route
 * with no matching own callable method. That is deliberate: `fortress init`
 * scaffolds `database: undefined!` and `key: process.env.FORTRESS_JWT_SECRET!`,
 * so requiring a bootable config would break codegen in CI — the one place
 * these commands most need to run.
 *
 * One more difference from construction: a plugin's `methods()` factory can
 * mutate its routes, and no factory runs here. This describes the routes a
 * config *declares*.
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
