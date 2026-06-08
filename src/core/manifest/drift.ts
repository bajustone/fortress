import type { OpenAPISpec } from '../../plugins/openapi/spec-builder';
import type { EndpointDefinition } from '../endpoint';
import type { Fortress } from '../fortress';
import type { RouteManifestEntry } from './route-manifest';
import { buildRouteManifest } from './route-manifest';

export interface RouteManifestDrift {
  mountedMissingFromManifest: string[];
  manifestMissingFromMounted: string[];
  openapiMissingFromManifest: string[];
  manifestMissingFromOpenapi: string[];
  rbacPermissionMismatches: Array<{
    route: string;
    expected?: string;
    actual?: string;
  }>;
}

export interface DetectRouteManifestDriftOptions {
  manifest?: RouteManifestEntry[];
  openapi?: OpenAPISpec;
}

function endpointKey(route: Pick<EndpointDefinition, 'method' | 'path'>): string {
  return `${route.method.toUpperCase()} ${route.path}`;
}

function manifestKey(route: Pick<RouteManifestEntry, 'method' | 'path'>): string {
  return `${route.method.toUpperCase()} ${route.path}`;
}

function toOpenAPIPath(path: string): string {
  return path.replace(/:(\w+)/g, '{$1}');
}

function fromOpenAPIPath(path: string): string {
  return path.replace(/\{(\w+)\}/g, ':$1');
}

function permissionKey(permission: { resource: string; action: string } | undefined): string | undefined {
  return permission ? `${permission.resource}:${permission.action}` : undefined;
}

function diffSets(expected: Set<string>, actual: Set<string>): string[] {
  return [...expected].filter(item => !actual.has(item)).sort();
}

export function detectRouteManifestDrift(
  fortress: Pick<Fortress, 'endpoints' | 'config' | 'manifest'>,
  options: DetectRouteManifestDriftOptions = {},
): RouteManifestDrift {
  const manifest = options.manifest ?? fortress.manifest ?? buildRouteManifest(fortress);

  const mounted = new Set(fortress.endpoints.map(endpointKey));
  const manifestRoutes = new Set(manifest.filter(entry => entry.mounted).map(manifestKey));

  let openapiRoutes = new Set<string>();
  if (options.openapi) {
    for (const [path, operations] of Object.entries(options.openapi.paths)) {
      for (const method of Object.keys(operations))
        openapiRoutes.add(`${method.toUpperCase()} ${fromOpenAPIPath(path)}`);
    }
  }
  else {
    openapiRoutes = new Set(fortress.endpoints.map(ep => `${ep.method.toUpperCase()} ${toOpenAPIPath(ep.path)}`).map(key => key.replace(/\{(\w+)\}/g, ':$1')));
  }

  const endpointPermissions = new Map<string, string | undefined>();
  for (const endpoint of fortress.endpoints)
    endpointPermissions.set(endpointKey(endpoint), permissionKey(endpoint.meta?.permission));

  const rbacPermissionMismatches: RouteManifestDrift['rbacPermissionMismatches'] = [];
  for (const entry of manifest) {
    const key = manifestKey(entry);
    const expected = endpointPermissions.get(key);
    const actual = permissionKey(entry.permission);
    if (expected !== actual) {
      rbacPermissionMismatches.push({ route: key, expected, actual });
      continue;
    }
    if (entry.classification === 'rbac' && !actual) {
      rbacPermissionMismatches.push({ route: key, expected, actual });
    }
  }

  return {
    mountedMissingFromManifest: diffSets(mounted, manifestRoutes),
    manifestMissingFromMounted: diffSets(manifestRoutes, mounted),
    openapiMissingFromManifest: diffSets(openapiRoutes, manifestRoutes),
    manifestMissingFromOpenapi: diffSets(manifestRoutes, openapiRoutes),
    rbacPermissionMismatches,
  };
}

export function hasRouteManifestDrift(drift: RouteManifestDrift): boolean {
  return drift.mountedMissingFromManifest.length > 0
    || drift.manifestMissingFromMounted.length > 0
    || drift.openapiMissingFromManifest.length > 0
    || drift.manifestMissingFromOpenapi.length > 0
    || drift.rbacPermissionMismatches.length > 0;
}
