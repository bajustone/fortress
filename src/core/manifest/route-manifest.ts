import type { FortressManifestRuntime } from '../capabilities';
import type {
  EndpointDefinition,
  EndpointDefinitionLike,
  EndpointPermission,
  HttpMethod,
  PublishedEndpointPermission,
  SecurityRequirement,
} from '../endpoint';
import type { MiddlewareDefinition, RuntimeFortressPlugin } from '../plugin';
import { authEndpoints } from '../auth/auth-endpoints';
import { isAuthenticationOnlyEndpoint } from '../endpoint-security';
import { resolveCsrfConfig } from '../http/csrf';
import { iamEndpoints } from '../iam/iam-endpoints';
import { snapshotPluginMembership } from '../plugin-membership';
import { endpointProvenance, HOST_ROUTES_PLUGIN_NAME, isSelfManagedOAuthRoute } from '../route-assembly';

export type RouteClassification = 'public' | 'authenticated' | 'rbac' | 'oauth-protocol' | 'default-deny';

export interface RouteManifestEntry {
  method: HttpMethod;
  path: string;
  handler: string;
  plugin: string | null;
  classification: RouteClassification;
  permission?: EndpointPermission;
  security: SecurityRequirement[];
  bearerKind?: 'jwt' | 'oauth';
  csrfApplicable: boolean;
  rateLimited: boolean;
  mounted: boolean;
}

/** One immutable entry in the cached manifest published by a Fortress instance. */
export interface PublishedRouteManifestEntry {
  readonly method: HttpMethod;
  readonly path: string;
  readonly handler: string;
  readonly plugin: string | null;
  readonly classification: RouteClassification;
  readonly permission?: PublishedEndpointPermission;
  readonly security: readonly SecurityRequirement[];
  readonly bearerKind?: 'jwt' | 'oauth';
  readonly csrfApplicable: boolean;
  readonly rateLimited: boolean;
  readonly mounted: boolean;
}

/** The frozen manifest array published by a Fortress instance. */
export type PublishedRouteManifest = readonly PublishedRouteManifestEntry[];

/** A mutable generated entry or immutable instance-published entry. */
export type RouteManifestEntryLike = RouteManifestEntry | PublishedRouteManifestEntry;

interface EndpointWithOrigin {
  endpoint: EndpointDefinitionLike;
  plugin: string | null;
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function endpointKey(endpoint: Pick<EndpointDefinitionLike, 'method' | 'path'>): string {
  return `${endpoint.method.toUpperCase()} ${endpoint.path}`;
}

function classifyEndpoint(endpoint: EndpointDefinitionLike): RouteClassification {
  const security = endpoint.meta?.security ?? [];
  if (isSelfManagedOAuthRoute(endpoint))
    return 'oauth-protocol';
  if (security.includes('none'))
    return 'public';
  if (endpoint.meta?.permission)
    return 'rbac';
  // `basic` is deliberately absent: Fortress has no Basic verifier, so a
  // Basic route with no permission is not authenticated. Construction rejects
  // it outright; an unassembled runtime lands here and is reported
  // `default-deny` rather than being mislabelled as authenticated.
  if (isAuthenticationOnlyEndpoint(endpoint))
    return 'authenticated';
  return 'default-deny';
}

function pathPatternToRegex(pattern: string): RegExp {
  const regexStr = pattern
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/:[^/]+/g, '[^/]+')
    .replace(/\\\*/g, '.*')
    .replace(/\//g, '\\/');
  return new RegExp(`^${regexStr}$`);
}

function middlewareMatchesEndpoint(middleware: MiddlewareDefinition, endpoint: EndpointDefinitionLike): boolean {
  if (!pathPatternToRegex(middleware.path).test(endpoint.path))
    return false;

  const methods = middleware.methods;
  if (methods && !methods.map(m => m.toUpperCase()).includes(endpoint.method.toUpperCase()))
    return false;

  return true;
}

function isRateLimited(endpoint: EndpointDefinitionLike, plugins: readonly RuntimeFortressPlugin[]): boolean {
  for (const plugin of plugins) {
    if (plugin.name !== 'rate-limit')
      continue;
    for (const middleware of plugin.middleware ?? []) {
      if (middlewareMatchesEndpoint(middleware, endpoint))
        return true;
    }
  }

  // The built-in auth protections are hook-based rather than path middleware.
  // Classify only the specific hook captured in the validated plugin snapshot.
  if (endpoint.method === 'POST' && endpoint.path === '/auth/login') {
    return plugins.some(plugin =>
      plugin.name === 'rate-limit' && typeof plugin.hooks?.beforeLogin === 'function');
  }
  if (endpoint.method === 'POST' && endpoint.path === '/auth/register') {
    return plugins.some(plugin =>
      plugin.name === 'rate-limit' && typeof plugin.hooks?.beforeRegister === 'function');
  }
  if (endpoint.method === 'POST' && endpoint.path === '/auth/refresh') {
    return plugins.some(plugin =>
      plugin.name === 'rate-limit' && typeof plugin.hooks?.beforeTokenRefresh === 'function');
  }

  return false;
}

function csrfApplies(endpoint: EndpointDefinitionLike, fortress: Pick<FortressManifestRuntime, 'config'>): boolean {
  const csrf = resolveCsrfConfig(fortress.config.csrf);
  if (!csrf.enabled)
    return false;
  if (SAFE_METHODS.has(endpoint.method.toUpperCase()))
    return false;
  for (const skip of csrf.skipPaths) {
    if (endpoint.path === skip || endpoint.path.startsWith(`${skip}/`))
      return false;
  }
  return true;
}

function collectEndpointOrigins(
  fortress: Pick<FortressManifestRuntime, 'endpoints' | 'config'>,
  plugins: readonly RuntimeFortressPlugin[],
): EndpointWithOrigin[] {
  const origins = new Map<string, EndpointWithOrigin>();

  const coreAuth = Object.values(authEndpoints) as EndpointDefinition[];
  const coreIam = Object.values(iamEndpoints) as EndpointDefinition[];
  for (const endpoint of coreAuth)
    origins.set(endpointKey(endpoint), { endpoint, plugin: 'auth' });
  for (const endpoint of coreIam)
    origins.set(endpointKey(endpoint), { endpoint, plugin: 'iam' });

  // Genuine instances publish the synthetic host descriptor in the validated
  // capability view. Focused config-only fixtures retain the legacy fallback.
  if (!plugins.some(plugin => plugin.name === HOST_ROUTES_PLUGIN_NAME)) {
    for (const endpoint of Object.values(fortress.config.routes ?? {}) as EndpointDefinition[])
      origins.set(endpointKey(endpoint), { endpoint, plugin: null });
  }
  for (const plugin of plugins) {
    for (const endpoint of Object.values(plugin.routes ?? {}) as EndpointDefinition[]) {
      origins.set(endpointKey(endpoint), {
        endpoint,
        plugin: plugin.name === HOST_ROUTES_PLUGIN_NAME ? null : plugin.name,
      });
    }
  }

  const byKey = new Map<string, EndpointWithOrigin>();
  for (const endpoint of fortress.endpoints) {
    const key = endpointKey(endpoint);
    // An assembled snapshot carries its own origin, so the manifest still
    // reports the validated owner after a plugin rewrites or drops its route
    // record. Endpoints from an arbitrary, fake, or config-only runtime have
    // no provenance and keep the live-config derivation above.
    const provenance = endpointProvenance(endpoint);
    byKey.set(
      key,
      provenance
        ? { endpoint, plugin: provenance.manifestLabel }
        : origins.get(key) ?? { endpoint, plugin: null },
    );
  }
  return [...byKey.values()];
}

export function buildRouteManifest(fortress: Pick<FortressManifestRuntime, 'endpoints' | 'config'>): RouteManifestEntry[] {
  const plugins = snapshotPluginMembership(fortress);
  return collectEndpointOrigins(fortress, plugins)
    .map(({ endpoint, plugin }) => {
      const security = endpoint.meta?.security ?? [];
      return {
        method: endpoint.method,
        path: endpoint.path,
        handler: endpoint.handler,
        plugin,
        classification: classifyEndpoint(endpoint),
        ...(endpoint.meta?.permission ? { permission: { ...endpoint.meta.permission } } : {}),
        security: [...security],
        ...(endpoint.meta?.bearerKind ? { bearerKind: endpoint.meta.bearerKind } : {}),
        csrfApplicable: csrfApplies(endpoint, fortress),
        rateLimited: isRateLimited(endpoint, plugins),
        // Top-level host routes are metadata/protection declarations only.
        // Framework adapters must fall through to the host's own handler.
        mounted: plugin !== null,
      };
    })
    .sort((a, b) => `${a.method} ${a.path}`.localeCompare(`${b.method} ${b.path}`));
}
