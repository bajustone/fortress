import type { EndpointDefinition, EndpointPermission, HttpMethod, SecurityRequirement } from '../endpoint';
import type { Fortress } from '../fortress';
import type { FortressPlugin, MiddlewareDefinition } from '../plugin';
import { authEndpoints } from '../auth/auth-endpoints';
import { resolveCsrfConfig } from '../http/csrf';
import { iamEndpoints } from '../iam/iam-endpoints';

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

interface EndpointWithOrigin {
  endpoint: EndpointDefinition;
  plugin: string | null;
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

function endpointKey(endpoint: Pick<EndpointDefinition, 'method' | 'path'>): string {
  return `${endpoint.method.toUpperCase()} ${endpoint.path}`;
}

function classifyEndpoint(endpoint: EndpointDefinition): RouteClassification {
  const security = endpoint.meta?.security ?? [];
  if (endpoint.meta?.bearerKind === 'oauth')
    return 'oauth-protocol';
  if (security.includes('none'))
    return 'public';
  if (endpoint.meta?.permission)
    return 'rbac';
  if (security.includes('bearer') || security.includes('apiKey') || security.includes('basic'))
    return 'authenticated';
  return 'default-deny';
}

function pathPatternToRegex(pattern: string): RegExp {
  const regexStr = pattern
    .replace(/:[^/]+/g, '[^/]+')
    .replace(/\*/g, '.*')
    .replace(/\//g, '\\/');
  return new RegExp(`^${regexStr}$`);
}

function middlewareMatchesEndpoint(middleware: MiddlewareDefinition, endpoint: EndpointDefinition): boolean {
  if (!pathPatternToRegex(middleware.path).test(endpoint.path))
    return false;

  const methods = (middleware as MiddlewareDefinition & { methods?: string[] }).methods;
  if (methods && !methods.map(m => m.toUpperCase()).includes(endpoint.method.toUpperCase()))
    return false;

  return true;
}

function isRateLimited(endpoint: EndpointDefinition, plugins: readonly FortressPlugin[]): boolean {
  for (const plugin of plugins) {
    if (plugin.name !== 'rate-limit')
      continue;
    for (const middleware of plugin.middleware ?? []) {
      if (middlewareMatchesEndpoint(middleware, endpoint))
        return true;
    }
  }

  // The rate-limit plugin's login/register/refresh protections are hook-based,
  // not path middleware. Surface those as rate-limited in the manifest too.
  if (plugins.some(plugin => plugin.name === 'rate-limit')) {
    if (endpoint.method === 'POST' && endpoint.path === '/auth/login')
      return true;
    if (endpoint.method === 'POST' && endpoint.path === '/auth/register')
      return true;
    if (endpoint.method === 'POST' && endpoint.path === '/auth/refresh')
      return true;
  }

  return false;
}

function csrfApplies(endpoint: EndpointDefinition, fortress: Pick<Fortress, 'config'>): boolean {
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

function collectEndpointOrigins(fortress: Pick<Fortress, 'endpoints' | 'config'>): EndpointWithOrigin[] {
  const origins = new Map<string, EndpointWithOrigin>();

  const coreAuth = Object.values(authEndpoints) as EndpointDefinition[];
  const coreIam = Object.values(iamEndpoints) as EndpointDefinition[];
  for (const endpoint of coreAuth)
    origins.set(endpointKey(endpoint), { endpoint, plugin: 'auth' });
  for (const endpoint of coreIam)
    origins.set(endpointKey(endpoint), { endpoint, plugin: 'iam' });

  for (const endpoint of Object.values(fortress.config.routes ?? {}) as EndpointDefinition[]) {
    origins.set(endpointKey(endpoint), { endpoint, plugin: null });
  }
  for (const plugin of fortress.config.plugins ?? []) {
    for (const endpoint of Object.values(plugin.routes ?? {}) as EndpointDefinition[]) {
      origins.set(endpointKey(endpoint), { endpoint, plugin: plugin.name });
    }
  }

  const byKey = new Map<string, EndpointWithOrigin>();
  for (const endpoint of fortress.endpoints) {
    const key = endpointKey(endpoint);
    byKey.set(key, origins.get(key) ?? { endpoint, plugin: null });
  }
  return [...byKey.values()];
}

export function buildRouteManifest(fortress: Pick<Fortress, 'endpoints' | 'config'>): RouteManifestEntry[] {
  const plugins = fortress.config.plugins ?? [];
  return collectEndpointOrigins(fortress)
    .map(({ endpoint, plugin }) => {
      const security = endpoint.meta?.security ?? [];
      return {
        method: endpoint.method,
        path: endpoint.path,
        handler: endpoint.handler,
        plugin,
        classification: classifyEndpoint(endpoint),
        ...(endpoint.meta?.permission ? { permission: endpoint.meta.permission } : {}),
        security,
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
