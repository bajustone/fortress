import type { FortressConfig } from './config';
import type { EndpointDefinition } from './endpoint';
import type { FortressPlugin, RuntimeFortressPlugin } from './plugin';
import { authEndpoints } from './auth/auth-endpoints';
import { isHttpMethod } from './endpoint';
import { Errors } from './errors';
import { canonicalizeRouteShape } from './http/match';
import { iamEndpoints } from './iam/iam-endpoints';

/** Reserved plugin name backing top-level `routes`. */
export const HOST_ROUTES_PLUGIN_NAME = '__host';

/** The declarative half of a Fortress config — everything route assembly reads. */
export type RouteAssemblyConfig = Pick<FortressConfig, 'plugins' | 'routes'>;

export interface AssembledRoutes {
  /** Configured plugins, with the synthetic `__host` plugin prepended when present. */
  plugins: readonly RuntimeFortressPlugin[];
  /** Deduplicated endpoint set, in registration order. */
  endpoints: EndpointDefinition[];
  /**
   * Owner per canonical `METHOD /path` key: `'core'`, a plugin name, or
   * `'__host'`. The call tree uses this to drop core callables a plugin has
   * taken over.
   */
  endpointOwners: Map<string, string>;
}

/**
 * Assemble and validate the route surface from configuration alone.
 *
 * This is the side-effect-free half of `createFortress()`: it synthesizes the
 * `__host` plugin, validates plugin names and route shapes, merges endpoints
 * with the same precedence and the same conflict rules, and enforces the
 * route-level security invariants. It never invokes a plugin's `methods()`
 * factory, so no plugin worker starts and no database is touched.
 *
 * Both `createFortress()` and `describeRouteSurface()` go through here, so a
 * configuration the CLI accepts is one the application can actually boot —
 * and, critically, a conflict that would hide a route from an app-aware check
 * is rejected in both.
 *
 * Validation that genuinely needs a constructed instance stays in
 * `createFortress()`: JWT/session/cookie resolution, adapter instrumentation,
 * and the handler-must-be-an-own-callable check that requires plugin methods.
 */
export function assembleRoutes(config: RouteAssemblyConfig): AssembledRoutes {
  const userPlugins = config.plugins ?? [];
  if (config.routes) {
    const collision = userPlugins.find(plugin => plugin.name === HOST_ROUTES_PLUGIN_NAME);
    if (collision) {
      throw Errors.badRequest(
        `Plugin name '${HOST_ROUTES_PLUGIN_NAME}' is reserved for top-level \`routes\`; rename your plugin.`,
      );
    }
  }
  const hostRoutesPlugin: FortressPlugin | null = config.routes
    ? { name: HOST_ROUTES_PLUGIN_NAME, routes: config.routes }
    : null;
  const plugins = hostRoutesPlugin ? [hostRoutesPlugin, ...userPlugins] : userPlugins;

  validatePluginRouteShapes(plugins);

  const { endpoints, endpointOwners } = mergeEndpoints(plugins);
  assertRouteSecurityInvariants(endpoints);

  return { plugins, endpoints, endpointOwners };
}

function validatePluginRouteShapes(plugins: readonly RuntimeFortressPlugin[]): void {
  const pluginNames = new Set<string>();
  for (const plugin of plugins) {
    if (pluginNames.has(plugin.name)) {
      throw Errors.badRequest(`Duplicate plugin name: '${plugin.name}'`);
    }
    pluginNames.add(plugin.name);
    for (const [routeName, endpoint] of Object.entries(plugin.routes ?? {})) {
      if (
        !endpoint || typeof endpoint !== 'object'
        || !isHttpMethod(endpoint.method)
        || typeof endpoint.path !== 'string'
        || typeof endpoint.handler !== 'string'
      ) {
        throw Errors.badRequest(
          `Plugin "${plugin.name}" route "${routeName}" is not a valid endpoint definition`,
        );
      }
      if (plugin.name !== HOST_ROUTES_PLUGIN_NAME && routeName !== endpoint.handler) {
        throw Errors.badRequest(
          `Plugin "${plugin.name}" route key "${routeName}" must match handler "${endpoint.handler}"`,
        );
      }
      for (const location of ['body', 'query', 'params'] as const) {
        const schema = endpoint.input?.[location];
        if (schema?.type && schema.type !== 'object') {
          throw Errors.badRequest(
            `Plugin "${plugin.name}" route "${routeName}" ${location} schema must describe a flat object`,
          );
        }
      }
    }
  }
}

/**
 * Merge core, host, and plugin endpoints. A plugin may intentionally override a
 * core route once it declares the override, but two plugins claiming the same
 * method+path is ambiguous and therefore rejected instead of depending on
 * registration order.
 */
function mergeEndpoints(
  plugins: readonly RuntimeFortressPlugin[],
): Pick<AssembledRoutes, 'endpointOwners' | 'endpoints'> {
  const endpointMap = new Map<string, EndpointDefinition>();
  const endpointOwners = new Map<string, string>();

  const routeKeyOf = (endpoint: EndpointDefinition): string =>
    `${endpoint.method.toUpperCase()} ${canonicalizeRouteShape(endpoint.path)}`;

  const coreEndpoints: EndpointDefinition[] = [
    ...Object.values(authEndpoints) as EndpointDefinition[],
    ...Object.values(iamEndpoints) as EndpointDefinition[],
  ];
  for (const endpoint of coreEndpoints) {
    const routeKey = routeKeyOf(endpoint);
    endpointMap.set(routeKey, endpoint);
    endpointOwners.set(routeKey, 'core');
  }

  for (const plugin of plugins) {
    const appliedCoreOverrides = new Set<string>();
    for (const [routeName, value] of Object.entries(plugin.routes ?? {})) {
      const endpoint = value as EndpointDefinition;
      const routeKey = routeKeyOf(endpoint);
      const owner = endpointOwners.get(routeKey);
      if (owner && owner !== 'core') {
        throw Errors.badRequest(
          `Duplicate endpoint ${routeKey} declared by plugins "${owner}" and "${plugin.name}"`,
        );
      }
      if (owner === 'core') {
        if (plugin.name === HOST_ROUTES_PLUGIN_NAME) {
          throw Errors.badRequest(
            `Top-level route ${routeKey} collides with a Fortress core route; use an explicit plugin for intentional overrides.`,
          );
        }
        const coreHandler = endpointMap.get(routeKey)!.handler;
        if (!plugin.coreOverrides?.includes(coreHandler)) {
          throw Errors.badRequest(
            `Plugin "${plugin.name}" overrides core route ${routeKey}; declare "${coreHandler}" in coreOverrides so the derived call tree can remove the core callable safely.`,
          );
        }
        if (routeName !== coreHandler || endpoint.handler !== coreHandler) {
          throw Errors.badRequest(
            `Plugin "${plugin.name}" overrides core route ${routeKey}; its route key and handler must both be "${coreHandler}".`,
          );
        }
        appliedCoreOverrides.add(coreHandler);
      }
      endpointMap.set(routeKey, endpoint);
      endpointOwners.set(routeKey, plugin.name);
    }
    for (const declared of plugin.coreOverrides ?? []) {
      if (!appliedCoreOverrides.has(declared)) {
        throw Errors.badRequest(
          `Plugin "${plugin.name}" declares unused core override "${declared}"; it must provide a matching core method/path with the same route key and handler.`,
        );
      }
    }
  }

  return { endpoints: Array.from(endpointMap.values()), endpointOwners };
}

/**
 * Fail fast on `security: ['none']` + `permission` collisions, and on
 * `bearerKind: 'oauth'` outside the OAuth protocol routes.
 *
 * The first two are mutually exclusive: an unauthenticated route has no
 * subject to evaluate the permission against, so default-deny RBAC would
 * always reject it. `bearerKind: 'oauth'` means "this handler
 * self-authenticates" and skips the normal plugin/JWT/RBAC/JSON-validation
 * pipeline, so any other route trying to use it is almost certainly a latent
 * auth bypass.
 */
function assertRouteSecurityInvariants(endpoints: readonly EndpointDefinition[]): void {
  const oauthSelfAuthAllowlist = new Set([
    'GET /oauth/authorize',
    'POST /oauth/token',
    'POST /oauth/introspect',
    'POST /oauth/revoke',
    'GET /oauth/userinfo',
    'GET /oauth/.well-known/openid-configuration',
    'GET /oauth/.well-known/jwks.json',
  ]);

  for (const ep of endpoints) {
    const security = ep.meta?.security ?? [];
    if (security.includes('none') && ep.meta?.permission) {
      throw Errors.badRequest(
        `Endpoint ${ep.method} ${ep.path} declares security:['none'] AND a permission `
        + `(${ep.meta.permission.resource}:${ep.meta.permission.action}). These are mutually `
        + `exclusive — default-deny RBAC would reject every request.`,
      );
    }

    if (ep.meta?.bearerKind === 'oauth' && !oauthSelfAuthAllowlist.has(`${ep.method} ${ep.path}`)) {
      throw Errors.badRequest(
        `Endpoint ${ep.method} ${ep.path} sets bearerKind:'oauth' but is not an approved self-auth OAuth protocol route.`,
      );
    }
  }
}
