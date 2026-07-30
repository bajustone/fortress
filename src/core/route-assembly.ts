import type { FortressConfig } from './config';
import type { EndpointDefinition, EndpointMeta, EndpointResponse } from './endpoint';
import type { FortressPlugin, PluginDependency, RuntimeFortressPlugin } from './plugin';
import { authEndpoints } from './auth/auth-endpoints';
import { isHttpMethod } from './endpoint';
import { Errors } from './errors';
import { canonicalizeRouteShape } from './http/match';
import { iamEndpoints } from './iam/iam-endpoints';

/** Reserved plugin name backing top-level `routes`. */
export const HOST_ROUTES_PLUGIN_NAME = '__host';

/**
 * Owner marker for Fortress's built-in auth/IAM routes in
 * {@link AssembledRoutes.endpointOwners}.
 *
 * A unique symbol, deliberately not the string `'core'`: plugin owners are
 * stored as their (string) name, and a plugin may legitimately be named
 * `core`. A string sentinel would make that plugin's routes indistinguishable
 * from built-in ones — letting a second plugin silently "override" them
 * (bypassing duplicate detection) and letting them leak into the core call
 * tree as if Fortress owned them.
 */
export const CORE_ENDPOINT_OWNER: unique symbol = Symbol('fortress.core-endpoint-owner');

/** An endpoint's owner: a built-in route, or the plugin name that declared it. */
export type EndpointOwner = string | typeof CORE_ENDPOINT_OWNER;

/**
 * Owner provenance keyed by *cloned* endpoint identity.
 *
 * Route-key lookup (`METHOD /path`) is not sufficient: `path` and `method` are
 * themselves mutable inputs, so a key derived from an endpoint could be made to
 * name a different owner's route. Snapshot clones are per-instance and never
 * handed back to plugins, so their identity is a stable primary key.
 */
const endpointProvenanceRegistry = new WeakMap<object, EndpointProvenance>();

/**
 * What the validated snapshot records about one endpoint.
 *
 * Readonly and frozen before storage: this record is the authority for
 * dispatch ownership and for the manifest's `plugin`/`mounted` columns, and
 * {@link endpointProvenance} hands it straight to callers.
 */
export interface EndpointProvenance {
  /** Stable dispatch owner: the declaring plugin's name, or the core marker. */
  readonly owner: EndpointOwner;
  /**
   * Origin label the route manifest reports: `'auth'` / `'iam'` for built-in
   * routes, the plugin name for plugin routes, and `null` for top-level host
   * routes — which are metadata-only and therefore reported unmounted.
   */
  readonly manifestLabel: string | null;
}

/**
 * Provenance recorded for a snapshot endpoint, or `undefined` for any object
 * that did not come from {@link assembleEndpoints}.
 */
export function endpointProvenance(endpoint: EndpointDefinition): EndpointProvenance | undefined {
  return endpointProvenanceRegistry.get(endpoint);
}

/** Stable dispatch owner for a snapshot endpoint. */
export function endpointOwner(endpoint: EndpointDefinition): EndpointOwner | undefined {
  return endpointProvenanceRegistry.get(endpoint)?.owner;
}

/** Owner every self-managed OAuth protocol route must be declared by. */
const OAUTH_PLUGIN_NAME = 'oauth';

/** What the approval table records about one OAuth protocol route. */
interface OAuthProtocolRoute {
  /** The handler that must serve this route. */
  readonly handler: string;
  /**
   * Whether this handler verifies HTTP Basic *client* credentials, per
   * RFC 6749 §2.3.1, RFC 7662, and RFC 7009.
   *
   * Owning protocol security and verifying Basic are not the same property.
   * `authorize`, `userinfo`, discovery, and JWKS manage their own OAuth
   * protocol security (including intentional public access for discovery and
   * JWKS), but none checks a Basic credential — declaring one of them
   * `security: ['basic']` would falsely claim Basic protection; discovery and
   * JWKS would remain intentionally public. Only the three routes
   * flagged here may carry Basic without an IAM permission.
   */
  readonly verifiesBasicClientAuth: boolean;
}

/**
 * The only routes allowed to manage their own OAuth protocol security, keyed
 * by `METHOD path`.
 *
 * `bearerKind: 'oauth'` means the handler owns that security — authentication
 * or intentional public access — and bypasses Fortress principal resolution,
 * the bearer requirement, RBAC, and body validation. Matching on path alone
 * let any plugin claim the exemption by declaring a route at one of these
 * paths, so the owner and handler are part of the contract too.
 */
const OAUTH_SELF_MANAGED_ROUTES = new Map<string, OAuthProtocolRoute>([
  ['GET /oauth/authorize', { handler: 'handleAuthorizeRequest', verifiesBasicClientAuth: false }],
  ['POST /oauth/token', { handler: 'handleTokenRequest', verifiesBasicClientAuth: true }],
  ['POST /oauth/introspect', { handler: 'handleIntrospectRequest', verifiesBasicClientAuth: true }],
  ['POST /oauth/revoke', { handler: 'handleRevokeRequest', verifiesBasicClientAuth: true }],
  ['GET /oauth/userinfo', { handler: 'handleUserInfoRequest', verifiesBasicClientAuth: false }],
  ['GET /oauth/.well-known/openid-configuration', { handler: 'handleDiscovery', verifiesBasicClientAuth: false }],
  ['GET /oauth/.well-known/jwks.json', { handler: 'handleJwksRequest', verifiesBasicClientAuth: false }],
]);

/** The approved protocol route for this endpoint's owner, method, path, and handler. */
function approvedOAuthProtocolRoute(endpoint: EndpointDefinition): OAuthProtocolRoute | undefined {
  if (endpoint.meta?.bearerKind !== 'oauth')
    return undefined;
  if (endpointProvenance(endpoint)?.owner !== OAUTH_PLUGIN_NAME)
    return undefined;
  const approved = OAUTH_SELF_MANAGED_ROUTES.get(`${endpoint.method.toUpperCase()} ${endpoint.path}`);
  return approved?.handler === endpoint.handler ? approved : undefined;
}

/**
 * Whether an endpoint is an approved OAuth route that verifies Basic *client*
 * credentials in its own handler, and may therefore declare `security:
 * ['basic']` without an IAM permission.
 *
 * Strictly narrower than {@link isApprovedOAuthSelfManagedRoute}: it holds for
 * `POST /oauth/token`, `/oauth/introspect`, and `/oauth/revoke` only.
 */
function isApprovedOAuthBasicClientAuthRoute(endpoint: EndpointDefinition): boolean {
  return approvedOAuthProtocolRoute(endpoint)?.verifiesBasicClientAuth === true;
}

/**
 * Whether an assembled endpoint is an approved self-managed OAuth protocol
 * route: it declares `bearerKind: 'oauth'`, the validated snapshot
 * records `oauth` as its owner, and its canonical method/path maps to exactly
 * the handler expected to serve it.
 *
 * Requires provenance, so it answers `false` for anything that did not come
 * from {@link assembleEndpoints}. Construction validation uses this.
 */
export function isApprovedOAuthSelfManagedRoute(endpoint: EndpointDefinition): boolean {
  return approvedOAuthProtocolRoute(endpoint) !== undefined;
}

/**
 * Whether a route should manage its own OAuth protocol security at request time.
 *
 * Every site that acts on `bearerKind: 'oauth'` — skipping auth, classifying
 * the manifest, excluding a callable, selecting the OAuth parser — goes
 * through this so they cannot drift apart.
 *
 * A provenance-bearing endpoint must be strictly approved. An endpoint with no
 * provenance never went through {@link assembleEndpoints}, so there is nothing
 * to check it against and its declared metadata is honoured as before. That
 * fallback deliberately trusts a caller-supplied fake or capability runtime;
 * every real Fortress snapshot carries provenance and takes the strict path.
 */
export function isSelfManagedOAuthRoute(endpoint: EndpointDefinition): boolean {
  if (endpoint.meta?.bearerKind !== 'oauth')
    return false;
  if (endpointProvenance(endpoint) === undefined)
    return true;
  return isApprovedOAuthSelfManagedRoute(endpoint);
}

/**
 * Clone an endpoint's routing, auth, and response envelope, then freeze it.
 *
 * A plugin keeps references to the route objects it declared, and its
 * `methods()` factory receives them live. Publishing those same objects made
 * the validated route set advisory: flipping `bearerKind` or rewriting `path`
 * after `createFortress()` returned changed dispatch and auth while the cached
 * manifest kept describing the route as it was validated.
 *
 * Bounded on purpose. JSON Schema and Standard Schema objects are carried by
 * reference because schema *identity* binds `$ref` component context (the
 * `WeakMap` in `schema-builder.ts`); cloning them would silently break ref
 * resolution. Schema mutability is therefore a documented non-goal — this
 * freezes the route contract, not the validation schemas hanging off it.
 */
function snapshotEndpoint(endpoint: EndpointDefinition): EndpointDefinition {
  const clone: EndpointDefinition = { ...endpoint };

  if (endpoint.meta) {
    const meta: EndpointMeta = { ...endpoint.meta };
    if (endpoint.meta.tags)
      meta.tags = Object.freeze([...endpoint.meta.tags]) as unknown as string[];
    if (endpoint.meta.security)
      meta.security = Object.freeze([...endpoint.meta.security]) as unknown as EndpointMeta['security'];
    if (endpoint.meta.permission)
      meta.permission = Object.freeze({ ...endpoint.meta.permission });
    clone.meta = Object.freeze(meta);
  }

  // Container only — `body`/`query`/`params` and their Standard Schema
  // counterparts stay referentially identical to the declared schemas.
  if (endpoint.input)
    clone.input = Object.freeze({ ...endpoint.input });

  // `endpointSuccessStatus` reads this on the request path, so the status map
  // and each response envelope are part of the frozen contract.
  if (endpoint.responses) {
    const source = endpoint.responses as Record<string, EndpointResponse>;
    // Null-prototype, and copied under the original property key. `Number(key)`
    // would rewrite a non-numeric key such as `default` to `NaN`; a plain `{}`
    // target would route an own `__proto__` key into the prototype setter
    // instead of preserving it. Both would silently drop a declared response.
    const responses = Object.create(null) as Record<string, EndpointResponse>;
    for (const [key, response] of Object.entries(source))
      responses[key] = Object.freeze({ ...response });
    clone.responses = Object.freeze(responses) as Record<number, EndpointResponse>;
  }

  return Object.freeze(clone);
}

/** The declarative half of a Fortress config — everything route assembly reads. */
export type RouteAssemblyConfig = Pick<FortressConfig, 'plugins' | 'routes'>;

export interface AssembledRoutes {
  /** Configured plugins, with the synthetic `__host` plugin prepended when present. */
  plugins: readonly RuntimeFortressPlugin[];
  /** Deduplicated endpoint set, in registration order. */
  endpoints: EndpointDefinition[];
  /**
   * Owner per canonical `METHOD /path` key: {@link CORE_ENDPOINT_OWNER} for a
   * built-in route, or the owning plugin's name (top-level `routes` are owned
   * by `'__host'`). The call tree uses this to drop core callables a plugin has
   * taken over.
   */
  endpointOwners: Map<string, EndpointOwner>;
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
 * route conflict that would hide a route from an app-aware check is rejected
 * in both. This is parity of the *route surface*, not a boot check — see
 * {@link describeRouteSurface} for what construction still validates on top.
 *
 * The work splits into two phases because a plugin's `methods()` factory can
 * mutate the route objects it was declared with. {@link normalizePlugins}
 * validates the declaration and is safe to run first; {@link assembleEndpoints}
 * derives and validates the resulting route set and must run after the
 * factories, which is what `createFortress()` does. Calling `assembleRoutes()`
 * runs both in one pass, which is correct for config-only tooling because no
 * factory has run — or ever will.
 */
export function assembleRoutes(config: RouteAssemblyConfig): AssembledRoutes {
  const plugins = normalizePlugins(config);
  return { plugins, ...assembleEndpoints(plugins) };
}

/**
 * Phase 1 — properties of the *declaration*, derivable from config alone.
 *
 * Synthesizes the `__host` plugin and validates what a plugin declares:
 * reserved names, duplicate plugin names, malformed endpoint definitions,
 * route-key/handler mismatches, non-object body/query/params schemas. Safe to
 * run before plugin factories, and `createFortress()` does exactly that so a
 * malformed config is rejected before any plugin worker starts.
 */
export function normalizePlugins(config: RouteAssemblyConfig): readonly RuntimeFortressPlugin[] {
  const userPlugins = config.plugins ?? [];
  // `__host` names the synthetic plugin backing top-level `routes`. Reserve it
  // unconditionally, even when no `routes` are declared: a user plugin holding
  // the name would collide the moment `routes` were added, and until then its
  // routes would masquerade as host-owned in the owner map.
  if (userPlugins.some(plugin => plugin.name === HOST_ROUTES_PLUGIN_NAME)) {
    throw Errors.badRequest(
      `Plugin name '${HOST_ROUTES_PLUGIN_NAME}' is reserved for top-level \`routes\`; rename your plugin.`,
    );
  }
  const hostRoutesPlugin: FortressPlugin | null = config.routes
    ? { name: HOST_ROUTES_PLUGIN_NAME, routes: config.routes }
    : null;
  // Always copy: without host routes this used to alias the caller's array, so
  // a later `config.plugins.push(...)` changed the plugin membership that
  // request handling and middleware run against.
  const plugins = Object.freeze(
    hostRoutesPlugin ? [hostRoutesPlugin, ...userPlugins] : [...userPlugins],
  );

  validatePluginRouteShapes(plugins);
  return plugins;
}

/**
 * Phase 2 — properties of the resulting route *set*, and the authoritative
 * one. **Must run after plugin factories.**
 *
 * A plugin's `methods()` factory receives the live route objects — via its own
 * closure and via `ctx.config.plugins[…].routes` — and can mutate them: flip
 * `bearerKind`, rewrite a path onto a core route, add a route, remove one.
 * Merge precedence and the security invariants are only meaningful once that
 * has happened, so `createFortress()` re-derives here and publishes *this*
 * set. Route shapes are re-validated too, since a factory may have added
 * routes that were never checked in phase 1.
 */
export function assembleEndpoints(
  plugins: readonly RuntimeFortressPlugin[],
): Pick<AssembledRoutes, 'endpointOwners' | 'endpoints'> {
  validatePluginRouteShapes(plugins);
  const merged = mergeEndpoints(plugins);
  assertRouteSecurityInvariants(merged.endpoints);
  return merged;
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

  // Only the declared *shape* is checked here, so config-only tooling still
  // rejects a malformed `dependencies` array. Whether a provider is actually
  // registered is a property of the composed runtime, not the declaration, and
  // belongs to `assertPluginDependencyProviders`.
  for (const plugin of plugins) {
    readDeclaredDependencies(plugin);
  }
}

/**
 * Validate the declared shape of `plugin.dependencies` and return it typed.
 *
 * Derivable from the declaration alone, so this is safe everywhere route
 * shapes are validated. It says nothing about whether a provider is registered.
 */
function readDeclaredDependencies(plugin: RuntimeFortressPlugin): readonly PluginDependency[] {
  const dependencies: unknown = plugin.dependencies;
  if (dependencies !== undefined && !Array.isArray(dependencies)) {
    throw Errors.badRequest(`Plugin "${plugin.name}" dependencies must be an array`, {
      details: { plugin: plugin.name, field: 'dependencies' },
    });
  }
  for (const [index, value] of (dependencies ?? []).entries()) {
    if (
      !value || typeof value !== 'object' || Array.isArray(value)
      || typeof value.plugin !== 'string' || value.plugin.length === 0
      || (value.methods !== undefined && (
        !Array.isArray(value.methods)
        || value.methods.some((method: unknown) => typeof method !== 'string' || method.length === 0)
      ))
    ) {
      throw Errors.badRequest(`Plugin "${plugin.name}" dependency at index ${index} is invalid`, {
        details: { plugin: plugin.name, field: `dependencies[${index}]` },
      });
    }
  }
  return (dependencies ?? []) as readonly PluginDependency[];
}

/**
 * Reject a plugin graph whose declared dependency providers are not registered.
 *
 * Runs before plugin factories so a missing provider fails before any factory
 * starts a worker or reaches for the database. Registration order is
 * irrelevant: the full name set is built up front.
 *
 * Composition, not declaration — which is why {@link describeRouteSurface}
 * does not call it. That entry point is explicitly not a boot check, and
 * `fortress init` scaffolds configs that are not yet bootable.
 */
export function assertPluginDependencyProviders(plugins: readonly RuntimeFortressPlugin[]): void {
  const pluginNames = new Set(plugins.map(plugin => plugin.name));
  for (const plugin of plugins) {
    for (const dependency of readDeclaredDependencies(plugin)) {
      if (!pluginNames.has(dependency.plugin)) {
        throw Errors.badRequest(
          `Plugin "${plugin.name}" requires plugin "${dependency.plugin}" to be registered`,
          {
            details: {
              plugin: plugin.name,
              missingPlugin: dependency.plugin,
              requiredMethods: dependency.methods ?? [],
            },
          },
        );
      }
    }
  }
}

/**
 * Re-validate the dependency graph against the surfaces plugin factories
 * actually produced.
 *
 * Presence is re-derived from the current plugin graph rather than from the
 * keys of `pluginMethods`. That map is filled in incrementally as each factory
 * returns, keying every plugin under the name it held at that moment, so a
 * later factory that renames an already-keyed plugin leaves behind a stale key
 * that would otherwise satisfy a dependency on a provider no longer in the
 * graph. Capabilities are
 * then checked per declared method against the surface that was actually
 * produced, closing the case where a plugin with the right name is registered
 * but does not expose what its consumer needs.
 */
export function assertPluginDependencyCapabilities(
  plugins: readonly RuntimeFortressPlugin[],
  pluginMethods: Readonly<Record<string, Readonly<Record<string, unknown>>>>,
): void {
  assertPluginDependencyProviders(plugins);

  for (const plugin of plugins) {
    for (const dependency of readDeclaredDependencies(plugin)) {
      const methods = pluginMethods[dependency.plugin];
      if (!methods) {
        // In the graph but with no surface: the plugin list itself was mutated
        // after `processPlugins` ran.
        throw Errors.badRequest(
          `Plugin "${plugin.name}" dependency "${dependency.plugin}" has no runtime method surface`,
          {
            details: {
              plugin: plugin.name,
              dependencyPlugin: dependency.plugin,
              requiredMethods: dependency.methods ?? [],
            },
          },
        );
      }
      for (const method of dependency.methods ?? []) {
        if (!Object.hasOwn(methods, method) || typeof methods[method] !== 'function') {
          throw Errors.badRequest(
            `Plugin "${plugin.name}" requires callable method "${dependency.plugin}.${method}"`,
            {
              details: {
                plugin: plugin.name,
                dependencyPlugin: dependency.plugin,
                missingMethod: method,
              },
            },
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
  const endpointOwners = new Map<string, EndpointOwner>();

  const routeKeyOf = (endpoint: EndpointDefinition): string =>
    `${endpoint.method.toUpperCase()} ${canonicalizeRouteShape(endpoint.path)}`;

  const coreEndpoints: { endpoint: EndpointDefinition; label: string }[] = [
    ...(Object.values(authEndpoints) as EndpointDefinition[])
      .map(endpoint => ({ endpoint, label: 'auth' })),
    ...(Object.values(iamEndpoints) as EndpointDefinition[])
      .map(endpoint => ({ endpoint, label: 'iam' })),
  ];
  // Core endpoints are module singletons shared by every instance in the
  // process, so they are cloned rather than frozen in place: freezing them
  // would make constructing one Fortress mutate global state for all others.
  for (const { endpoint, label } of coreEndpoints) {
    const routeKey = routeKeyOf(endpoint);
    const snapshot = snapshotEndpoint(endpoint);
    endpointProvenanceRegistry.set(snapshot, Object.freeze({
      owner: CORE_ENDPOINT_OWNER,
      manifestLabel: label,
    }));
    endpointMap.set(routeKey, snapshot);
    endpointOwners.set(routeKey, CORE_ENDPOINT_OWNER);
  }

  for (const plugin of plugins) {
    const appliedCoreOverrides = new Set<string>();
    for (const [routeName, value] of Object.entries(plugin.routes ?? {})) {
      const endpoint = value as EndpointDefinition;
      const routeKey = routeKeyOf(endpoint);
      const owner = endpointOwners.get(routeKey);
      if (owner !== undefined && owner !== CORE_ENDPOINT_OWNER) {
        throw Errors.badRequest(
          `Duplicate endpoint ${routeKey} declared by plugins "${owner}" and "${plugin.name}"`,
        );
      }
      if (owner === CORE_ENDPOINT_OWNER) {
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
      const snapshot = snapshotEndpoint(endpoint);
      endpointProvenanceRegistry.set(snapshot, Object.freeze({
        owner: plugin.name,
        // Top-level `routes` are reported with no owning plugin.
        manifestLabel: plugin.name === HOST_ROUTES_PLUGIN_NAME ? null : plugin.name,
      }));
      endpointMap.set(routeKey, snapshot);
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
 * Fail fast on incompatible security metadata and forged OAuth exemptions.
 *
 * An unauthenticated route has no subject to evaluate a permission against,
 * so default-deny RBAC would always reject it. `bearerKind: 'oauth'` means the
 * handler owns its OAuth protocol security (authentication or intentional
 * public access) and bypasses the normal plugin/JWT/RBAC/JSON-validation
 * pipeline, so any unapproved route trying to use it is a latent auth bypass.
 */
function assertRouteSecurityInvariants(endpoints: readonly EndpointDefinition[]): void {
  for (const ep of endpoints) {
    const security = ep.meta?.security ?? [];

    // 1. Anything claiming the self-managed security exemption must be a
    //    genuine OAuth protocol route. Checked first: a forged route typically
    //    also carries Basic, and the forgery is the more specific diagnosis.
    if (ep.meta?.bearerKind === 'oauth' && !isApprovedOAuthSelfManagedRoute(ep)) {
      const owner = endpointProvenance(ep)?.owner;
      const expectedHandler = OAUTH_SELF_MANAGED_ROUTES.get(`${ep.method.toUpperCase()} ${ep.path}`)?.handler;
      throw Errors.badRequest(
        `Endpoint ${ep.method} ${ep.path} sets bearerKind:'oauth' but is not an approved self-managed OAuth protocol route `
        + `(owner=${typeof owner === 'string' ? `'${owner}'` : 'core'}; expected owner '${OAUTH_PLUGIN_NAME}'`
        + `${expectedHandler ? ` with handler '${expectedHandler}', got '${ep.handler}'` : ' and an approved method/path'}).`,
        { details: { method: ep.method, path: ep.path, handler: ep.handler, expectedHandler } },
      );
    }

    // 2. An approved self-managed route skips principal resolution and
    //    Fortress RBAC outright, so a permission it declares would never be
    //    evaluated — and would otherwise satisfy the Basic rule below, which
    //    is how a permission could make discovery publicly readable while
    //    looking protected.
    if (isApprovedOAuthSelfManagedRoute(ep) && ep.meta?.permission) {
      throw Errors.badRequest(
        `Endpoint ${ep.method} ${ep.path} is a self-managed OAuth protocol route and cannot declare a permission `
        + `(${ep.meta.permission.resource}:${ep.meta.permission.action}). These handlers own their OAuth protocol security `
        + `(authentication or intentional public access) and bypass the Fortress principal/RBAC pipeline, so the permission `
        + `would never be evaluated.`,
        { details: { method: ep.method, path: ep.path, handler: ep.handler } },
      );
    }

    // 3. An unauthenticated route has no subject to evaluate a permission
    //    against, so default-deny RBAC would reject every request.
    if (security.includes('none') && ep.meta?.permission) {
      throw Errors.badRequest(
        `Endpoint ${ep.method} ${ep.path} declares security:['none'] AND a permission `
        + `(${ep.meta.permission.resource}:${ep.meta.permission.action}). These are mutually `
        + `exclusive — default-deny RBAC would reject every request.`,
      );
    }

    // 4. Fortress ships no Basic credential verifier, so Basic metadata alone
    //    does not require a credential and could leave a route unauthenticated.
    //    Only the OAuth client-auth endpoints are exempt, because their handlers
    //    verify those credentials.
    if (security.includes('basic') && !ep.meta?.permission && !isApprovedOAuthBasicClientAuthRoute(ep)) {
      throw Errors.badRequest(
        `Endpoint ${ep.method} ${ep.path} declares security:['basic'] without a permission. `
        + `Fortress ships no Basic credential verifier, so this route does not require Basic credentials and could be served unauthenticated. `
        + `Add a permission and resolve a subject for it (a credential plugin's resolvePrincipal can supply one), `
        + `use security:['bearer'], or use security:['none'] only if the route is intentionally public.`,
        { details: { method: ep.method, path: ep.path, handler: ep.handler } },
      );
    }
  }
}
