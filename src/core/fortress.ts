import type { OpenAPISpec } from '../plugins/openapi/spec-builder';
import type { AuthEvent } from './auth/auth-service';
import type { CallTree } from './call-tree';
import type {
  FortressAuthRuntime,
  FortressHttpRuntime,
  FortressManifestRuntime,
  FortressMigrationRuntime,
  FortressObservabilityRuntime,
  FortressPluginRuntime,
  FortressToOpenAPIOptions,
  MigrateOptions,
  MigrateResult,
  PluginMethodsValidator,
} from './capabilities';
import type { FortressConfig } from './config';
import type { EndpointDefinition } from './endpoint';
import type { AuthCookiePayload } from './http/cookie-serialize';
import type { ResolvedPrincipal } from './http/principal';
import type { IamEvent, PermissionCheckEvent } from './iam/iam-service';
import type { PermissionSyncOptions, PermissionSyncResult } from './iam/permission-sync';
import type { RouteManifestEntry } from './manifest/route-manifest';
import type { FortressPlugin, PluginMethod, RuntimeFortressPlugin } from './plugin';
import type { InferPlugins } from './plugin-methods-map';
import { authEndpoints } from './auth/auth-endpoints';
import { createAuthService } from './auth/auth-service';
import { resolveCookieConfig } from './config';
import { isHttpMethod } from './endpoint';
import { Errors } from './errors';
import { buildCall } from './http/call';
import { serializeAuthCookies as serializeAuthCookiesFn } from './http/cookie-serialize';
import { buildHandleRequest } from './http/handle-request';
import { canonicalizeRouteShape } from './http/match';
import { runPluginMiddleware as runPluginMiddlewareFn } from './http/plugin-middleware';
import { resolveRequestPrincipal as resolveRequestPrincipalFn } from './http/principal';
import { extractAccessToken as extractAccessTokenFn } from './http/token-extraction';
import { iamEndpoints } from './iam/iam-endpoints';
import { createIamService } from './iam/iam-service';
import { runPermissionSync } from './iam/permission-sync';
import { buildRouteManifest } from './manifest/route-manifest';
import { migrateUp } from './migrations/engine';
import { instrumentAdapter } from './observability/db-instrumentation';
import { SILENT_LOGGER } from './observability/logger';
import { NO_OP_TELEMETRY } from './observability/types';
import { toOpenAPI as endpointsToOpenAPI } from './openapi';
import { processPlugins } from './plugin-runner';

/**
 * Configured fortress instance returned by {@link createFortress}.
 *
 * One generic — the `const` plugin tuple passed to {@link createFortress} —
 * is the source of every derived surface: the typed plugin methods
 * (`plugins`) and the namespaced typed call tree (`call`) are both
 * projections of it and cannot drift apart (ADR 0001 §1).
 *
 * Everything else the instance exposes is declared on the composed runtime
 * capability interfaces (`src/core/capabilities.ts`): HTTP dispatch, the
 * auth boundary, plugin middleware/dynamic lookup, manifest introspection,
 * migrations, and observability. Adapters and utilities accept those focused
 * capabilities rather than this full interface.
 */
export interface Fortress<
  TPlugins extends readonly RuntimeFortressPlugin[] = readonly RuntimeFortressPlugin[],
> extends
  FortressHttpRuntime,
  FortressAuthRuntime,
  FortressPluginRuntime,
  FortressManifestRuntime,
  FortressMigrationRuntime,
  FortressObservabilityRuntime {
  /**
   * Typed plugin-method surfaces inferred from the configured tuple. Known
   * plugin names are exact keys; unknown keys are compile errors. For
   * dynamically named plugins use
   * {@link FortressPluginRuntime.resolvePlugin} instead.
   */
  readonly plugins: InferPlugins<TPlugins>;
  /**
   * Namespaced typed in-process client: `call.auth.*` and `call.iam.*` for
   * core endpoints, `call.plugins.<name>.*` for each configured plugin with
   * concrete routes. Input/output types are inferred from each endpoint's
   * declared body/query/params/response schemas.
   *
   * Under the hood, each callable serializes its input to a `Request` and
   * delegates to `fortress.handleRequest`, so middleware, token
   * verification, RBAC, and validation all run — the same path a network
   * client would eventually hit. See `src/core/http/call.ts`.
   */
  readonly call: CallTree<TPlugins>;
}

// Option/result types for the migration, manifest, and plugin capabilities
// live with their capability interfaces; re-exported here for discoverability
// next to `createFortress`.
export type {
  FortressToOpenAPIOptions,
  MigrateOptions,
  MigrateResult,
  PluginMethodsValidator,
} from './capabilities';

const MIN_SECRET_BYTES = 32;

type IsAny<T> = 0 extends (1 & T) ? true : false;
type NoInferCompat<T> = [T][T extends any ? 0 : never];
type CallableMethodProjection<TMethods extends object> = IsAny<TMethods> extends true
  ? TMethods
  : { [K in keyof TMethods]: TMethods[K] extends PluginMethod ? TMethods[K] : never };
type ValidatePluginMethodSurface<P> = P extends {
  methods: (...args: infer TArgs) => infer TMethods extends object;
}
  ? Omit<P, 'methods'> & { methods: (...args: TArgs) => CallableMethodProjection<TMethods> }
  : P;
type ValidateConfiguredPlugins<C extends FortressConfig> = C extends {
  plugins: infer TPlugins extends readonly RuntimeFortressPlugin[];
}
  ? { plugins: { readonly [K in keyof TPlugins]: ValidatePluginMethodSurface<TPlugins[K]> } }
  : unknown;
type PluginsFromConfig<C extends FortressConfig> = C extends { plugins: infer TPlugins }
  ? TPlugins extends readonly RuntimeFortressPlugin[] ? TPlugins : readonly []
  : C extends { plugins?: undefined } ? readonly [] : readonly RuntimeFortressPlugin[];

/**
 * Build a configured {@link Fortress} instance from a {@link FortressConfig}.
 *
 * Validates the JWT secret strength, deduplicates and processes the plugin
 * list, wires up auth/IAM services, and returns the assembled instance with
 * type-safe plugin method access for any plugins listed in the config.
 */
export function createFortress(
  config: FortressConfig & { plugins?: undefined },
): Fortress<readonly []>;
export function createFortress<const C extends FortressConfig>(
  config: C & ValidateConfiguredPlugins<NoInferCompat<C>>,
): Fortress<PluginsFromConfig<C>>;
export function createFortress<const T extends readonly RuntimeFortressPlugin[]>(
  config: FortressConfig & { plugins?: T },
): Fortress<T> {
  // Validate JWT key strength (HS256 shared-secret bytes).
  const keys = Array.isArray(config.jwt.key) ? config.jwt.key : [config.jwt.key];
  for (const key of keys) {
    if (new TextEncoder().encode(key).length < MIN_SECRET_BYTES) {
      throw Errors.badRequest(
        `JWT key must be at least ${MIN_SECRET_BYTES} bytes for HS256 security. Got ${new TextEncoder().encode(key).length} bytes.`,
      );
    }
  }

  const session = config.jwt.session;
  if (session) {
    for (const [name, value] of Object.entries(session)) {
      if (value != null && (!Number.isInteger(value) || value <= 0)) {
        throw Errors.badRequest(`jwt.session.${name} must be a positive integer`);
      }
    }
  }

  // Synthesize a virtual plugin from any top-level `routes` field so host
  // apps don't have to hand-roll a one-field plugin just to register their
  // own endpoints. Prepended to the plugin list so its routes appear before
  // explicit plugins in the manifest, matching the registration order a
  // user would write themselves.
  const HOST_ROUTES_PLUGIN_NAME = '__host';
  const userPlugins = config.plugins ?? [];
  if (config.routes) {
    const collision = userPlugins.find(p => p.name === HOST_ROUTES_PLUGIN_NAME);
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

  // Resolve observability defaults. SILENT_LOGGER and NO_OP_TELEMETRY are
  // zero-allocation singletons — if the caller doesn't opt in, Fortress
  // never writes to stderr and every metric/span call is a no-op.
  const logger = config.logger ?? SILENT_LOGGER;
  const telemetry = config.observability ?? NO_OP_TELEMETRY;

  // Wrap the adapter with DB instrumentation. When `telemetry` is the
  // no-op default, the wrapper records into a no-op histogram — essentially
  // free. When a real OTel adapter is wired, every Fortress-internal query
  // (and every plugin query that also uses this adapter) emits the stable
  // `db.client.operation.duration` metric with standard attributes.
  const db = instrumentAdapter(config.database, telemetry);

  // Validate plugin name uniqueness
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

  // Token-verify histogram is built before the auth service so it can be
  // passed in via deps. Kept here (not inside auth-service) so the metric
  // catalog lives in one place.
  const tokenVerifyDuration = telemetry.meter.createHistogram('fortress.auth.token_verify.duration', {
    unit: 's',
    description: 'JWT access token verification latency',
    boundaries: [0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1],
  });

  const auth = createAuthService(db, config, plugins, { logger, telemetry, tokenVerifyDuration });
  const iam = createIamService(db, config, { logger, telemetry });
  const pluginMethods = processPlugins(plugins, db, config, auth, iam, logger);

  // A Fortress-mounted plugin route is executable only when its handler is
  // an own callable method. Fail at startup rather than publishing a call
  // namespace whose first request would 404; top-level host routes remain
  // metadata-only and are intentionally exempt.
  for (const plugin of plugins) {
    if (plugin.name === HOST_ROUTES_PLUGIN_NAME || !plugin.routes)
      continue;
    const methods = pluginMethods[plugin.name];
    for (const endpoint of Object.values(plugin.routes)) {
      if (!Object.hasOwn(methods, endpoint.handler) || typeof methods[endpoint.handler] !== 'function') {
        throw Errors.badRequest(
          `Plugin "${plugin.name}" route handler "${endpoint.handler}" must be an own callable method`,
        );
      }
    }
  }

  // --- Wire built-in telemetry observers ------------------------------
  //
  // Translate AuthEvent / IamEvent / PermissionCheckEvent into metric
  // updates. Attribute keys follow the Prometheus `.total` convention
  // for counters and seconds for durations. User IDs are NEVER placed
  // on metric attributes (cardinality bomb) — they go on spans/logs.
  const authEventCounter = telemetry.meter.createCounter('fortress.auth.events.total', {
    description: 'Auth lifecycle events (login, register, refresh, logout, token reuse)',
  });
  const iamEventCounter = telemetry.meter.createCounter('fortress.iam.events.total', {
    description: 'IAM mutation events (role/permission/binding/group changes)',
  });
  const permissionCheckDuration = telemetry.meter.createHistogram('fortress.iam.permission_check.duration', {
    unit: 's',
    description: 'Permission check latency',
    boundaries: [0.0001, 0.0005, 0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1],
  });
  const cacheHitCounter = telemetry.meter.createCounter('fortress.iam.permission_check.cache.hits', {
    description: 'Permission check resolved from cache',
  });
  const cacheMissCounter = telemetry.meter.createCounter('fortress.iam.permission_check.cache.misses', {
    description: 'Permission check that hit the database',
  });

  auth.addAuthObserver((event: AuthEvent) => {
    authEventCounter.add(1, {
      event: event.eventType,
      outcome: event.outcome ?? 'n/a',
      method: event.method ?? 'n/a',
    });
  });

  iam.addIamObserver((event: IamEvent) => {
    iamEventCounter.add(1, { event: event.eventType });
  });

  iam.addPermissionCheckObserver((event: PermissionCheckEvent) => {
    permissionCheckDuration.record(event.durationSeconds, {
      subject_type: event.subjectType,
      result: event.allowed ? 'allow' : 'deny',
      cached: event.cached ? 'true' : 'false',
    });
    if (event.cached) {
      cacheHitCounter.add(1);
    }
    else {
      cacheMissCounter.add(1);
    }
  });

  // Wire IAM events → audit log if the plugin is registered
  if (Object.hasOwn(pluginMethods, 'audit-log') && Object.hasOwn(pluginMethods['audit-log'], 'logCustomEvent')) {
    const logCustomEvent = pluginMethods['audit-log'].logCustomEvent as (event: IamEvent) => Promise<void>;
    iam.addIamObserver(event => logCustomEvent(event));
  }

  // Assemble all endpoint definitions. A plugin may intentionally override a
  // core route, but two plugins claiming the same method+path is ambiguous and
  // therefore rejected instead of depending on registration order.
  const endpointMap = new Map<string, EndpointDefinition>();
  const endpointOwners = new Map<string, string>();
  const coreEndpoints: EndpointDefinition[] = [
    ...Object.values(authEndpoints) as EndpointDefinition[],
    ...Object.values(iamEndpoints) as EndpointDefinition[],
  ];
  for (const ep of coreEndpoints) {
    const routeKey = `${ep.method.toUpperCase()} ${canonicalizeRouteShape(ep.path)}`;
    endpointMap.set(routeKey, ep);
    endpointOwners.set(routeKey, 'core');
  }
  for (const plugin of plugins) {
    const appliedCoreOverrides = new Set<string>();
    for (const [routeName, value] of Object.entries(plugin.routes ?? {})) {
      const ep = value as EndpointDefinition;
      const routeKey = `${ep.method.toUpperCase()} ${canonicalizeRouteShape(ep.path)}`;
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
        if (routeName !== coreHandler || ep.handler !== coreHandler) {
          throw Errors.badRequest(
            `Plugin "${plugin.name}" overrides core route ${routeKey}; its route key and handler must both be "${coreHandler}".`,
          );
        }
        appliedCoreOverrides.add(coreHandler);
      }
      endpointMap.set(routeKey, ep);
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
  const endpoints = Array.from(endpointMap.values());

  // L-tier: fail-fast on `security: ['none']` + `permission` collisions.
  // The two are mutually exclusive: an unauthenticated route has no subject
  // to evaluate the permission against, so default-deny RBAC would always
  // reject it. Catch the misconfiguration at startup, not at first request.
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

    // P3.6: `bearerKind: 'oauth'` means "this handler self-authenticates"
    // and therefore skips the normal plugin/JWT/RBAC/JSON-validation
    // pipeline. It is intentionally reserved for the OAuth protocol routes
    // that parse form bodies or OAuth access tokens themselves. Any other
    // route trying to use it is almost certainly a latent auth bypass.
    if (ep.meta?.bearerKind === 'oauth' && !oauthSelfAuthAllowlist.has(`${ep.method} ${ep.path}`)) {
      throw Errors.badRequest(
        `Endpoint ${ep.method} ${ep.path} sets bearerKind:'oauth' but is not an approved self-auth OAuth protocol route.`,
      );
    }
  }

  // Resolve cookie config once at startup so all HTTP entry points share names.
  const cookies = resolveCookieConfig(config.cookies);

  // Build the framework-agnostic HTTP auxiliary closures upfront. `handleRequest`
  // and `call` both get bound after the instance is constructed because
  // they need the assembled `Fortress` object (route table is built from
  // `endpoints`; `call` delegates to `handleRequest`).
  let routeManifest: RouteManifestEntry[] | undefined;

  const resolvePlugin = (<TMethods>(name: string, validator?: PluginMethodsValidator<TMethods>): TMethods | unknown => {
    // Dynamic lookup is erased by design: without a runtime validator the
    // caller gets `unknown`. Static access goes through `fortress.plugins`.
    if (!Object.hasOwn(pluginMethods, name))
      throw Errors.notFound(`Plugin '${name}' is not registered`);
    const methods = (pluginMethods as Record<string, unknown>)[name];
    if (validator && !validator(methods))
      throw Errors.badRequest(`Plugin '${name}' methods failed runtime validation`);
    return methods;
  }) as Fortress<T>['resolvePlugin'];

  const instance: Fortress<T> = {
    auth,
    iam,
    plugins: pluginMethods as InferPlugins<T>,
    call: Object.assign(Object.create(null), {
      auth: Object.create(null),
      iam: Object.create(null),
      plugins: Object.create(null),
    }) as Fortress<T>['call'],
    resolvePlugin,
    config,
    endpoints,
    get manifest(): RouteManifestEntry[] {
      routeManifest ??= buildRouteManifest(this);
      return routeManifest;
    },
    cookies,
    logger,
    telemetry,
    handleRequest: undefined as unknown as (request: Request) => Promise<Response>,
    runPluginMiddleware: (phase, ctx): Promise<void> => runPluginMiddlewareFn(plugins, config, phase, ctx),
    extractAccessToken: (request: Request): string | null => extractAccessTokenFn(request, cookies),
    resolvePrincipal: (request: Request): Promise<ResolvedPrincipal | null> =>
      resolveRequestPrincipalFn(instance, request),
    serializeAuthCookies: (payload: AuthCookiePayload): string[] =>
      serializeAuthCookiesFn(payload, cookies, {
        access: config.jwt.accessTokenExpirySeconds ?? 900,
        refresh: config.jwt.refreshTokenExpirySeconds ?? 604_800,
      }),
    async migrate(opts?: MigrateOptions): Promise<MigrateResult> {
      // Fortress migrations first — app schemas commonly FK to fortress
      // tables, so this order is the safe default. Unwrap the instrumented
      // adapter so `db.dialect` reflects the underlying engine.
      const fortressResult = await migrateUp(db, opts?.dialect, opts?.targetVersion);
      let appRan = false;
      if (opts?.migrateApp) {
        await opts.migrateApp();
        appRan = true;
      }
      return { fortress: fortressResult, appRan };
    },
    syncPermissionsFromManifest(opts?: PermissionSyncOptions): Promise<PermissionSyncResult> {
      return runPermissionSync(iam, opts?.endpoints ?? instance.endpoints, opts);
    },
    toOpenAPI(opts?: FortressToOpenAPIOptions): OpenAPISpec {
      return endpointsToOpenAPI(opts?.endpoints ?? instance.endpoints, opts);
    },
  };

  instance.handleRequest = buildHandleRequest(instance);

  // Assemble the namespaced typed call tree (ADR 0001 §5). Core auth/IAM
  // callables live under fixed namespaces; each plugin with routes gets its
  // own namespace keyed by its (startup-unique) name, so cross-plugin call
  // collisions are impossible by construction. Top-level `routes` are
  // metadata for manifest/OpenAPI/protected host routes; they carry no
  // plugin methods, so exposing them as callables would create a runtime
  // `NOT_FOUND` footgun — the `__host` virtual plugin is skipped.
  const pluginCallTree: Record<string, Record<string, unknown>> = Object.create(null) as Record<string, Record<string, unknown>>;
  for (const plugin of plugins) {
    if (plugin.name === HOST_ROUTES_PLUGIN_NAME || !plugin.routes)
      continue;
    const genericRoutes = Object.create(null) as Record<string, EndpointDefinition>;
    for (const [name, endpoint] of Object.entries(plugin.routes)) {
      if (endpoint.meta?.bearerKind !== 'oauth')
        genericRoutes[name] = endpoint;
    }
    pluginCallTree[plugin.name] = buildCall(instance, genericRoutes);
  }
  // `call` is readonly on the returned public surface, but is populated once
  // here after `handleRequest` has been bound.
  const effectiveCoreRoutes = (
    routes: Record<string, EndpointDefinition>,
  ): Record<string, EndpointDefinition> => {
    const effective = Object.create(null) as Record<string, EndpointDefinition>;
    for (const [name, endpoint] of Object.entries(routes)) {
      const key = `${endpoint.method.toUpperCase()} ${canonicalizeRouteShape(endpoint.path)}`;
      if (endpointOwners.get(key) === 'core')
        effective[name] = endpoint;
    }
    return effective;
  };
  (instance as { call: unknown }).call = Object.assign(Object.create(null), {
    auth: buildCall(instance, effectiveCoreRoutes(authEndpoints as unknown as Record<string, EndpointDefinition>)),
    iam: buildCall(instance, effectiveCoreRoutes(iamEndpoints as unknown as Record<string, EndpointDefinition>)),
    plugins: pluginCallTree,
  });

  return instance;
}
