import type { DatabaseAdapter, MigratableDatabaseAdapter } from '../adapters/database';
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
import type {
  PluginMethod,
  PluginMethodsOf,
  RuntimeFortressPlugin,
  ValidatePluginRoutes,
} from './plugin';
import type { InferPlugins } from './plugin-methods-map';
import { authEndpoints } from './auth/auth-endpoints';
import { createAuthService } from './auth/auth-service';
import { resolveCookieConfig } from './config';
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
import { publishPluginMembership } from './plugin-membership';
import { processPlugins } from './plugin-runner';
import {
  assembleEndpoints,
  assertPluginDependencyCapabilities,
  assertPluginDependencyProviders,
  CORE_ENDPOINT_OWNER,
  endpointOwner,
  HOST_ROUTES_PLUGIN_NAME,
  isSelfManagedOAuthRoute,
  normalizePlugins,
} from './route-assembly';

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
type ValidateConfiguredPlugin<P> = ValidatePluginMethodSurface<P>
  & (P extends { routes: infer TRoutes }
    ? { routes: ValidatePluginRoutes<TRoutes, NoInferCompat<PluginMethodsOf<P>>> }
    : unknown);
type ValidateConfiguredPlugins<C extends FortressConfig> = C extends {
  plugins: infer TPlugins extends readonly RuntimeFortressPlugin[];
}
  ? { plugins: { readonly [K in keyof TPlugins]: ValidateConfiguredPlugin<TPlugins[K]> } }
  : unknown;
type PluginsFromConfig<C extends FortressConfig> = C extends { plugins: infer TPlugins }
  ? TPlugins extends readonly RuntimeFortressPlugin[] ? TPlugins : readonly []
  : C extends { plugins?: undefined } ? readonly [] : readonly RuntimeFortressPlugin[];

function assertMigratableDatabaseAdapter(
  database: DatabaseAdapter,
): asserts database is MigratableDatabaseAdapter {
  if (
    (database.dialect !== 'sqlite' && database.dialect !== 'pg')
    || typeof database.rawQuery !== 'function'
  ) {
    throw Errors.badRequest(
      'Fortress migrations require a database adapter with dialect: \'sqlite\' | \'pg\' and rawQuery support; use a dialect-specific Drizzle factory or provide a MigratableDatabaseAdapter',
    );
  }
}

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

  // Synthesize a virtual plugin from any top-level `routes` field and validate
  // the declaration, sharing the rules with `describeRouteSurface()` so tooling
  // that reads a config without booting the app sees the same conflicts. This
  // early pass is fail-fast only: a malformed config is rejected before any
  // plugin factory runs. The authoritative endpoint set is re-derived after
  // the factories, below.
  const plugins = normalizePlugins(config);

  // Composition check, deliberately not shared with `describeRouteSurface()`:
  // a plugin declaring a dependency on an unregistered plugin can never boot,
  // and rejecting it here means no factory starts a worker or opens a database
  // handle first. Re-checked after the factories, which may mutate the graph.
  assertPluginDependencyProviders(plugins);

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

  // Derive and revalidate the authoritative graph and route set now that every
  // plugin factory has run. Factories receive live config/route objects and can
  // mutate them, so this pass must precede capability dereferencing as well as
  // publication.
  const { endpoints, endpointOwners } = assembleEndpoints(plugins);
  // The published route set is the authority for dispatch, the manifest,
  // OpenAPI, and the call tree. Its entries were cloned and frozen during
  // assembly; freezing the array itself stops a consumer adding or dropping
  // routes from the validated set after construction.
  Object.freeze(endpoints);

  // Route key -> snapshot endpoint. Call trees bind these clones rather than
  // the originals a plugin still holds, so mutating a declared route object
  // later cannot change what `fortress.call.*` invokes.
  const snapshotByRouteKey = new Map<string, EndpointDefinition>(
    endpoints.map(endpoint => [
      `${endpoint.method.toUpperCase()} ${canonicalizeRouteShape(endpoint.path)}`,
      endpoint,
    ]),
  );
  assertPluginDependencyCapabilities(plugins, pluginMethods);

  // A Fortress-mounted plugin route is executable only when its handler is
  // an own callable method. Fail at startup rather than publishing a call
  // namespace whose first request would 404; top-level host routes remain
  // metadata-only and are intentionally exempt.
  for (const plugin of plugins) {
    if (plugin.name === HOST_ROUTES_PLUGIN_NAME || !plugin.routes)
      continue;
    const methods = pluginMethods[plugin.name];
    if (methods === undefined)
      throw Errors.badRequest(`Plugin "${plugin.name}" did not provide a method map`);
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

  // Wire IAM events → audit log if the plugin is registered.
  if (Object.hasOwn(pluginMethods, 'audit-log')) {
    const auditMethods = pluginMethods['audit-log'];
    if (auditMethods === undefined)
      throw Errors.badRequest('Plugin "audit-log" did not provide a method map');
    if (Object.hasOwn(auditMethods, 'logCustomEvent')) {
      const logCustomEvent = auditMethods.logCustomEvent;
      if (typeof logCustomEvent !== 'function')
        throw Errors.badRequest('Plugin "audit-log" method "logCustomEvent" must be callable');
      iam.addIamObserver(event => logCustomEvent(event));
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
      // Derived once and frozen. This is the authoritative view of the
      // validated route set, so a consumer must not be able to edit the
      // baseline it is checking against. Only the instance's cached manifest
      // is frozen; a direct `buildRouteManifest()` result stays a plain array
      // for callers that legitimately build and adjust their own.
      routeManifest ??= Object.freeze(
        buildRouteManifest(this).map(entry => Object.freeze(entry)),
      ) as RouteManifestEntry[];
      return routeManifest;
    },
    cookies,
    logger,
    telemetry,
    handleRequest: undefined as unknown as (request: Request) => Promise<Response>,
    runPluginMiddleware: (phase, ctx): Promise<void> => runPluginMiddlewareFn(plugins, config, phase, ctx),
    extractAccessToken: (request: Request): string | null => extractAccessTokenFn(request, cookies),
    resolvePrincipal: (request: Request): Promise<ResolvedPrincipal | null> =>
      resolveRequestPrincipalFn(instance, request, plugins),
    serializeAuthCookies: (payload: AuthCookiePayload): string[] =>
      serializeAuthCookiesFn(payload, cookies, {
        access: config.jwt.accessTokenExpirySeconds ?? 900,
        refresh: config.jwt.refreshTokenExpirySeconds ?? 604_800,
      }),
    async migrate(opts?: MigrateOptions): Promise<MigrateResult> {
      // Fortress migrations first — app schemas commonly FK to Fortress
      // tables, so this order is the safe default. The configured adapter
      // owns the migration dialect; instrumentation preserves that capability.
      assertMigratableDatabaseAdapter(db);
      const fortressResult = await migrateUp(db, opts?.targetVersion);
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

  // Publish only after every startup validation has succeeded. A global-symbol
  // property plus the shared registry keeps the snapshot visible when an
  // instance crosses independently loaded ESM/CJS adapter bundles.
  publishPluginMembership(instance, plugins);
  instance.handleRequest = buildHandleRequest(instance, plugins);

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
    // Derived from the validated snapshot, keyed by handler — plugin route
    // keys are required to equal their handler, so this reproduces the
    // declared namespace without reading the mutable route record.
    const genericRoutes = Object.create(null) as Record<string, EndpointDefinition>;
    for (const endpoint of endpoints) {
      if (endpointOwner(endpoint) !== plugin.name)
        continue;
      if (!isSelfManagedOAuthRoute(endpoint))
        genericRoutes[endpoint.handler] = endpoint;
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
      // Core route names come from the built-in maps, but the values bound
      // into the call tree are the per-instance clones.
      const snapshot = snapshotByRouteKey.get(key);
      if (snapshot && endpointOwners.get(key) === CORE_ENDPOINT_OWNER)
        effective[name] = snapshot;
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
