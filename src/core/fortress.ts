import type { AuthEvent, AuthService } from './auth/auth-service';
import type { FortressConfig, ResolvedCookieConfig } from './config';
import type { EndpointDefinition } from './endpoint';
import type { AuthCookiePayload } from './http/cookie-serialize';
import type { PluginRequestContext } from './http/plugin-middleware';
import type { ResolvedPrincipal } from './http/principal';
import type { IamEvent, IamService, PermissionCheckEvent } from './iam/iam-service';
import type { FortressLogger } from './observability/logger';
import type { TelemetryProvider } from './observability/types';
import type { FortressPlugin, MiddlewareDefinition } from './plugin';
import type { InferPlugins } from './plugin-methods-map';
import { authEndpoints } from './auth/auth-endpoints';
import { createAuthService } from './auth/auth-service';
import { resolveCookieConfig } from './config';
import { Errors } from './errors';
import { serializeAuthCookies as serializeAuthCookiesFn } from './http/cookie-serialize';
import { buildHandleRequest } from './http/handle-request';
import { runPluginMiddleware as runPluginMiddlewareFn } from './http/plugin-middleware';
import { resolveRequestPrincipal as resolveRequestPrincipalFn } from './http/principal';
import { extractAccessToken as extractAccessTokenFn } from './http/token-extraction';
import { iamEndpoints } from './iam/iam-endpoints';
import { createIamService } from './iam/iam-service';
import { instrumentAdapter } from './observability/db-instrumentation';
import { SILENT_LOGGER } from './observability/logger';
import { NO_OP_TELEMETRY } from './observability/types';
import { processPlugins } from './plugin-runner';

/**
 * Configured fortress instance returned by {@link createFortress}. Holds the
 * core auth and IAM services, the resolved config, every endpoint definition
 * (auth + IAM + plugin routes), and the typed plugin method surface.
 *
 * Also exposes the framework-agnostic HTTP entry points
 * ({@link Fortress.handleRequest}, {@link Fortress.runPluginMiddleware},
 * {@link Fortress.extractAccessToken}, {@link Fortress.serializeAuthCookies})
 * that adapters delegate to. See `src/core/http/`.
 */
// eslint-disable-next-line ts/no-unsafe-function-type -- fallback type for untyped plugin access
export interface Fortress<TPlugins = Record<string, Record<string, Function>>> {
  auth: AuthService;
  iam: IamService;
  plugins: TPlugins;
  config: Readonly<FortressConfig>;
  /** All endpoint definitions (auth + IAM + plugins) with JSON Schema metadata. */
  endpoints: EndpointDefinition[];
  /** Resolved auth-cookie names and attributes (NODE_ENV-aware). */
  cookies: ResolvedCookieConfig;
  /** Resolved logger (defaults to a silent no-op when `config.logger` is unset). */
  logger: FortressLogger;
  /** Resolved telemetry provider (defaults to a no-op when `config.observability` is unset). */
  telemetry: TelemetryProvider;
  /**
   * Handle a Fortress-managed request and return a web-standard `Response`.
   * Composes plugin middleware, token verification, default-deny RBAC,
   * validation, and dispatch.
   *
   * Adapters call this for paths owned by Fortress (e.g. `/auth/*`,
   * `/iam/*`, plugin-registered routes). See `src/core/http/handle-request.ts`.
   */
  handleRequest: (request: Request) => Promise<Response>;
  /**
   * Run plugin middleware at a given lifecycle phase, passing a duck-typed
   * request context. Adapters call this on user-owned routes so plugins
   * like rate-limit and audit-log still apply outside Fortress paths.
   */
  runPluginMiddleware: (
    phase: MiddlewareDefinition['position'],
    ctx: PluginRequestContext,
  ) => Promise<void>;
  /**
   * Extract the access token from a request, preferring the configured
   * cookie and falling back to `Authorization: Bearer`.
   */
  extractAccessToken: (request: Request) => string | null;
  /**
   * Resolve the request principal by trying plugin `resolvePrincipal`
   * hooks (e.g. `api-key`) first, then falling back to the configured JWT
   * bearer token. Non-throwing — returns `null` when no credential is
   * present or the JWT fails to verify.
   *
   * Adapter user-route middleware calls this so api-keys, cookies, and
   * bearer tokens authenticate uniformly on user-owned routes — not just
   * Fortress-owned routes dispatched through `handleRequest`.
   */
  resolvePrincipal: (request: Request) => Promise<ResolvedPrincipal | null>;
  /**
   * Serialize an auth result (or pair of tokens) into one or two
   * `Set-Cookie` header values using the resolved cookie config and the
   * configured token expiries.
   */
  serializeAuthCookies: (payload: AuthCookiePayload) => string[];
}

/**
 * Type-safe helper to retrieve a plugin's methods from a Fortress instance.
 *
 * Since plugin methods are dynamically typed at runtime, this helper lets
 * consumers provide a known interface for type-safe access without casting.
 *
 * @example
 * ```ts
 * interface TwoFactorMethods {
 *   setup: (userId: number) => Promise<{ secret: string; qrCode: string }>;
 *   verify: (userId: number, code: string) => Promise<boolean>;
 * }
 *
 * const twoFactor = getPluginMethods<TwoFactorMethods>(fortress, 'two-factor');
 * const result = await twoFactor.setup(userId); // fully typed
 * ```
 */
export function getPluginMethods<T>(fortress: Fortress, pluginName: string): T {
  const methods = fortress.plugins[pluginName];
  if (!methods) {
    throw Errors.notFound(`Plugin '${pluginName}' is not registered`);
  }
  return methods as T;
}

const MIN_SECRET_BYTES = 32;

/**
 * Build a configured {@link Fortress} instance from a {@link FortressConfig}.
 *
 * Validates the JWT secret strength, deduplicates and processes the plugin
 * list, wires up auth/IAM services, and returns the assembled instance with
 * type-safe plugin method access for any plugins listed in the config.
 */
export function createFortress<const T extends readonly FortressPlugin[]>(
  config: FortressConfig & { plugins?: T },
): Fortress<InferPlugins<T>> {
  // Validate JWT secret strength
  const secrets = Array.isArray(config.jwt.secret) ? config.jwt.secret : [config.jwt.secret];
  for (const secret of secrets) {
    if (new TextEncoder().encode(secret).length < MIN_SECRET_BYTES) {
      throw Errors.badRequest(
        `JWT secret must be at least ${MIN_SECRET_BYTES} bytes for HS256 security. Got ${new TextEncoder().encode(secret).length} bytes.`,
      );
    }
  }

  const plugins = config.plugins ?? [];

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
  if (pluginMethods['audit-log']?.logCustomEvent) {
    const logCustomEvent = pluginMethods['audit-log'].logCustomEvent as (event: IamEvent) => Promise<void>;
    iam.addIamObserver(event => logCustomEvent(event));
  }

  // Assemble all endpoint definitions: core auth + IAM + plugin routes
  // Deduplicate by method+path — plugin routes take priority over core definitions
  const pluginEndpoints: EndpointDefinition[] = [];
  for (const plugin of plugins) {
    if (plugin.routes) {
      pluginEndpoints.push(...plugin.routes);
    }
  }
  const endpointMap = new Map<string, EndpointDefinition>();
  for (const ep of [...authEndpoints, ...iamEndpoints, ...pluginEndpoints]) {
    endpointMap.set(`${ep.method} ${ep.path}`, ep);
  }
  const endpoints = Array.from(endpointMap.values());

  // Resolve cookie config once at startup so all HTTP entry points share names.
  const cookies = resolveCookieConfig(config.cookies);

  // Build the framework-agnostic HTTP auxiliary closures upfront. `handleRequest`
  // gets bound after the instance is constructed because it needs the
  // assembled `Fortress` object (route table is built from `endpoints`).
  const instance = {
    auth,
    iam,
    plugins: pluginMethods as InferPlugins<T>,
    config,
    endpoints,
    cookies,
    logger,
    telemetry,
    handleRequest: undefined as unknown as (request: Request) => Promise<Response>,
    runPluginMiddleware: (phase, ctx) => runPluginMiddlewareFn(plugins, config, phase, ctx),
    extractAccessToken: (request: Request): string | null => extractAccessTokenFn(request, cookies),
    resolvePrincipal: (request: Request): Promise<ResolvedPrincipal | null> =>
      resolveRequestPrincipalFn(instance as Fortress, request),
    serializeAuthCookies: (payload: AuthCookiePayload): string[] =>
      serializeAuthCookiesFn(payload, cookies, {
        access: config.jwt.accessTokenExpirySeconds ?? 900,
        refresh: config.jwt.refreshTokenExpirySeconds ?? 604_800,
      }),
  } satisfies Fortress<InferPlugins<T>>;

  instance.handleRequest = buildHandleRequest(instance as Fortress);
  return instance;
}
