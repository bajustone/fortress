/**
 * Minimal runtime capability interfaces.
 *
 * Framework adapters and utility boundaries accept the capability they
 * actually use instead of a full (erased) `Fortress` instance. Every
 * concrete `Fortress<TPlugins>` composes all of these interfaces, so any
 * instance satisfies any capability parameter with no casts; conversely, a
 * test can hand-roll a capability object without building a full instance.
 *
 * Member sets are derived from an audit of every erased-boundary call site
 * (issue #32 / ADR 0001) — a capability never carries a member no consumer
 * uses.
 */

import type { OpenAPISpec } from '../plugins/openapi/spec-builder';
import type { AuthService } from './auth/auth-service';
import type { FortressConfig, ResolvedCookieConfig } from './config';
import type { AnyPublishedEndpointDefinition, EndpointDefinitionLike } from './endpoint';
import type { AuthCookiePayload } from './http/cookie-serialize';
import type { PluginRequestContext } from './http/plugin-middleware';
import type { ResolvedPrincipal } from './http/principal';
import type { IamService } from './iam/iam-service';
import type { PermissionSyncOptions, PermissionSyncResult } from './iam/permission-sync';
import type { PublishedRouteManifest } from './manifest/route-manifest';
import type { MigrationApplyResult } from './migrations/engine';
import type { FortressLogger } from './observability/logger';
import type { TelemetryProvider } from './observability/types';
import type { ToOpenAPIOptions } from './openapi';
import type { MiddlewareDefinition } from './plugin';

/** Options accepted by {@link FortressManifestRuntime.toOpenAPI}. */
export interface FortressToOpenAPIOptions extends ToOpenAPIOptions {
  /** Override the endpoints to emit. Defaults to the instance's `endpoints`. */
  endpoints?: readonly EndpointDefinitionLike[];
}

/** Options accepted by {@link FortressMigrationRuntime.migrate}. */
export interface MigrateOptions {
  /**
   * Optional host-app migration step. Runs after Fortress migrations
   * complete; any thrown error propagates after Fortress migrations have
   * already been applied. Library-agnostic: pass any `() => Promise<void>`
   * — e.g. drizzle's `migrate(db, { migrationsFolder })`, Knex's
   * `db.migrate.latest()`, a hand-rolled SQL runner.
   */
  migrateApp?: () => Promise<void>;
  /** Stop applying Fortress migrations after this version. Defaults to the latest. */
  targetVersion?: number;
}

/** Result returned by {@link FortressMigrationRuntime.migrate}. */
export interface MigrateResult {
  /** Result of the Fortress-managed migration step. */
  fortress: MigrationApplyResult;
  /** `true` if `migrateApp` was supplied and ran to completion. */
  appRan: boolean;
}

/** Type-guard used by {@link FortressPluginRuntime.resolvePlugin} to prove a dynamic plugin surface. */
export type PluginMethodsValidator<T> = (value: unknown) => value is T;

/**
 * HTTP dispatch capability: everything needed to mount Fortress-owned routes
 * on a host framework and forward requests into the core pipeline.
 */
export interface FortressHttpRuntime {
  /** All endpoint definitions (auth + IAM + plugins) with JSON Schema metadata. */
  readonly endpoints: readonly AnyPublishedEndpointDefinition[];
  /** Canonical generated route-security manifest derived from endpoint metadata. */
  readonly manifest: PublishedRouteManifest;
  readonly config: Readonly<FortressConfig>;
  /**
   * Handle a Fortress-managed request and return a web-standard `Response`.
   * Composes plugin middleware, token verification, default-deny RBAC,
   * validation, and dispatch.
   */
  handleRequest: (request: Request) => Promise<Response>;
}

/**
 * Auth boundary capability: principal resolution, token extraction, cookie
 * serialization, and the auth/IAM services — what adapter middleware needs
 * on user-owned routes.
 */
export interface FortressAuthRuntime {
  readonly auth: AuthService;
  readonly iam: IamService;
  /** Resolved auth-cookie names and attributes. */
  readonly cookies: ResolvedCookieConfig;
  readonly config: Readonly<FortressConfig>;
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
 * Plugin access capability: run plugin middleware on user-owned routes and
 * resolve plugin method surfaces dynamically.
 *
 * The `plugins` member is intentionally erased to `object` here — static,
 * inferred access lives on `Fortress<TPlugins>.plugins`; dynamic access goes
 * through {@link FortressPluginRuntime.resolvePlugin} and is `unknown`
 * unless a runtime validator proves it.
 */
export interface FortressPluginRuntime {
  readonly config: Readonly<FortressConfig>;
  /** Erased plugin-methods record. Prefer typed `Fortress<TPlugins>.plugins`. */
  readonly plugins: object;
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
   * Dynamic plugin lookup. Without a validator the result is `unknown`;
   * pass a type-guard to prove the surface at runtime. Caller-selected
   * generic assertions are intentionally not expressible.
   */
  readonly resolvePlugin: {
    (name: string): unknown;
    <T>(name: string, validator: PluginMethodsValidator<T>): Readonly<T>;
  };
}

/**
 * Introspection capability: endpoint definitions, the generated route
 * manifest, and OpenAPI emission — what CI checks and docs tooling consume.
 */
export interface FortressManifestRuntime {
  readonly endpoints: readonly AnyPublishedEndpointDefinition[];
  readonly manifest: PublishedRouteManifest;
  readonly config: Readonly<FortressConfig>;
  /**
   * Emit a complete OpenAPI 3.1 spec from the endpoint definitions Fortress
   * knows about: core auth/IAM routes, plugin routes, and any top-level
   * host `routes` registered on {@link FortressConfig}.
   */
  toOpenAPI: (opts?: FortressToOpenAPIOptions) => OpenAPISpec;
}

/** Schema lifecycle capability: apply Fortress migrations and seed IAM permissions. */
export interface FortressMigrationRuntime {
  /**
   * Run Fortress's pending schema migrations against the configured database
   * and, optionally, an application-supplied migration step afterwards.
   * Fortress migrations always run first because app schemas commonly
   * reference fortress tables (foreign keys to `user.id`, etc.).
   */
  migrate: (opts?: MigrateOptions) => Promise<MigrateResult>;
  /**
   * Seed permissions discovered on registered endpoints into the IAM
   * database and, optionally, bind them onto a set of default roles.
   * Idempotent — re-running adds only what's missing and never revokes.
   */
  syncPermissionsFromManifest: (opts?: PermissionSyncOptions) => Promise<PermissionSyncResult>;
}

/** Observability capability: the resolved logger and telemetry provider. */
export interface FortressObservabilityRuntime {
  /** Resolved logger (defaults to a silent no-op when `config.logger` is unset). */
  readonly logger: FortressLogger;
  /** Resolved telemetry provider (defaults to a no-op when `config.observability` is unset). */
  readonly telemetry: TelemetryProvider;
}

/**
 * Exact capability consumed by the `protect()` pipeline: route lookup,
 * CSRF, principal resolution, RBAC, cookie attachment, and error logging.
 */
export type FortressProtectRuntime
  = & Pick<FortressManifestRuntime, 'endpoints' | 'manifest' | 'config'>
    & Pick<FortressAuthRuntime, 'auth' | 'iam' | 'cookies' | 'extractAccessToken' | 'serializeAuthCookies'>
    & Pick<FortressObservabilityRuntime, 'logger'>;

/**
 * Every capability composed — the erased shape of a complete instance.
 * Internal core machinery (request dispatch, instance assembly) consumes
 * this; external boundaries should prefer the narrowest capability that
 * covers their needs.
 */
export type FortressRuntime
  = & FortressHttpRuntime
    & FortressAuthRuntime
    & FortressPluginRuntime
    & FortressManifestRuntime
    & FortressMigrationRuntime
    & FortressObservabilityRuntime;
