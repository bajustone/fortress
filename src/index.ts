/**
 * Fortress — framework-agnostic authentication and authorization for TypeScript.
 *
 * The main entrypoint exposes the {@link createFortress} factory, plugin and
 * adapter interfaces, the schema builder DSL, and every public type. Combine
 * with one of the framework adapters (`@bajustone/fortress/hono`,
 * `@bajustone/fortress/express`, `@bajustone/fortress/sveltekit`) and a
 * database adapter (`@bajustone/fortress/drizzle`,
 * `@bajustone/fortress/testing`).
 *
 * @example
 * ```ts
 * import { createFortress } from '@bajustone/fortress';
 * import { createPostgresDrizzleAdapter } from '@bajustone/fortress/drizzle';
 *
 * const fortress = createFortress({
 *   database: createPostgresDrizzleAdapter(db),
 *   jwt: { key: process.env.JWT_SECRET! },
 * });
 *
 * const result = await fortress.auth.login('a@b.co', 'secret');
 * ```
 *
 * @module
 */

/** Generic CRUD database adapter interface — implement to back fortress with any datastore. */
export type { DatabaseAdapter, DatabaseDialect, MigratableDatabaseAdapter } from './adapters/database';

/** Where-clause primitives used by adapters and `scopeRules` to express filters. */
export type { CoreOperator, ScopeRule, WhereClause } from './adapters/database/types';

/** Pre-built endpoint definitions, schemas, and stable JSON wire types for core auth routes. */
export type {
  AuthChallengeWire,
  AuthEndpointsMap,
  AuthImpersonationWire,
  AuthPendingWire,
  AuthResultWire,
  AuthSuccessWire,
} from './core/auth/auth-endpoints';
export { authComponentSchemas, authEndpoints } from './core/auth/auth-endpoints';

/** The authentication service surface exposed as `fortress.auth`, plus its observer contracts. */
export type { AuthEvent, AuthEventListener, AuthService } from './core/auth/auth-service';

/** Public JWT key-material type used by FortressConfig. */
export type { JwtKeyMaterial } from './core/auth/jwt';

export type {
  PasswordBreachCheckOptions,
  PasswordBreachDegradedEvent,
  PasswordBreachFailureMode,
  PasswordPolicyConfig,
  PasswordPolicyObserver,
} from './core/auth/password-policy';
/** Namespaced typed call tree derived from the configured plugin tuple (ADR 0001 §5). */
export type { CallClient, CallTree, EndpointCall, PluginCallTree } from './core/call-tree';
/**
 * Minimal runtime capability interfaces (ADR 0001 §4). Framework adapters
 * and utility boundaries accept these instead of a full instance; every
 * `Fortress<TPlugins>` composes all of them.
 */
export type {
  FortressAuthRuntime,
  FortressHttpRuntime,
  FortressManifestRuntime,
  FortressMigrationRuntime,
  FortressObservabilityRuntime,
  FortressPluginRuntime,
  FortressProtectRuntime,
  FortressRuntime,
} from './core/capabilities';

/** Top-level fortress configuration, cookie policy, and pluggable password-hasher contract. */
export type { CookieConfig, FortressConfig, PasswordHasher, ResolvedCookieConfig, SessionConfig } from './core/config';
/** Definition-site validation and branding for exact endpoint collections (ADR 0001 §2). */
export { defineEndpoints } from './core/define-endpoints';

export type { DefinedEndpoints, ValidEndpointRecord } from './core/define-endpoints';

/**
 * Endpoint definition primitives — declarative `EndpointDefinition` objects
 * carrying request/response schemas, OpenAPI metadata, and HTTP method info
 * so framework adapters can mount routes without per-framework duplication.
 *
 * Plus the `InferEndpoint*` helpers that extract body/query/params/response
 * types from an endpoint's generic parameters — the foundation of the typed
 * `fortress.call.*` in-process client.
 */
export type {
  AnyEndpointDefinition,
  ComponentSchemas,
  EndpointDefinition,
  EndpointInput,
  EndpointMeta,
  EndpointPermission,
  EndpointResponse,
  HttpMethod,
  InferEndpointBody,
  InferEndpointBodyInput,
  InferEndpointCallInput,
  InferEndpointHandler,
  InferEndpointParams,
  InferEndpointParamsInput,
  InferEndpointQuery,
  InferEndpointQueryInput,
  InferEndpointResponses,
  InferEndpointSuccessResponse,
  InferEndpointValidatedInput,
  SecurityRequirement,
} from './core/endpoint';
/** Single error class plus the typed factory used throughout fortress. */
export { Errors, FortressError } from './core/errors';
/** Discriminated string unions for Fortress and OAuth errors. */
export type { FortressErrorCode, OAuthErrorCode } from './core/errors';

/** Factory that builds a configured fortress instance. */
export { createFortress } from './core/fortress';

/** The fortress instance type returned by {@link createFortress}. */
export type { Fortress, FortressToOpenAPIOptions, MigrateOptions, MigrateResult, PluginMethodsValidator } from './core/fortress';

/** Typed in-process client builder and per-call options. */
export { buildCall } from './core/http/call';

export type { CallOptions } from './core/http/call';

/** Decoded payload of the fortress auth cookie. */
export type { AuthCookiePayload } from './core/http/cookie-serialize';

/**
 * Core CSRF policy. This is the canonical `CsrfConfig`; the Hono and Express
 * adapters export their own framework-specific shapes, also available under the
 * unambiguous aliases `HonoCsrfConfig` and `ExpressCsrfConfig`.
 */
export type { CsrfConfig } from './core/http/csrf';

/** Cross-adapter context passed to plugin middleware under core, Hono, and Express. */
export type { PluginRequestContext } from './core/http/plugin-middleware';

/** The authenticated subject resolved from a request by `protect` and the adapters. */
export type { ResolvedPrincipal } from './core/http/principal';
export { describeProtectedTarget, protect, resolveProtectedEndpoint } from './core/http/protect';
export type { ProtectedRouteContext, ProtectedRouteHandler, ProtectedRouteTarget, ProtectOptions } from './core/http/protect';

/** Permission debugging helper — "why does subject X have / not have permission Y?". */
export { explainPermission } from './core/iam/explain';
export type { PermissionExplanation, PermissionExplanationSource } from './core/iam/explain';
/** Pre-built endpoint definitions and component schemas for the core IAM routes. */
export { iamComponentSchemas, iamEndpoints } from './core/iam/iam-endpoints';

/** Declared shape of the exported `iamEndpoints` collection. */
export type { IamEndpointsMap } from './core/iam/iam-endpoints';

/** IAM mutation and permission-check observer contracts. */
export type {
  IamEvent,
  IamEventListener,
  IamService,
  PermissionCheckEvent,
  PermissionCheckListener,
} from './core/iam/iam-service';
/** Manifest-driven RBAC permission seeding. See {@link Fortress.syncPermissionsFromManifest}. */
export { runPermissionSync } from './core/iam/permission-sync';
export type { PermissionSyncOptions, PermissionSyncResult } from './core/iam/permission-sync';
export { parseResourceFile } from './core/iam/resource-sync';

export type { ResourceDefinition, ResourceFile } from './core/iam/resource-sync';
/** JSON Schema types and the inferred TypeScript type helpers used by the schema builder. */
export type { FortressSchema, Infer, JSONSchema, Simplify } from './core/json-schema';

/** Canonical route-security manifest and drift checker. */
export { detectRouteManifestDrift, hasRouteManifestDrift } from './core/manifest/drift';

export type { DetectRouteManifestDriftOptions, RouteManifestDrift } from './core/manifest/drift';

export { buildRouteManifest } from './core/manifest/route-manifest';
export type { RouteClassification, RouteManifestEntry } from './core/manifest/route-manifest';
export { describeRouteSurface } from './core/manifest/route-surface';
export type { RouteSurface } from './core/manifest/route-surface';
/** Fortress schema migration metadata and runner helpers. */
export { detectMigrationDrift, getMigrationStatus, hasMigrationDrift, migrateDown, migrateUp } from './core/migrations/engine';
export type { MigrationApplyResult, MigrationDownResult, MigrationDrift, MigrationStatus } from './core/migrations/engine';

export { FORTRESS_TABLES, fortressMigrations, getExpectedColumns, getFortressMigrations, getLatestMigrationVersion, getMigrationUpSql } from './core/migrations/migrations';
export type { FortressMigration, MigrationDialect } from './core/migrations/migrations';
export type { Unsubscribe } from './core/observability/listener-list';
/** Runtime-neutral logging, telemetry, and observer contracts. */
export type { FortressLogger, LogFn, LogLevel } from './core/observability/logger';

export type {
  Attributes,
  AttributeValue,
  Counter,
  Histogram,
  Meter,
  Span,
  TelemetryProvider,
  Tracer,
} from './core/observability/types';

export { toOpenAPI } from './core/openapi';

export type { ToOpenAPIOptions } from './core/openapi';
/**
 * Plugin authoring types — implement {@link FortressPlugin} to extend fortress
 * with new models, hooks, methods, routes, middleware, scope rules, or
 * adapter wrappers.
 */
export { definePlugin } from './core/plugin';
export type {
  AfterHookContext,
  FieldDefinition,
  FortressPlugin,
  FortressPluginDefinition,
  HookContext,
  HookResult,
  JsonOf,
  LegacyPluginMethods,
  MiddlewareDefinition,
  ModelConstraint,
  ModelDefinition,
  PluginContext,
  PluginDependency,
  PluginHooks,
  PluginMethod,
  PluginMethodsOf,
  PluginRouteContext,
  PluginRoutes,
  PluginRoutesOf,
  PostAuthGateContext,
  PostAuthGateDecision,
  PostAuthGateProvider,
  PostAuthGateVerificationContext,
  RouteHandlerIncompatible,
  RouteHandlerKeyMismatch,
  RouteHandlerMissing,
  RouteInputNotFlat,
  RuntimeFortressPlugin,
  ValidatePluginRoutes,
} from './core/plugin';
/** Plugin-methods inference plus the deprecated legacy augmentation bridge. */
export type { InferPlugins, PluginMethodsMap } from './core/plugin-methods-map';
/** Declarative policy-as-code: loader, diff, and apply primitives. */
export { applyPolicyPlan, applyResourceOps } from './core/policy/apply';
export type { ApplyPolicyResult } from './core/policy/apply';
export { diffPolicy } from './core/policy/diff';
export { DEFAULT_POLICY_FILE, loadPolicy, parsePolicyDocument, resolvePolicyPath } from './core/policy/loader';
export type { LoadPolicyOptions } from './core/policy/loader';

export type { DiffPolicyOptions, PolicyDocument, PolicyGroup, PolicyOp, PolicyPermission, PolicyPlan, PolicyResource, PolicyRole, PolicyServiceAccount } from './core/policy/types';

/**
 * Fluent JSON Schema builder DSL. Compose `obj`, `str`, `int`, `arr`, etc.
 * to build typed endpoint inputs/outputs that double as runtime validators
 * and OpenAPI component schemas.
 */
export {
  anyOf,
  arr,
  bool,
  date,
  datetime,
  defineComponents,
  discriminatedUnion,
  email,
  endpoint,
  EndpointBuilder,
  enums,
  ErrorEnvelope,
  extractJsonSchema,
  id,
  int,
  intersect,
  isFortressSchema,
  isStandardSchema,
  literal,
  nullable,
  nullType,
  num,
  obj,
  oneOf,
  record,
  recordOf,
  ref,
  str,
  strFormat,
  strict,
  time,
  url,
  uuid,
} from './core/schema-builder';

/** Public types used by the schema builder and inferred endpoint responses. */
export type { ErrorEnvelopeBody, NumberOptions, SchemaInput, StringOptions } from './core/schema-builder';
/** Standard Schema v1 interop type — fortress schemas implement this. */
export type { StandardSchemaV1 } from './core/standard-schema';

/**
 * Core domain types — users, identifiers, groups, roles, permissions, and
 * the auth result shapes returned by sign-in / refresh / impersonate.
 */
export type {
  AuthChallenge,
  AuthImpersonation,
  AuthMethod,
  AuthPending,
  AuthResult,
  AuthSuccess,
  AuthTokenPair,
  ConditionRef,
  ConditionValue,
  CreateServiceAccountInput,
  CreateUserInput,
  FortressUser,
  Group,
  LoginIdentifier,
  LoginIdentifierType,
  PendingReason,
  Permission,
  PermissionCondition,
  PermissionContext,
  PermissionInput,
  RequestMeta,
  Role,
  RoleBinding,
  ServiceAccount,
  SessionInfo,
  Subject,
  SubjectType,
  TokenClaims,
} from './core/types';

/** Runtime guards for narrowing an {@link AuthResult} (`status`-discriminated). */
export { assertSuccess, isImpersonation, isPending, isSuccess } from './core/types';

/**
 * Framework-agnostic validation primitive. Validates a `{ body, query, params }`
 * object against an `EndpointInput`, aggregates all issues, and throws
 * `Errors.validationError` (HTTP 422, code `VALIDATION_ERROR`) on failure.
 * Use this from any runtime — SvelteKit `+server.ts`, Next.js route handlers,
 * Bun.serve, Deno, or custom middleware — to validate consumer-defined routes
 * with the same shape fortress's own dispatch uses internally.
 */
export { validateRequest } from './core/validation';

/** Shape returned by {@link validateRequest}. */
export type { ValidatedRequestData } from './core/validation';

/** Type-safe method surface contributed by the account lockout plugin. */
export type { AccountLockoutMethods } from './plugins/account-lockout';

/** Type-safe method surface contributed by the admin plugin. */
export type { AdminMethods } from './plugins/admin';

/** Type-safe method surface contributed by the API key plugin. */
export type { ApiKeyMethods } from './plugins/api-key';

/** Type-safe method surface contributed by the audit log plugin. */
export type { AuditLogMethods } from './plugins/audit-log';

/** Type-safe method surface contributed by the data isolation plugin. */
export type { DataIsolationMethods } from './plugins/data-isolation';

/** Type-safe method surface contributed by the email verification plugin. */
export type { EmailVerificationMethods } from './plugins/email-verification';

/** Type-safe method surface contributed by the magic-link plugin. */
export type { MagicLinkMethods } from './plugins/magic-link';

/** Type-safe method surface and request/response shapes for the OAuth server plugin. */
export type { AuthorizeRequestParams, ClientAuth, OAuthMethods, PendingFlowRecord, TokenRequestBody } from './plugins/oauth';

/** Type-safe method surface contributed by the OpenAPI plugin. */
export type { OpenAPIMethods } from './plugins/openapi';

export type { OpenAPISpec, SpecBuilderOptions } from './plugins/openapi/spec-builder';

/** Type-safe method surface contributed by the rate-limit plugin. */
export type { RateLimitMethods } from './plugins/rate-limit';

/** Type-safe method surface contributed by the social login plugin. */
export type { SocialLoginMethods } from './plugins/social-login';

/** Type-safe method surface contributed by the tenancy plugin. */
export type { TenancyMethods } from './plugins/tenancy';

/** Type-safe method surface contributed by the two-factor plugin. */
export type { TwoFactorMethods } from './plugins/two-factor';

/** Type-safe method surface contributed by the WebAuthn plugin. */
export type { WebAuthnMethods } from './plugins/webauthn';

/** Type-safe method surface contributed by the webhook plugin. */
export type { WebhookMethods } from './plugins/webhook';
