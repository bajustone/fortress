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
 * import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';
 *
 * const fortress = await createFortress({
 *   db: createDrizzleAdapter(db, { dialect: 'pg' }),
 *   jwt: { secret: process.env.JWT_SECRET! },
 * });
 *
 * const result = await fortress.signIn({ email: 'a@b.co', password: 'secret' });
 * ```
 *
 * @module
 */

/** Generic CRUD database adapter interface — implement to back fortress with any datastore. */
export type { DatabaseAdapter } from './adapters/database';

/** Where-clause primitives used by adapters and `scopeRules` to express filters. */
export type { CoreOperator, ScopeRule, WhereClause } from './adapters/database/types';

/** Pre-built endpoint definitions and component schemas for the core auth routes. */
export { authComponentSchemas, authEndpoints } from './core/auth/auth-endpoints';

/** Top-level fortress configuration and pluggable password-hasher contract. */
export type { FortressConfig, PasswordHasher } from './core/config';

/**
 * Endpoint definition primitives — declarative `EndpointDefinition` objects
 * carrying request/response schemas, OpenAPI metadata, and HTTP method info
 * so framework adapters can mount routes without per-framework duplication.
 */
export type {
  ComponentSchemas,
  EndpointDefinition,
  EndpointInput,
  EndpointMeta,
  EndpointResponse,
  HttpMethod,
  SecurityRequirement,
} from './core/endpoint';

/** Single error class plus the typed factory used throughout fortress. */
export { Errors, FortressError } from './core/errors';

/** Discriminated string union of every error code fortress can throw. */
export type { FortressErrorCode } from './core/errors';

/** Factory that builds a configured fortress instance and the helper for type-safe plugin method access. */
export { createFortress, getPluginMethods } from './core/fortress';

/** The fortress instance type returned by {@link createFortress}. */
export type { Fortress } from './core/fortress';

/** Pre-built endpoint definitions and component schemas for the core IAM routes. */
export { iamComponentSchemas, iamEndpoints } from './core/iam/iam-endpoints';

/** JSON Schema types and the inferred TypeScript type helpers used by the schema builder. */
export type { FortressSchema, Infer, JSONSchema, Simplify } from './core/json-schema';

/**
 * Plugin authoring types — implement {@link FortressPlugin} to extend fortress
 * with new models, hooks, methods, routes, middleware, scope rules, or
 * adapter wrappers.
 */
export type {
  AfterHookContext,
  FieldDefinition,
  FortressPlugin,
  HookContext,
  HookResult,
  MiddlewareDefinition,
  ModelConstraint,
  ModelDefinition,
  PluginContext,
  PluginHooks,
  RouteDefinition,
} from './core/plugin';

/** Type-level mapping helpers used to expose plugin methods on the fortress instance. */
export type { InferPlugins, PluginMethodsMap } from './core/plugin-methods-map';

/**
 * Fluent JSON Schema builder DSL. Compose `obj`, `str`, `int`, `arr`, etc.
 * to build typed endpoint inputs/outputs that double as runtime validators
 * and OpenAPI component schemas.
 */
export {
  anyOf,
  arr,
  bool,
  endpoint,
  EndpointBuilder,
  enums,
  extractJsonSchema,
  int,
  isFortressSchema,
  isStandardSchema,
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
} from './core/schema-builder';

/** Input type accepted by `endpoint(...).input()` and friends. */
export type { SchemaInput } from './core/schema-builder';

/** Standard Schema v1 interop type — fortress schemas implement this. */
export type { StandardSchemaV1 } from './core/standard-schema';

/**
 * Core domain types — users, identifiers, groups, roles, permissions, and
 * the auth response shapes returned by sign-in / refresh / impersonate.
 */
export type {
  AuthResponse,
  AuthResponseImpersonation,
  AuthResponsePending,
  AuthResponseSuccess,
  AuthTokenPair,
  ConditionRef,
  ConditionValue,
  CreateUserInput,
  FortressUser,
  Group,
  LoginIdentifier,
  LoginIdentifierType,
  Permission,
  PermissionCondition,
  PermissionContext,
  PermissionInput,
  RequestMeta,
  Role,
  RoleBinding,
  SubjectType,
  TokenClaims,
} from './core/types';

/**
 * Framework-agnostic validation primitive. Validates a `{ body, query, params }`
 * object against an `EndpointInput`, aggregates all issues, and throws
 * `Errors.validationError` (HTTP 422, code `VALIDATION_ERROR`) on failure.
 * Use this from any runtime — SvelteKit `+server.ts`, Next.js route handlers,
 * Bun.serve, Deno, or custom middleware — to validate consumer-defined routes
 * with the same shape fortress's own dispatch uses internally.
 */
export { validateRequest } from './core/validation';

/** Type-safe method surface contributed by the API key plugin. */
export type { ApiKeyMethods } from './plugins/api-key';

/** Type-safe method surface contributed by the audit log plugin. */
export type { AuditLogMethods } from './plugins/audit-log';

/** Type-safe method surface contributed by the data isolation plugin. */
export type { DataIsolationMethods } from './plugins/data-isolation';

/** Type-safe method surface contributed by the email verification plugin. */
export type { EmailVerificationMethods } from './plugins/email-verification';

/** Type-safe method surface and request/response shapes for the OAuth server plugin. */
export type { AuthorizeRequestParams, ClientAuth, OAuthMethods, PendingFlowRecord, TokenRequestBody } from './plugins/oauth';

/** Type-safe method surface contributed by the social login plugin. */
export type { SocialLoginMethods } from './plugins/social-login';

/** Type-safe method surface contributed by the tenancy plugin. */
export type { TenancyMethods } from './plugins/tenancy';

/** Type-safe method surface contributed by the two-factor plugin. */
export type { TwoFactorMethods } from './plugins/two-factor';

/** Type-safe method surface contributed by the WebAuthn plugin. */
export type { WebAuthnMethods } from './plugins/webauthn';
