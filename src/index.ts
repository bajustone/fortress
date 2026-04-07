// Database adapter
export type { DatabaseAdapter } from './adapters/database';

export type { CoreOperator, ScopeRule, WhereClause } from './adapters/database/types';

// Pre-built endpoint definitions & component schemas
export { authComponentSchemas, authEndpoints } from './core/auth/auth-endpoints';
// Config
export type { FortressConfig, PasswordHasher } from './core/config';

// Endpoint definitions & schema builders
export type {
  ComponentSchemas,
  EndpointDefinition,
  EndpointInput,
  EndpointMeta,
  EndpointResponse,
  HttpMethod,
  SecurityRequirement,
} from './core/endpoint';
// Errors
export { Errors, FortressError } from './core/errors';

export type { FortressErrorCode } from './core/errors';

// Fortress factory
export { createFortress, getPluginMethods } from './core/fortress';
export type { Fortress } from './core/fortress';
export { iamComponentSchemas, iamEndpoints } from './core/iam/iam-endpoints';

export type { FortressSchema, Infer, JSONSchema, Simplify } from './core/json-schema';
// Plugin system
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
export type { InferPlugins, PluginMethodsMap } from './core/plugin-methods-map';
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

export type { SchemaInput } from './core/schema-builder';
export type { StandardSchemaV1 } from './core/standard-schema';
// Core types
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

export type { ApiKeyMethods } from './plugins/api-key';
export type { AuditLogMethods } from './plugins/audit-log';
export type { DataIsolationMethods } from './plugins/data-isolation';
export type { EmailVerificationMethods } from './plugins/email-verification';
export type { AuthorizeRequestParams, ClientAuth, OAuthMethods, PendingFlowRecord, TokenRequestBody } from './plugins/oauth';
export type { SocialLoginMethods } from './plugins/social-login';
export type { TenancyMethods } from './plugins/tenancy';
// Plugin method interfaces (for type-safe plugin access)
export type { TwoFactorMethods } from './plugins/two-factor';
export type { WebAuthnMethods } from './plugins/webauthn';
