// Database adapter
export type { DatabaseAdapter } from './adapters/database';

export type { CoreOperator, ScopeRule, WhereClause } from './adapters/database/types';

// Config
export type { FortressConfig, PasswordHasher } from './core/config';
// Errors
export { Errors, FortressError } from './core/errors';

export type { FortressErrorCode } from './core/errors';
// Fortress factory
export { createFortress, getPluginMethods } from './core/fortress';

export type { Fortress } from './core/fortress';

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
