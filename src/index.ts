// Database adapter
export type { DatabaseAdapter } from './adapters/database';

export type { CoreOperator, ScopeRule, WhereClause } from './adapters/database/types';

// Config
export type { FortressConfig, PasswordHasher } from './core/config';
// Errors
export { Errors, FortressError } from './core/errors';

export type { FortressErrorCode } from './core/errors';
// Fortress factory
export { createFortress } from './core/fortress';

export type { Fortress } from './core/fortress';

// Plugin system
export type {
  AfterHookContext,
  FieldDefinition,
  FortressPlugin,
  HookContext,
  HookResult,
  InferPlugins,
  MiddlewareDefinition,
  ModelDefinition,
  PluginContext,
  PluginHooks,
  RouteDefinition,
} from './core/plugin';
// Core types
export type {
  AuthResponse,
  AuthTokenPair,
  CreateUserInput,
  FortressUser,
  Group,
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
