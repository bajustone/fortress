import type { DatabaseAdapter } from '../adapters/database';
import type { ScopeRule } from '../adapters/database/types';
import type { AuthService } from './auth/auth-service';
import type { FortressConfig } from './config';
import type { IamService } from './iam/iam-service';
import type {
  AuthResponse,
  AuthTokenPair,
  CreateUserInput,
  FortressUser,
  RequestMeta,
  TokenClaims,
} from './types';

export interface FortressPlugin {
  /** Unique plugin identifier */
  name: string;

  /** DB models this plugin needs */
  models?: ModelDefinition[];

  /** Hooks into auth lifecycle (executed in plugin registration order) */
  hooks?: PluginHooks;

  /** Extra methods exposed on fortress.plugins.<name> */
  // eslint-disable-next-line ts/no-unsafe-function-type -- plugin methods are dynamically typed
  methods?: (ctx: PluginContext) => Record<string, Function>;

  /** HTTP routes this plugin adds */
  routes?: RouteDefinition[];

  /** Middleware to inject into the request pipeline */
  middleware?: MiddlewareDefinition[];

  /** Wrap the DatabaseAdapter per-request */
  wrapAdapter?: (
    adapter: DatabaseAdapter,
    requestContext: Record<string, unknown>,
  ) => DatabaseAdapter;

  /** Extend JWT token claims */
  enrichTokenClaims?: (
    userId: number,
    ctx: PluginContext,
  ) => Promise<Record<string, unknown>>;

  /** Scope data access by user context (row-level data isolation) */
  scopeRules?: (
    userId: number,
    model: string,
    ctx: PluginContext,
  ) => Promise<ScopeRule | null>;
}

// --- Hooks ---

export interface PluginHooks {
  beforeLogin?: (ctx: HookContext & { email: string }) => Promise<HookResult | void>;
  beforeRegister?: (ctx: HookContext & { data: CreateUserInput }) => Promise<HookResult | void>;
  beforeTokenRefresh?: (ctx: HookContext & { token: string }) => Promise<HookResult | void>;
  beforeLogout?: (ctx: HookContext & { token: string }) => Promise<void>;
  onLoginFailure?: (ctx: HookContext & { identifier: string; error: Error }) => Promise<void>;

  afterLogin?: (ctx: AfterHookContext, result: AuthResponse) => Promise<AuthResponse>;
  afterRegister?: (ctx: AfterHookContext, user: FortressUser) => Promise<void>;
  afterTokenRefresh?: (ctx: AfterHookContext, result: AuthTokenPair) => Promise<AuthTokenPair>;
}

export interface HookContext {
  db: DatabaseAdapter;
  config: FortressConfig;
  meta?: RequestMeta;
}

export interface AfterHookContext extends HookContext {
  responseHeaders: Headers;
}

export interface HookResult {
  stop: true;
  response: Record<string, unknown>;
}

// --- Supporting Types ---

export type ModelConstraint
  = | { type: 'unique'; fields: string[] }
    | { type: 'index'; fields: string[]; name?: string };

export interface ModelDefinition {
  name: string;
  fields: Record<string, FieldDefinition>;
  constraints?: ModelConstraint[];
}

export interface FieldDefinition {
  type: 'string' | 'number' | 'boolean' | 'date';
  required?: boolean;
  unique?: boolean;
  references?: { model: string; field: string };
}

export interface PluginContext {
  db: DatabaseAdapter;
  config: FortressConfig;
  /** Auth service reference. Optional at init time; available at runtime (enrichTokenClaims, scopeRules). */
  auth?: AuthService;
  /** IAM service reference. Optional at init time; available at runtime. */
  iam?: IamService;
}

/** @deprecated Use EndpointDefinition from './endpoint' instead. Kept as alias for backward compatibility. */
export type RouteDefinition = import('./endpoint').EndpointDefinition;

/**
 * Second argument passed to plugin HTTP route handlers by the dispatcher.
 * Carries the verified caller identity and the raw Request so handlers can
 * make authorization decisions, stamp audit entries, or read headers/cookies
 * without trusting client-supplied body fields.
 *
 * `userId` / `claims` are populated whenever the endpoint's `meta.security`
 * declared bearer auth (the dispatcher runs token verification first).
 * For public endpoints they are `undefined`.
 */
export interface PluginRouteContext {
  userId?: number;
  claims?: TokenClaims;
  meta?: RequestMeta;
  request: Request;
}

export interface MiddlewareDefinition {
  path: string;
  position: 'before-auth' | 'after-auth' | 'after-rbac';
  handler: (ctx: PluginContext, request: unknown, next: () => Promise<void>) => Promise<void>;
}
