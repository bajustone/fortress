import type { DatabaseAdapter } from '../adapters/database';
import type { ScopeRule } from '../adapters/database/types';
import type { FortressConfig } from './config';
import type {
  AuthResponse,
  AuthTokenPair,
  CreateUserInput,
  FortressUser,
  RequestMeta,
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

export interface ModelDefinition {
  name: string;
  fields: Record<string, FieldDefinition>;
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
}

export interface RouteDefinition {
  method: 'GET' | 'POST' | 'PUT' | 'DELETE';
  path: string;
  handler: string;
}

export interface MiddlewareDefinition {
  path: string;
  position: 'before-auth' | 'after-auth' | 'after-rbac';
  handler: (ctx: PluginContext, request: unknown, next: () => Promise<void>) => Promise<void>;
}

/** Infer typed plugin methods from the plugins array */
export type InferPlugins<T extends FortressPlugin[]> = {
  // eslint-disable-next-line ts/no-unsafe-function-type -- fallback type for untyped plugins
  [P in T[number] as P['name']]: P extends { _methods: infer M } ? M : Record<string, Function>;
};
