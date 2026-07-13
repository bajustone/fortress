import type { DatabaseAdapter } from '../adapters/database';
import type { ScopeRule } from '../adapters/database/types';
import type { AuthService } from './auth/auth-service';
import type { FortressConfig } from './config';
import type { EndpointDefinition } from './endpoint';
import type { IamService } from './iam/iam-service';
import type { FortressLogger } from './observability/logger';
import type {
  AuthResult,
  AuthTokenPair,
  CreateUserInput,
  FortressUser,
  RequestMeta,
  Subject,
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

  /**
   * HTTP routes this plugin adds, keyed by handler name.
   *
   * A keyed record (not an array) so each entry's full
   * `EndpointDefinition<TBody, TQuery, TParams, TResponses>` type is
   * preserved for the typed `fortress.call.*` proxy. The dispatcher looks
   * plugin route handlers up by name (`fortress.plugins[pluginName][handlerName]`),
   * so the keyed shape is already the natural fit at dispatch time — the
   * key just needs to match the `EndpointDefinition.handler` string.
   */
  routes?: Record<string, EndpointDefinition>;

  /** Middleware to inject into the request pipeline */
  middleware?: MiddlewareDefinition[];

  /** Wrap the DatabaseAdapter per-request */
  wrapAdapter?: (
    adapter: DatabaseAdapter,
    requestContext: Record<string, unknown>,
  ) => DatabaseAdapter;

  /** Extend JWT token claims */
  enrichTokenClaims?: (
    userId: string,
    ctx: PluginContext,
  ) => Promise<Record<string, unknown>>;

  /** Scope data access by user context (row-level data isolation) */
  scopeRules?: (
    userId: string,
    model: string,
    ctx: PluginContext,
  ) => Promise<ScopeRule | null>;

  /**
   * Resolve a request principal from a non-JWT credential — API key,
   * OAuth bearer, mTLS client cert, signed JWT assertion, etc.
   *
   * Called by `fortress.handleRequest` **before** the JWT fallback. Plugins
   * are tried in registration order; the first to return a non-null result
   * wins, and its subject (plus optional claims) become the request
   * principal for downstream RBAC. Returning `null` means "defer" — the
   * next plugin is tried, and if none resolve, the core JWT path runs.
   *
   * This is the extension point for any future credential mechanism. The
   * api-key plugin implements it to turn `Authorization: ApiKey <key>` /
   * `X-API-Key: <key>` headers into a `USER` or `SERVICE_ACCOUNT`
   * principal.
   */
  resolvePrincipal?: (
    request: Request,
    ctx: PluginContext,
  ) => Promise<{ subject: Subject; claims?: TokenClaims; scopes?: string[] | null } | null>;
}

// --- Hooks ---

export interface PluginHooks {
  beforeLogin?: (ctx: HookContext & { email: string }) => Promise<HookResult | void>;
  beforeRegister?: (ctx: HookContext & { data: CreateUserInput }) => Promise<HookResult | void>;
  beforeTokenRefresh?: (ctx: HookContext & { token: string }) => Promise<HookResult | void>;
  beforeLogout?: (ctx: HookContext & { token: string }) => Promise<void>;
  onLoginFailure?: (ctx: HookContext & { identifier: string; error: Error }) => Promise<void>;

  afterLogin?: (ctx: AfterHookContext, result: AuthResult) => Promise<AuthResult>;
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
  /** Normalized login identifier used for this auth flow, when applicable. */
  identifier?: string;
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
  /** Resolved logger (silent no-op if `config.logger` is unset). */
  logger?: FortressLogger;
}

/**
 * Second argument passed to plugin HTTP route handlers by the dispatcher.
 * Carries the verified caller identity and the raw Request so handlers can
 * make authorization decisions, stamp audit entries, or read headers/cookies
 * without trusting client-supplied body fields.
 *
 * `subject` / `claims` are populated whenever the endpoint's `meta.security`
 * declared bearer auth (the dispatcher resolves principals first). `userId`
 * is a convenience — it's present iff `subject?.type === 'USER'`, matching
 * the pre-SERVICE_ACCOUNT shape. For public endpoints all three are
 * `undefined`.
 */
export interface PluginRouteContext {
  /** Resolved request principal — USER or SERVICE_ACCOUNT. */
  subject?: Subject;
  /** Convenience alias for `subject?.id` when the subject is a USER. */
  userId?: string;
  claims?: TokenClaims;
  /** Credential-level narrowing scopes from principal resolution, if any. */
  scopes?: string[] | null;
  meta?: RequestMeta;
  request: Request;
}

export interface MiddlewareDefinition {
  path: string;
  position: 'before-auth' | 'after-auth' | 'after-rbac';
  handler: (ctx: PluginContext, request: unknown, next: () => Promise<void>) => Promise<void>;
}
