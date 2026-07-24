import type { DatabaseAdapter } from '../adapters/database';
import type { ScopeRule } from '../adapters/database/types';
import type { AuthService } from './auth/auth-service';
import type { FortressConfig } from './config';
import type { EndpointDefinition } from './endpoint';
import type { PluginRequestContext } from './http/plugin-middleware';
import type { IamService } from './iam/iam-service';
import type { FortressLogger } from './observability/logger';
import type {
  AuthSuccess,
  AuthTokenPair,
  CreateUserInput,
  FortressUser,
  PendingReason,
  RequestMeta,
  Subject,
  TokenClaims,
} from './types';

export type PluginMethod = (...args: any[]) => any;
export type LegacyPluginMethods = Record<string, PluginMethod>;
export type PluginRoutes = Readonly<Record<string, EndpointDefinition<any, any, any, any>>>;

export interface FortressPlugin<
  TName extends string = string,
  TMethods extends object = LegacyPluginMethods,
  TRoutes extends PluginRoutes | undefined = PluginRoutes | undefined,
> {
  /** Unique plugin identifier */
  name: TName;

  /** DB models this plugin needs */
  models?: ModelDefinition[];

  /** Hooks into auth lifecycle (executed in plugin registration order) */
  hooks?: PluginHooks;

  /** Extra function-valued methods exposed on fortress.plugins.<name>. */
  methods?: (ctx: PluginContext) => TMethods;

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
  routes?: TRoutes;

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

/** Internal broad shape used at runtime while preserving object method surfaces. */
export type RuntimeFortressPlugin = FortressPlugin<string, object, PluginRoutes | undefined>;

/** Extract the method surface carried by a plugin definition. */
export type PluginMethodsOf<P> = P extends { methods: (...args: any[]) => infer TMethods extends object }
  ? TMethods
  : P extends FortressPlugin<any, infer TMethods, any> ? TMethods : Record<never, never>;

/** Extract the route record carried by a plugin definition. */
export type PluginRoutesOf<P> = P extends { routes: infer TRoutes }
  ? TRoutes
  : P extends FortressPlugin<any, any, infer TRoutes> ? TRoutes : undefined;

/**
 * Preserve a plugin definition's literal name, exact methods, and exact routes.
 * This identity helper is the preferred authoring API for third-party plugins.
 */
export function definePlugin<
  const TDefinition,
  const TName extends string,
  TMethods extends object,
  const TRoutes extends PluginRoutes | undefined,
>(definition: TDefinition & FortressPlugin<TName, TMethods, TRoutes>): TDefinition
  & Omit<FortressPlugin<TName, TMethods, TRoutes>, 'name' | 'methods' | 'routes'>;
export function definePlugin(definition: FortressPlugin): FortressPlugin {
  return definition;
}

// --- Hooks ---

export interface PluginHooks {
  beforeLogin?: (ctx: HookContext & { email: string }) => Promise<HookResult | void>;
  beforeRegister?: (ctx: HookContext & { data: CreateUserInput }) => Promise<HookResult | void>;
  beforeTokenRefresh?: (ctx: HookContext & { token: string }) => Promise<HookResult | void>;
  beforeLogout?: (ctx: HookContext & { token: string }) => Promise<void>;
  onLoginFailure?: (ctx: HookContext & { identifier: string; error: Error }) => Promise<void>;

  /** Runs after primary credentials succeed but before any token is issued. */
  postAuthGate?: PostAuthGateProvider;

  afterLogin?: (ctx: AfterHookContext, result: AuthSuccess) => Promise<AuthSuccess>;
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

export interface PostAuthGateContext extends HookContext {
  user: FortressUser;
  /** Reasons already satisfied by the continuation currently being completed. */
  completedReasons: readonly PendingReason[];
}

export interface PostAuthGateDecision {
  pluginData?: Record<string, unknown>;
}

export interface PostAuthGateVerificationContext extends HookContext {
  user: FortressUser;
  continuation: {
    id: string;
    reason: PendingReason;
    expiresAt: Date;
  };
}

export interface PostAuthGateProvider {
  reason: PendingReason;
  /** Durable failed-proof policy stored on each continuation. */
  maxAttempts?: number;
  cooldownSeconds?: number;
  evaluate: (ctx: PostAuthGateContext) => Promise<PostAuthGateDecision | void>;
  /** Return optional plugin data to include in the final AuthResult. */
  verify: (ctx: PostAuthGateVerificationContext, completion: unknown) => Promise<Record<string, unknown> | void>;
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
  handler: (ctx: PluginContext, request: PluginRequestContext, next: () => Promise<void>) => Promise<void>;
}
