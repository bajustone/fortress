import type { DatabaseAdapter } from '../adapters/database';
import type { ScopeRule } from '../adapters/database/types';
import type { AuthService } from './auth/auth-service';
import type { FortressConfig } from './config';
import type {
  AnyEndpointDefinition,
  InferEndpointCallInput,
  InferEndpointHandler,
  InferEndpointSuccessResponse,
} from './endpoint';
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
export type PluginRoutes = Readonly<Record<string, AnyEndpointDefinition>>;

type CallableMethodSurface<TMethods extends object> = {
  [K in keyof TMethods]: TMethods[K] extends PluginMethod ? TMethods[K] : never;
};

export interface FortressPluginDefinition<
  TName extends string,
  TRoutes extends PluginRoutes | undefined,
> {
  /** Unique plugin identifier */
  name: TName;

  /** DB models this plugin needs */
  models?: ModelDefinition[];

  /** Hooks into auth lifecycle (executed in plugin registration order) */
  hooks?: PluginHooks;

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

/**
 * Plugin definition contract. Concrete method surfaces require a methods
 * implementation and every property must be callable. The default legacy
 * surface and the erased runtime shape keep methods optional.
 */
export type FortressPlugin<
  TName extends string = string,
  TMethods extends object = LegacyPluginMethods,
  TRoutes extends PluginRoutes | undefined = PluginRoutes | undefined,
> = FortressPluginDefinition<TName, TRoutes>
  & (LegacyPluginMethods extends TMethods
    ? { methods?: (ctx: PluginContext) => CallableMethodSurface<TMethods> }
    : { methods: (ctx: PluginContext) => CallableMethodSurface<TMethods> });

/** Internal broad shape used at runtime while preserving object method surfaces. */
export type RuntimeFortressPlugin = FortressPlugin<string, object, PluginRoutes | undefined>;

/** Extract the method surface carried by a plugin definition. */
export type PluginMethodsOf<P> = P extends { methods: (...args: any[]) => infer TMethods extends object }
  ? TMethods
  : 'methods' extends keyof P
    ? P extends { methods?: (...args: any[]) => infer TMethods extends object } ? TMethods : Record<never, never>
    : Record<never, never>;

/** Extract the route record carried by a plugin definition. */
export type PluginRoutesOf<P> = 'routes' extends keyof P
  ? P extends { routes: infer TRoutes }
    ? TRoutes
    : P extends { routes?: infer TRoutes } ? TRoutes : undefined
  : undefined;

/** JSON-wire projection used to compare handler returns with response schemas. */
export type JsonOf<T> = T extends Date ? string
  : T extends (...args: any[]) => any ? never
    : T extends readonly (infer U)[] ? JsonOf<U>[]
      : T extends object ? { [K in keyof T]: JsonOf<T[K]> }
        : T;

type ContainsNonJsonValue<T> = T extends Date ? false
  : T extends ((...args: any[]) => any) | bigint | symbol | undefined ? true
    : T extends readonly (infer U)[]
      ? true extends ContainsNonJsonValue<U> ? true : false
      : T extends object
        ? true extends {
          [K in keyof T]-?: ContainsNonJsonValue<Exclude<T[K], undefined>>;
        }[keyof T] ? true : false
        : false;

type HandlerInputCompatible<M, E> = M extends (input: infer I, ...rest: any[]) => any
  ? InferEndpointCallInput<E> extends I ? true : false
  : false;

type HandlerReturnCompatible<M, E> = M extends (...args: any[]) => infer R
  ? unknown extends InferEndpointSuccessResponse<E>
    ? true
    : true extends ContainsNonJsonValue<Awaited<R>>
      ? false
      : JsonOf<Awaited<R>> extends infer J
        ? [J] extends [never]
            ? false
            : [J] extends [InferEndpointSuccessResponse<E>] ? true : false
        : false
  : false;

/** Compile-time diagnostic for a route key that differs from its handler. */
export interface RouteHandlerKeyMismatch<TKey extends string, THandler extends string> {
  readonly 'fortress:route-error': `route key '${TKey}' must match handler '${THandler}'`;
}

/** Compile-time diagnostic for a route that names no plugin method. */
export interface RouteHandlerMissing<THandler extends string> {
  readonly 'fortress:route-error': `route handler '${THandler}' is not a plugin method — declare it in methods()`;
}

/** Compile-time diagnostic for a route whose method does not match its I/O. */
export interface RouteHandlerIncompatible<THandler extends string> {
  readonly 'fortress:route-error': `plugin method '${THandler}' does not accept this endpoint's input or return its declared success response`;
}

type ContractlessEndpoint<E> = keyof InferEndpointCallInput<E> extends never
  ? unknown extends InferEndpointSuccessResponse<E> ? true : false
  : false;

type ValidatePluginRoute<K extends string, E, TMethods> = E extends AnyEndpointDefinition
  ? InferEndpointHandler<E> extends infer H extends string
    ? [K, H] extends [H, K]
        ? H extends keyof TMethods
          ? E extends { meta: { bearerKind: 'oauth' } }
            ? E
            : ContractlessEndpoint<E> extends true
              ? E
              : [HandlerInputCompatible<TMethods[H], E>, HandlerReturnCompatible<TMethods[H], E>] extends [true, true]
                  ? E
                  : RouteHandlerIncompatible<H>
          : RouteHandlerMissing<H>
        : RouteHandlerKeyMismatch<K, H>
    : never
  : never;

/** Validate concrete route records; widened records remain runtime-checked. */
export type ValidatePluginRoutes<TRoutes, TMethods> = string extends keyof TRoutes
  ? TRoutes
  : {
      [K in keyof TRoutes as K extends string ? K : never]: K extends string
        ? undefined extends TRoutes[K]
          ? ValidatePluginRoute<K, Exclude<TRoutes[K], undefined>, TMethods> | undefined
          : ValidatePluginRoute<K, TRoutes[K], TMethods>
        : never;
    };

/**
 * Preserve a plugin definition's literals while validating callable methods
 * and correlating every concrete route handler with its method contract.
 */
export function definePlugin<
  const TDefinition,
  const TName extends string,
  TMethods extends object,
  const TRoutes extends PluginRoutes | undefined,
>(definition: TDefinition & FortressPlugin<TName, TMethods, TRoutes>
  & { routes?: ValidatePluginRoutes<TRoutes, NoInfer<TMethods>> }): TDefinition
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
