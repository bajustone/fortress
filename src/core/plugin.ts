import type { DatabaseAdapter } from '../adapters/database';
import type { ScopeRule } from '../adapters/database/types';
import type { AuthService } from './auth/auth-service';
import type { FortressConfig } from './config';
import type {
  AnyEndpointDefinition,
  InferEndpointBody,
  InferEndpointBodyInput,
  InferEndpointCallInput,
  InferEndpointHandler,
  InferEndpointParams,
  InferEndpointParamsInput,
  InferEndpointQuery,
  InferEndpointQueryInput,
  InferEndpointSuccessResponse,
  InferEndpointValidatedInput,
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

/**
 * A startup dependency on another registered plugin and, optionally, on
 * callable methods that plugin must expose. Dependency metadata is declarative
 * so Fortress can reject an invalid plugin graph before serving requests.
 */
export interface PluginDependency {
  /** Registered plugin name that provides the dependency. */
  plugin: string;
  /** Method capabilities required from the dependency's runtime surface. */
  methods?: readonly string[];
}

type CallableMethodSurface<TMethods extends object> = {
  [K in keyof TMethods]: TMethods[K] extends PluginMethod ? TMethods[K] : never;
};

/**
 * Plugin fields shared by concrete and runtime-widened definitions.
 *
 * Descriptor slots are construction-time declarations. Fortress invokes every
 * `methods()` factory first, then captures the final names, routes, hooks,
 * middleware, and callable capability identities into an internal validated
 * view. After every factory returns, Fortress also captures the effective
 * callable membership and direct callable identities of each returned method
 * surface into an immutable facade. Reassigning, adding, removing, or
 * reordering those caller-owned slots after `createFortress()` returns does
 * not replace Fortress-controlled entry points, and Fortress never freezes or
 * rewrites the caller's objects.
 *
 * Captured functions and their closures are intentionally live. Each callable
 * is invoked with its original descriptor, hook, middleware, or returned method
 * object as receiver for compatibility. Plugins may keep counters, caches, key
 * material, feature state, and other runtime state behind that receiver or
 * closure; changing such retained state remains observable. The fixed boundary is
 * descriptor/container membership and directly selected callable identity,
 * not arbitrary objects captured plugin code chooses to read. In particular,
 * trusted method code that performs `this.other()`, `super.other()`, or an
 * external lookup may observe later mutation of that retained state.
 */
export interface FortressPluginDefinition<
  TName extends string,
  TRoutes extends PluginRoutes | undefined,
> {
  /** Unique plugin identifier */
  name: TName;

  /** DB models this plugin needs */
  models?: ModelDefinition[];

  /** Other plugin capabilities required for this plugin configuration. */
  dependencies?: readonly PluginDependency[];

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

  /**
   * Core call keys this plugin intentionally overrides. Required when a route
   * claims a core method/path so the derived call tree can omit that core
   * callable without guessing from widened or configurable route records.
   */
  coreOverrides?: readonly string[];

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
 * Plugin contract. Concrete method surfaces require an implementation and
 * every effective own or inherited property must be callable. Fortress
 * publishes a frozen construction-owned facade that captures own and inherited
 * callables, including symbols, non-enumerables, and getter-backed methods. Captured
 * methods run with the original returned object as receiver, preserving
 * private and receiver-owned state. Runtime-widened and legacy surfaces keep
 * `methods` optional.
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

/**
 * The JSON-wire projection of a handler's return value: `Date`s serialize
 * to ISO strings, everything else keeps its shape. Route success-response
 * schemas describe the wire, so handler returns are compared through this
 * mapping.
 */
export type JsonOf<T> = T extends Date ? string
  : T extends (...args: any[]) => any ? never
    : T extends readonly (infer U)[] ? JsonOf<U>[]
      : T extends object ? { [K in keyof T]: JsonOf<T[K]> }
        : T;

type IsAny<T> = 0 extends (1 & T) ? true : false;
type IsUnknown<T> = IsAny<T> extends true ? false : unknown extends T ? [keyof T] extends [never] ? true : false : false;
type FunctionPropertyKeys<T> = {
  [K in keyof T]-?: Exclude<T[K], undefined> extends (...args: any[]) => any ? K : never;
}[keyof T];
type IsFlatInputObject<T> = IsAny<T> extends true
  ? true
  : IsUnknown<T> extends true
    ? true
    : [T] extends [object]
        ? [Extract<T, Date | readonly unknown[] | ((...args: any[]) => any)>] extends [never]
            ? [FunctionPropertyKeys<T>] extends [never] ? true : false
            : false
        : false;
type EndpointInputCompatible<E> = [
  IsFlatInputObject<InferEndpointBodyInput<E>>,
  IsFlatInputObject<InferEndpointQueryInput<E>>,
  IsFlatInputObject<InferEndpointParamsInput<E>>,
  IsFlatInputObject<InferEndpointBody<E>>,
  IsFlatInputObject<InferEndpointQuery<E>>,
  IsFlatInputObject<InferEndpointParams<E>>,
] extends [true, true, true, true, true, true] ? true : false;

type ContainsNonJsonValue<T> = T extends Date ? false
  : T extends ((...args: any[]) => any) | bigint | symbol | undefined ? true
    : T extends readonly (infer U)[]
      ? true extends ContainsNonJsonValue<U> ? true : false
      : T extends object
        ? true extends {
          [K in keyof T]-?: ContainsNonJsonValue<Exclude<T[K], undefined>>;
        }[keyof T] ? true : false
        : false;

/**
 * Does the handler accept the exact call dispatch performs? Function
 * assignability permits handlers that ignore either argument, while still
 * checking optional/rest parameters and rejecting required trailing ones.
 */
type HandlerInvocationCompatible<M, E> = M extends (
  input: InferEndpointValidatedInput<E>,
  context: PluginRouteContext,
) => any ? true : false;

/**
 * Does the handler's resolved return value serialize to the endpoint's
 * declared success response? Skipped when the endpoint declares no 2xx
 * schema (`unknown` success).
 */
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

/** Compile-time diagnostic: a concrete route key differs from its handler. */
export interface RouteHandlerKeyMismatch<TKey extends string, THandler extends string> {
  readonly 'fortress:route-error': `route key '${TKey}' must match handler '${THandler}'`;
}

/** Compile-time diagnostic: a route names a handler that is not a plugin method. */
export interface RouteHandlerMissing<THandler extends string> {
  readonly 'fortress:route-error': `route handler '${THandler}' is not a plugin method — declare it in methods()`;
}

/** Compile-time diagnostic: a route declares input incompatible with flat dispatch. */
export interface RouteInputNotFlat<THandler extends string> {
  readonly 'fortress:route-error': `route handler '${THandler}' requires body/query/params schemas that accept and return flat objects`;
}

/** Compile-time diagnostic: a route's handler method does not match the endpoint's I/O. */
export interface RouteHandlerIncompatible<THandler extends string> {
  readonly 'fortress:route-error': `plugin method '${THandler}' does not accept this endpoint's input or return its declared success response`;
}

/**
 * `true` when an endpoint declares no phantom contract at all — no inferred
 * input keys and an `unknown` success response. Hand-authored JSON-schema
 * route literals (not built with `endpoint()`) look like this; with nothing
 * declared, there is nothing to correlate beyond handler existence.
 */
type ContractlessEndpoint<E> = keyof InferEndpointCallInput<E> extends never
  ? unknown extends InferEndpointSuccessResponse<E> ? true : false
  : false;

type ValidatePluginRoute<K extends string, E, TMethods> = E extends AnyEndpointDefinition
  ? InferEndpointHandler<E> extends infer H extends string
    ? [K, H] extends [H, K]
        ? H extends keyof TMethods
          ? E extends { meta: { bearerKind: 'oauth' } | { dispatchKind: 'oauth' } }
            ? E
            : EndpointInputCompatible<E> extends true
              ? HandlerInvocationCompatible<TMethods[H], E> extends true
                ? ContractlessEndpoint<E> extends true
                  ? E
                  : HandlerReturnCompatible<TMethods[H], E> extends true
                    ? E
                    : RouteHandlerIncompatible<H>
                : RouteHandlerIncompatible<H>
              : RouteInputNotFlat<H>
          : RouteHandlerMissing<H>
        : RouteHandlerKeyMismatch<K, H>
    : never
  : never;

/**
 * Definition-site validation of a plugin's route record against its method
 * surface. Each route must (1) name an existing plugin method via its
 * literal `handler`, and (2) — for routes that declare a phantom contract —
 * be signature-compatible with how dispatch invokes it: the method must
 * accept the flat validated input (the Standard Schema output), and its
 * resolved return must serialize ({@link JsonOf}) to the declared success
 * response.
 *
 * Two exemptions from the I/O check (handler existence is always enforced):
 * - routes marked `meta.bearerKind: 'oauth'` or
 *   `meta.dispatchKind: 'oauth'` use bespoke OAuth dispatch calling
 *   conventions (see `dispatchOAuth`); typing that boundary is tracked by
 *   issue #27;
 * - {@link ContractlessEndpoint contractless} routes declare nothing to
 *   check against. Author routes with `endpoint()` to opt into full I/O
 *   correlation.
 */
export type ValidatePluginRoutes<TRoutes, TMethods> = string extends keyof TRoutes
  // Dynamically aggregated route records (string index signature) carry no
  // per-property declarations to check statically; dispatch validates their
  // handlers at runtime. They also contribute no typed call namespace.
  ? TRoutes
  : {
      [K in keyof TRoutes as K extends string ? K : never]: K extends string
        ? undefined extends TRoutes[K]
          ? ValidatePluginRoute<K, Exclude<TRoutes[K], undefined>, TMethods> | undefined
          : ValidatePluginRoute<K, TRoutes[K], TMethods>
        : never;
    };

/**
 * Canonical plugin authoring API. Preserves a plugin definition's literal
 * name, exact methods, and exact routes, and statically verifies that every
 * route's `handler` names an existing plugin method whose signature is
 * compatible with the endpoint's declared input and success response.
 *
 * Third-party plugins get the full typed surface from inference alone — no
 * central registry edit or module augmentation required.
 */
/** Package-owned inference blocker compatible with the advertised TypeScript 5.0 floor. */
type NoInferCompat<T> = [T][T extends any ? 0 : never];

export function definePlugin<
  const TDefinition,
  const TName extends string,
  TMethods extends object,
  const TRoutes extends PluginRoutes | undefined,
>(definition: TDefinition & FortressPlugin<TName, TMethods, TRoutes>
  & { routes?: ValidatePluginRoutes<TRoutes, NoInferCompat<TMethods>> }): TDefinition
    & Omit<FortressPlugin<TName, TMethods, TRoutes>, 'name' | 'methods' | 'routes' | 'coreOverrides'>;
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
  /**
   * Look up the single captured runtime method facade for a registered plugin.
   * Capture this function during `methods()` initialization and call it lazily
   * from returned methods; calling it before the whole Fortress construction
   * succeeds is rejected so lookup semantics do not depend on registration
   * order and failed construction cannot leak a provisional surface.
   *
   * Only `createFortress()` supplies this. A hand-assembled context — calling
   * `plugin.methods(ctx)` directly rather than registering the plugin — will
   * not have it, so treat its absence as the dependency being unavailable.
   */
  getPluginMethods?: (name: string) => Readonly<Record<string, PluginMethod>> | undefined;
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
  /** Optional HTTP-method filter. Matching is case-insensitive; authoring arrays remain mutable. */
  methods?: string[];
  handler: (ctx: PluginContext, request: PluginRequestContext, next: () => Promise<void>) => Promise<void>;
}
