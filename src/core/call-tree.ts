/**
 * Namespaced typed call tree (ADR 0001 §5).
 *
 * The in-process call client is ownership-aware: core auth and IAM callables
 * live under `call.auth.*` and `call.iam.*`, and every plugin that ships
 * concrete routes gets its own namespace under `call.plugins.<name>.*`.
 * Because plugin names are unique by construction (rejected at startup and
 * keyed by `InferPlugins`), cross-plugin call-name collisions are impossible
 * — no intersection machinery, no key filtering, no destructive fallbacks.
 */

import type { AuthEndpointsMap } from './auth/auth-endpoints';
import type {
  AnyEndpointDefinition,
  InferEndpointCallInput,
  InferEndpointSuccessResponse,
} from './endpoint';
import type { CallOptions } from './http/call';
import type { IamEndpointsMap } from './iam/iam-endpoints';
import type { PluginRoutesOf, RuntimeFortressPlugin } from './plugin';

/** One typed in-process callable derived from an endpoint definition. */
export type EndpointCall<E> = (
  input: InferEndpointCallInput<E>,
  options?: CallOptions,
) => Promise<InferEndpointSuccessResponse<E>>;

/**
 * The call client for an exact endpoint collection — a plain mapped type.
 * Collections are validated at their definition site (`defineEndpoints`),
 * so no member needs filtering; the `& string` only strips the phantom
 * validation brand's symbol key.
 */
export type CallClient<E> = {
  readonly [K in keyof E & string]: EndpointCall<E[K]>;
};

type IsAny<T> = 0 extends (1 & T) ? true : false;

type GenericCallableRoutes<E> = {
  [K in keyof E as Exclude<E[K], undefined> extends { meta: { bearerKind: 'oauth' } } ? never : K]: E[K];
};

type CoreOverrideKeys<TPlugins extends readonly RuntimeFortressPlugin[]>
  = TPlugins[number] extends infer P
    ? P extends { coreOverrides: readonly (infer K extends string)[] } ? K : never
    : never;

type EffectiveCoreClient<
  E,
  TPlugins extends readonly RuntimeFortressPlugin[],
> = [CoreOverrideKeys<TPlugins>] extends [never]
  ? CallClient<E>
  : {
      readonly [K in keyof E & string as K extends CoreOverrideKeys<TPlugins> ? never : K]: EndpointCall<E[K]>;
    };

type ConcreteRoutesValue<R> = [R] extends [object]
  ? undefined extends R
    ? never
    : string extends keyof R
      ? never
      : Exclude<R[keyof R & string], undefined> extends AnyEndpointDefinition ? R : never
  : never;

/**
 * The concrete route record contributed by one plugin, or `never` when the
 * plugin declares no routes, optional routes, or a widened (string-indexed)
 * record that would poison the namespace with an index signature. The
 * `'routes' extends keyof P` split mirrors `definePlugin`'s return type,
 * which omits `routes` entirely for definitions that never declare it.
 */
type ConcretePluginRoutes<P> = 'routes' extends keyof P
  ? Record<never, never> extends Pick<P, 'routes' & keyof P>
    ? never
    : P extends { routes: infer R } ? ConcreteRoutesValue<R> : never
  : ConcreteRoutesValue<PluginRoutesOf<P>>;

/**
 * Plugin namespaces of the call tree — one per configured plugin that ships
 * concrete routes. Ownership is explicit at every call site:
 * `fortress.call.plugins.oauth.handleGetFlow(...)`. OAuth protocol routes
 * that require form/basic/bearer semantics are intentionally excluded.
 */
export type PluginCallTree<TPlugins extends readonly RuntimeFortressPlugin[]> = {
  readonly [P in TPlugins[number] as P extends { methods: (...args: any[]) => object }
    ? IsAny<P['name']> extends true
      ? never
      : string extends P['name'] ? never : [ConcretePluginRoutes<P>] extends [never] ? never : P['name']
    : never]:
  CallClient<GenericCallableRoutes<ConcretePluginRoutes<P>>>;
};

/**
 * The full namespaced call surface derived from the configured plugin
 * tuple. Each callable serializes its input to a `Request` and delegates to
 * `fortress.handleRequest`, so middleware, token verification, RBAC, and
 * validation all run — the same path a network client would hit.
 */
interface PreciseCallTree<TPlugins extends readonly RuntimeFortressPlugin[]> {
  /** Core authentication callables (`login`, `refresh`, `me`, ...). */
  readonly auth: EffectiveCoreClient<AuthEndpointsMap, TPlugins>;
  /** Core IAM callables (`createRole`, `bindRoleToUser`, ...). */
  readonly iam: EffectiveCoreClient<IamEndpointsMap, TPlugins>;
  /** One namespace per configured plugin with concrete routes. */
  readonly plugins: PluginCallTree<TPlugins>;
}

interface ErasedCallTree {
  readonly auth: Record<never, never>;
  readonly iam: Record<never, never>;
  readonly plugins: Record<never, never>;
}

/**
 * The broad default is an erased supertype that makes no callable promises;
 * concrete plugin tuples resolve to the precise derived tree.
 */
export type CallTree<
  TPlugins extends readonly RuntimeFortressPlugin[] = readonly RuntimeFortressPlugin[],
> = readonly RuntimeFortressPlugin[] extends TPlugins
  ? ErasedCallTree
  : PreciseCallTree<TPlugins>;
