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
  InferEndpointCallInput,
  InferEndpointSuccessResponse,
} from './endpoint';
import type { CallOptions } from './http/call';
import type { IamEndpointsMap } from './iam/iam-endpoints';
import type { PluginRoutes, PluginRoutesOf, RuntimeFortressPlugin } from './plugin';

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

type ConcreteRoutesValue<R> = [R] extends [PluginRoutes]
  ? undefined extends R
    ? never
    : string extends keyof R ? never : R
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
 * `fortress.call.plugins.oauth.authorize(...)`.
 */
export type PluginCallTree<TPlugins extends readonly RuntimeFortressPlugin[]> = {
  readonly [P in TPlugins[number] as [ConcretePluginRoutes<P>] extends [never] ? never : P['name']]:
  CallClient<ConcretePluginRoutes<P>>;
};

/**
 * The full namespaced call surface derived from the configured plugin
 * tuple. Each callable serializes its input to a `Request` and delegates to
 * `fortress.handleRequest`, so middleware, token verification, RBAC, and
 * validation all run — the same path a network client would hit.
 */
export interface CallTree<
  TPlugins extends readonly RuntimeFortressPlugin[] = readonly RuntimeFortressPlugin[],
> {
  /** Core authentication callables (`login`, `refresh`, `me`, ...). */
  readonly auth: CallClient<AuthEndpointsMap>;
  /** Core IAM callables (`createRole`, `bindRoleToUser`, ...). */
  readonly iam: CallClient<IamEndpointsMap>;
  /** One namespace per configured plugin with concrete routes. */
  readonly plugins: PluginCallTree<TPlugins>;
}
