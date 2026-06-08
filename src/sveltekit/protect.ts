import type { EndpointDefinition } from '../core/endpoint';
import type { Fortress } from '../core/fortress';
import type {
  ProtectedRouteContext,
  ProtectedRouteHandler,
  ProtectedRouteTarget,
  ProtectOptions,
} from '../core/http/protect';
import type { SvelteKitRequestEvent } from './types';
import { protect } from '../core/http/protect';
import { replayCookies } from './cookies';

/**
 * SvelteKit-flavoured host callback. `E` flows in from the endpoint passed
 * to `protectedRoute()`, so `ctx.body` / `ctx.query` / `ctx.params` /
 * `ctx.input` are typed from the endpoint's phantom generics. String
 * targets degrade to the loose default.
 */
export type SvelteKitProtectedRouteHandler<

  E extends EndpointDefinition<any, any, any, any> = EndpointDefinition,
  TResult = unknown,
> = (
  event: SvelteKitRequestEvent,
  ctx: ProtectedRouteContext<E>,
) => TResult | Response | Promise<TResult | Response>;

/**
 * Wrap a host-owned SvelteKit route/action in Fortress's protection pipeline.
 *
 * Two overloads, mirroring `protect()`:
 *
 * - **Typed target** — passing an `EndpointDefinition` flows its phantom
 *   generics through `ctx`.
 * - **String target** — passing a unique `handler` name keeps the loose
 *   `Record<string, unknown>` / `unknown` typing.
 */
export function protectedRoute<

  E extends EndpointDefinition<any, any, any, any>,
  TResult = unknown,
>(
  fortress: Fortress,
  target: E,
  handler: SvelteKitProtectedRouteHandler<E, TResult>,
  options?: ProtectOptions,
): (event: SvelteKitRequestEvent) => Promise<Response>;
export function protectedRoute<TResult = unknown>(
  fortress: Fortress,
  target: string,
  handler: SvelteKitProtectedRouteHandler<EndpointDefinition, TResult>,
  options?: ProtectOptions,
): (event: SvelteKitRequestEvent) => Promise<Response>;
export function protectedRoute(
  fortress: Fortress,
  target: ProtectedRouteTarget,

  handler: SvelteKitProtectedRouteHandler<any, unknown>,
  options: ProtectOptions = {},
): (event: SvelteKitRequestEvent) => Promise<Response> {
  return async (event) => {
    // Cast: core `protect` overloads require a concrete branch; impl is loose.
    const protectedHandler = (protect as (
      f: Fortress,
      t: ProtectedRouteTarget,
      h: ProtectedRouteHandler,
      o?: ProtectOptions,
    ) => (request: Request) => Promise<Response>)(
      fortress,
      target,
      ctx => handler(event, ctx),
      { ...options, method: options.method ?? event.request.method },
    );
    const response = await protectedHandler(event.request);
    replayCookies(response, event);
    return response;
  };
}

export type { ProtectedRouteContext, ProtectedRouteTarget, ProtectOptions };
