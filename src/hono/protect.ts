import type { Context, Env, MiddlewareHandler } from 'hono';
import type { FortressProtectRuntime } from '../core/capabilities';
import type { EndpointDefinition } from '../core/endpoint';
import type {
  ProtectedRouteContext,
  ProtectedRouteHandler,
  ProtectedRouteTarget,
  ProtectOptions,
} from '../core/http/protect';
import { protect } from '../core/http/protect';

/**
 * Hono-flavoured host callback. `E` flows in from the endpoint passed to
 * `protectedRoute()`, so `ctx.body` / `ctx.query` / `ctx.params` / `ctx.input`
 * are typed from the endpoint's phantom generics.
 *
 * `HEnv` is Hono's environment generic (renamed from `E` so it no longer
 * collides with the endpoint generic). String targets degrade to the
 * loose default just like the core helper.
 */
export type HonoProtectedRouteHandler<

  E extends EndpointDefinition<any, any, any, any> = EndpointDefinition,
  HEnv extends Env = Env,
  TResult = unknown,
> = (
  c: Context<HEnv>,
  ctx: ProtectedRouteContext<E>,
) => TResult | Response | Promise<TResult | Response>;

/**
 * Wrap a host-owned Hono route in Fortress's route protection pipeline.
 *
 * Two overloads, mirroring `protect()`:
 *
 * - **Typed target** — passing an `EndpointDefinition` flows its phantom
 *   generics through `ctx.body` / `ctx.query` / `ctx.params` / `ctx.input`.
 * - **String target** — passing a unique `handler` name keeps the loose
 *   `Record<string, unknown>` / `unknown` typing.
 */
export function protectedRoute<

  E extends EndpointDefinition<any, any, any, any>,
  HEnv extends Env = Env,
  TResult = unknown,
>(
  fortress: FortressProtectRuntime,
  target: E,
  handler: HonoProtectedRouteHandler<E, HEnv, TResult>,
  options?: ProtectOptions,
): MiddlewareHandler<HEnv>;
export function protectedRoute<HEnv extends Env = Env, TResult = unknown>(
  fortress: FortressProtectRuntime,
  target: string,
  handler: HonoProtectedRouteHandler<EndpointDefinition, HEnv, TResult>,
  options?: ProtectOptions,
): MiddlewareHandler<HEnv>;
export function protectedRoute(
  fortress: FortressProtectRuntime,
  target: ProtectedRouteTarget,

  handler: HonoProtectedRouteHandler<any, any, unknown>,
  options: ProtectOptions = {},
): MiddlewareHandler {
  return async (c) => {
    // Cast: core `protect` overloads require a concrete branch; impl is loose.
    const protectedHandler = (protect as (
      f: FortressProtectRuntime,
      t: ProtectedRouteTarget,
      h: ProtectedRouteHandler,
      o?: ProtectOptions,
    ) => (request: Request) => Promise<Response>)(
      fortress,
      target,
      ctx => handler(c, ctx),
      { ...options, method: options.method ?? c.req.method },
    );
    return protectedHandler(c.req.raw);
  };
}

export type {
  ProtectedRouteContext,
  ProtectedRouteHandler,
  ProtectedRouteTarget,
  ProtectOptions,
};
