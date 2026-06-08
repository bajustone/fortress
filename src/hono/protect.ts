import type { Context, Env, MiddlewareHandler } from 'hono';
import type { Fortress } from '../core/fortress';
import type {
  ProtectedRouteContext,
  ProtectedRouteHandler,
  ProtectedRouteTarget,
  ProtectOptions,
} from '../core/http/protect';
import { protect } from '../core/http/protect';

export type HonoProtectedRouteHandler<E extends Env = Env, TResult = unknown> = (
  c: Context<E>,
  ctx: ProtectedRouteContext,
) => TResult | Response | Promise<TResult | Response>;

/**
 * Wrap a host-owned Hono route in Fortress's route protection pipeline.
 *
 * The target is a handler name from `fortress.endpoints` or an
 * `EndpointDefinition`. Its endpoint metadata supplies auth/RBAC/validation
 * policy; your callback owns the business response.
 */
export function protectedRoute<E extends Env = Env, TResult = unknown>(
  fortress: Fortress,
  target: ProtectedRouteTarget,
  handler: HonoProtectedRouteHandler<E, TResult>,
  options: ProtectOptions = {},
): MiddlewareHandler<E> {
  return async (c) => {
    const protectedHandler = protect<TResult>(
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
