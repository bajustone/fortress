import type { Fortress } from '../core/fortress';
import type {
  ProtectedRouteContext,
  ProtectedRouteTarget,
  ProtectOptions,
} from '../core/http/protect';
import type { SvelteKitRequestEvent } from './types';
import { protect } from '../core/http/protect';
import { replayCookies } from './cookies';

export type SvelteKitProtectedRouteHandler<TResult = unknown> = (
  event: SvelteKitRequestEvent,
  ctx: ProtectedRouteContext,
) => TResult | Response | Promise<TResult | Response>;

/** Wrap a host-owned SvelteKit route/action in Fortress's protection pipeline. */
export function protectedRoute<TResult = unknown>(
  fortress: Fortress,
  target: ProtectedRouteTarget,
  handler: SvelteKitProtectedRouteHandler<TResult>,
  options: ProtectOptions = {},
): (event: SvelteKitRequestEvent) => Promise<Response> {
  return async (event) => {
    const protectedHandler = protect<TResult>(
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
