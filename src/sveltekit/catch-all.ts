/**
 * Optional catch-all `+server.ts` escape hatch.
 *
 * Lets users colocate Fortress routes inside their normal `src/routes/`
 * tree instead of (or in addition to) the handle-hook approach.
 *
 * @example
 * ```ts
 * // src/routes/api/fortress/[...path]/+server.ts
 * import { toSvelteKitHandler } from '@bajustone/fortress/sveltekit';
 * import { fortress } from '$lib/server/fortress';
 *
 * export const { GET, POST, PUT, DELETE, PATCH } = toSvelteKitHandler(fortress);
 * ```
 */

import type { Fortress } from '../core/fortress';
import type { SvelteKitRequestEvent } from './types';

/** Per-method handler signature compatible with SvelteKit `+server.ts` exports. */
export type SvelteKitRouteHandler = (event: SvelteKitRequestEvent) => Promise<Response>;

/**
 * Build a `{ GET, POST, PUT, DELETE, PATCH }` set of handlers that all
 * delegate to `fortress.handleRequest`. Suitable for `export const { ... } =
 * toSvelteKitHandler(fortress)` in a catch-all `+server.ts`.
 */
export function toSvelteKitHandler(fortress: Fortress<any, any>): {
  GET: SvelteKitRouteHandler;
  POST: SvelteKitRouteHandler;
  PUT: SvelteKitRouteHandler;
  DELETE: SvelteKitRouteHandler;
  PATCH: SvelteKitRouteHandler;
} {
  const handler: SvelteKitRouteHandler = event => fortress.handleRequest(event.request);
  return {
    GET: handler,
    POST: handler,
    PUT: handler,
    DELETE: handler,
    PATCH: handler,
  };
}
