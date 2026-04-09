/**
 * SvelteKit adapter for fortress.
 *
 * Provides:
 *
 * - {@link createSvelteKitHandle} — primary `handle` hook for
 *   `hooks.server.ts`. Intercepts Fortress-managed paths and delegates to
 *   `fortress.handleRequest`. Handles auto-refresh, locals population, and
 *   user-route plugin middleware.
 * - {@link toSvelteKitHandler} — escape hatch for catch-all `+server.ts`
 *   files (`src/routes/api/fortress/[...path]/+server.ts`).
 * - {@link fortressActions} — form-action helpers (`login`, `logout`,
 *   `register`, `refresh`) for use in `+page.server.ts`.
 * - {@link getUserId} / {@link getClaims} / {@link getDb} /
 *   {@link getScopedDb} — read the per-request fortress context inside
 *   server load functions and `+server.ts` handlers.
 * - {@link FortressLocals} — type for augmenting SvelteKit's `App.Locals`.
 *
 * @example
 * ```ts
 * // src/lib/server/fortress.ts
 * import { createFortress } from '@bajustone/fortress';
 * import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';
 *
 * export const fortress = createFortress({
 *   database: createDrizzleAdapter(...),
 *   jwt: { secret: process.env.JWT_SECRET! },
 * });
 *
 * // src/hooks.server.ts
 * import { sequence } from '@sveltejs/kit/hooks';
 * import { createSvelteKitHandle } from '@bajustone/fortress/sveltekit';
 * import { fortress } from '$lib/server/fortress';
 *
 * export const handle = sequence(createSvelteKitHandle(fortress, { basePath: '/api' }));
 *
 * // src/app.d.ts
 * import type { FortressLocals } from '@bajustone/fortress/sveltekit';
 *
 * declare global {
 *   namespace App {
 *     interface Locals extends FortressLocals {}
 *   }
 * }
 * ```
 *
 * @module
 */

export { fortressActions } from './actions';
export type {
  FortressActionFailure,
  FortressActionOptions,
  FortressActions,
  FortressActionSuccess,
} from './actions';
export { toSvelteKitHandler } from './catch-all';
export type { SvelteKitRouteHandler } from './catch-all';
export { clearAuthCookies, replayCookies, setAuthCookies } from './cookies';
export { createSvelteKitHandle } from './handle';
export { getClaims, getDb, getScopedDb, getUserId } from './helpers';
export type {
  FortressLocals,
  SvelteKitAction,
  SvelteKitAdapterOptions,
  SvelteKitCookieOptions,
  SvelteKitCookies,
  SvelteKitHandle,
  SvelteKitRequestEvent,
} from './types';
