/**
 * Protected route. Reads the authenticated user via `getUserId`.
 * If the auth handle hook didn't populate `event.locals.fortress.userId`
 * (no token, expired beyond refresh, etc.), `getUserId` throws and the
 * caller redirects to `/login`.
 *
 * In a real project the load function uses SvelteKit's `error()` /
 * `redirect()` from `@sveltejs/kit` instead of throwing fortress errors
 * directly. This example throws to keep the dependencies minimal.
 */

import type { SvelteKitRequestEvent } from '../../../../../src/sveltekit';
import { getUserId } from '../../../../../src/sveltekit';
import { fortress } from '../../lib/server/fortress';

export async function load(event: SvelteKitRequestEvent): Promise<{ user: { id: string; email: string } }> {
  const userId = getUserId(event as never);
  const user = await fortress.auth.me(userId);
  return { user };
}
