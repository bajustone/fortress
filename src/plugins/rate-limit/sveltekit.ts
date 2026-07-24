/**
 * SvelteKit helper for the rate-limit plugin.
 *
 * Call from `hooks.server.ts` or inside a load/action to rate-limit a given
 * route. Throws a `FortressError` with code `RATE_LIMITED` when the limit
 * is exceeded — the fortress SvelteKit handle (or your own `handleError`)
 * will render a proper 429 response via `errorToResponse`.
 *
 * @example
 * ```ts
 * // hooks.server.ts
 * import { svelteKitRateLimit } from '@bajustone/fortress/plugins/rate-limit/sveltekit';
 *
 * export const handle = async ({ event, resolve }) => {
 *   if (event.url.pathname.startsWith('/api/')) {
 *     await svelteKitRateLimit(fortress, 'api', event);
 *   }
 *   return resolve(event);
 * };
 * ```
 *
 * @module
 */

import type { AnyFortress } from '../../core/fortress';

export interface SvelteKitRateLimitEvent {
  request: Request;
  locals?: { fortressUserId?: string };
}

interface RateLimitCheck {
  check: (rule: string, keys: { ip?: string; userId?: string }) => Promise<void>;
}

function ipFromRequest(request: Request): string | undefined {
  const xff = request.headers.get('x-forwarded-for');
  if (xff)
    return xff.split(',')[0].trim();
  return request.headers.get('x-real-ip') ?? undefined;
}

/**
 * Run a rate-limit check against the named rule for the given SvelteKit
 * request event. Returns void on pass; throws `FortressError` (RATE_LIMITED)
 * on exceed.
 */
export async function svelteKitRateLimit(
  fortress: AnyFortress,
  ruleName: string,
  event: SvelteKitRateLimitEvent,
  options: { keyByUser?: boolean } = {},
): Promise<void> {
  const methods = (fortress.plugins as Record<string, unknown>)['rate-limit'] as RateLimitCheck | undefined;
  if (!methods?.check) {
    throw new Error(
      'rate-limit plugin is not registered — add rateLimit({...}) to your FortressConfig.plugins',
    );
  }
  const keyByUser = options.keyByUser ?? true;
  const userId = keyByUser ? event.locals?.fortressUserId : undefined;
  await methods.check(ruleName, {
    ip: ipFromRequest(event.request),
    userId,
  });
}
