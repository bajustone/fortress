/**
 * Hono middleware wrapper for the rate-limit plugin.
 *
 * Thin adapter that extracts the client IP (and optional authenticated
 * userId) from a Hono context and delegates to
 * `fortress.plugins['rate-limit'].check(rule, keys)`. A `FortressError` with
 * code `RATE_LIMITED` is thrown when the limit is exceeded — pair this with
 * `createHonoMiddleware(fortress).errorHandler` (or any handler that calls
 * `errorToResponse`) to render a proper 429 with `Retry-After`.
 *
 * @example
 * ```ts
 * import { Hono } from 'hono';
 * import { honoRateLimit } from '@bajustone/fortress/plugins/rate-limit/hono';
 *
 * const app = new Hono();
 * app.use('/api/*', honoRateLimit(fortress, 'api'));
 * ```
 *
 * @module
 */

import type { Context, MiddlewareHandler } from 'hono';
import type { Fortress } from '../../core/fortress';

export interface HonoRateLimitOptions {
  /**
   * Include the authenticated user in the key (requires fortress auth
   * middleware to have run first, populating `fortressUserId`). Defaults to
   * `true` — falls back to IP-only when no user is present.
   */
  keyByUser?: boolean;
  /** Override IP extraction. Default reads `X-Forwarded-For` then `X-Real-IP`. */
  extractIp?: (c: Context) => string | undefined;
}

interface RateLimitCheck {
  check: (rule: string, keys: { ip?: string; userId?: number | string }) => Promise<void>;
}

function defaultExtractIp(c: Context): string | undefined {
  const xff = c.req.header('x-forwarded-for');
  if (xff)
    return xff.split(',')[0].trim();
  return c.req.header('x-real-ip');
}

/**
 * Returns a Hono middleware that rate-limits requests against the named rule
 * defined in your `rateLimit({ rules: { ... } })` config.
 */
export function honoRateLimit(
  fortress: Fortress,
  ruleName: string,
  options: HonoRateLimitOptions = {},
): MiddlewareHandler {
  const methods = fortress.plugins['rate-limit'] as unknown as RateLimitCheck | undefined;
  if (!methods?.check) {
    throw new Error(
      'rate-limit plugin is not registered — add rateLimit({...}) to your FortressConfig.plugins',
    );
  }
  const extractIp = options.extractIp ?? defaultExtractIp;
  const keyByUser = options.keyByUser ?? true;

  return async (c, next) => {
    const ip = extractIp(c);
    const userId = keyByUser
      ? (c.get('fortressUserId' as never) as number | undefined)
      : undefined;
    await methods.check(ruleName, { ip, userId });
    await next();
  };
}
