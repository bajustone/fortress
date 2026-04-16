/**
 * Express middleware wrapper for the rate-limit plugin.
 *
 * Thin adapter that extracts the client IP (and optional authenticated
 * userId) from an Express request and delegates to
 * `fortress.plugins['rate-limit'].check(rule, keys)`. A `FortressError` with
 * code `RATE_LIMITED` is passed to `next(err)` on exceed — the Express error
 * middleware (`createErrorMiddleware` from `@bajustone/fortress/express`)
 * renders a proper 429 with `Retry-After`.
 *
 * @example
 * ```ts
 * import express from 'express';
 * import { expressRateLimit } from '@bajustone/fortress/plugins/rate-limit/express';
 *
 * const app = express();
 * app.use('/api', expressRateLimit(fortress, 'api'));
 * ```
 *
 * @module
 */

import type { Fortress } from '../../core/fortress';

// Minimal Express-compatible types so users bring their own express version.
/** Shape fortress reads from; compatible with any modern Express request. */
export interface MinimalExpressRequest {
  ip?: string;
  headers: Record<string, string | string[] | undefined>;
  fortressUserId?: number;
}

export interface ExpressRateLimitOptions {
  /**
   * Include the authenticated user in the key (requires fortress auth
   * middleware to have run first, populating `req.fortressUserId`). Defaults
   * to `true` — falls back to IP-only when no user is present.
   */
  keyByUser?: boolean;
  /** Override IP extraction. Default uses `req.ip` then forwarding headers. */
  extractIp?: (req: MinimalExpressRequest) => string | undefined;
}

interface RateLimitCheck {
  check: (rule: string, keys: { ip?: string; userId?: number | string }) => Promise<void>;
}

function defaultExtractIp(req: MinimalExpressRequest): string | undefined {
  if (req.ip)
    return req.ip;
  const xff = req.headers['x-forwarded-for'];
  if (typeof xff === 'string')
    return xff.split(',')[0].trim();
  if (Array.isArray(xff) && xff.length > 0)
    return xff[0].split(',')[0].trim();
  const xri = req.headers['x-real-ip'];
  return typeof xri === 'string' ? xri : undefined;
}

/**
 * Returns an Express middleware that rate-limits requests against the named
 * rule defined in your `rateLimit({ rules: { ... } })` config.
 */
export function expressRateLimit(
  fortress: Fortress,
  ruleName: string,
  options: ExpressRateLimitOptions = {},
): (req: MinimalExpressRequest, _res: unknown, next: (err?: unknown) => void) => void {
  const methods = fortress.plugins['rate-limit'] as unknown as RateLimitCheck | undefined;
  if (!methods?.check) {
    throw new Error(
      'rate-limit plugin is not registered — add rateLimit({...}) to your FortressConfig.plugins',
    );
  }
  const extractIp = options.extractIp ?? defaultExtractIp;
  const keyByUser = options.keyByUser ?? true;

  return (req, _res, next) => {
    const ip = extractIp(req);
    const userId = keyByUser ? req.fortressUserId : undefined;
    methods
      .check(ruleName, { ip, userId })
      .then(() => next())
      .catch(next);
  };
}
