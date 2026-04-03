import type { ErrorHandler } from 'hono';
import { FortressError } from '../../core/errors';

/**
 * Hono error handler that maps FortressError to HTTP responses.
 * Adds Retry-After header for rate limit errors.
 */
export function createErrorHandler(): ErrorHandler {
  return (err, c) => {
    if (err instanceof FortressError) {
      if (err.code === 'RATE_LIMITED' && err.retryAfter) {
        c.header('Retry-After', String(err.retryAfter));
      }

      return c.json(err.toJSON(), err.statusCode as any);
    }

    // Unknown error — don't leak internals
    console.error('Unhandled error:', err);
    return c.json({ code: 'INTERNAL_ERROR', message: 'Internal server error', statusCode: 500 }, 500);
  };
}
