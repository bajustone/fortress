import type { ErrorHandler } from 'hono';
import { errorToResponse } from '../../core/http/error-response';

/**
 * Hono error handler that maps FortressError to HTTP responses.
 * Delegates to the framework-agnostic `errorToResponse` in core so the
 * mapping (status codes, `Retry-After`, sanitized 500s) stays consistent
 * across Hono / Express / SvelteKit / `fortress.handleRequest`.
 */
export function createErrorHandler(): ErrorHandler {
  return err => errorToResponse(err);
}
