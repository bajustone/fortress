/**
 * Map any thrown error to a web-standard `Response`.
 *
 * Knows about {@link FortressError} (typed status + retry-after handling)
 * and falls back to a sanitized 500 for everything else. Used by
 * `fortress.handleRequest` and re-exportable by adapters.
 */

import type { FortressLogger } from '../observability/logger';
import { FortressError } from '../errors';

/** JSON shape of an internal/unknown error response. */
interface InternalErrorBody {
  code: 'INTERNAL_ERROR';
  message: 'Internal server error';
  statusCode: 500;
}

/**
 * Convert any caught error into a JSON `Response`. {@link FortressError}
 * instances are mapped to their declared status code, with `Retry-After`
 * set for `RATE_LIMITED`. Unknown errors return a sanitized 500 with no
 * stack trace; the original error is routed to the caller-supplied
 * {@link FortressLogger} at `error` level.
 */
export function errorToResponse(err: unknown, logger?: FortressLogger): Response {
  if (err instanceof FortressError) {
    const headers: Record<string, string> = { 'Content-Type': 'application/json' };
    if (err.code === 'RATE_LIMITED' && err.retryAfter !== undefined) {
      headers['Retry-After'] = String(err.retryAfter);
    }
    return new Response(JSON.stringify(err.toJSON()), {
      status: err.statusCode,
      headers,
    });
  }

  logger?.error(
    { err, message: err instanceof Error ? err.message : 'Unknown error' },
    'unhandled error in fortress.handleRequest',
  );
  const body: InternalErrorBody = {
    code: 'INTERNAL_ERROR',
    message: 'Internal server error',
    statusCode: 500,
  };
  return new Response(JSON.stringify(body), {
    status: 500,
    headers: { 'Content-Type': 'application/json' },
  });
}

/**
 * Append `Set-Cookie` headers to an existing `Response`. The web-standard
 * `Headers.set` only keeps the last `set-cookie`, so multiple cookies must
 * use `append`. This helper centralizes that quirk for adapters.
 *
 * Returns a *new* `Response` with the cookies merged in. The original is
 * not mutated (its body is teed via `.clone()` semantics through the
 * constructor).
 */
export function withCookies(response: Response, setCookies: string[]): Response {
  if (setCookies.length === 0)
    return response;
  const headers = new Headers(response.headers);
  for (const cookie of setCookies) {
    headers.append('set-cookie', cookie);
  }
  return new Response(response.body, {
    status: response.status,
    statusText: response.statusText,
    headers,
  });
}
