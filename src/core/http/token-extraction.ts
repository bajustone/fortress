/**
 * Token extraction from a web-standard Request.
 *
 * Reads the access token from the configured cookie first, then falls back
 * to the `Authorization: Bearer` header. Pure function — no side effects,
 * no framework dependencies.
 */

import type { ResolvedCookieConfig } from '../config';
import { parseCookieHeader } from './cookie-serialize';

const BEARER_PREFIX = 'Bearer ';

/**
 * Extract the access token from a request, preferring the cookie configured
 * via {@link ResolvedCookieConfig.accessName} and falling back to
 * `Authorization: Bearer <token>`.
 *
 * Returns `null` if neither source carries a token.
 */
export function extractAccessToken(
  request: Request,
  cookies: ResolvedCookieConfig,
): string | null {
  const jar = parseCookieHeader(request.headers.get('cookie'));
  const fromCookie = jar[cookies.accessName];
  if (fromCookie)
    return fromCookie;

  const auth = request.headers.get('authorization');
  if (auth?.startsWith(BEARER_PREFIX)) {
    return auth.slice(BEARER_PREFIX.length) || null;
  }

  return null;
}

/**
 * Extract the refresh token from a request's cookie jar. Refresh tokens are
 * never read from headers — they live in `httpOnly` cookies only.
 */
export function extractRefreshToken(
  request: Request,
  cookies: ResolvedCookieConfig,
): string | null {
  const jar = parseCookieHeader(request.headers.get('cookie'));
  return jar[cookies.refreshName] ?? null;
}
