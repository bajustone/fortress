/**
 * Token extraction from a web-standard Request.
 *
 * Reads the access token from the configured cookie first, then falls back
 * to the `Authorization: Bearer` header. Pure function — no side effects,
 * no framework dependencies.
 */

import type { ResolvedCookieConfig } from '../config';
import { parseCookieHeader } from './cookie-serialize';

/**
 * Extract the access token from a request, preferring the
 * `Authorization: Bearer <token>` header and falling back to the cookie
 * configured via {@link ResolvedCookieConfig.accessName}.
 *
 * P3.7 fix: the previous implementation read the cookie first, which on a
 * shared cookie domain could let a same-origin attacker's cookie shadow
 * the caller's intended bearer token. The Authorization header is an
 * explicit, intentional credential and takes precedence; the cookie is
 * only consulted when no bearer header is present.
 *
 * Returns `null` if neither source carries a token.
 */
export function extractAccessToken(
  request: Request,
  cookies: ResolvedCookieConfig,
): string | null {
  const auth = request.headers.get('authorization');
  if (auth) {
    const separator = auth.indexOf(' ');
    if (separator > 0 && auth.slice(0, separator).toLowerCase() === 'bearer') {
      const fromHeader = auth.slice(separator + 1).trim();
      if (fromHeader)
        return fromHeader;
    }
  }

  const jar = parseCookieHeader(request.headers.get('cookie'));
  return jar[cookies.accessName] ?? null;
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
