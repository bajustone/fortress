/**
 * SvelteKit cookie bridging.
 *
 * Translates between fortress's auth result objects and SvelteKit's
 * `event.cookies` API. Cookie attributes (name, secure, sameSite, path,
 * domain) come from the resolved {@link ResolvedCookieConfig} on the
 * Fortress instance, so SvelteKit, Hono, and Express all emit cookies with
 * the same shape.
 */

import type { FortressAuthRuntime } from '../core/capabilities';
import type { ResolvedCookieConfig } from '../core/config';
import type { AuthCookiePayload } from '../core/http/cookie-serialize';
import type { SvelteKitCookieOptions, SvelteKitRequestEvent } from './types';
import { parseCookieHeader } from '../core/http/cookie-serialize';

/**
 * Set the access + refresh cookies on a SvelteKit `RequestEvent` from a
 * fortress auth result. Used by the form-action helpers and the auto-refresh
 * path inside `createSvelteKitHandle`.
 */
export function setAuthCookies(
  event: SvelteKitRequestEvent,
  fortress: Pick<FortressAuthRuntime, 'cookies' | 'config'>,
  payload: AuthCookiePayload,
): void {
  const cookies = fortress.cookies;
  const accessExpiry = fortress.config.jwt.accessTokenExpirySeconds ?? 900;
  const refreshExpiry = fortress.config.jwt.refreshTokenExpirySeconds ?? 604_800;

  event.cookies.set(cookies.accessName, payload.accessToken, optsFor(cookies, accessExpiry));
  if (payload.refreshToken) {
    event.cookies.set(cookies.refreshName, payload.refreshToken, optsFor(cookies, refreshExpiry));
  }
}

/** Clear both fortress auth cookies (logout). */
export function clearAuthCookies(event: SvelteKitRequestEvent, fortress: Pick<FortressAuthRuntime, 'cookies' | 'config'>): void {
  const cookies = fortress.cookies;
  event.cookies.delete(cookies.accessName, optsFor(cookies));
  event.cookies.delete(cookies.refreshName, optsFor(cookies));
}

/**
 * Replay any `Set-Cookie` headers from a `Response` (typically returned by
 * `fortress.handleRequest`) through `event.cookies.set` so they're visible
 * to subsequent same-request reads. Returns the original response unchanged
 * — the cookies are already on it; this just mirrors them into SvelteKit's
 * cookie jar for in-request use.
 */
export function replayCookies(response: Response, event: SvelteKitRequestEvent): void {
  const setCookies = response.headers.getSetCookie();
  for (const raw of setCookies) {
    const parsed = parseSetCookie(raw);
    if (!parsed)
      continue;
    event.cookies.set(parsed.name, parsed.value, parsed.opts);
  }
}

type RequiredPathCookieOptions = SvelteKitCookieOptions & { path: string };

function optsFor(cookies: ResolvedCookieConfig, maxAgeSeconds?: number): RequiredPathCookieOptions {
  const opts: RequiredPathCookieOptions = {
    path: cookies.path,
    httpOnly: true,
    secure: cookies.secure,
    sameSite: cookies.sameSite,
  };
  if (cookies.domain)
    opts.domain = cookies.domain;
  if (maxAgeSeconds !== undefined)
    opts.maxAge = maxAgeSeconds;
  return opts;
}

interface ParsedSetCookie {
  name: string;
  value: string;
  opts: RequiredPathCookieOptions;
}

/**
 * Parse a single `Set-Cookie` header string into name/value/options.
 *
 * Handles the attributes fortress emits (Path, Domain, HttpOnly, Secure,
 * SameSite, Max-Age, Expires). Unknown attributes are ignored.
 */
function parseSetCookie(raw: string): ParsedSetCookie | null {
  const parts = raw.split(';').map(p => p.trim());
  if (parts.length === 0)
    return null;
  const first = parts.shift();
  if (!first)
    return null;
  const eq = first.indexOf('=');
  if (eq === -1)
    return null;

  const name = first.slice(0, eq).trim();
  const rawValue = first.slice(eq + 1).trim();
  let value: string;
  try {
    value = decodeURIComponent(rawValue);
  }
  catch {
    value = rawValue;
  }

  // Reuse parseCookieHeader by formatting the attribute list as a single
  // header string would not work — attributes have boolean variants like
  // `Secure` and `HttpOnly`. Walk parts manually.
  const opts: RequiredPathCookieOptions = { path: '/' };
  for (const part of parts) {
    const [k, v = ''] = part.split('=', 2);
    const key = k.toLowerCase();
    if (key === 'path')
      opts.path = v;
    else if (key === 'domain')
      opts.domain = v;
    else if (key === 'httponly')
      opts.httpOnly = true;
    else if (key === 'secure')
      opts.secure = true;
    else if (key === 'samesite')
      opts.sameSite = v.toLowerCase() as 'lax' | 'strict' | 'none';
    else if (key === 'max-age')
      opts.maxAge = Number(v);
    else if (key === 'expires')
      opts.expires = new Date(v);
  }
  return { name, value, opts };
}

// Re-export so callers can use it from this module too
export { parseCookieHeader };
