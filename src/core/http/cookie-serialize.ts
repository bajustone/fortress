/**
 * Cookie serialization for fortress auth tokens.
 *
 * Produces and parses cookie strings for the access/refresh token pair using
 * the resolved {@link ResolvedCookieConfig} (which already accounts for
 * `__Host-` prefix rules and dev-vs-prod relaxation).
 *
 * Returns raw `Set-Cookie` header values so any framework adapter can append
 * them to a `Response` directly without depending on a framework cookie API.
 */

import type { ResolvedCookieConfig } from '../config';

/** Result of an auth flow that may set cookies on a Response. */
export interface AuthCookiePayload {
  accessToken: string;
  refreshToken?: string | null;
}

/**
 * Build the `Set-Cookie` header values for an access + refresh token pair.
 * Returns one or two strings depending on whether `refreshToken` is present.
 */
export function serializeAuthCookies(
  payload: AuthCookiePayload,
  cookies: ResolvedCookieConfig,
  expirySeconds: { access?: number; refresh?: number } = {},
): string[] {
  const out: string[] = [];
  out.push(serializeCookie(cookies.accessName, payload.accessToken, cookies, expirySeconds.access));
  if (payload.refreshToken) {
    out.push(serializeCookie(cookies.refreshName, payload.refreshToken, cookies, expirySeconds.refresh));
  }
  return out;
}

/**
 * Build expired `Set-Cookie` header values that clear both auth cookies.
 * Used by logout flows.
 */
export function clearAuthCookies(cookies: ResolvedCookieConfig): string[] {
  return [
    serializeCookie(cookies.accessName, '', cookies, 0),
    serializeCookie(cookies.refreshName, '', cookies, 0),
  ];
}

/**
 * Serialize a single cookie attribute set into a `Set-Cookie` header value.
 *
 * `maxAgeSeconds` of 0 produces an immediately-expiring cookie (used for
 * `clearAuthCookies`). Omit it to set a session cookie. Otherwise the cookie
 * gets both `Max-Age` and `Expires` for broad client compatibility.
 */
export function serializeCookie(
  name: string,
  value: string,
  cookies: ResolvedCookieConfig,
  maxAgeSeconds?: number,
): string {
  const parts: string[] = [`${name}=${encodeURIComponent(value)}`];
  parts.push(`Path=${cookies.path}`);
  if (cookies.domain) {
    parts.push(`Domain=${cookies.domain}`);
  }
  parts.push('HttpOnly');
  if (cookies.secure) {
    parts.push('Secure');
  }
  parts.push(`SameSite=${capitalize(cookies.sameSite)}`);
  if (maxAgeSeconds !== undefined) {
    parts.push(`Max-Age=${maxAgeSeconds}`);
    const expires = new Date(Date.now() + maxAgeSeconds * 1000);
    parts.push(`Expires=${expires.toUTCString()}`);
  }
  return parts.join('; ');
}

/**
 * Parse a `Cookie` request header into a name → value map. Returns an empty
 * object if the header is missing or malformed. Values are URL-decoded.
 */
export function parseCookieHeader(header: string | null | undefined): Record<string, string> {
  if (!header)
    return {};
  const out: Record<string, string> = {};
  for (const part of header.split(';')) {
    const eq = part.indexOf('=');
    if (eq === -1)
      continue;
    const name = part.slice(0, eq).trim();
    if (!name)
      continue;
    const raw = part.slice(eq + 1).trim();
    try {
      out[name] = decodeURIComponent(raw);
    }
    catch {
      out[name] = raw;
    }
  }
  return out;
}

function capitalize(s: string): string {
  return s.charAt(0).toUpperCase() + s.slice(1);
}
