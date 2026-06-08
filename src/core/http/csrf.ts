/**
 * Pipeline-level CSRF protection.
 *
 * Activated by default for unsafe HTTP methods (`POST/PUT/PATCH/DELETE`)
 * when the request authenticated via a Fortress auth cookie. Bearer-only
 * and API-key requests are CSRF-immune by construction (no ambient
 * credential the browser would auto-attach) and are skipped.
 *
 * The check is intentionally narrow:
 *
 * 1. Reject when `Sec-Fetch-Site: cross-site`. Modern browsers send this
 *    header on every fetch — its presence + value is a reliable signal.
 * 2. Reject when the required custom header (`X-Fortress-CSRF` by default)
 *    is absent. Custom-header CSRF leverages the browser preflight rule:
 *    a cross-origin request can't set the header without an explicit
 *    server-side CORS allowance.
 *
 * Closes H5 — before this, `mountFortress` / `createSvelteKitHandle`
 * dispatched straight to `handleRequest` with no CSRF check. This check now
 * runs inside `handleRequest`, so every Fortress-managed route is covered
 * regardless of adapter (Hono, Express, SvelteKit). The SvelteKit adapter's
 * user-route silent token refresh — the one remaining Fortress state-change
 * outside this pipeline — is independently gated to safe HTTP methods.
 */

import type { ResolvedCookieConfig } from '../config';
import { Errors } from '../errors';
import { parseCookieHeader } from './cookie-serialize';

/** Resolved CSRF configuration. */
export interface ResolvedCsrfConfig {
  enabled: boolean;
  headerName: string;
  skipPaths: string[];
  rejectSameSite: boolean;
}

/** User-facing CSRF configuration (all fields optional). */
export interface CsrfConfig {
  /**
   * Set to `false` to disable the pipeline CSRF check entirely. Useful for
   * pure bearer-only API deployments where no Fortress route is reachable
   * with ambient credentials. Default: `true`.
   */
  enabled?: boolean;
  /** Required header name. Default: `'X-Fortress-CSRF'`. */
  headerName?: string;
  /**
   * Exact-path allow-list of routes the check should skip. Matched at
   * segment boundaries (i.e. `'/foo'` matches `/foo` and `/foo/bar` but
   * not `/foobar`).
   */
  skipPaths?: string[];
  /**
   * Additionally reject `Sec-Fetch-Site: same-site` requests. Single-host
   * deployments (web app + Fortress on the same origin) can opt in to the
   * stricter posture; multi-host (`api.example.com` + `app.example.com`)
   * deployments leave this `false` so the legit app traffic passes.
   * Default: `false`.
   */
  rejectSameSite?: boolean;
}

/** Resolve user-facing CSRF config against defaults. */
export function resolveCsrfConfig(config?: CsrfConfig): ResolvedCsrfConfig {
  return {
    enabled: config?.enabled ?? true,
    headerName: config?.headerName ?? 'X-Fortress-CSRF',
    skipPaths: config?.skipPaths ?? [],
    rejectSameSite: config?.rejectSameSite ?? false,
  };
}

const SAFE_METHODS = new Set(['GET', 'HEAD', 'OPTIONS']);

/**
 * Test whether `path` falls under any of the configured skip paths,
 * matched at segment boundaries (so `/foo` doesn't accidentally skip
 * `/foobar`).
 */
export function matchesSkipPath(path: string, skipPaths: string[]): boolean {
  for (const skip of skipPaths) {
    if (path === skip)
      return true;
    if (path.startsWith(`${skip}/`))
      return true;
  }
  return false;
}

/**
 * Detect whether the request authenticated through a Fortress auth
 * cookie. We treat cookie-based auth as "browser ambient credentials
 * exist" — the only condition under which a cross-site request can use
 * the user's session.
 */
function isCookieAuthenticated(
  request: Request,
  cookies: ResolvedCookieConfig,
): boolean {
  const jar = parseCookieHeader(request.headers.get('cookie'));
  // Either cookie counts as ambient credentials. A session whose access
  // cookie has expired still carries a valid refresh cookie, and adapters
  // can silently rotate it — so a refresh-only request is just as
  // CSRF-exposed as an access-cookie request.
  const hasCookie = (name: string): boolean =>
    typeof jar[name] === 'string' && jar[name].length > 0;
  return hasCookie(cookies.accessName) || hasCookie(cookies.refreshName);
}

/**
 * Enforce CSRF on unsafe, cookie-authenticated requests. Throws
 * {@link FortressError} (403) when the request is rejected. Returns
 * silently when the request is safe or the check is bypassed.
 */
export function enforceCsrf(
  request: Request,
  pathname: string,
  csrf: ResolvedCsrfConfig,
  cookies: ResolvedCookieConfig,
): void {
  if (!csrf.enabled)
    return;

  // GET/HEAD/OPTIONS are safe-by-method per RFC 9110.
  if (SAFE_METHODS.has(request.method.toUpperCase()))
    return;

  if (matchesSkipPath(pathname, csrf.skipPaths))
    return;

  // Bearer / API-key flows have no ambient credential. We detect "cookie
  // auth" by inspecting the cookie jar directly rather than the resolved
  // principal so the check works the same way regardless of which plugin
  // resolved the request.
  if (!isCookieAuthenticated(request, cookies))
    return;

  const fetchSite = request.headers.get('sec-fetch-site');
  if (fetchSite === 'cross-site')
    throw Errors.forbidden('CSRF: cross-site request rejected');
  if (csrf.rejectSameSite && fetchSite === 'same-site')
    throw Errors.forbidden('CSRF: same-site request rejected');

  const tokenHeader = request.headers.get(csrf.headerName);
  if (!tokenHeader)
    throw Errors.forbidden(`CSRF: missing ${csrf.headerName} header`);
}
