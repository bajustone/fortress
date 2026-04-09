/**
 * Framework-agnostic HTTP entry point: `fortress.handleRequest(request)`.
 *
 * Composes route matching → plugin `before-auth` → token verification →
 * plugin `after-auth` → fortress-RBAC default-deny → plugin `after-rbac` →
 * validation → endpoint dispatch → cookie attachment → JSON response.
 *
 * Adapters (Hono / Express / SvelteKit) detect Fortress-managed paths and
 * delegate to this function with the raw `Request`. The returned `Response`
 * is web-standard and can be returned directly from any framework that
 * supports `Response`.
 */

import type { Fortress } from '../fortress';
import type { TokenClaims } from '../types';
import type { RouteEntry } from './match';
import { resolveCookieConfig } from '../config';
import { Errors, FortressError } from '../errors';
import { validateRequest } from '../validation';
import { serializeAuthCookies } from './cookie-serialize';
import { dispatchEndpoint } from './dispatch';
import { errorToResponse, withCookies } from './error-response';
import {
  enforceFortressPermission,
  getPluginPathPrefixes,
  isFortressPath,
} from './fortress-rbac';
import { buildRouteTable, matchRoute } from './match';
import { runPluginMiddleware } from './plugin-middleware';
import { extractAccessToken } from './token-extraction';

/**
 * Build the request handler closure for a Fortress instance. Called once
 * during `createFortress` and exposed as `fortress.handleRequest`.
 *
 * The returned function is `async (request: Request) => Promise<Response>`.
 * It owns the route table, the resolved cookie config, and the cached
 * plugin path prefixes — building these once at startup avoids per-request
 * recomputation.
 */
export function buildHandleRequest(
  fortress: Fortress,
): (request: Request) => Promise<Response> {
  const routeTable = buildRouteTable(fortress.endpoints);
  const cookieConfig = resolveCookieConfig(fortress.config.cookies);
  const plugins = fortress.config.plugins ?? [];
  const pluginPathPrefixes = getPluginPathPrefixes(plugins);

  return async function handleRequest(request: Request): Promise<Response> {
    try {
      const url = new URL(request.url);
      const pathname = url.pathname;

      // 1. Plugin before-auth middleware (rate limit, audit log, etc.)
      await runPluginMiddleware(plugins, fortress.config, 'before-auth', { request });

      // 2. Match path + method to an endpoint
      const matched = matchRoute(routeTable, request.method, pathname);
      if (!matched) {
        // Only return 404 for fortress-owned paths; otherwise the caller
        // (an adapter) might want to fall through to its own router.
        if (isFortressPath(pathname, pluginPathPrefixes)) {
          throw Errors.notFound(`No endpoint matches ${request.method} ${pathname}`);
        }
        // Non-fortress path with no match — also a 404 from this entry point
        throw Errors.notFound(`No endpoint matches ${request.method} ${pathname}`);
      }
      const { endpoint, params } = matched;

      // 3. Token verification (only if the endpoint requires bearer auth)
      let userId: number | undefined;
      let claims: TokenClaims | undefined;
      const requiresBearer = endpoint.meta?.security?.includes('bearer') ?? false;
      if (requiresBearer) {
        const token = extractAccessToken(request, cookieConfig);
        if (!token)
          throw Errors.unauthorized('Missing access token');
        try {
          claims = await fortress.auth.verifyToken(token);
          userId = claims.sub;
        }
        catch (err) {
          if (err instanceof FortressError)
            throw err;
          throw Errors.unauthorized('Invalid access token');
        }
      }

      // 4. Plugin after-auth middleware
      await runPluginMiddleware(plugins, fortress.config, 'after-auth', {
        request,
        fortressUserId: userId,
        fortressClaims: claims,
      });

      // 5. Fortress-managed default-deny RBAC
      await enforceFortressPermission(endpoint, userId, {
        checkPermission: (uid, resource, action): Promise<boolean> =>
          fortress.iam.checkPermission(uid, resource, action),
      });

      // 6. Plugin after-rbac middleware
      await runPluginMiddleware(plugins, fortress.config, 'after-rbac', {
        request,
        fortressUserId: userId,
        fortressClaims: claims,
      });

      // 7. Body parse + validation. Validation reads the body via clone()
      //    so dispatch can re-read it. We sniff the content-type to know
      //    whether validateRequest can parse JSON.
      let parsedBody: unknown;
      if (
        request.method !== 'GET'
        && request.method !== 'HEAD'
        && (request.headers.get('content-type') ?? '').includes('json')
      ) {
        parsedBody = await request.clone().json().catch(() => undefined);
      }
      const query = Object.fromEntries(url.searchParams);
      await validateRequest(endpoint.input, { body: parsedBody, query, params });

      // 8. Dispatch + serialize. Pass IP/UA from headers as RequestMeta so
      //    auth handlers can stamp refresh tokens with their origin.
      const meta = {
        ipAddress:
          request.headers.get('x-forwarded-for')
          ?? request.headers.get('x-real-ip')
          ?? undefined,
        userAgent: request.headers.get('user-agent') ?? undefined,
      };
      const response = await dispatchEndpoint(fortress, request, endpoint, params, {
        userId,
        meta,
      });

      // 9. If the endpoint emitted an auth result, serialize cookies.
      //    Detected by checking the response body for accessToken/refreshToken
      //    fields. We avoid touching streamed/HTML responses.
      const cookies = await maybeBuildAuthCookies(
        endpoint.handler,
        response,
        fortress,
        request,
      );
      if (cookies.length > 0) {
        return withCookies(cookies.response, cookies.setCookies);
      }

      return response;
    }
    catch (err) {
      return errorToResponse(err);
    }
  };
}

/**
 * Inspect the dispatched response and, if it's an auth-issuing endpoint
 * (`login`, `refresh`, `register-and-login`, etc.), build the matching
 * `Set-Cookie` headers using the resolved cookie config.
 *
 * Returns the (possibly clone-replaced) response so callers can use
 * `withCookies` against the body that was actually consumed.
 */
async function maybeBuildAuthCookies(
  handler: string,
  response: Response,
  fortress: Fortress,
  _request: Request,
): Promise<{ setCookies: string[]; response: Response; length: number }> {
  // Only inspect successful auth-related handlers.
  const isAuthIssuing = handler === 'login' || handler === 'refresh' || handler === 'impersonate';
  if (!isAuthIssuing)
    return { setCookies: [], response, length: 0 };
  if (response.status >= 400)
    return { setCookies: [], response, length: 0 };
  const contentType = response.headers.get('content-type') ?? '';
  if (!contentType.includes('json'))
    return { setCookies: [], response, length: 0 };

  // Read the JSON body once and reconstruct the response.
  const bodyText = await response.clone().text();
  let parsed: unknown;
  try {
    parsed = JSON.parse(bodyText);
  }
  catch {
    return { setCookies: [], response, length: 0 };
  }
  const obj = parsed as { accessToken?: unknown; refreshToken?: unknown };
  if (typeof obj?.accessToken !== 'string') {
    return { setCookies: [], response, length: 0 };
  }

  const cookieConfig = resolveCookieConfig(fortress.config.cookies);
  const accessExpiry = fortress.config.jwt.accessTokenExpirySeconds ?? 900;
  const refreshExpiry = fortress.config.jwt.refreshTokenExpirySeconds ?? 604_800;
  const setCookies = serializeAuthCookies(
    {
      accessToken: obj.accessToken,
      refreshToken: typeof obj.refreshToken === 'string' ? obj.refreshToken : null,
    },
    cookieConfig,
    { access: accessExpiry, refresh: refreshExpiry },
  );

  // Reconstruct the response from the consumed body so the caller can stream it.
  const replaced = new Response(bodyText, {
    status: response.status,
    statusText: response.statusText,
    headers: response.headers,
  });
  return { setCookies, response: replaced, length: setCookies.length };
}

// Re-export for adapter use
export type { RouteEntry };
