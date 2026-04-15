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
import type { Subject, TokenClaims } from '../types';
import type { RouteEntry } from './match';
import { resolveCookieConfig } from '../config';
import { Errors, FortressError } from '../errors';
import { coerceBySchema, validateRequest } from '../validation';
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
import { tryPluginPrincipal } from './principal';
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
    // Outer span for the whole pipeline. No-op when `config.observability`
    // is unset — `NO_OP_TELEMETRY` returns a shared singleton span.
    // Attributes are set progressively as they become available; the final
    // `http.status_code` lands in the finally block.
    const span = fortress.telemetry.tracer.startSpan('fortress.handleRequest', {
      'http.method': request.method,
    });
    let response: Response | undefined;
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
      // Upgrade span attributes now that we know the matched route.
      // `endpoint.path` is parameterized (e.g. `/iam/roles/:id`) so it's
      // low-cardinality and safe to put on a span/metric attribute.
      span.setAttribute('http.route', endpoint.path);
      span.setAttribute('fortress.handler', endpoint.handler);

      // 3. Principal resolution. Three paths, tried in order:
      //
      //    3a. Plugin-backed credential resolvers (api-key, future
      //        OAuth client_credentials, future mTLS). First plugin to
      //        return non-null wins — its subject + optional claims
      //        become the request principal.
      //    3b. JWT bearer fallback. Used when no plugin resolves the
      //        request and the endpoint declared `security: 'bearer'`.
      //    3c. OAuth paths declare `security: 'bearer'` but the bearer
      //        is an OAuth access token, not a Fortress JWT — dispatch
      //        parses those inside the OAuth handler, so we skip both
      //        the resolver chain and the JWT check here.
      let subject: Subject | undefined;
      let userId: number | undefined;
      let claims: TokenClaims | undefined;
      const isOauthPath = endpoint.path.startsWith('/oauth/');

      if (!isOauthPath) {
        const resolved = await tryPluginPrincipal(fortress, request);
        if (resolved) {
          subject = resolved.subject;
          claims = resolved.claims;
        }
      }

      const requiresBearer
        = !isOauthPath && (endpoint.meta?.security?.includes('bearer') ?? false);
      if (!subject && requiresBearer) {
        const token = extractAccessToken(request, cookieConfig);
        if (!token)
          throw Errors.unauthorized('Missing access token');
        try {
          claims = await fortress.auth.verifyToken(token);
          subject = { type: claims.subjectType, id: claims.sub };
        }
        catch (err) {
          if (err instanceof FortressError)
            throw err;
          throw Errors.unauthorized('Invalid access token');
        }
      }

      // Convenience alias: downstream code that only needs `userId` (adapters,
      // plugin middleware) still works for USER subjects. Non-user principals
      // leave `userId` undefined, which is correct — they'd be hitting routes
      // that RBAC-check via `subject` now.
      if (subject?.type === 'USER')
        userId = subject.id;

      if (subject) {
        span.setAttribute('fortress.subject_type', subject.type);
      }

      // 4. Plugin after-auth middleware
      await runPluginMiddleware(plugins, fortress.config, 'after-auth', {
        request,
        fortressSubject: subject,
        fortressUserId: userId,
        fortressClaims: claims,
      });

      // 5. Fortress-managed default-deny RBAC. OAuth paths self-authenticate
      //    inside their handlers (the bearer is an OAuth token, not a JWT)
      //    so they're exempt from the IAM check too.
      if (!isOauthPath) {
        await enforceFortressPermission(endpoint, subject, {
          checkPermission: (subj, resource, action): Promise<boolean> =>
            fortress.iam.checkPermission(subj, resource, action),
        });
      }

      // 6. Plugin after-rbac middleware
      await runPluginMiddleware(plugins, fortress.config, 'after-rbac', {
        request,
        fortressSubject: subject,
        fortressUserId: userId,
        fortressClaims: claims,
      });

      // 7. Body parse + validation. Validation reads the body via clone()
      //    so dispatch can re-read it. We sniff the content-type to know
      //    whether validateRequest can parse JSON. Skip for OAuth — its
      //    bodies are `application/x-www-form-urlencoded` and the OAuth
      //    dispatcher does its own parsing/validation per RFC 6749.
      if (!isOauthPath) {
        let parsedBody: unknown;
        if (
          request.method !== 'GET'
          && request.method !== 'HEAD'
          && (request.headers.get('content-type') ?? '').includes('json')
        ) {
          parsedBody = await request.clone().json().catch(() => undefined);
        }
        const query = Object.fromEntries(url.searchParams);
        // URL-sourced data is always strings. Coerce query/params to the
        // types declared in the endpoint's JSON Schema before validation
        // so `:id`/`?limit=2` don't trip integer/number/boolean checks.
        const coercedQuery = coerceBySchema(endpoint.input?.query, query);
        const coercedParams = coerceBySchema(endpoint.input?.params, params);
        await validateRequest(endpoint.input, { body: parsedBody, query: coercedQuery, params: coercedParams });
      }

      // 8. Dispatch + serialize. Pass IP/UA from headers as RequestMeta so
      //    auth handlers can stamp refresh tokens with their origin.
      const meta = {
        ipAddress:
          request.headers.get('x-forwarded-for')
          ?? request.headers.get('x-real-ip')
          ?? undefined,
        userAgent: request.headers.get('user-agent') ?? undefined,
      };
      const dispatched = await dispatchEndpoint(fortress, request, endpoint, params, {
        subject,
        userId,
        claims,
        meta,
      });

      // 9. If the endpoint emitted an auth result, serialize cookies.
      //    Detected by checking the response body for accessToken/refreshToken
      //    fields. We avoid touching streamed/HTML responses.
      const cookies = await maybeBuildAuthCookies(
        endpoint.handler,
        dispatched,
        fortress,
        request,
      );
      response = cookies.length > 0
        ? withCookies(cookies.response, cookies.setCookies)
        : dispatched;
      return response;
    }
    catch (err) {
      response = errorToResponse(err, fortress.logger);
      span.recordException(err);
      span.setStatus({
        code: 'error',
        message: err instanceof Error ? err.message : String(err),
      });
      return response;
    }
    finally {
      if (response) {
        span.setAttribute('http.status_code', response.status);
        if (response.status >= 200 && response.status < 400) {
          span.setStatus({ code: 'ok' });
        }
        else if (response.status >= 400) {
          // 4xx/5xx without an exception (e.g. a FortressError already
          // serialized). Mark the span as error so traces highlight it.
          span.setStatus({
            code: 'error',
            message: `HTTP ${response.status}`,
          });
        }
      }
      span.end();
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
