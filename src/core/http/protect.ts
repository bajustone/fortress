/**
 * Host-owned route protection.
 *
 * Lets adapters and framework-less hosts run the same Fortress security
 * pipeline used by `fortress.handleRequest()` around handlers they register
 * themselves: plugin middleware, CSRF, principal resolution, RBAC,
 * validation, and auth-cookie attachment.
 */

import type {
  EndpointDefinition,
  InferEndpointBody,
  InferEndpointCallInput,
  InferEndpointParams,
  InferEndpointQuery,
  InferEndpointResponses,
} from '../endpoint';
import type { AnyFortress } from '../fortress';
import type { RouteManifestEntry } from '../manifest/route-manifest';
import type { Subject, TokenClaims } from '../types';
import { Errors, FortressError } from '../errors';
import { coerceBySchema, validateRequest } from '../validation';
import { enforceCsrf, resolveCsrfConfig } from './csrf';
import { errorToResponse, withCookies } from './error-response';
import { enforceFortressPermission } from './fortress-rbac';
import { buildRouteTable, matchRoute } from './match';
import { runPluginMiddleware } from './plugin-middleware';
import { tryPluginPrincipal } from './principal';

/**
 * What you point `protect()` at: an `EndpointDefinition` (preferred — its
 * phantom `<TBody, TQuery, TParams, TResponses>` types flow into the
 * `ProtectedRouteContext`) or a handler name from `fortress.endpoints`
 * (looser typing, falls back to `Record<string, unknown>` / `unknown`).
 */

export type ProtectedRouteTarget<E extends EndpointDefinition<any, any, any, any> = EndpointDefinition>
  = string | E;

/**
 * Widen `{}` (the `EndpointDefinition` default for an unspecified input slot)
 * back to `Record<string, unknown>` so adapter callers that pass a string
 * target — or an untyped `EndpointDefinition` — keep the loose ergonomics
 * they had before generics existed. A real declared schema produces a
 * narrow object type, which passes through unchanged.
 */
type WidenObj<T> = [keyof T] extends [never] ? Record<string, unknown> : T;

export interface ProtectOptions {
  /**
   * Canonical path to use for plugin middleware / CSRF matching when the
   * host-owned route is mounted at a path different from the endpoint path.
   * Defaults to the incoming request pathname.
   */
  path?: string;
  /** Override HTTP method for manifest lookup. Defaults to request.method. */
  method?: string;
  /** Explicit params for host paths that do not match the endpoint path. */
  params?: Record<string, string>;
  /** Attach auth cookies when the handler returns `{ accessToken, refreshToken? }`. Default `true`. */
  attachAuthCookies?: boolean;
}

/**
 * Per-request context handed to the host callback. When `target` is a
 * typed `EndpointDefinition`, `body` / `query` / `params` / `input` are
 * inferred from its phantom generics; when `target` is a handler name
 * string, they fall back to `Record<string, unknown>` / `unknown`.
 */
export interface ProtectedRouteContext<

  E extends EndpointDefinition<any, any, any, any> = EndpointDefinition,
> {
  request: Request;
  /** The resolved endpoint definition (typed when the target was typed). */
  endpoint: E;
  manifest: RouteManifestEntry;
  subject?: Subject;
  userId?: string;
  claims?: TokenClaims;
  scopes?: string[] | null;
  params: WidenObj<InferEndpointParams<E>>;
  query: WidenObj<InferEndpointQuery<E>>;
  /**
   * Parsed request body.
   *
   * When the endpoint declares a body schema, the handler only runs after
   * that body passes Standard Schema validation, so `body` is narrowed to a
   * non-optional `T` — use it directly without `!` or reaching for
   * `ctx.input`. Endpoints with no declared body schema fall back to the
   * loose `unknown` (which still admits `undefined`), matching the
   * pre-generics ergonomics for string / untyped targets.
   */
  body: [keyof InferEndpointBody<E>] extends [never]
    ? unknown
    : InferEndpointBody<E>;
  /**
   * Merged `{ ...body, ...query, ...params }` input after URL coercion.
   * Typed as the same intersection the `fortress.call.*` proxy uses.
   */
  input: [keyof InferEndpointCallInput<E>] extends [never]
    ? Record<string, unknown>
    : InferEndpointCallInput<E>;
  /**
   * Build a typed JSON response for a status declared on the endpoint.
   *
   * When `target` was a typed `EndpointDefinition`, `status` is narrowed
   * to the response codes that endpoint actually declares and `body` is
   * narrowed to that response's schema output. Use this instead of
   * hand-rolling `new Response(JSON.stringify(...), { status })` for
   * non-2xx returns:
   *
   * ```ts
   * protectedRoute(fortress, getSchool, async (ctx) => {
   *   const school = await loadSchool(ctx.params.id);
   *   if (!school)
   *     return ctx.respond(404, { code: 'NOT_FOUND', message: 'School not found', statusCode: 404 });
   *   return { data: school };  // 2xx success returned as a plain object
   * });
   * ```
   *
   * For string-target / untyped endpoints, both arguments fall back to
   * `number` / `unknown`, matching the loose ergonomics elsewhere in the
   * context.
   */
  respond: [keyof InferEndpointResponses<E>] extends [never]
    ? (status: number, body: unknown) => Response
    : <S extends keyof InferEndpointResponses<E> & number>(
        status: S,
        body: InferEndpointResponses<E>[S],
      ) => Response;
}

export type ProtectedRouteHandler<

  E extends EndpointDefinition<any, any, any, any> = EndpointDefinition,
  TResult = unknown,
> = (
  ctx: ProtectedRouteContext<E>,
) => TResult | Response | Promise<TResult | Response>;

function targetLabel(target: ProtectedRouteTarget): string {
  return typeof target === 'string' ? target : `${target.method} ${target.path}`;
}

function routeKey(route: Pick<EndpointDefinition, 'method' | 'path'>): string {
  return `${route.method.toUpperCase()} ${route.path}`;
}

function findEndpoint(fortress: AnyFortress, target: ProtectedRouteTarget, method?: string): EndpointDefinition {
  if (typeof target !== 'string') {
    return target;
  }

  const matches = fortress.endpoints.filter(endpoint => endpoint.handler === target);
  if (matches.length === 0)
    throw Errors.notFound(`No endpoint found for handler '${target}'`);

  if (method) {
    const byMethod = matches.find(endpoint => endpoint.method.toUpperCase() === method.toUpperCase());
    if (byMethod)
      return byMethod;
  }

  if (matches.length > 1) {
    throw Errors.badRequest(
      `Handler '${target}' maps to multiple endpoints; pass the EndpointDefinition or ProtectOptions.method.`,
    );
  }

  return matches[0];
}

function findManifestEntry(fortress: AnyFortress, endpoint: EndpointDefinition): RouteManifestEntry {
  const key = routeKey(endpoint);
  const entry = fortress.manifest.find(route => `${route.method.toUpperCase()} ${route.path}` === key);
  if (!entry)
    throw Errors.notFound(`No route manifest entry found for ${key}`);
  return entry;
}

function rewriteRequestPath(request: Request, pathname: string): Request {
  const current = new URL(request.url);
  if (current.pathname === pathname)
    return request;
  const rewritten = new URL(request.url);
  rewritten.pathname = pathname;
  return new Request(rewritten, request);
}

async function parseJsonBody(request: Request): Promise<unknown> {
  if (request.method === 'GET' || request.method === 'HEAD')
    return undefined;
  if (!(request.headers.get('content-type') ?? '').includes('json'))
    return undefined;
  return request.clone().json().catch(() => undefined);
}

function objectOrEmpty(value: unknown): Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

function successStatus(endpoint: EndpointDefinition): number {
  const status = Object.keys(endpoint.responses ?? {})
    .map(Number)
    .find(code => code >= 200 && code < 300);
  return status ?? 200;
}

function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body ?? { ok: true }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}

function maybeAttachAuthCookies(fortress: AnyFortress, result: Response | unknown, response: Response): Response {
  if (result instanceof Response)
    return response;
  const obj = result as { accessToken?: unknown; refreshToken?: unknown } | undefined;
  if (typeof obj?.accessToken !== 'string')
    return response;
  return withCookies(response, fortress.serializeAuthCookies({
    accessToken: obj.accessToken,
    refreshToken: typeof obj.refreshToken === 'string' ? obj.refreshToken : null,
  }));
}

/**
 * Build a web-standard protected route handler for a host-owned route.
 * Adapter-specific helpers wrap this function for Hono, Express, and
 * SvelteKit ergonomics.
 *
 * Two overloads:
 *
 * - **Typed target** — pass an `EndpointDefinition` (e.g. the value produced
 *   by `endpoint(...).build()`). Its `<TBody, TQuery, TParams, TResponses>`
 *   phantoms flow into `ctx.body` / `ctx.query` / `ctx.params` / `ctx.input`.
 * - **String target** — pass a unique `handler` name. Inputs fall back to
 *   `Record<string, unknown>` / `unknown`, matching pre-0.2.x behaviour.
 *
 * The runtime is identical in both forms; this is purely typing.
 */
export function protect<

  E extends EndpointDefinition<any, any, any, any>,
  TResult = unknown,
>(
  fortress: AnyFortress,
  target: E,
  handler: ProtectedRouteHandler<E, TResult>,
  options?: ProtectOptions,
): (request: Request) => Promise<Response>;
export function protect<TResult = unknown>(
  fortress: AnyFortress,
  target: string,
  handler: ProtectedRouteHandler<EndpointDefinition, TResult>,
  options?: ProtectOptions,
): (request: Request) => Promise<Response>;
export function protect(
  fortress: AnyFortress,
  target: ProtectedRouteTarget,

  handler: ProtectedRouteHandler<any, unknown>,
  options: ProtectOptions = {},
): (request: Request) => Promise<Response> {
  const endpoint = findEndpoint(fortress, target, options.method);
  const manifest = findManifestEntry(fortress, endpoint);
  const endpointRouteTable = buildRouteTable([endpoint]);
  const csrfConfig = resolveCsrfConfig(fortress.config.csrf);
  const plugins = fortress.config.plugins ?? [];

  return async function protectedRequestHandler(request: Request): Promise<Response> {
    let response: Response | undefined;
    try {
      const url = new URL(request.url);
      const pipelinePath = options.path ?? url.pathname;
      const pipelineRequest = rewriteRequestPath(request, pipelinePath);

      await runPluginMiddleware(plugins, fortress.config, 'before-auth', { request: pipelineRequest });
      enforceCsrf(pipelineRequest, pipelinePath, csrfConfig, fortress.cookies);

      let subject: Subject | undefined;
      let userId: string | undefined;
      let claims: TokenClaims | undefined;
      let scopes: string[] | null | undefined;
      const selfManagedBearer = endpoint.meta?.bearerKind === 'oauth';

      if (!selfManagedBearer) {
        const pluginResolved = await tryPluginPrincipal(fortress, pipelineRequest);
        if (pluginResolved) {
          subject = pluginResolved.subject;
          claims = pluginResolved.claims;
          scopes = pluginResolved.scopes;
        }
      }

      const requiresBearer = !selfManagedBearer
        && ((endpoint.meta?.security?.includes('bearer') ?? false) || !!endpoint.meta?.permission);
      if (!subject && requiresBearer) {
        const token = fortress.extractAccessToken(pipelineRequest);
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

      if (subject?.type === 'USER')
        userId = subject.id;

      await runPluginMiddleware(plugins, fortress.config, 'after-auth', {
        request: pipelineRequest,
        fortressSubject: subject,
        fortressUserId: userId,
        fortressClaims: claims,
        fortressScopes: scopes,
      });

      if (!selfManagedBearer) {
        await enforceFortressPermission(endpoint, subject, {
          checkPermission: (subj, resource, action, credentialScopes): Promise<boolean> =>
            fortress.iam.checkPermission(subj, resource, action, { credentialScopes }),
        }, scopes);
      }

      await runPluginMiddleware(plugins, fortress.config, 'after-rbac', {
        request: pipelineRequest,
        fortressSubject: subject,
        fortressUserId: userId,
        fortressClaims: claims,
        fortressScopes: scopes,
      });

      const body = await parseJsonBody(request);
      const rawQuery = Object.fromEntries(url.searchParams);
      const match = matchRoute(endpointRouteTable, endpoint.method, options.path ?? url.pathname);
      const rawParams = options.params ?? match?.params ?? {};
      const query = coerceBySchema(endpoint.input?.query, rawQuery) ?? rawQuery;
      const params = coerceBySchema(endpoint.input?.params, rawParams) ?? rawParams;
      await validateRequest(endpoint.input, { body, query, params });

      const input = { ...objectOrEmpty(body), ...query, ...params };
      const result = await handler({
        request,
        endpoint,
        manifest,
        subject,
        userId,
        claims,
        scopes,
        params,
        query,
        body,
        input,
        respond: (status: number, responseBody: unknown) => jsonResponse(responseBody, status),
        // Cast: the runtime values are untyped records; the generic context
        // type narrows them for the caller, but the impl signature uses the
        // loose `ProtectedRouteContext<EndpointDefinition>`.
      } as ProtectedRouteContext);

      response = result instanceof Response ? result : jsonResponse(result, successStatus(endpoint));
      if (options.attachAuthCookies ?? true)
        response = maybeAttachAuthCookies(fortress, result, response);
      return response;
    }
    catch (err) {
      response = errorToResponse(err, fortress.logger);
      return response;
    }
  };
}

/** Resolve an endpoint eagerly; useful for adapter wrappers and diagnostics. */
export function resolveProtectedEndpoint(
  fortress: AnyFortress,
  target: ProtectedRouteTarget,
  method?: string,
): EndpointDefinition {
  return findEndpoint(fortress, target, method);
}

/** Human-readable name for errors/logs. */
export function describeProtectedTarget(target: ProtectedRouteTarget): string {
  return targetLabel(target);
}
