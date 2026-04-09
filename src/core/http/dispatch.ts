/**
 * Endpoint dispatch — body parsing and handler invocation.
 *
 * Given a matched {@link EndpointDefinition}, this module:
 *
 * 1. Parses the request body (JSON, or `application/x-www-form-urlencoded`
 *    for OAuth endpoints).
 * 2. Invokes the right service or plugin method by name. Auth + IAM
 *    endpoints dispatch through hardcoded switches that mirror the
 *    positional argument shapes of `fortress.auth.*` / `fortress.iam.*`.
 *    Plugin endpoints dispatch via `fortress.plugins[name][handler]` with
 *    the merged `{ ...body, ...params }` shape used by the existing
 *    adapter route mounts.
 * 3. Serializes the result into a `Response` (JSON by default; HTML for
 *    the OpenAPI Scalar UI plugin).
 *
 * OAuth has special-case handling because RFC 6749 requires
 * form-encoded bodies and Basic-auth client authentication.
 */

import type { ClientAuth } from '../../plugins/oauth';
import type { EndpointDefinition } from '../endpoint';
import type { Fortress } from '../fortress';
import type { FortressPlugin } from '../plugin';
import type { RequestMeta } from '../types';
import { Errors, FortressError } from '../errors';

/** Auth context resolved by `handleRequest` before dispatch. */
export interface DispatchAuth {
  userId?: number;
  meta?: RequestMeta;
}

/** Result of dispatching a request — a fully-formed `Response`. */
export type DispatchResult = Response;

/**
 * Dispatch a matched endpoint to the right service or plugin method and
 * return a `Response`. Body parsing is performed here so the right
 * content-type strategy is picked per endpoint family (JSON for most,
 * `application/x-www-form-urlencoded` for OAuth).
 *
 * The caller is expected to have already run plugin middleware, token
 * verification, validation, and {@link enforceFortressPermission}.
 */
export async function dispatchEndpoint(
  fortress: Fortress,
  request: Request,
  endpoint: EndpointDefinition,
  pathParams: Record<string, string>,
  auth: DispatchAuth,
): Promise<DispatchResult> {
  // OAuth endpoints get form-encoded body parsing + Basic auth handling.
  const owningPlugin = findOwningPlugin(fortress, endpoint);
  if (owningPlugin?.name === 'oauth') {
    return dispatchOAuth(fortress, request, endpoint);
  }

  // Parse body / query into a generic object.
  const body = await parseBodyOrQuery(request);

  // Plugin route (non-oauth)
  if (owningPlugin) {
    return dispatchPlugin(fortress, owningPlugin, endpoint, body, pathParams);
  }

  // Core auth / IAM dispatch
  if (endpoint.path.startsWith('/auth/')) {
    const result = await invokeAuthHandler(fortress, endpoint.handler, body, pathParams, auth);
    return jsonResponse(result, successStatus(endpoint));
  }
  if (endpoint.path.startsWith('/iam/')) {
    const result = await invokeIamHandler(fortress, endpoint.handler, body, pathParams);
    return jsonResponse(result, successStatus(endpoint));
  }

  // Unknown endpoint family — return ok shape
  return jsonResponse({ ok: true }, 200);
}

// ── Body parsing ─────────────────────────────────────────────────────

/**
 * Parse the request body as JSON for write methods, or fall back to query
 * params for GET. Returns an empty object if parsing fails or there is no
 * body — handlers tolerate missing fields.
 */
async function parseBodyOrQuery(request: Request): Promise<Record<string, unknown>> {
  if (request.method === 'GET' || request.method === 'HEAD') {
    return Object.fromEntries(new URL(request.url).searchParams);
  }
  // Some requests have no body at all (e.g. DELETE without payload).
  const contentType = request.headers.get('content-type') ?? '';
  if (!contentType.includes('json')) {
    // No body or non-JSON body for write methods — try query params.
    return Object.fromEntries(new URL(request.url).searchParams);
  }
  try {
    return (await request.json()) as Record<string, unknown>;
  }
  catch {
    return {};
  }
}

async function parseFormBody(request: Request): Promise<Record<string, string>> {
  const text = await request.text();
  const params = new URLSearchParams(text);
  const out: Record<string, string> = {};
  for (const [k, v] of params) out[k] = v;
  return out;
}

function parseBasicAuth(header: string | null): ClientAuth | undefined {
  if (!header?.startsWith('Basic '))
    return undefined;
  let decoded: string;
  try {
    decoded = atob(header.slice(6));
  }
  catch {
    return undefined;
  }
  const colon = decoded.indexOf(':');
  if (colon === -1)
    return undefined;
  return {
    clientId: decoded.slice(0, colon),
    clientSecret: decoded.slice(colon + 1),
  };
}

function parseBearerToken(header: string | null): string | undefined {
  if (!header?.startsWith('Bearer '))
    return undefined;
  return header.slice(7);
}

// ── Plugin dispatch (non-oauth) ─────────────────────────────────────

/** Find the plugin (if any) that owns the given endpoint. */
function findOwningPlugin(fortress: Fortress, endpoint: EndpointDefinition): FortressPlugin | undefined {
  const plugins = fortress.config.plugins ?? [];
  for (const plugin of plugins) {
    if (!plugin.routes)
      continue;
    if (plugin.routes.some(r => r.method === endpoint.method && r.path === endpoint.path)) {
      return plugin;
    }
  }
  return undefined;
}

async function dispatchPlugin(
  fortress: Fortress,
  plugin: FortressPlugin,
  endpoint: EndpointDefinition,
  body: Record<string, unknown>,
  pathParams: Record<string, string>,
): Promise<Response> {
  const methods = (fortress.plugins as Record<string, Record<string, (...args: unknown[]) => unknown>>)[plugin.name];
  if (!methods?.[endpoint.handler]) {
    throw Errors.notFound(`Plugin handler '${plugin.name}.${endpoint.handler}' not found`);
  }

  // Call as `methods.<handler>(...)` so the `this` binding is preserved —
  // some plugin methods reference sibling helpers via `this`.
  // OpenAPI Scalar UI returns HTML, not JSON.
  if (plugin.name === 'openapi' && endpoint.handler === 'getUI') {
    const html = methods.getUI() as string;
    return new Response(html, {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  const result = await methods[endpoint.handler]({ ...body, ...pathParams });
  // Allow handlers to opt into HTML by returning a string starting with `<!`.
  if (typeof result === 'string' && result.trimStart().startsWith('<!')) {
    return new Response(result, {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }
  return jsonResponse(result ?? { ok: true }, successStatus(endpoint));
}

// ── OAuth special case ──────────────────────────────────────────────

async function dispatchOAuth(
  fortress: Fortress,
  request: Request,
  endpoint: EndpointDefinition,
): Promise<Response> {
  const methods = (fortress.plugins as Record<string, Record<string, (...args: unknown[]) => unknown>>).oauth;
  if (!methods)
    throw Errors.notFound(`OAuth plugin not registered`);
  const handlerName = endpoint.handler;
  if (!methods[handlerName])
    throw Errors.notFound(`OAuth handler '${handlerName}' not found`);

  // IMPORTANT: invoke as `methods.<name>(...)` so the `this` binding is the
  // methods object — the OAuth plugin's `handleTokenRequest` calls
  // `this.clientCredentialsGrant(...)` and friends, which would otherwise
  // throw "Cannot read properties of undefined" if called bare.
  const m = methods as Record<string, (...args: unknown[]) => Promise<unknown> | unknown>;
  const authHeader = request.headers.get('authorization');

  switch (handlerName) {
    case 'handleTokenRequest': {
      const body = await parseFormBody(request);
      const clientAuth = parseBasicAuth(authHeader);
      const result = await m.handleTokenRequest(body, clientAuth);
      return jsonResponse(result, 200);
    }
    case 'handleIntrospectRequest': {
      const body = await parseFormBody(request);
      const clientAuth = parseBasicAuth(authHeader);
      if (!clientAuth) {
        return jsonResponse(
          { error: 'invalid_client', error_description: 'Client authentication required' },
          401,
        );
      }
      const result = await m.handleIntrospectRequest({ token: body.token }, clientAuth);
      return jsonResponse(result, 200);
    }
    case 'handleRevokeRequest': {
      const body = await parseFormBody(request);
      await m.handleRevokeRequest({ token: body.token });
      return jsonResponse({}, 200);
    }
    case 'handleUserInfoRequest': {
      const bearer = parseBearerToken(authHeader);
      if (!bearer) {
        return jsonResponse(
          { error: 'invalid_token', error_description: 'Bearer token required' },
          401,
        );
      }
      const user = (await m.handleUserInfoRequest(bearer)) as {
        id: number;
        email: string;
        name: string;
      } | null;
      if (!user) {
        return jsonResponse(
          { error: 'invalid_token', error_description: 'Token invalid or expired' },
          401,
        );
      }
      return jsonResponse(
        { sub: String(user.id), email: user.email, name: user.name },
        200,
      );
    }
    case 'handleDiscovery': {
      const result = m.handleDiscovery();
      return jsonResponse(result, 200);
    }
    default: {
      // Authorize endpoint and friends — JSON body. Call through `m` so the
      // `this` binding survives.
      const body = (await request.json().catch(() => ({}))) as unknown;
      const result = await m[handlerName](body);
      return jsonResponse(result ?? { ok: true }, successStatus(endpoint));
    }
  }
}

// ── Auth / IAM hardcoded dispatch ────────────────────────────────────

async function invokeAuthHandler(
  fortress: Fortress,
  handler: string,
  body: Record<string, unknown>,
  params: Record<string, string>,
  auth: DispatchAuth,
): Promise<unknown> {
  const meta = auth.meta;
  switch (handler) {
    case 'login':
      return fortress.auth.login(String(body.identifier ?? ''), String(body.password ?? ''), meta);
    case 'createUser':
      return fortress.auth.createUser(body as never);
    case 'refresh':
      return fortress.auth.refresh(String(body.refreshToken ?? ''), meta);
    case 'logout':
      await fortress.auth.logout(String(body.refreshToken ?? ''));
      return { ok: true };
    case 'me':
      return fortress.auth.me(requireUserId(auth));
    case 'listSessions':
      return fortress.auth.listSessions(requireUserId(auth));
    case 'revokeSession':
      await fortress.auth.revokeSession(requireUserId(auth), Number(params.id));
      return { ok: true };
    case 'revokeAllOtherSessions':
      await fortress.auth.revokeAllOtherSessions(requireUserId(auth), Number(body.currentTokenId));
      return { ok: true };
    case 'addLoginIdentifier':
      await fortress.auth.addLoginIdentifier(
        requireUserId(auth),
        body.type as never,
        String(body.value ?? ''),
      );
      return { ok: true };
    case 'removeLoginIdentifier':
      await fortress.auth.removeLoginIdentifier(
        requireUserId(auth),
        body.type as never,
        String(body.value ?? ''),
      );
      return { ok: true };
    case 'getLoginIdentifiers':
      return fortress.auth.getLoginIdentifiers(requireUserId(auth));
    case 'impersonate':
      return fortress.auth.impersonate(requireUserId(auth), Number(body.targetUserId), {
        reason: body.reason as string | undefined,
        expirySeconds: body.expirySeconds as number | undefined,
      });
    default:
      throw Errors.notFound(`Auth handler '${handler}' not found`);
  }
}

async function invokeIamHandler(
  fortress: Fortress,
  handler: string,
  body: Record<string, unknown>,
  params: Record<string, string>,
): Promise<unknown> {
  switch (handler) {
    case 'getResources':
      return fortress.iam.getResources();
    case 'getRoles':
      return fortress.iam.getRoles();
    case 'createRole':
      return fortress.iam.createRole(
        String(body.name ?? ''),
        body.permissions as never,
        body.description as string | undefined,
      );
    case 'deleteRole':
      await fortress.iam.deleteRole(Number(params.id));
      return { ok: true };
    case 'bindRoleToUser':
      await fortress.iam.bindRoleToUser(
        Number(body.userId),
        Number(params.id),
        body.tenantId as string | undefined,
      );
      return { ok: true };
    case 'bindRoleToGroup':
      await fortress.iam.bindRoleToGroup(
        Number(body.groupId),
        Number(params.id),
        body.tenantId as string | undefined,
      );
      return { ok: true };
    case 'unbindRole':
      await fortress.iam.unbindRole(
        body.subjectType as never,
        Number(body.subjectId),
        Number(params.id),
        body.tenantId as string | undefined,
      );
      return { ok: true };
    case 'createGroup':
      return fortress.iam.createGroup(
        String(body.name ?? ''),
        body.description as string | undefined,
      );
    case 'addUserToGroup':
      await fortress.iam.addUserToGroup(Number(params.id), Number(body.userId));
      return { ok: true };
    case 'removeUserFromGroup':
      await fortress.iam.removeUserFromGroup(Number(params.id), Number(params.userId));
      return { ok: true };
    case 'getUserPermissions':
      return fortress.iam.getUserPermissions(
        Number(params.id),
        body.tenantId as string | undefined,
      );
    case 'checkPermission': {
      const allowed = await fortress.iam.checkPermission(
        Number(body.userId),
        String(body.resource ?? ''),
        String(body.action ?? ''),
        body.context as never,
      );
      return { allowed };
    }
    case 'bindPermissionToUser':
      await fortress.iam.bindPermissionToUser(
        Number(body.userId),
        body.permission as never,
        body.tenantId as string | undefined,
      );
      return { ok: true };
    case 'bindPermissionToGroup':
      await fortress.iam.bindPermissionToGroup(
        Number(body.groupId),
        body.permission as never,
        body.tenantId as string | undefined,
      );
      return { ok: true };
    case 'unbindPermissionFromUser':
      await fortress.iam.unbindPermissionFromUser(
        Number(body.userId),
        Number(body.permissionId),
        body.tenantId as string | undefined,
      );
      return { ok: true };
    case 'unbindPermissionFromGroup':
      await fortress.iam.unbindPermissionFromGroup(
        Number(body.groupId),
        Number(body.permissionId),
        body.tenantId as string | undefined,
      );
      return { ok: true };
    default:
      throw Errors.notFound(`IAM handler '${handler}' not found`);
  }
}

function requireUserId(auth: DispatchAuth): number {
  if (!auth.userId)
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  return auth.userId;
}

// ── Response helpers ────────────────────────────────────────────────

/**
 * Pick the first 2xx status declared in `endpoint.responses` (e.g. `201`
 * for `POST /auth/register`), defaulting to `200`.
 */
function successStatus(endpoint: EndpointDefinition): number {
  if (!endpoint.responses)
    return 200;
  for (const code of Object.keys(endpoint.responses)) {
    const num = Number(code);
    if (num >= 200 && num < 300)
      return num;
  }
  return 200;
}

/** Build a JSON `Response` with the right `Content-Type`. */
export function jsonResponse(body: unknown, status: number): Response {
  return new Response(JSON.stringify(body ?? { ok: true }), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
