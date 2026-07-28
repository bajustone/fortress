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

import type { ClientAuth, TokenRequestBody } from '../../plugins/oauth';
import type { AuthEndpointsMap } from '../auth/auth-endpoints';
import type { FortressRuntime } from '../capabilities';
import type {
  EndpointDefinition,
  InferEndpointBody,
} from '../endpoint';
import type { IamEndpointsMap } from '../iam/iam-endpoints';
import type { PluginMethod, PluginRouteContext, RuntimeFortressPlugin } from '../plugin';
import type { PluginCapability } from '../plugin-methods-map';
import type {
  CreateUserInput,
  LoginIdentifierType,
  PermissionCondition,
  PermissionContext,
  PermissionInput,
  RequestMeta,
  Subject,
  SubjectType,
  TokenClaims,
} from '../types';
import type { ValidatedRequestData } from '../validation';
import { endpointSuccessStatus } from '../endpoint';
import { Errors, FortressError } from '../errors';
import { resolvePluginCapability } from '../plugin-methods-map';

/** Auth context resolved by `handleRequest` before dispatch. */
export interface DispatchAuth {
  /** Resolved request principal — USER or SERVICE_ACCOUNT. Present iff authenticated. */
  subject?: Subject;
  /** Convenience alias for `subject?.id` when the subject is a USER. */
  userId?: string;
  claims?: TokenClaims;
  /** Credential-level narrowing scopes (e.g. API-key scopes). */
  scopes?: string[] | null;
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
  fortress: FortressRuntime,
  request: Request,
  endpoint: EndpointDefinition,
  input: ValidatedRequestData,
  auth: DispatchAuth,
): Promise<DispatchResult> {
  // OAuth endpoints get form-encoded body parsing + Basic auth handling.
  const owningPlugin = findOwningPlugin(fortress, endpoint);
  if (owningPlugin?.name === 'oauth') {
    return dispatchOAuth(fortress, request, endpoint, auth);
  }

  const body = objectOrEmpty(input.body);
  const query = objectOrEmpty(input.query);
  const params = objectOrEmpty(input.params);

  // Plugin route (non-oauth)
  if (owningPlugin) {
    return dispatchPlugin(fortress, owningPlugin, endpoint, body, query, params, request, auth);
  }

  // Core auth / IAM dispatch. Query values are available on every method;
  // params remain separate for the existing positional service calls.
  const bodyAndQuery = { ...body, ...query };
  if (endpoint.path.startsWith('/auth/')) {
    const result = await invokeAuthHandler(fortress, endpoint.handler, bodyAndQuery, params, auth);
    return jsonResponse(result, endpointSuccessStatus(endpoint));
  }
  if (endpoint.path.startsWith('/iam/')) {
    const result = await invokeIamHandler(fortress, endpoint.handler, bodyAndQuery, params);
    return jsonResponse(result, endpointSuccessStatus(endpoint));
  }

  // Top-level host routes are metadata-only and have no Fortress handler.
  // Framework adapters exclude them from their mounted route table so the
  // host handler runs; direct core dispatch fails closed instead of inventing
  // a successful response.
  throw Errors.notFound(`No Fortress handler is mounted for ${endpoint.method} ${endpoint.path}`);
}

// ── Body parsing ─────────────────────────────────────────────────────

function objectOrEmpty(value: unknown): Record<string, unknown> {
  return value && typeof value === 'object' && !Array.isArray(value)
    ? value as Record<string, unknown>
    : {};
}

async function parseFormBody(request: Request): Promise<Partial<Record<string, string>>> {
  const text = await request.text();
  const params = new URLSearchParams(text);
  const out = Object.create(null) as Partial<Record<string, string>>;
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

function isPluginMethodRecord(value: unknown): value is Record<string, PluginMethod> {
  if (value === null || typeof value !== 'object' || Array.isArray(value))
    return false;
  return Object.values(value).every(method => typeof method === 'function');
}

/** Find the plugin (if any) that owns the given endpoint. */
function findOwningPlugin(fortress: FortressRuntime, endpoint: EndpointDefinition): RuntimeFortressPlugin | undefined {
  const plugins = fortress.config.plugins ?? [];
  for (const plugin of plugins) {
    if (!plugin.routes)
      continue;
    const routes = Object.values(plugin.routes) as EndpointDefinition[];
    if (routes.some(r => r.method === endpoint.method && r.path === endpoint.path)) {
      return plugin;
    }
  }
  return undefined;
}

async function dispatchPlugin(
  fortress: FortressRuntime,
  plugin: RuntimeFortressPlugin,
  endpoint: EndpointDefinition,
  body: Record<string, unknown>,
  query: Record<string, unknown>,
  pathParams: Record<string, unknown>,
  request: Request,
  auth: DispatchAuth,
): Promise<Response> {
  // OpenAPI Scalar UI returns HTML, not JSON. Use the named capability so
  // this core-owned route cannot silently drift from the plugin contract.
  if (plugin.name === 'openapi' && endpoint.handler === 'getUI') {
    const html = resolvePluginCapability(fortress, 'openapi', 'getUI').getUI();
    return new Response(html, {
      status: 200,
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }

  const methods = fortress.resolvePlugin(plugin.name, isPluginMethodRecord);
  const method = Object.hasOwn(methods, endpoint.handler) ? methods[endpoint.handler] : undefined;
  if (typeof method !== 'function')
    throw Errors.notFound(`Plugin handler '${plugin.name}.${endpoint.handler}' not found`);

  // Call as `methods.<handler>(...)` so the `this` binding is preserved —
  // some plugin methods reference sibling helpers via `this`.

  const ctx: PluginRouteContext = {
    subject: auth.subject,
    userId: auth.subject?.type === 'USER' ? auth.subject.id : undefined,
    claims: auth.claims,
    scopes: auth.scopes,
    meta: auth.meta,
    request,
  };
  const result = await method.call(methods, { ...body, ...query, ...pathParams }, ctx);
  // Allow handlers to opt into HTML by returning a string starting with `<!`.
  if (typeof result === 'string' && result.trimStart().startsWith('<!')) {
    return new Response(result, {
      status: endpointSuccessStatus(endpoint),
      headers: { 'Content-Type': 'text/html; charset=utf-8' },
    });
  }
  return jsonResponse(result, endpointSuccessStatus(endpoint));
}

// ── OAuth special case ──────────────────────────────────────────────

type OAuthCapabilityMethod = Extract<keyof PluginCapability<'oauth'>, string>;

function resolveOAuthMethod<M extends OAuthCapabilityMethod>(
  fortress: FortressRuntime,
  method: M,
): Pick<PluginCapability<'oauth'>, M> {
  try {
    return resolvePluginCapability(fortress, 'oauth', method);
  }
  catch (error) {
    if (error instanceof FortressError && error.code === 'BAD_REQUEST')
      throw Errors.notFound(`OAuth handler '${method}' not found`);
    throw error;
  }
}

async function dispatchOAuth(
  fortress: FortressRuntime,
  request: Request,
  endpoint: EndpointDefinition,
  auth: DispatchAuth,
): Promise<Response> {
  const handlerName = endpoint.handler;
  const authHeader = request.headers.get('authorization');

  switch (handlerName) {
    case 'handleTokenRequest': {
      const m = resolveOAuthMethod(fortress, 'handleTokenRequest');
      const body = parseTokenRequestBody(await parseFormBody(request));
      const clientAuth = parseBasicAuth(authHeader);
      const result = await m.handleTokenRequest(body, clientAuth);
      return jsonResponse(result, 200);
    }
    case 'handleIntrospectRequest': {
      const m = resolveOAuthMethod(fortress, 'handleIntrospectRequest');
      const body = await parseFormBody(request);
      const clientAuth = parseBasicAuth(authHeader);
      if (!clientAuth) {
        return jsonResponse(
          { error: 'invalid_client', error_description: 'Client authentication required' },
          401,
        );
      }
      const result = await m.handleIntrospectRequest({ token: body.token ?? '' }, clientAuth);
      return jsonResponse(result, 200);
    }
    case 'handleRevokeRequest': {
      const m = resolveOAuthMethod(fortress, 'handleRevokeRequest');
      const body = await parseFormBody(request);
      const clientAuth = parseBasicAuth(authHeader);
      if (!clientAuth) {
        return jsonResponse(
          { error: 'invalid_client', error_description: 'Client authentication required' },
          401,
        );
      }
      await m.handleRevokeRequest({ token: body.token ?? '' }, clientAuth);
      return jsonResponse({}, 200);
    }
    case 'handleUserInfoRequest': {
      const m = resolveOAuthMethod(fortress, 'handleUserInfoRequest');
      // RFC 6750 §2.1: bearer token from Authorization header.
      // The plugin's `handleUserInfoRequest` now returns OIDC-Core-§5.3
      // shaped claims directly (sub-as-string, scope-gated standard
      // claims, optional userinfoClaims hook output) and throws 401 for
      // an invalid / expired token — which the standard error mapper
      // serialises to a `{ code, message }` body. We just pass the result
      // through.
      const bearer = parseBearerToken(authHeader);
      if (!bearer) {
        return jsonResponse(
          { error: 'invalid_token', error_description: 'Bearer token required' },
          401,
        );
      }
      const claims = await m.handleUserInfoRequest(bearer);
      return jsonResponse(claims, 200);
    }
    case 'handleDiscovery': {
      const m = resolveOAuthMethod(fortress, 'handleDiscovery');
      const result = m.handleDiscovery();
      return jsonResponse(result, 200);
    }
    case 'handleJwksRequest': {
      const m = resolveOAuthMethod(fortress, 'handleJwksRequest');
      // RFC 7517 / OIDC Discovery: public JWKS for id_token verification.
      // Cacheable for a short window — long enough that key rotation
      // doesn't immediately bust every RP, short enough that a rotated
      // key reaches them within the grace period.
      const result = await m.handleJwksRequest();
      return new Response(JSON.stringify(result), {
        status: 200,
        headers: {
          'Content-Type': 'application/json',
          'Cache-Control': 'public, max-age=300',
        },
      });
    }
    case 'handleAuthorizeRequest': {
      const m = resolveOAuthMethod(fortress, 'handleAuthorizeRequest');
      // GET /oauth/authorize — front door for the auth-code flow.
      // Reads query params, optionally identifies the user, then 302s to
      // either the configured loginUrl or consentUrl with `?flow=<id>`.
      const query = Object.fromEntries(new URL(request.url).searchParams);
      const result = await m.handleAuthorizeRequest(query, { userId: auth.userId });
      return new Response(null, {
        status: 302,
        headers: { Location: result.redirectUrl },
      });
    }
    case 'handleGetFlow': {
      const m = resolveOAuthMethod(fortress, 'handleGetFlow');
      // H6 fix — every consent-flow endpoint requires authentication so the
      // owner check has someone to compare against. Without this guard, an
      // unauthenticated caller could read another user's pending flow.
      if (auth.userId === undefined) {
        return jsonResponse(
          { error: 'unauthorized', error_description: 'Authentication required' },
          401,
        );
      }
      const flowId = consentFlowIdFromUrl(request.url);
      const result = await m.handleGetFlow(flowId, { userId: auth.userId });
      return jsonResponse(result, 200);
    }
    case 'handleApproveFlow': {
      const m = resolveOAuthMethod(fortress, 'handleApproveFlow');
      if (auth.userId === undefined) {
        return jsonResponse(
          { error: 'unauthorized', error_description: 'Authentication required' },
          401,
        );
      }
      const flowId = consentFlowIdFromUrl(request.url);
      const result = await m.handleApproveFlow(flowId, { userId: auth.userId });
      return jsonResponse(result, 200);
    }
    case 'handleDenyFlow': {
      const m = resolveOAuthMethod(fortress, 'handleDenyFlow');
      if (auth.userId === undefined) {
        return jsonResponse(
          { error: 'unauthorized', error_description: 'Authentication required' },
          401,
        );
      }
      const flowId = consentFlowIdFromUrl(request.url);
      const result = await m.handleDenyFlow(flowId, { userId: auth.userId });
      return jsonResponse(result, 200);
    }
    default:
      throw Errors.notFound(`OAuth handler '${handlerName}' not found`);
  }
}

const FLOW_ID_PATTERN = /\/oauth\/flows\/([^/]+)/;

/**
 * Extract the opaque `:flowId` path segment from a
 * `/oauth/flows/:flowId[/...]` URL. Throws if the segment is missing.
 */
function consentFlowIdFromUrl(url: string): string {
  const path = new URL(url).pathname;
  const match = FLOW_ID_PATTERN.exec(path);
  if (!match)
    throw Errors.badRequest('Invalid flow id');
  return decodeURIComponent(match[1]);
}

// ── Auth / IAM dispatch ──────────────────────────────────────────────

/** Validated body types are derived from the endpoint maps, not re-declared here. */
type AuthBody<K extends keyof AuthEndpointsMap> = InferEndpointBody<AuthEndpointsMap[K]>;
type IamBody<K extends keyof IamEndpointsMap> = InferEndpointBody<IamEndpointsMap[K]>;
type PermissionWire = IamBody<'createRole'>['permissions'][number];

function validationFailure(field: string): never {
  throw Errors.validationError([{
    path: [field],
    message: `Invalid ${field}`,
  }]);
}

function requiredString(value: unknown, field: string): string {
  return typeof value === 'string' ? value : validationFailure(field);
}

function optionalString(value: unknown, field: string): string | undefined {
  if (value === undefined)
    return undefined;
  return requiredString(value, field);
}

function optionalBoolean(value: unknown, field: string): boolean | undefined {
  if (value === undefined)
    return undefined;
  return typeof value === 'boolean' ? value : validationFailure(field);
}

function optionalNumber(value: unknown, field: string): number | undefined {
  if (value === undefined)
    return undefined;
  return typeof value === 'number' && Number.isFinite(value) ? value : validationFailure(field);
}

function optionalNullableString(value: unknown, field: string): string | null | undefined {
  if (value === undefined || value === null)
    return value;
  return requiredString(value, field);
}

function requiredOAuthFormValue(value: string | undefined, field: string): string {
  if (!value)
    throw Errors.oauth('invalid_request', `${field} is required`);
  return value;
}

function parseTokenRequestBody(value: Partial<Record<string, string>>): TokenRequestBody {
  return {
    grant_type: requiredOAuthFormValue(value.grant_type, 'grant_type'),
    code: optionalString(value.code, 'code'),
    redirect_uri: optionalString(value.redirect_uri, 'redirect_uri'),
    client_id: optionalString(value.client_id, 'client_id'),
    client_secret: optionalString(value.client_secret, 'client_secret'),
    code_verifier: optionalString(value.code_verifier, 'code_verifier'),
    scope: optionalString(value.scope, 'scope'),
    refresh_token: optionalString(value.refresh_token, 'refresh_token'),
  };
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function parseCreateUserInput(value: Record<string, unknown>): AuthBody<'createUser'> {
  const input: CreateUserInput = {
    email: requiredString(value.email, 'email'),
    name: requiredString(value.name, 'name'),
  };
  const password = optionalString(value.password, 'password');
  const isActive = optionalBoolean(value.isActive, 'isActive');
  if (password !== undefined)
    input.password = password;
  if (isActive !== undefined)
    input.isActive = isActive;
  return input;
}

function parseLoginIdentifierType(value: unknown): LoginIdentifierType {
  if (value === 'email' || value === 'phone' || value === 'username')
    return value;
  return validationFailure('type');
}

function parseSubjectType(value: unknown): SubjectType {
  if (value === 'USER' || value === 'GROUP' || value === 'SERVICE_ACCOUNT')
    return value;
  return validationFailure('subjectType');
}

function isPermissionWire(value: unknown): value is PermissionWire {
  if (!isRecord(value)
    || typeof value.resource !== 'string'
    || typeof value.action !== 'string'
    || (value.effect !== undefined && value.effect !== 'ALLOW' && value.effect !== 'DENY')) {
    return false;
  }
  if (value.conditions === undefined) {
    return true;
  }
  return Array.isArray(value.conditions) && value.conditions.every((condition) => {
    if (!isRecord(condition)
      || typeof condition.field !== 'string'
      || (condition.operator !== 'eq' && condition.operator !== 'neq' && condition.operator !== 'in' && condition.operator !== 'startsWith')) {
      return false;
    }
    return typeof condition.value === 'string';
  });
}

function parsePermissionInput(value: unknown): PermissionInput {
  if (!isPermissionWire(value))
    return validationFailure('permission');
  const permission: PermissionInput = {
    resource: value.resource,
    action: value.action,
  };
  if (value.effect !== undefined)
    permission.effect = value.effect;
  if (value.conditions !== undefined) {
    permission.conditions = value.conditions.map(condition => ({
      field: condition.field,
      operator: condition.operator,
      value: condition.value,
    } satisfies PermissionCondition));
  }
  return permission;
}

function parsePermissionInputs(value: unknown): PermissionInput[] {
  if (!Array.isArray(value) || !value.every(isPermissionWire))
    return validationFailure('permissions');
  return value.map(parsePermissionInput);
}

function parsePermissionContext(value: unknown): PermissionContext {
  if (value === undefined)
    return {};
  if (!isRecord(value))
    return validationFailure('context');
  const context: PermissionContext = {};
  if (value.tenantId !== undefined)
    context.tenantId = requiredString(value.tenantId, 'context.tenantId');
  if (value.request !== undefined) {
    if (!isRecord(value.request))
      return validationFailure('context.request');
    context.request = value.request;
  }
  return context;
}

async function invokeAuthHandler(
  fortress: FortressRuntime,
  handler: string,
  body: Record<string, unknown>,
  params: Record<string, unknown>,
  auth: DispatchAuth,
): Promise<unknown> {
  const meta = auth.meta;
  switch (handler) {
    case 'login':
      return fortress.auth.login(String(body.identifier ?? ''), String(body.password ?? ''), {
        ...meta,
        ...(typeof body.trustedDeviceToken === 'string' ? { trustedDeviceToken: body.trustedDeviceToken } : {}),
      });
    case 'verifyTwoFactor': {
      let methods: Pick<PluginCapability<'two-factor'>, 'verify'>;
      try {
        methods = resolvePluginCapability(fortress, 'two-factor', 'verify');
      }
      catch (error) {
        if (error instanceof FortressError && (error.code === 'NOT_FOUND' || error.code === 'BAD_REQUEST'))
          throw Errors.badRequest('Two-factor plugin is not configured');
        throw error;
      }
      return methods.verify(String(body.continuationToken ?? ''), String(body.code ?? ''), {
        ...meta,
        ...(body.rememberDevice === true ? { rememberDevice: true } : {}),
      });
    }
    case 'verifyMagicLink': {
      let methods: Pick<PluginCapability<'magic-link'>, 'verify'>;
      try {
        methods = resolvePluginCapability(fortress, 'magic-link', 'verify');
      }
      catch (error) {
        if (error instanceof FortressError && (error.code === 'NOT_FOUND' || error.code === 'BAD_REQUEST'))
          throw Errors.badRequest('Magic-link plugin is not configured');
        throw error;
      }
      return methods.verify(String(body.token ?? ''), meta);
    }
    case 'createUser':
      return fortress.auth.createUser(parseCreateUserInput(body));
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
      await fortress.auth.revokeSession(requireUserId(auth), requiredString(params.id, 'id'));
      return { ok: true };
    case 'revokeAllOtherSessions':
      await fortress.auth.revokeAllOtherSessions(requireUserId(auth), String(body.currentTokenId ?? ''));
      return { ok: true };
    case 'addLoginIdentifier':
      await fortress.auth.addLoginIdentifier(
        requireUserId(auth),
        parseLoginIdentifierType(body.type),
        requiredString(body.value, 'value'),
      );
      return { ok: true };
    case 'removeLoginIdentifier':
      await fortress.auth.removeLoginIdentifier(
        requireUserId(auth),
        parseLoginIdentifierType(body.type),
        requiredString(body.value, 'value'),
      );
      return { ok: true };
    case 'getLoginIdentifiers':
      return fortress.auth.getLoginIdentifiers(requireUserId(auth));
    case 'impersonate':
      return fortress.auth.impersonate(requireUserId(auth), requiredString(body.targetUserId, 'targetUserId'), {
        reason: optionalString(body.reason, 'reason'),
        expirySeconds: optionalNumber(body.expirySeconds, 'expirySeconds'),
      });
    default:
      throw Errors.notFound(`Auth handler '${handler}' not found`);
  }
}

async function invokeIamHandler(
  fortress: FortressRuntime,
  handler: string,
  body: Record<string, unknown>,
  params: Record<string, unknown>,
): Promise<unknown> {
  switch (handler) {
    case 'getResources':
      return fortress.iam.getResources();
    case 'getRoles':
      return fortress.iam.getRoles();
    case 'createRole':
      return fortress.iam.createRole(
        requiredString(body.name, 'name'),
        parsePermissionInputs(body.permissions),
        optionalString(body.description, 'description'),
      );
    case 'deleteRole':
      await fortress.iam.deleteRole(requiredString(params.id, 'id'));
      return { ok: true };
    case 'bindRoleToUser':
      await fortress.iam.bindRoleToUser(
        requiredString(body.userId, 'userId'),
        requiredString(params.id, 'id'),
        optionalString(body.tenantId, 'tenantId'),
      );
      return { ok: true };
    case 'bindRoleToGroup':
      await fortress.iam.bindRoleToGroup(
        requiredString(body.groupId, 'groupId'),
        requiredString(params.id, 'id'),
        optionalString(body.tenantId, 'tenantId'),
      );
      return { ok: true };
    case 'unbindRole':
      await fortress.iam.unbindRole(
        parseSubjectType(body.subjectType),
        requiredString(body.subjectId, 'subjectId'),
        requiredString(params.id, 'id'),
        optionalString(body.tenantId, 'tenantId'),
      );
      return { ok: true };
    case 'createGroup':
      return fortress.iam.createGroup(
        requiredString(body.name, 'name'),
        optionalString(body.description, 'description'),
      );
    case 'addUserToGroup':
      await fortress.iam.addUserToGroup(requiredString(params.id, 'id'), requiredString(body.userId, 'userId'));
      return { ok: true };
    case 'removeUserFromGroup':
      await fortress.iam.removeUserFromGroup(requiredString(params.id, 'id'), requiredString(params.userId, 'userId'));
      return { ok: true };
    case 'getUserPermissions':
      return fortress.iam.getPermissionsForSubject(
        { type: 'USER', id: requiredString(params.id, 'id') },
        optionalString(body.tenantId, 'tenantId'),
      );
    case 'checkPermission': {
      // Accept either the new `{ subject: { type, id } }` shape or the
      // legacy `{ userId }` shape. Defaulting to USER keeps this backwards
      // compatible for callers that haven't migrated yet — step 10 updates
      // the endpoint body schema to the new shape.
      const subjectIn = isRecord(body.subject) ? body.subject : undefined;
      const subject: Subject = subjectIn
        ? { type: parseSubjectType(subjectIn.type), id: requiredString(subjectIn.id, 'subject.id') }
        : { type: 'USER', id: requiredString(body.userId, 'userId') };
      // Sanitize caller-supplied context before forwarding to the evaluator.
      // The diagnostic route must not accept credential scopes or forged user
      // and resource data from JSON.
      const allowed = await fortress.iam.checkPermission(
        subject,
        requiredString(body.resource, 'resource'),
        requiredString(body.action, 'action'),
        parsePermissionContext(body.context),
      );
      return { allowed };
    }
    case 'bindPermissionToUser':
      await fortress.iam.bindPermissionToUser(
        requiredString(body.userId, 'userId'),
        parsePermissionInput(body.permission),
        optionalString(body.tenantId, 'tenantId'),
      );
      return { ok: true };
    case 'bindPermissionToGroup':
      await fortress.iam.bindPermissionToGroup(
        requiredString(body.groupId, 'groupId'),
        parsePermissionInput(body.permission),
        optionalString(body.tenantId, 'tenantId'),
      );
      return { ok: true };
    case 'unbindPermissionFromUser':
      await fortress.iam.unbindPermissionFromUser(
        requiredString(body.userId, 'userId'),
        requiredString(body.permissionId, 'permissionId'),
        optionalString(body.tenantId, 'tenantId'),
      );
      return { ok: true };
    case 'unbindPermissionFromGroup':
      await fortress.iam.unbindPermissionFromGroup(
        requiredString(body.groupId, 'groupId'),
        requiredString(body.permissionId, 'permissionId'),
        optionalString(body.tenantId, 'tenantId'),
      );
      return { ok: true };

    // ── Service Accounts ──────────────────────────────────────────
    case 'createServiceAccount':
      return fortress.iam.createServiceAccount({
        name: requiredString(body.name, 'name'),
        displayName: optionalString(body.displayName, 'displayName'),
        description: optionalString(body.description, 'description'),
      });
    case 'listServiceAccounts':
      return fortress.iam.listServiceAccounts({
        limit: optionalNumber(body.limit, 'limit'),
        offset: optionalNumber(body.offset, 'offset'),
      });
    case 'getServiceAccount':
      return fortress.iam.getServiceAccount(requiredString(params.id, 'id'));
    case 'updateServiceAccount':
      return fortress.iam.updateServiceAccount(requiredString(params.id, 'id'), {
        displayName: optionalNullableString(body.displayName, 'displayName'),
        description: optionalNullableString(body.description, 'description'),
        isActive: optionalBoolean(body.isActive, 'isActive'),
      });
    case 'deleteServiceAccount':
      await fortress.iam.deleteServiceAccount(requiredString(params.id, 'id'));
      return { ok: true };
    case 'getServiceAccountPermissions':
      return fortress.iam.getPermissionsForSubject(
        { type: 'SERVICE_ACCOUNT', id: requiredString(params.id, 'id') },
        optionalString(body.tenantId, 'tenantId'),
      );
    case 'bindRoleToServiceAccount':
      await fortress.iam.bindRoleToServiceAccount(
        requiredString(body.serviceAccountId, 'serviceAccountId'),
        requiredString(params.id, 'id'),
        optionalString(body.tenantId, 'tenantId'),
      );
      return { ok: true };
    case 'unbindRoleFromServiceAccount':
      await fortress.iam.unbindRoleFromServiceAccount(
        requiredString(body.serviceAccountId, 'serviceAccountId'),
        requiredString(params.id, 'id'),
        optionalString(body.tenantId, 'tenantId'),
      );
      return { ok: true };
    case 'bindPermissionToServiceAccount':
      await fortress.iam.bindPermissionToServiceAccount(
        requiredString(body.serviceAccountId, 'serviceAccountId'),
        parsePermissionInput(body.permission),
        optionalString(body.tenantId, 'tenantId'),
      );
      return { ok: true };
    case 'unbindPermissionFromServiceAccount':
      await fortress.iam.unbindPermissionFromServiceAccount(
        requiredString(body.serviceAccountId, 'serviceAccountId'),
        requiredString(body.permissionId, 'permissionId'),
        optionalString(body.tenantId, 'tenantId'),
      );
      return { ok: true };

    default:
      throw Errors.notFound(`IAM handler '${handler}' not found`);
  }
}

function requireUserId(auth: DispatchAuth): string {
  if (!auth.userId)
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  return auth.userId;
}

// ── Response helpers ────────────────────────────────────────────────

/** Build a JSON `Response` with the right `Content-Type`. */
export function jsonResponse(body: unknown, status: number): Response {
  if (status === 204 || status === 205)
    return new Response(null, { status });
  return new Response(JSON.stringify(body === undefined ? { ok: true } : body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  });
}
