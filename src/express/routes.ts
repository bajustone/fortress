import type { EndpointDefinition } from '../core/endpoint';
import type { Fortress } from '../core/fortress';
import type { FortressPlugin } from '../core/plugin';
import type { ClientAuth, TokenRequestBody } from '../plugins/oauth';
import type { ExpressMiddleware, ExpressNextFunction, ExpressRequest, ExpressResponse } from './middleware';
import { FortressError } from '../core/errors';

// Minimal app interface — users bring their own Express
interface ExpressApp {
  get: (path: string, ...handlers: ExpressMiddleware[]) => void;
  post: (path: string, ...handlers: ExpressMiddleware[]) => void;
  put: (path: string, ...handlers: ExpressMiddleware[]) => void;
  delete: (path: string, ...handlers: ExpressMiddleware[]) => void;
  patch: (path: string, ...handlers: ExpressMiddleware[]) => void;
}

interface MountOptions {
  prefix?: string;
}

// ── Plugin Route Mounting ───────────────────────────────────────────

/**
 * Mount plugin-defined HTTP routes onto an Express app.
 *
 * Reads `routes[]` from each registered plugin and creates Express handlers
 * that parse requests, call the corresponding plugin method, and return JSON.
 */
export function mountPluginRoutes(
  app: ExpressApp,
  fortress: Fortress,
  options?: MountOptions,
): void {
  const prefix = options?.prefix ?? '';
  const plugins = fortress.config.plugins ?? [];

  for (const plugin of plugins) {
    if (!plugin.routes)
      continue;

    const methods = fortress.plugins[plugin.name] as Record<string, (...args: any[]) => any> | undefined;
    if (!methods)
      continue;

    for (const route of plugin.routes) {
      const fullPath = `${prefix}${toExpressPath(route.path)}`;
      const handler = methods[route.handler];
      if (!handler)
        continue;

      const expressHandler = createPluginRouteHandler(plugin, route.handler, methods);
      mountRoute(app, route.method, fullPath, expressHandler);
    }
  }
}

// ── Full Route Mounting (auth + IAM + plugins) ──────────────────────

/**
 * Mount ALL Fortress endpoints onto an Express app with auto-wired handlers.
 *
 * Registers routes for core auth, IAM, and all plugin endpoints.
 * Each handler dispatches to the appropriate fortress service method.
 *
 * @example
 * ```ts
 * import { createFortress } from '@bajustone/fortress';
 * import { mountFortressRoutes } from '@bajustone/fortress/express';
 * import { openapi } from '@bajustone/fortress/plugins/openapi';
 *
 * const fortress = createFortress({ plugins: [openapi({ title: 'My API' })] });
 * mountFortressRoutes(app, fortress);
 * // All auth, IAM, plugin, and OpenAPI endpoints are now registered
 * ```
 */
export function mountFortressRoutes(
  app: ExpressApp,
  fortress: Fortress,
  options?: MountOptions,
): void {
  const prefix = options?.prefix ?? '';

  for (const ep of fortress.endpoints) {
    const fullPath = `${prefix}${toExpressPath(ep.path)}`;

    // For plugin routes, use the plugin-aware handler
    if (!ep.path.startsWith('/auth/') && !ep.path.startsWith('/iam/')) {
      const pluginHandler = findPluginHandler(fortress, ep);
      if (pluginHandler) {
        mountRoute(app, ep.method, fullPath, pluginHandler);
        continue;
      }
    }

    const handler = createAutoHandler(fortress, ep);
    mountRoute(app, ep.method, fullPath, handler);
  }
}

// ── Internals ───────────────────────────────────────────────────────

/** Convert :param to Express :param (already the right format, but handle edge cases) */
function toExpressPath(path: string): string {
  return path;
}

function mountRoute(app: ExpressApp, method: string, path: string, handler: ExpressMiddleware): void {
  switch (method) {
    case 'GET':
      app.get(path, handler);
      break;
    case 'POST':
      app.post(path, handler);
      break;
    case 'PUT':
      app.put(path, handler);
      break;
    case 'DELETE':
      app.delete(path, handler);
      break;
    case 'PATCH':
      app.patch(path, handler);
      break;
  }
}

function parseBasicAuth(header: string | undefined): ClientAuth | undefined {
  if (!header?.startsWith('Basic '))
    return undefined;
  const decoded = atob(header.slice(6));
  const colonIndex = decoded.indexOf(':');
  if (colonIndex === -1)
    return undefined;
  return {
    clientId: decoded.slice(0, colonIndex),
    clientSecret: decoded.slice(colonIndex + 1),
  };
}

function parseBearerToken(header: string | undefined): string | undefined {
  if (!header?.startsWith('Bearer '))
    return undefined;
  return header.slice(7);
}

function getHeader(req: ExpressRequest, name: string): string | undefined {
  const val = req.headers[name];
  return typeof val === 'string' ? val : undefined;
}

function createPluginRouteHandler(
  plugin: FortressPlugin,
  handlerName: string,
  methods: Record<string, (...args: any[]) => any>,
): ExpressMiddleware {
  return async (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => {
    try {
      if (plugin.name === 'oauth') {
        await handleOAuthRoute(req, res, handlerName, methods);
        return;
      }

      // OpenAPI plugin: getUI returns HTML, not JSON
      if (plugin.name === 'openapi' && handlerName === 'getUI') {
        const html = methods.getUI() as string;
        res.setHeader('Content-Type', 'text/html');
        (res as any).send?.(html) ?? res.json(html);
        return;
      }

      const body = req.method === 'GET'
        ? (req as any).query ?? {}
        : (req as any).body ?? {};

      const result = await methods[handlerName](body);
      res.status(200).json(result ?? { ok: true });
    }
    catch (error) {
      if (error instanceof FortressError) {
        res.status(error.statusCode).json({
          error: error.code,
          error_description: error.message,
        });
        return;
      }
      next(error);
    }
  };
}

async function handleOAuthRoute(
  req: ExpressRequest,
  res: ExpressResponse,
  handlerName: string,
  methods: Record<string, (...args: any[]) => any>,
): Promise<void> {
  const authHeader = getHeader(req, 'authorization');

  switch (handlerName) {
    case 'handleTokenRequest': {
      const body = (req as any).body as TokenRequestBody;
      const clientAuth = parseBasicAuth(authHeader);
      const result = await methods.handleTokenRequest(body, clientAuth);
      res.status(200).json(result);
      return;
    }
    case 'handleIntrospectRequest': {
      const body = (req as any).body;
      const clientAuth = parseBasicAuth(authHeader);
      if (!clientAuth) {
        res.status(401).json({ error: 'invalid_client', error_description: 'Client authentication required' });
        return;
      }
      const result = await methods.handleIntrospectRequest({ token: body.token }, clientAuth);
      res.status(200).json(result);
      return;
    }
    case 'handleRevokeRequest': {
      const body = (req as any).body;
      await methods.handleRevokeRequest({ token: body.token });
      res.status(200).json({});
      return;
    }
    case 'handleUserInfoRequest': {
      const bearer = parseBearerToken(authHeader);
      if (!bearer) {
        res.status(401).json({ error: 'invalid_token', error_description: 'Bearer token required' });
        return;
      }
      const user = await methods.handleUserInfoRequest(bearer);
      if (!user) {
        res.status(401).json({ error: 'invalid_token', error_description: 'Token invalid or expired' });
        return;
      }
      res.status(200).json({ sub: String(user.id), email: user.email, name: user.name });
      return;
    }
    case 'handleDiscovery': {
      const result = methods.handleDiscovery();
      res.status(200).json(result);
      return;
    }
    default: {
      const body = (req as any).body ?? {};
      const result = await methods[handlerName](body);
      res.status(200).json(result ?? { ok: true });
    }
  }
}

function findPluginHandler(fortress: Fortress, ep: EndpointDefinition): ExpressMiddleware | null {
  const plugins = fortress.config.plugins ?? [];
  for (const plugin of plugins) {
    if (!plugin.routes)
      continue;
    const match = plugin.routes.find(r => r.path === ep.path && r.method === ep.method);
    if (match) {
      const methods = (fortress.plugins as Record<string, Record<string, (...args: any[]) => any>>)[plugin.name];
      if (methods?.[ep.handler]) {
        return createPluginRouteHandler(plugin, ep.handler, methods);
      }
    }
  }
  return null;
}

function createAutoHandler(fortress: Fortress, ep: EndpointDefinition): ExpressMiddleware {
  return async (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => {
    try {
      const body = (req as any).body;
      const params = (req as any).params ?? {};
      const userId = req.fortressUserId;

      let result: unknown;

      if (ep.path.startsWith('/auth/')) {
        result = await invokeAuthHandler(fortress, ep.handler, body, params, userId, req);
      }
      else if (ep.path.startsWith('/iam/')) {
        result = await invokeIamHandler(fortress, ep.handler, body, params);
      }
      else {
        result = { ok: true };
      }

      const statusCodes = ep.responses ? Object.keys(ep.responses).map(Number) : [200];
      const successCode = statusCodes.find(s => s >= 200 && s < 300) ?? 200;
      res.status(successCode).json(result ?? { ok: true });
    }
    catch (error) {
      if (error instanceof FortressError) {
        res.status(error.statusCode).json({
          code: error.code,
          message: error.message,
          statusCode: error.statusCode,
        });
        return;
      }
      next(error);
    }
  };
}

async function invokeAuthHandler(
  fortress: Fortress,
  handler: string,
  body: any,
  params: Record<string, string>,
  userId: number | undefined,
  req: ExpressRequest,
): Promise<unknown> {
  const meta = {
    ipAddress: getHeader(req, 'x-forwarded-for') ?? getHeader(req, 'x-real-ip'),
    userAgent: getHeader(req, 'user-agent'),
  };

  switch (handler) {
    case 'login':
      return fortress.auth.login(body.identifier, body.password, meta);
    case 'createUser':
      return fortress.auth.createUser(body);
    case 'refresh':
      return fortress.auth.refresh(body.refreshToken, meta);
    case 'logout':
      await fortress.auth.logout(body.refreshToken);
      return { ok: true };
    case 'me':
      return fortress.auth.me(userId!);
    case 'listSessions':
      return fortress.auth.listSessions(userId!);
    case 'revokeSession':
      await fortress.auth.revokeSession(userId!, Number(params.id));
      return { ok: true };
    case 'revokeAllOtherSessions':
      await fortress.auth.revokeAllOtherSessions(userId!, body.currentTokenId);
      return { ok: true };
    case 'addLoginIdentifier':
      await fortress.auth.addLoginIdentifier(userId!, body.type, body.value);
      return { ok: true };
    case 'removeLoginIdentifier':
      await fortress.auth.removeLoginIdentifier(userId!, body.type, body.value);
      return { ok: true };
    case 'getLoginIdentifiers':
      return fortress.auth.getLoginIdentifiers(userId!);
    case 'impersonate':
      return fortress.auth.impersonate(userId!, body.targetUserId, {
        reason: body.reason,
        expirySeconds: body.expirySeconds,
      });
    default:
      return { ok: true };
  }
}

async function invokeIamHandler(
  fortress: Fortress,
  handler: string,
  body: any,
  params: Record<string, string>,
): Promise<unknown> {
  switch (handler) {
    case 'createRole':
      return fortress.iam.createRole(body.name, body.permissions, body.description);
    case 'deleteRole':
      await fortress.iam.deleteRole(Number(params.id));
      return { ok: true };
    case 'bindRoleToUser':
      await fortress.iam.bindRoleToUser(body.userId, Number(params.id), body.tenantId);
      return { ok: true };
    case 'bindRoleToGroup':
      await fortress.iam.bindRoleToGroup(body.groupId, Number(params.id), body.tenantId);
      return { ok: true };
    case 'unbindRole':
      await fortress.iam.unbindRole(body.subjectType, body.subjectId, Number(params.id), body.tenantId);
      return { ok: true };
    case 'createGroup':
      return fortress.iam.createGroup(body.name, body.description);
    case 'addUserToGroup':
      await fortress.iam.addUserToGroup(Number(params.id), body.userId);
      return { ok: true };
    case 'removeUserFromGroup':
      await fortress.iam.removeUserFromGroup(Number(params.id), Number(params.userId));
      return { ok: true };
    case 'getUserPermissions':
      return fortress.iam.getUserPermissions(Number(params.id), body?.tenantId);
    case 'checkPermission': {
      const allowed = await fortress.iam.checkPermission(body.userId, body.resource, body.action, body.context);
      return { allowed };
    }
    case 'bindPermissionToUser':
      await fortress.iam.bindPermissionToUser(body.userId, body.permission, body.tenantId);
      return { ok: true };
    case 'bindPermissionToGroup':
      await fortress.iam.bindPermissionToGroup(body.groupId, body.permission, body.tenantId);
      return { ok: true };
    case 'unbindPermissionFromUser':
      await fortress.iam.unbindPermissionFromUser(body.userId, body.permissionId, body.tenantId);
      return { ok: true };
    case 'unbindPermissionFromGroup':
      await fortress.iam.unbindPermissionFromGroup(body.groupId, body.permissionId, body.tenantId);
      return { ok: true };
    default:
      return { ok: true };
  }
}
