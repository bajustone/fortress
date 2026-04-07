import type { Hono } from 'hono';
import type { Fortress } from '../core/fortress';
import type { FortressPlugin } from '../core/plugin';
import type { ClientAuth, TokenRequestBody } from '../plugins/oauth';
import type { FortressEnv } from './middleware/auth';
import { FortressError } from '../core/errors';

/**
 * Mount plugin-defined HTTP routes onto a Hono app.
 *
 * Reads `routes[]` from each registered plugin and creates Hono handlers
 * that parse requests, call the corresponding plugin method, and return JSON.
 *
 * OAuth routes follow RFC 6749 conventions:
 * - POST endpoints parse `application/x-www-form-urlencoded` bodies
 * - Client authentication via Basic auth or body params
 */
export function mountPluginRoutes(
  app: Hono<FortressEnv>,
  fortress: Fortress<any>,
  options?: { prefix?: string },
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
      const fullPath = `${prefix}${route.path}`;
      const handler = methods[route.handler];

      if (!handler)
        continue;

      const honoHandler = createRouteHandler(plugin, route.handler, handler, methods);

      switch (route.method) {
        case 'GET':
          app.get(fullPath, honoHandler);
          break;
        case 'POST':
          app.post(fullPath, honoHandler);
          break;
        case 'PUT':
          app.put(fullPath, honoHandler);
          break;
        case 'DELETE':
          app.delete(fullPath, honoHandler);
          break;
        case 'PATCH':
          app.patch(fullPath, honoHandler);
          break;
      }
    }
  }
}

/** Parse Basic auth from Authorization header */
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

/** Parse Bearer token from Authorization header */
function parseBearerToken(header: string | undefined): string | undefined {
  if (!header?.startsWith('Bearer '))
    return undefined;
  return header.slice(7);
}

/** Parse x-www-form-urlencoded body into a plain object */
async function parseFormBody(request: Request): Promise<Record<string, string>> {
  const text = await request.text();
  const params = new URLSearchParams(text);
  const result: Record<string, string> = {};
  for (const [key, value] of params) {
    result[key] = value;
  }
  return result;
}

function createRouteHandler(
  plugin: FortressPlugin,
  handlerName: string,
  _handler: (...args: any[]) => any,
  methods: Record<string, (...args: any[]) => any>,
) {
  return async (c: any): Promise<Response> => {
    try {
      // OAuth-specific request parsing
      if (plugin.name === 'oauth') {
        return await handleOAuthRoute(c, handlerName, methods);
      }

      // Generic plugin route: pass parsed body + path params to handler
      const body = c.req.method === 'GET'
        ? Object.fromEntries(new URL(c.req.url).searchParams)
        : await c.req.json().catch(() => ({}));

      const params = c.req.param();
      const result = await methods[handlerName]({ ...body, ...params });
      if (typeof result === 'string' && result.trimStart().startsWith('<!')) {
        return c.html(result);
      }
      return c.json(result ?? { ok: true });
    }
    catch (error) {
      if (error instanceof FortressError) {
        return c.json(
          { error: error.code, error_description: error.message },
          error.statusCode,
        );
      }
      throw error;
    }
  };
}

async function handleOAuthRoute(
  c: any,
  handlerName: string,
  methods: Record<string, (...args: any[]) => any>,
): Promise<Response> {
  const authHeader = c.req.header('authorization');

  switch (handlerName) {
    case 'handleTokenRequest': {
      const body = await parseFormBody(c.req.raw) as unknown as TokenRequestBody;
      const clientAuth = parseBasicAuth(authHeader);
      const result = await methods.handleTokenRequest(body, clientAuth);
      return c.json(result);
    }

    case 'handleIntrospectRequest': {
      const body = await parseFormBody(c.req.raw);
      const clientAuth = parseBasicAuth(authHeader);
      if (!clientAuth) {
        return c.json({ error: 'invalid_client', error_description: 'Client authentication required' }, 401);
      }
      const result = await methods.handleIntrospectRequest({ token: body.token }, clientAuth);
      return c.json(result);
    }

    case 'handleRevokeRequest': {
      const body = await parseFormBody(c.req.raw);
      await methods.handleRevokeRequest({ token: body.token });
      return c.json({}, 200);
    }

    case 'handleUserInfoRequest': {
      const bearer = parseBearerToken(authHeader);
      if (!bearer) {
        return c.json({ error: 'invalid_token', error_description: 'Bearer token required' }, 401);
      }
      const user = await methods.handleUserInfoRequest(bearer);
      if (!user) {
        return c.json({ error: 'invalid_token', error_description: 'Token invalid or expired' }, 401);
      }
      return c.json({ sub: String(user.id), email: user.email, name: user.name });
    }

    case 'handleDiscovery': {
      const result = methods.handleDiscovery();
      return c.json(result);
    }

    default: {
      const body = await c.req.json();
      const result = await methods[handlerName](body);
      return c.json(result ?? { ok: true });
    }
  }
}
