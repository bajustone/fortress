/**
 * Hono OpenAPI adapter for Fortress.
 *
 * Schema-library agnostic — accepts a converter function from the user.
 * Users pass their own JSON Schema → schema-library converter (Zod, Valibot, etc.).
 *
 * Users pass their schema library's JSON Schema converter:
 *   - Zod v4: `z.fromJSONSchema`
 *   - TypeBox: schemas are JSON Schema natively
 *   - ArkType: `@ark/jsonschema`
 */

import type { EndpointDefinition } from '../core/endpoint';
import type { Fortress } from '../core/fortress';
import type { JSONSchema } from '../core/json-schema';
import { FortressError } from '../core/errors';

/**
 * A function that converts a JSON Schema to whatever schema type your
 * framework adapter expects (e.g. Zod schema, Valibot schema). Used by
 * {@link buildRouteDefinition} so fortress's OpenAPI generator stays
 * schema-library agnostic.
 */
export type SchemaConverter<T = unknown> = (jsonSchema: JSONSchema) => T;

interface MountOptions<T = unknown> {
  /** Convert JSON Schema → your schema library (e.g., jsonSchemaToZod from '@bajustone/fortress/zod') */
  schemaConverter: SchemaConverter<T>;
  /** Paths to skip (won't be mounted) */
  skipPaths?: string[];
  /** Function to create a route definition from an endpoint (framework-specific) */
  createRoute: (def: Record<string, unknown>) => unknown;
  /** Function to register security schemes on the app */
  registerSecuritySchemes?: (app: unknown) => void;
}

interface GenericOpenAPIApp {
  openapi: (route: unknown, handler: (...args: any[]) => any) => void;
}

function toOpenAPIPath(path: string): string {
  return path.replace(/:(\w+)/g, '{$1}');
}

/**
 * Build a framework-agnostic route definition object from an EndpointDefinition.
 * The schemaConverter transforms JSON Schema into whatever the target framework expects.
 */
export function buildRouteDefinition<T>(
  ep: EndpointDefinition,
  schemaConverter: SchemaConverter<T>,
): Record<string, unknown> {
  const openAPIPath = toOpenAPIPath(ep.path);
  const method = ep.method.toLowerCase() as 'get' | 'post' | 'put' | 'delete' | 'patch';

  const routeDef: Record<string, unknown> = {
    method,
    path: openAPIPath,
    operationId: ep.handler,
    responses: {} as Record<number, { description: string; content?: Record<string, unknown> }>,
  };

  if (ep.meta?.summary)
    routeDef.summary = ep.meta.summary;
  if (ep.meta?.description)
    routeDef.description = ep.meta.description;
  if (ep.meta?.tags)
    routeDef.tags = ep.meta.tags;
  if (ep.meta?.deprecated)
    routeDef.deprecated = true;

  // Security
  if (ep.meta?.security) {
    const sec: Array<Record<string, string[]>> = [];
    for (const s of ep.meta.security) {
      if (s === 'none')
        sec.push({});
      else if (s === 'bearer')
        sec.push({ bearerAuth: [] });
      else if (s === 'basic')
        sec.push({ basicAuth: [] });
      else if (s === 'apiKey')
        sec.push({ apiKeyAuth: [] });
    }
    routeDef.security = sec;
  }

  // Request
  const request: Record<string, unknown> = {};

  if (ep.input?.body) {
    request.body = {
      content: {
        'application/json': { schema: schemaConverter(ep.input.body) },
      },
    };
  }

  if (ep.input?.params?.properties) {
    const shape: Record<string, unknown> = {};
    const required = new Set(ep.input.params.required ?? []);

    for (const [key, schema] of Object.entries(ep.input.params.properties)) {
      const converted = schemaConverter({ ...schema, type: schema.type ?? 'string' });
      shape[key] = required.has(key) ? converted : converted;
    }
    // Wrap params in an object schema
    request.params = schemaConverter({
      type: 'object',
      properties: ep.input.params.properties,
      required: ep.input.params.required,
    });
  }

  if (ep.input?.query?.properties) {
    request.query = schemaConverter(ep.input.query);
  }

  if (Object.keys(request).length > 0) {
    routeDef.request = request;
  }

  // Responses
  const responses: Record<number, { description: string; content?: Record<string, unknown> }> = {};
  if (ep.responses) {
    for (const [status, resp] of Object.entries(ep.responses)) {
      const entry: { description: string; content?: Record<string, unknown> } = {
        description: resp.description,
      };
      if (resp.schema) {
        entry.content = {
          'application/json': { schema: schemaConverter(resp.schema) },
        };
      }
      responses[Number(status)] = entry;
    }
  }
  else {
    responses[200] = { description: 'Success' };
  }
  routeDef.responses = responses;

  return routeDef;
}

/**
 * Auto-mount all Fortress endpoints on an OpenAPI-compatible Hono app.
 *
 * Schema-library agnostic: you provide the converter.
 *
 * @example
 * ```ts
 * import { OpenAPIHono, createRoute } from '@hono/zod-openapi';
 * import { mountFortressOpenAPI } from '@bajustone/fortress/hono';
 * import { jsonSchemaToZod } from '@bajustone/fortress/zod';
 *
 * const app = new OpenAPIHono();
 * mountFortressOpenAPI(app, fortress, {
 *   schemaConverter: jsonSchemaToZod,
 *   createRoute,
 * });
 * ```
 */
export function mountFortressOpenAPI<T>(
  app: GenericOpenAPIApp & { openAPIRegistry?: { registerComponent: (type: string, name: string, schema: Record<string, unknown>) => void } },
  fortress: Fortress,
  options: MountOptions<T>,
): void {
  const skipPaths = new Set(options.skipPaths ?? []);

  // Register security schemes if the app supports it
  if (app.openAPIRegistry) {
    app.openAPIRegistry.registerComponent('securitySchemes', 'bearerAuth', {
      type: 'http',
      scheme: 'bearer',
      bearerFormat: 'JWT',
    });
    app.openAPIRegistry.registerComponent('securitySchemes', 'basicAuth', {
      type: 'http',
      scheme: 'basic',
    });
    app.openAPIRegistry.registerComponent('securitySchemes', 'apiKeyAuth', {
      type: 'apiKey',
      name: 'X-API-Key',
      in: 'header',
    });
  }

  // Custom security scheme registration
  options.registerSecuritySchemes?.(app);

  for (const ep of fortress.endpoints) {
    if (skipPaths.has(ep.path))
      continue;

    const routeDef = buildRouteDefinition(ep, options.schemaConverter);
    const route = options.createRoute(routeDef);
    const handler = createAutoHandler(fortress, ep);

    app.openapi(route, handler);
  }
}

/**
 * Get all Fortress endpoint definitions as framework route definitions.
 * Returns a map of `{ [handlerName]: routeDef }`.
 */
export function getFortressRoutes<T>(
  fortress: Fortress,
  schemaConverter: SchemaConverter<T>,
  createRoute: (def: Record<string, unknown>) => unknown,
): Record<string, unknown> {
  const result: Record<string, unknown> = {};

  for (const ep of fortress.endpoints) {
    const routeDef = buildRouteDefinition(ep, schemaConverter);
    result[ep.handler] = createRoute(routeDef);
  }

  return result;
}

// ── Auto-handler wiring ──────���──────────────────────────────────────

function createAutoHandler(fortress: Fortress, ep: EndpointDefinition): (c: any) => Promise<Response> {
  return async (c: any) => {
    try {
      const result = await invokeHandler(fortress, ep, c);
      const statusCodes = ep.responses ? Object.keys(ep.responses).map(Number) : [200];
      const successCode = statusCodes.find(s => s >= 200 && s < 300) ?? 200;
      return c.json(result ?? { ok: true }, successCode);
    }
    catch (error) {
      if (error instanceof FortressError) {
        return c.json(
          { code: error.code, message: error.message, statusCode: error.statusCode },
          error.statusCode,
        );
      }
      throw error;
    }
  };
}

async function invokeHandler(fortress: Fortress, ep: EndpointDefinition, c: any): Promise<unknown> {
  const body = ['POST', 'PUT', 'PATCH'].includes(ep.method)
    ? await c.req.json().catch(() => ({}))
    : Object.fromEntries(new URL(c.req.url).searchParams);

  const params = c.req.param?.() ?? {};
  const userId = c.get?.('fortressUserId') as number | undefined;

  if (ep.path.startsWith('/auth/')) {
    return invokeAuthHandler(fortress, ep.handler, body, params, userId, c);
  }

  // Check plugin routes first (plugins can register routes under /iam/ etc.)
  const plugins = fortress.config.plugins ?? [];
  for (const plugin of plugins) {
    if (!plugin.routes)
      continue;
    const match = (Object.values(plugin.routes) as EndpointDefinition[]).find(r => r.path === ep.path && r.method === ep.method);
    if (match) {
      const methods = (fortress.plugins as Record<string, Record<string, (...args: any[]) => any>>)[plugin.name];
      if (methods?.[ep.handler]) {
        return methods[ep.handler]({ ...body, ...params });
      }
    }
  }

  // Core IAM handlers
  if (ep.path.startsWith('/iam/')) {
    return invokeIamHandler(fortress, ep.handler, body, params);
  }

  return { ok: true };
}

async function invokeAuthHandler(
  fortress: Fortress,
  handler: string,
  body: any,
  params: Record<string, string>,
  userId: number | undefined,
  c: any,
): Promise<unknown> {
  const meta = {
    ipAddress: c.req.header?.('x-forwarded-for') ?? c.req.header?.('x-real-ip'),
    userAgent: c.req.header?.('user-agent'),
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
    case 'getResources':
      return fortress.iam.getResources();
    case 'getRoles':
      return fortress.iam.getRoles();
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
      return fortress.iam.getPermissionsForSubject({ type: 'USER', id: Number(params.id) }, body?.tenantId);
    case 'checkPermission': {
      const allowed = await fortress.iam.checkPermission({ type: 'USER', id: body.userId }, body.resource, body.action, body.context);
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
