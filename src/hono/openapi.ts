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

function createAutoHandler(fortress: Fortress, _ep: EndpointDefinition): (c: any) => Promise<Response> {
  return async (c: any) => {
    const raw = c.req?.raw as Request | undefined;
    if (raw)
      return fortress.handleRequest(raw);

    const request = new Request(c.req.url, {
      method: c.req.method,
      headers: c.req.raw?.headers ?? undefined,
      body: ['GET', 'HEAD'].includes(c.req.method) ? undefined : await c.req.text(),
    });
    return fortress.handleRequest(request);
  };
}
