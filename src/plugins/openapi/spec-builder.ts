import type { ComponentSchemas, EndpointDefinition, SecurityRequirement } from '../../core/endpoint';
import type { JSONSchema } from '../../core/json-schema';
import { parsePathSegments } from '../../core/http/match';
import { cleanJsonSchema } from '../../core/json-schema-utils';
import { assertComponentName } from '../../core/openapi-ref';

/** Minimal OpenAPI 3.1 spec shape produced by {@link buildOpenAPISpec}. */
export interface OpenAPISpec {
  openapi: string;
  info: { title: string; version: string; description?: string };
  servers?: Array<{ url: string; description?: string }>;
  tags?: Array<{ name: string; description?: string }>;
  paths: Record<string, Record<string, OpenAPIOperation>>;
  components: {
    schemas: Record<string, JSONSchema>;
    securitySchemes: Record<string, OpenAPISecurityScheme>;
  };
}

interface OpenAPIOperation {
  operationId?: string;
  summary?: string;
  description?: string;
  tags?: string[];
  deprecated?: boolean;
  security?: Array<Record<string, string[]>>;
  parameters?: OpenAPIParameter[];
  requestBody?: {
    required?: boolean;
    content: { 'application/json': { schema: JSONSchema } };
  };
  responses: Record<string, {
    description: string;
    content?: { 'application/json': { schema: JSONSchema } };
  }>;
}

interface OpenAPIParameter {
  name: string;
  in: 'query' | 'path';
  required?: boolean;
  description?: string;
  schema: JSONSchema;
}

interface OpenAPISecurityScheme {
  type: string;
  scheme?: string;
  bearerFormat?: string;
  name?: string;
  in?: string;
}

/** Options accepted by {@link buildOpenAPISpec}. */
export interface SpecBuilderOptions {
  title: string;
  version: string;
  description?: string;
  servers?: Array<{ url: string; description?: string }>;
  /** Optional top-level OpenAPI tags. */
  tags?: Array<{ name: string; description?: string }>;
  /**
   * Operation ID strategy. Defaults to the historical Fortress method+path
   * generator. `fortress.toOpenAPI()` defaults this to `'handler'` so host
   * specs match the endpoint contract names consumers already chose.
   */
  operationId?: 'methodPath' | 'handler' | ((endpoint: EndpointDefinition) => string | undefined);
}

const SECURITY_SCHEMES: Record<string, OpenAPISecurityScheme> = {
  bearer: { type: 'http', scheme: 'bearer', bearerFormat: 'JWT' },
  basic: { type: 'http', scheme: 'basic' },
  apiKey: { type: 'apiKey', name: 'X-API-Key', in: 'header' },
};

const SECURITY_MAP: Record<SecurityRequirement, Record<string, string[]>> = {
  bearer: { bearerAuth: [] },
  basic: { basicAuth: [] },
  apiKey: { apiKeyAuth: [] },
  none: {},
};

const RE_LEADING_SLASH = /^\//;
const RE_PARAM_COLON = /\/:(\w+)/g;
const RE_SLASH = /\//g;
const RE_NON_WORD = /\W/g;

function toOperationId(method: string, path: string): string {
  // /auth/sessions/:id → auth_sessions_id, POST → post_auth_sessions_id
  const normalized = path
    .replace(RE_LEADING_SLASH, '')
    .replace(RE_PARAM_COLON, '/$1')
    .replace(RE_SLASH, '_')
    .replace(RE_NON_WORD, '_');
  return `${method.toLowerCase()}_${normalized}`;
}

/**
 * Render a route path as its OpenAPI-templated form plus the path parameters it
 * declares, parsing segments with the same rules the runtime router matches
 * with (see {@link parsePathSegments}). A `:name` segment becomes `{name}`
 * using the whole name — so `:item-id` yields the parameter `item-id`, not the
 * `item` the old `\w+` scan produced.
 *
 * Declarations OpenAPI cannot represent faithfully are rejected rather than
 * emitted as a document that disagrees with the routes actually served:
 *
 * - a literal segment containing '{' or '}', which the router matches verbatim
 *   but OpenAPI would read as a parameter template with no declared parameter;
 * - a path-parameter name repeated within one path, which is the duplicate
 *   `(name, in)` pair OpenAPI forbids.
 */
function buildOpenAPIPath(
  path: string,
  paramSchemas?: JSONSchema,
): { openAPIPath: string; params: OpenAPIParameter[] } {
  const params: OpenAPIParameter[] = [];
  const seen = new Set<string>();

  const rendered = parsePathSegments(path).map((segment) => {
    if (segment.param === undefined) {
      if (segment.raw.includes('{') || segment.raw.includes('}')) {
        throw new Error(
          `Route path '${path}' has a literal segment '${segment.raw}' containing '{' or '}'. `
          + `Declare path parameters with ':name'; brace segments are matched literally by the `
          + `router and cannot be represented as OpenAPI path parameters.`,
        );
      }
      return segment.raw;
    }

    const name = segment.param;
    if (name === '')
      throw new Error(`Route path '${path}' has an empty ':' path-parameter segment.`);
    // The whole suffix is the parameter name, so '/:a{b}' would otherwise emit
    // the invalid path '/{a{b}}'. Braces are OpenAPI path-template syntax and
    // cannot appear in a parameter name.
    if (name.includes('{') || name.includes('}')) {
      throw new Error(
        `Route path '${path}' has a path parameter ':${name}' containing '{' or '}'. `
        + `Brace characters are OpenAPI path-template syntax and cannot appear in a parameter name.`,
      );
    }
    if (seen.has(name))
      throw new Error(`Route path '${path}' declares path parameter ':${name}' more than once.`);
    seen.add(name);

    const schema = paramSchemas?.properties?.[name] ?? { type: 'string' as const };
    params.push({
      name,
      in: 'path',
      required: true,
      description: schema.description,
      schema: { type: schema.type ?? 'string' },
    });
    return `{${name}}`;
  });

  return { openAPIPath: `/${rendered.join('/')}`, params };
}

function extractQueryParams(querySchema?: JSONSchema): OpenAPIParameter[] {
  if (!querySchema?.properties)
    return [];

  const params: OpenAPIParameter[] = [];
  const required = new Set(querySchema.required ?? []);

  for (const [name, schema] of Object.entries(querySchema.properties)) {
    params.push({
      name,
      in: 'query',
      required: required.has(name),
      description: schema.description,
      schema,
    });
  }

  return params;
}

function resolveOperationId(endpoint: EndpointDefinition, options: SpecBuilderOptions): string | undefined {
  if (typeof options.operationId === 'function')
    return options.operationId(endpoint);
  if (options.operationId === 'handler')
    return endpoint.handler;
  return toOperationId(endpoint.method, endpoint.path);
}

/** Walk every endpoint definition and component-schemas record and emit a complete OpenAPI 3.1 {@link OpenAPISpec}. */
export function buildOpenAPISpec(
  endpoints: EndpointDefinition[],
  componentSchemas: ComponentSchemas,
  options: SpecBuilderOptions,
): OpenAPISpec {
  // Backstop for every caller that supplies its own component schemas —
  // `toOpenAPI({ schemas })`, the OpenAPI plugin's `additionalSchemas`, and the
  // CLI's `--module componentSchemas`. An illegal key produces a document no
  // conformant tool can resolve.
  for (const name of Object.keys(componentSchemas))
    assertComponentName(name);

  // `paths` is keyed by caller-supplied route paths; a null prototype keeps a
  // pathological name from reaching Object.prototype.
  const paths: Record<string, Record<string, OpenAPIOperation>> = Object.create(null);
  const usedSecuritySchemes = new Set<string>();

  for (const ep of endpoints) {
    const { openAPIPath, params: pathParams } = buildOpenAPIPath(
      ep.path,
      ep.input?.params && cleanJsonSchema(ep.input.params),
    );
    const method = ep.method.toLowerCase();

    if (!paths[openAPIPath]) {
      paths[openAPIPath] = Object.create(null) as Record<string, OpenAPIOperation>;
    }
    // Path-parameter names do not affect routing, so two endpoints that differ
    // only in a parameter name share one route shape, which route assembly
    // rejects before the spec is built. This stays as a backstop so a route
    // that survived assembly can never silently vanish between manifest and spec.
    if (paths[openAPIPath][method]) {
      throw new Error(
        `Two endpoints map to the same OpenAPI operation ${ep.method.toUpperCase()} ${openAPIPath}: `
        + `'${paths[openAPIPath][method].operationId ?? 'unnamed'}' and '${ep.handler}'.`,
      );
    }

    const operation: OpenAPIOperation = {
      operationId: resolveOperationId(ep, options),
      responses: {},
    };

    // Meta
    if (ep.meta) {
      if (ep.meta.summary)
        operation.summary = ep.meta.summary;
      if (ep.meta.description)
        operation.description = ep.meta.description;
      if (ep.meta.tags)
        operation.tags = ep.meta.tags;
      if (ep.meta.deprecated)
        operation.deprecated = true;

      // Security
      if (ep.meta.security) {
        const secArr: Array<Record<string, string[]>> = [];
        for (const s of ep.meta.security) {
          if (s === 'none') {
            secArr.push({});
          }
          else {
            secArr.push(SECURITY_MAP[s]);
            usedSecuritySchemes.add(s);
          }
        }
        operation.security = secArr;
      }
    }

    // Parameters
    const params: OpenAPIParameter[] = [
      ...pathParams,
      ...extractQueryParams(ep.input?.query && cleanJsonSchema(ep.input.query)),
    ];
    if (params.length > 0) {
      operation.parameters = params;
    }

    // Request body
    if (ep.input?.body) {
      operation.requestBody = {
        required: true,
        content: { 'application/json': { schema: cleanJsonSchema(ep.input.body) } },
      };
    }

    // Responses
    if (ep.responses) {
      for (const [status, resp] of Object.entries(ep.responses)) {
        const entry: { description: string; content?: { 'application/json': { schema: JSONSchema } } } = {
          description: resp.description,
        };
        if (resp.schema) {
          entry.content = { 'application/json': { schema: cleanJsonSchema(resp.schema) } };
        }
        operation.responses[status] = entry;
      }
    }
    else {
      operation.responses['200'] = { description: 'Success' };
    }

    paths[openAPIPath][method] = operation;
  }

  // Build security schemes (only include those actually used)
  const securitySchemes: Record<string, OpenAPISecurityScheme> = {};
  const schemeNameMap: Record<string, string> = { bearer: 'bearerAuth', basic: 'basicAuth', apiKey: 'apiKeyAuth' };
  for (const scheme of usedSecuritySchemes) {
    const name = schemeNameMap[scheme];
    if (name && SECURITY_SCHEMES[scheme]) {
      securitySchemes[name] = SECURITY_SCHEMES[scheme];
    }
  }

  const spec: OpenAPISpec = {
    openapi: '3.1.0',
    info: {
      title: options.title,
      version: options.version,
      ...(options.description && { description: options.description }),
    },
    paths,
    components: {
      // Clean each schema node, not the component-name map. Map keys are data.
      schemas: Object.fromEntries(
        Object.entries(componentSchemas).map(([name, schema]) => [name, cleanJsonSchema(schema)]),
      ),
      securitySchemes,
    },
  };

  if (options.servers && options.servers.length > 0) {
    spec.servers = options.servers;
  }
  if (options.tags && options.tags.length > 0) {
    spec.tags = options.tags;
  }

  return spec;
}
