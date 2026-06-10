import type { ComponentSchemas, EndpointDefinition, SecurityRequirement } from '../../core/endpoint';
import type { JSONSchema } from '../../core/json-schema';

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

function extractPathParams(path: string, paramSchemas?: JSONSchema): OpenAPIParameter[] {
  const params: OpenAPIParameter[] = [];
  const matches = path.matchAll(/:(\w+)/g);

  for (const match of matches) {
    const name = match[1];
    const schema = paramSchemas?.properties?.[name] ?? { type: 'string' as const };
    params.push({
      name,
      in: 'path',
      required: true,
      description: schema.description,
      schema: { type: schema.type ?? 'string' },
    });
  }

  return params;
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

function toOpenAPIPath(path: string): string {
  return path.replace(/:(\w+)/g, '{$1}');
}

/**
 * Deep-clean Standard Schema / runtime-only fields from schema objects before
 * embedding them in OpenAPI. Fortress schemas are JSON Schema objects with a
 * `~standard` validator attached; external schema adapters can also hang
 * functions or undefined values off the object. OpenAPI must receive pure
 * JSON-serializable JSON Schema, so strip any key beginning with `~`, any
 * function value, and any `undefined` value recursively.
 */
function cleanSchema<T>(value: T): T {
  if (Array.isArray(value))
    return value.map(cleanSchema) as T;

  if (typeof value === 'object' && value !== null) {
    return Object.fromEntries(
      Object.entries(value as Record<string, unknown>)
        .filter(([key]) => !key.startsWith('~'))
        .filter(([, entry]) => typeof entry !== 'function' && entry !== undefined)
        .map(([key, entry]) => [key, cleanSchema(entry)]),
    ) as T;
  }

  return value;
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
  const paths: Record<string, Record<string, OpenAPIOperation>> = {};
  const usedSecuritySchemes = new Set<string>();

  for (const ep of endpoints) {
    const openAPIPath = toOpenAPIPath(ep.path);
    const method = ep.method.toLowerCase();

    if (!paths[openAPIPath]) {
      paths[openAPIPath] = {};
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
      ...extractPathParams(ep.path, cleanSchema(ep.input?.params)),
      ...extractQueryParams(cleanSchema(ep.input?.query)),
    ];
    if (params.length > 0) {
      operation.parameters = params;
    }

    // Request body
    if (ep.input?.body) {
      operation.requestBody = {
        required: true,
        content: { 'application/json': { schema: cleanSchema(ep.input.body) } },
      };
    }

    // Responses
    if (ep.responses) {
      for (const [status, resp] of Object.entries(ep.responses)) {
        const entry: { description: string; content?: { 'application/json': { schema: JSONSchema } } } = {
          description: resp.description,
        };
        if (resp.schema) {
          entry.content = { 'application/json': { schema: cleanSchema(resp.schema) } };
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
      schemas: cleanSchema(componentSchemas),
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
