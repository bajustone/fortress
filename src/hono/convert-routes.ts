/**
 * Convert external route definitions (e.g., from @hono/zod-openapi createRoute)
 * into Fortress EndpointDefinitions.
 *
 * Schema-library agnostic — the user provides a converter function
 * that turns their schema objects into JSON Schema.
 *
 * @example
 * ```ts
 * import { z } from 'zod';
 * import { convertRoutes } from '@bajustone/fortress/hono';
 * import { loginRoute, listUsersRoute } from './modules/auth/routes';
 *
 * const endpoints = convertRoutes(
 *   [loginRoute, listUsersRoute],
 *   { prefix: '/api/v1/auth', schemaConverter: z.toJSONSchema },
 * );
 * ```
 */

import type { EndpointDefinition, EndpointInput, EndpointResponse, HttpMethod, SecurityRequirement } from '../core/endpoint';
import type { JSONSchema } from '../core/json-schema';

const TRAILING_SLASH_REGEX = /\/$/;

/** A function that converts a schema object (Zod, Valibot, etc.) to JSON Schema. */
export type ToJSONSchemaConverter = (schema: unknown) => JSONSchema;

/**
 * Generic route shape matching what `createRoute` from `@hono/zod-openapi` returns.
 * No dependency on any specific framework or schema library.
 */
export interface ExternalRoute {
  method: string;
  path: string;
  tags?: string[];
  summary?: string;
  description?: string;
  deprecated?: boolean;
  security?: Array<Record<string, string[]>>;
  request?: {
    body?: { content: { 'application/json': { schema: unknown } } };
    params?: unknown;
    query?: unknown;
  };
  responses: Record<number | string, {
    description: string;
    content?: { 'application/json': { schema: unknown } };
  }>;
}

export interface ConvertRoutesOptions {
  /** Convert your schema objects to JSON Schema (e.g., `z.toJSONSchema` for Zod v4). */
  schemaConverter: ToJSONSchemaConverter;
  /** Path prefix to prepend (e.g., '/api/v1/auth'). */
  prefix?: string;
}

const RE_LEADING_SLASH = /^\//;
const RE_PARAM_BRACE = /\{(\w+)\}/g;
const RE_SLASH = /\//g;
const RE_NON_WORD = /\W/g;

/** Convert OpenAPI `{param}` path to Express-style `:param`. */
function fromOpenAPIPath(path: string): string {
  return path.replace(RE_PARAM_BRACE, ':$1');
}

/** Generate a handler/operationId from method + path. */
function toOperationId(method: string, path: string): string {
  const normalized = path
    .replace(RE_LEADING_SLASH, '')
    .replace(RE_PARAM_BRACE, '$1')
    .replace(RE_SLASH, '_')
    .replace(RE_NON_WORD, '_');
  return `${method.toLowerCase()}_${normalized}`;
}

const VALID_METHODS = new Set<HttpMethod>(['GET', 'POST', 'PUT', 'DELETE', 'PATCH']);

/** Reverse map from security scheme names to SecurityRequirement. */
const SECURITY_REVERSE: Record<string, SecurityRequirement> = {
  bearer: 'bearer',
  bearerauth: 'bearer',
  basic: 'basic',
  basicauth: 'basic',
  apikey: 'apiKey',
  apikeyauth: 'apiKey',
};

function mapSecurity(security: Array<Record<string, string[]>>): SecurityRequirement[] {
  const result: SecurityRequirement[] = [];
  for (const entry of security) {
    const keys = Object.keys(entry);
    if (keys.length === 0) {
      result.push('none');
      continue;
    }
    for (const key of keys) {
      const mapped = SECURITY_REVERSE[key.toLowerCase()];
      if (mapped && !result.includes(mapped)) {
        result.push(mapped);
      }
    }
  }
  return result;
}

/**
 * Convert an array of external route definitions into Fortress EndpointDefinitions.
 *
 * The `schemaConverter` is called for every schema object encountered in request/response
 * definitions. Fortress never imports or depends on your schema library.
 */
export function convertRoutes(
  routes: ExternalRoute[],
  options: ConvertRoutesOptions,
): EndpointDefinition[] {
  const { schemaConverter, prefix } = options;
  const result: EndpointDefinition[] = [];

  for (const route of routes) {
    const method = route.method.toUpperCase() as HttpMethod;
    if (!VALID_METHODS.has(method))
      continue;

    const rawPath = prefix ? `${prefix.replace(TRAILING_SLASH_REGEX, '')}${route.path}` : route.path;
    const path = fromOpenAPIPath(rawPath);
    const handler = toOperationId(method, rawPath);

    // Meta
    const meta: EndpointDefinition['meta'] = {
      summary: route.summary ?? '',
    };
    if (route.tags)
      meta.tags = route.tags;
    if (route.description)
      meta.description = route.description;
    if (route.deprecated)
      meta.deprecated = true;
    if (route.security) {
      const mapped = mapSecurity(route.security);
      if (mapped.length > 0)
        meta.security = mapped;
    }

    // Input
    const input: EndpointInput = {};
    let hasInput = false;

    if (route.request?.body?.content?.['application/json']?.schema) {
      input.body = schemaConverter(route.request.body.content['application/json'].schema);
      hasInput = true;
    }

    if (route.request?.params) {
      input.params = schemaConverter(route.request.params);
      hasInput = true;
    }

    if (route.request?.query) {
      input.query = schemaConverter(route.request.query);
      hasInput = true;
    }

    // Responses
    const responses: Record<number, EndpointResponse> = {};
    let hasResponses = false;

    for (const [status, resp] of Object.entries(route.responses)) {
      const entry: EndpointResponse = { description: resp.description };
      if (resp.content?.['application/json']?.schema) {
        entry.schema = schemaConverter(resp.content['application/json'].schema);
      }
      responses[Number(status)] = entry;
      hasResponses = true;
    }

    const endpoint: EndpointDefinition = {
      method,
      path,
      handler,
      meta,
    };

    if (hasInput)
      endpoint.input = input;
    if (hasResponses)
      endpoint.responses = responses;

    result.push(endpoint);
  }

  return result;
}
