import type { JSONSchema } from '../core/json-schema';
import type { ExternalRoute } from './convert-routes';
import { describe, expect, it } from 'vitest';
import { convertRoutes } from './convert-routes';

/** Passthrough converter — returns whatever it receives as JSONSchema. */
const identity = (schema: unknown): JSONSchema => schema as JSONSchema;

function requireExactlyOne<T>(values: readonly T[], description: string): T {
  if (values.length !== 1)
    throw new Error(`Expected exactly one ${description}, received ${values.length}`);
  const value = values[0];
  if (value === undefined)
    throw new Error(`Expected exactly one ${description}, received no value`);
  return value;
}

function requireAt<T>(values: readonly T[], index: number, description: string): T {
  const value = values[index];
  if (value === undefined)
    throw new Error(`Expected ${description} at index ${index}, received ${values.length} routes`);
  return value;
}

/** Tracking converter — records calls and returns the input. */
function trackingConverter(): { converter: (s: unknown) => JSONSchema; calls: unknown[] } {
  const calls: unknown[] = [];
  return {
    converter: (s: unknown) => {
      calls.push(s);
      return s as JSONSchema;
    },
    calls,
  };
}

const GET_HEALTH: ExternalRoute = {
  method: 'get',
  path: '/health',
  tags: ['Health'],
  summary: 'Health check',
  responses: {
    200: {
      description: 'OK',
      content: { 'application/json': { schema: { type: 'object', properties: { status: { type: 'string' } } } } },
    },
  },
};

const POST_LOGIN: ExternalRoute = {
  method: 'post',
  path: '/login',
  tags: ['Auth'],
  summary: 'Login',
  security: [{ Bearer: [] }],
  request: {
    body: {
      content: {
        'application/json': {
          schema: { type: 'object', properties: { email: { type: 'string' }, password: { type: 'string' } } },
        },
      },
    },
  },
  responses: {
    200: { description: 'Login successful', content: { 'application/json': { schema: { type: 'object' } } } },
    401: { description: 'Invalid credentials' },
  },
};

const GET_USER: ExternalRoute = {
  method: 'get',
  path: '/users/{id}',
  tags: ['Users'],
  summary: 'Get user by ID',
  security: [{ Bearer: [] }],
  request: {
    params: { type: 'object', properties: { id: { type: 'integer' } }, required: ['id'] },
  },
  responses: {
    200: { description: 'User found', content: { 'application/json': { schema: { type: 'object' } } } },
  },
};

const LIST_ITEMS: ExternalRoute = {
  method: 'get',
  path: '/items',
  summary: 'List items',
  request: {
    query: { type: 'object', properties: { page: { type: 'integer' }, limit: { type: 'integer' } } },
  },
  responses: {
    200: { description: 'Items list' },
  },
};

describe('convertRoutes', () => {
  it('converts a simple GET route', () => {
    const ep = requireExactlyOne(convertRoutes([GET_HEALTH], { schemaConverter: identity }), 'converted health route');

    expect(ep.method).toBe('GET');
    expect(ep.path).toBe('/health');
    expect(ep.handler).toBe('get_health');
    expect(ep.meta?.tags).toEqual(['Health']);
    expect(ep.meta?.summary).toBe('Health check');
    expect(ep.responses?.[200]?.description).toBe('OK');
    expect(ep.responses?.[200]?.schema).toEqual({ type: 'object', properties: { status: { type: 'string' } } });
    expect(ep.input).toBeUndefined();
  });

  it('converts a POST route with body and security', () => {
    const ep = requireExactlyOne(convertRoutes([POST_LOGIN], { schemaConverter: identity }), 'converted login route');

    expect(ep.method).toBe('POST');
    expect(ep.path).toBe('/login');
    expect(ep.meta?.security).toEqual(['bearer']);
    expect(ep.input?.body).toEqual({
      type: 'object',
      properties: { email: { type: 'string' }, password: { type: 'string' } },
    });
    expect(ep.responses?.[200]?.description).toBe('Login successful');
    expect(ep.responses?.[401]?.description).toBe('Invalid credentials');
    expect(ep.responses?.[401]?.schema).toBeUndefined();
  });

  it('converts {param} to :param in paths', () => {
    const ep = requireExactlyOne(convertRoutes([GET_USER], { schemaConverter: identity }), 'converted user route');

    expect(ep.path).toBe('/users/:id');
    expect(ep.input?.params).toEqual({
      type: 'object',
      properties: { id: { type: 'integer' } },
      required: ['id'],
    });
  });

  it('converts query parameters', () => {
    const ep = requireExactlyOne(convertRoutes([LIST_ITEMS], { schemaConverter: identity }), 'converted items route');

    expect(ep.input?.query).toEqual({
      type: 'object',
      properties: { page: { type: 'integer' }, limit: { type: 'integer' } },
    });
  });

  it('applies prefix to paths', () => {
    const endpoints = convertRoutes([GET_HEALTH, GET_USER], {
      schemaConverter: identity,
      prefix: '/api/v1',
    });

    const healthEndpoint = requireAt(endpoints, 0, 'prefixed health route');
    const userEndpoint = requireAt(endpoints, 1, 'prefixed user route');
    expect(healthEndpoint.path).toBe('/api/v1/health');
    expect(healthEndpoint.handler).toBe('get_api_v1_health');
    expect(userEndpoint.path).toBe('/api/v1/users/:id');
  });

  it('strips trailing slash from prefix', () => {
    const ep = requireExactlyOne(convertRoutes([GET_HEALTH], {
      schemaConverter: identity,
      prefix: '/api/v1/',
    }), 'converted prefixed health route');

    expect(ep.path).toBe('/api/v1/health');
  });

  it('calls schemaConverter for every schema', () => {
    const { converter, calls } = trackingConverter();

    convertRoutes([POST_LOGIN], { schemaConverter: converter });

    // body schema + 200 response schema (401 has no schema)
    expect(calls).toHaveLength(2);
  });

  it('calls schemaConverter for params and query', () => {
    const route: ExternalRoute = {
      method: 'get',
      path: '/items/{id}',
      request: {
        params: { type: 'object', properties: { id: { type: 'string' } } },
        query: { type: 'object', properties: { expand: { type: 'boolean' } } },
      },
      responses: { 200: { description: 'OK' } },
    };

    const { converter, calls } = trackingConverter();
    convertRoutes([route], { schemaConverter: converter });

    // params + query (no body, no response schema)
    expect(calls).toHaveLength(2);
  });

  it('maps security schemes correctly', () => {
    const routes: ExternalRoute[] = [
      { ...GET_HEALTH, security: [{ Bearer: [] }] },
      { ...GET_HEALTH, path: '/basic', security: [{ BasicAuth: [] }] },
      { ...GET_HEALTH, path: '/apikey', security: [{ ApiKeyAuth: [] }] },
      { ...GET_HEALTH, path: '/public', security: [{}] },
    ];

    const endpoints = convertRoutes(routes, { schemaConverter: identity });

    expect(requireAt(endpoints, 0, 'bearer security route').meta?.security).toEqual(['bearer']);
    expect(requireAt(endpoints, 1, 'basic security route').meta?.security).toEqual(['basic']);
    expect(requireAt(endpoints, 2, 'API key security route').meta?.security).toEqual(['apiKey']);
    expect(requireAt(endpoints, 3, 'public security route').meta?.security).toEqual(['none']);
  });

  it('handles deprecated routes', () => {
    const route: ExternalRoute = { ...GET_HEALTH, deprecated: true };
    const ep = requireExactlyOne(convertRoutes([route], { schemaConverter: identity }), 'converted deprecated route');

    expect(ep.meta?.deprecated).toBe(true);
  });

  it('converts multiple routes at once', () => {
    const endpoints = convertRoutes(
      [GET_HEALTH, POST_LOGIN, GET_USER, LIST_ITEMS],
      { schemaConverter: identity },
    );

    expect(endpoints).toHaveLength(4);
    expect(endpoints.map(e => e.method)).toEqual(['GET', 'POST', 'GET', 'GET']);
  });

  it('skips invalid HTTP methods', () => {
    const route: ExternalRoute = { ...GET_HEALTH, method: 'OPTIONS' };
    const endpoints = convertRoutes([route], { schemaConverter: identity });

    expect(endpoints).toHaveLength(0);
  });

  it('returns empty array for empty input', () => {
    expect(convertRoutes([], { schemaConverter: identity })).toEqual([]);
  });
});
