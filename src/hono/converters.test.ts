import type { EndpointDefinition } from '../core/endpoint';
import { describe, expect, it } from 'vitest';
import { obj, str } from '../core/schema-builder';
import { convertRoutes } from './convert-routes';
import { fetcherSchemaConverter, identitySchemaConverter, toJSONSchemaConverter } from './converters';
import { buildRouteDefinition } from './openapi';

describe('hono OpenAPI converters (Zod-free defaults)', () => {
  it('identitySchemaConverter passes JSON Schema through unchanged', () => {
    const js = { type: 'object' as const, properties: { a: { type: 'string' as const } } };
    expect(identitySchemaConverter(js)).toBe(js);
  });

  it('fetcherSchemaConverter compiles JSON Schema into a validating Standard Schema', () => {
    const schema = fetcherSchemaConverter({ type: 'object', properties: { a: { type: 'string' } }, required: ['a'] });
    expect(typeof schema['~standard'].validate).toBe('function');
    expect(schema['~standard'].validate({ a: 'x' })).toEqual({ value: { a: 'x' } });
    const bad = schema['~standard'].validate({}) as { issues?: unknown };
    expect(bad.issues).toBeTruthy(); // missing required `a`
  });

  it('toJSONSchemaConverter extracts JSON Schema from a fortress/fetcher builder schema', () => {
    const js = toJSONSchemaConverter(obj({ a: str() }, 'a'));
    expect(js.type).toBe('object');
    expect(js.properties?.a?.type).toBe('string');
  });

  it('mounting works with identitySchemaConverter (no Zod)', () => {
    const ep: EndpointDefinition = {
      method: 'POST',
      path: '/x',
      handler: 'x',
      input: { body: { type: 'object', properties: { a: { type: 'string' } }, required: ['a'] } },
    };
    const def = buildRouteDefinition(ep, identitySchemaConverter);
    expect((def.request as any).body.content['application/json'].schema).toEqual(ep.input!.body);
  });

  it('convertRoutes imports a fetcher/fortress-authored route via toJSONSchemaConverter', () => {
    const route = {
      method: 'POST',
      path: '/users',
      responses: { 200: { description: 'ok' } },
      request: { body: { content: { 'application/json': { schema: obj({ name: str() }, 'name') } } } },
    };
    const [ep] = convertRoutes([route as any], { schemaConverter: toJSONSchemaConverter });
    expect(ep.input?.body?.type).toBe('object');
    expect(ep.input?.body?.properties?.name?.type).toBe('string');
  });
});
