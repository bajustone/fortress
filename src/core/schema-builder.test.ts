import { describe, expect, it } from 'vitest';
import { anyOf, arr, bool, endpoint, enums, int, nullable, num, obj, oneOf, ref, str, strFormat } from './schema-builder';

describe('schema builders', () => {
  it('str() returns string schema', () => {
    expect(str()).toEqual({ type: 'string' });
    expect(str('An email')).toEqual({ type: 'string', description: 'An email' });
  });

  it('num() returns number schema', () => {
    expect(num()).toEqual({ type: 'number' });
  });

  it('int() returns integer schema', () => {
    expect(int()).toEqual({ type: 'integer' });
  });

  it('bool() returns boolean schema', () => {
    expect(bool()).toEqual({ type: 'boolean' });
  });

  it('arr() returns array schema', () => {
    expect(arr(str())).toEqual({ type: 'array', items: { type: 'string' } });
  });

  it('obj() returns object schema with required', () => {
    const schema = obj({ name: str(), age: int() }, 'name');
    expect(schema).toEqual({
      type: 'object',
      properties: { name: { type: 'string' }, age: { type: 'integer' } },
      required: ['name'],
    });
  });

  it('obj() without required fields omits required', () => {
    const schema = obj({ name: str() });
    expect(schema.required).toBeUndefined();
  });

  it('nullable() wraps schema', () => {
    expect(nullable(str())).toEqual({ type: 'string', nullable: true });
  });

  it('oneOf() composes schemas', () => {
    expect(oneOf(str(), int())).toEqual({ oneOf: [{ type: 'string' }, { type: 'integer' }] });
  });

  it('anyOf() composes schemas', () => {
    expect(anyOf(str(), int())).toEqual({ anyOf: [{ type: 'string' }, { type: 'integer' }] });
  });

  it('ref() returns $ref', () => {
    expect(ref('User')).toEqual({ $ref: '#/components/schemas/User' });
  });

  it('enums() returns enum schema', () => {
    expect(enums('a', 'b', 'c')).toEqual({ enum: ['a', 'b', 'c'] });
  });

  it('strFormat() returns string with format', () => {
    expect(strFormat('email')).toEqual({ type: 'string', format: 'email' });
    expect(strFormat('date-time', 'Timestamp')).toEqual({ type: 'string', format: 'date-time', description: 'Timestamp' });
  });
});

describe('endpoint builder', () => {
  it('builds a minimal endpoint', () => {
    const ep = endpoint('GET', '/health').handler('healthCheck').build();
    expect(ep).toEqual({
      method: 'GET',
      path: '/health',
      handler: 'healthCheck',
    });
  });

  it('builds a full endpoint with all fields', () => {
    const ep = endpoint('POST', '/auth/login')
      .summary('Login')
      .description('Authenticate with credentials')
      .tags('Auth')
      .security('none')
      .body(obj({ identifier: str(), password: str() }, 'identifier', 'password'))
      .response(200, 'Success', ref('AuthResponse'))
      .response(401, 'Invalid credentials', ref('ErrorResponse'))
      .handler('login')
      .build();

    expect(ep.method).toBe('POST');
    expect(ep.path).toBe('/auth/login');
    expect(ep.handler).toBe('login');
    expect(ep.meta?.summary).toBe('Login');
    expect(ep.meta?.description).toBe('Authenticate with credentials');
    expect(ep.meta?.tags).toEqual(['Auth']);
    expect(ep.meta?.security).toEqual(['none']);
    expect(ep.input?.body?.type).toBe('object');
    expect(ep.input?.body?.required).toEqual(['identifier', 'password']);
    expect(ep.responses?.[200]?.description).toBe('Success');
    expect(ep.responses?.[401]?.schema?.$ref).toBe('#/components/schemas/ErrorResponse');
  });

  it('supports deprecated endpoints', () => {
    const ep = endpoint('GET', '/old').summary('Old').deprecated().handler('old').build();
    expect(ep.meta?.deprecated).toBe(true);
  });

  it('supports query and params', () => {
    const ep = endpoint('GET', '/users/:id')
      .summary('Get user')
      .params(obj({ id: int('User ID') }, 'id'))
      .query(obj({ include: str('Relations to include') }))
      .handler('getUser')
      .build();

    expect(ep.input?.params?.properties?.id).toEqual({ type: 'integer', description: 'User ID' });
    expect(ep.input?.query?.properties?.include).toEqual({ type: 'string', description: 'Relations to include' });
  });

  it('supports multiple tags', () => {
    const ep = endpoint('GET', '/test').summary('Test').tags('Auth', 'Admin').handler('test').build();
    expect(ep.meta?.tags).toEqual(['Auth', 'Admin']);
  });
});
