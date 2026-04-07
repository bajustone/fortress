import type { Infer } from './json-schema';
import type { StandardSchemaV1 } from './standard-schema';
import { describe, expect, it } from 'vitest';
import { anyOf, arr, bool, endpoint, enums, int, nullable, nullType, num, obj, oneOf, record, recordOf, ref, str, strFormat } from './schema-builder';

/** Assert validation fails and return issues. */
function expectIssues(result: StandardSchemaV1.Result<any>): void {
  expect('issues' in result && result.issues !== undefined).toBe(true);
}

describe('schema builders', () => {
  it('str() returns string schema with ~standard', () => {
    const s = str();
    expect(s.type).toBe('string');
    expect(s['~standard'].version).toBe(1);
    expect(s['~standard'].vendor).toBe('fortress');
    expect(typeof s['~standard'].validate).toBe('function');

    expect(str('An email').description).toBe('An email');
  });

  it('num() returns number schema', () => {
    expect(num().type).toBe('number');
  });

  it('int() returns integer schema', () => {
    expect(int().type).toBe('integer');
  });

  it('bool() returns boolean schema', () => {
    expect(bool().type).toBe('boolean');
  });

  it('arr() returns array schema', () => {
    const s = arr(str());
    expect(s.type).toBe('array');
    expect(s.items?.type).toBe('string');
  });

  it('obj() returns object schema with required', () => {
    const schema = obj({ name: str(), age: int() }, 'name');
    expect(schema.type).toBe('object');
    expect(schema.properties?.name?.type).toBe('string');
    expect(schema.properties?.age?.type).toBe('integer');
    expect(schema.required).toEqual(['name']);
  });

  it('obj() without required fields omits required', () => {
    const schema = obj({ name: str() });
    expect(schema.required).toBeUndefined();
  });

  it('nullable() wraps schema', () => {
    const s = nullable(str());
    expect(s.type).toBe('string');
    expect(s.nullable).toBe(true);
  });

  it('oneOf() composes schemas', () => {
    const s = oneOf(str(), int());
    expect(s.oneOf).toHaveLength(2);
  });

  it('anyOf() composes schemas', () => {
    const s = anyOf(str(), int());
    expect(s.anyOf).toHaveLength(2);
  });

  it('ref() returns $ref', () => {
    expect(ref('User').$ref).toBe('#/components/schemas/User');
  });

  it('enums() returns enum schema', () => {
    expect(enums('a', 'b', 'c').enum).toEqual(['a', 'b', 'c']);
  });

  it('strFormat() returns string with format', () => {
    const s = strFormat('email');
    expect(s.type).toBe('string');
    expect(s.format).toBe('email');

    const s2 = strFormat('date-time', 'Timestamp');
    expect(s2.description).toBe('Timestamp');
  });

  it('nullType() returns null schema', () => {
    expect(nullType().type).toBe('null');
  });

  it('record() returns object with additionalProperties', () => {
    const s = record('Some data');
    expect(s.type).toBe('object');
    expect(s.additionalProperties).toBe(true);
    expect(s.description).toBe('Some data');
  });

  it('recordOf() returns object with typed additionalProperties', () => {
    const s = recordOf(str());
    expect(s.type).toBe('object');
    expect((s.additionalProperties as any).type).toBe('string');
  });
});

describe('standard Schema validation', () => {
  it('str() validates strings', () => {
    const s = str();
    const ok = s['~standard'].validate('hello');
    expect(ok).toEqual({ value: 'hello' });

    const fail = s['~standard'].validate(123);
    expectIssues(fail as StandardSchemaV1.Result<any>);
  });

  it('int() validates integers', () => {
    const s = int();
    expect(s['~standard'].validate(42)).toEqual({ value: 42 });

    const fail = s['~standard'].validate(3.14);
    expectIssues(fail as StandardSchemaV1.Result<any>);
  });

  it('bool() validates booleans', () => {
    const s = bool();
    expect(s['~standard'].validate(true)).toEqual({ value: true });

    const fail = s['~standard'].validate('true');
    expectIssues(fail as StandardSchemaV1.Result<any>);
  });

  it('obj() validates required fields', () => {
    const s = obj({ name: str(), age: int() }, 'name', 'age');

    const ok = s['~standard'].validate({ name: 'Alice', age: 30 });
    expect(ok).toEqual({ value: { name: 'Alice', age: 30 } });

    const fail = s['~standard'].validate({ name: 'Alice' });
    expectIssues(fail as StandardSchemaV1.Result<any>);
  });

  it('obj() validates property types', () => {
    const s = obj({ name: str() }, 'name');

    const fail = s['~standard'].validate({ name: 123 });
    expectIssues(fail as StandardSchemaV1.Result<any>);
  });

  it('arr() validates array items', () => {
    const s = arr(int());

    const ok = s['~standard'].validate([1, 2, 3]);
    expect(ok).toEqual({ value: [1, 2, 3] });

    const fail = s['~standard'].validate([1, 'two', 3]);
    expectIssues(fail as StandardSchemaV1.Result<any>);
  });

  it('enums() validates enum values', () => {
    const s = enums('a', 'b');

    expect(s['~standard'].validate('a')).toEqual({ value: 'a' });

    const fail = s['~standard'].validate('c');
    expectIssues(fail as StandardSchemaV1.Result<any>);
  });

  it('nullable() accepts null', () => {
    const s = nullable(str());

    expect(s['~standard'].validate(null)).toEqual({ value: null });
    expect(s['~standard'].validate('hello')).toEqual({ value: 'hello' });
  });
});

describe('type inference', () => {
  it('infers primitive types', () => {
    void (0 as unknown as Infer<ReturnType<typeof str>> satisfies string);
    void (0 as unknown as Infer<ReturnType<typeof int>> satisfies number);
    void (0 as unknown as Infer<ReturnType<typeof bool>> satisfies boolean);

    expect(str().type).toBe('string');
  });

  it('infers object types with required/optional', () => {
    const schema = obj({ name: str(), age: int() }, 'name');
    type T = Infer<typeof schema>;

    // Compile-time: name is required, age is optional
    void (0 as unknown as T satisfies { name: string; age?: number });

    expect(schema.required).toEqual(['name']);
  });

  it('infers array types', () => {
    const schema = arr(str());
    type T = Infer<typeof schema>;
    void (0 as unknown as T satisfies string[]);

    expect(schema.type).toBe('array');
  });

  it('infers enum types', () => {
    const schema = enums('a', 'b', 'c');
    type T = Infer<typeof schema>;
    void (0 as unknown as T satisfies 'a' | 'b' | 'c');

    expect(schema.enum).toEqual(['a', 'b', 'c']);
  });

  it('infers nullable types', () => {
    const schema = nullable(str());
    type T = Infer<typeof schema>;
    void (0 as unknown as T satisfies string | null);

    expect(schema.nullable).toBe(true);
  });

  it('inferOutput works with Standard Schema type', () => {
    const schema = obj({ x: int() }, 'x');
    type T = StandardSchemaV1.InferOutput<typeof schema>;
    void (0 as unknown as T satisfies { x: number });

    expect(schema.type).toBe('object');
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
    expect(ep.input?.bodySchema).toBeDefined();
    expect(ep.responses?.[200]?.description).toBe('Success');
    expect(ep.responses?.[401]?.schema?.$ref).toBe('#/components/schemas/ErrorResponse');
  });

  it('stores Standard Schema ref for validation', () => {
    const body = obj({ name: str() }, 'name');
    const ep = endpoint('POST', '/test')
      .body(body)
      .handler('test')
      .build();

    expect(ep.input?.bodySchema).toBeDefined();
    expect(typeof (ep.input?.bodySchema as any)['~standard'].validate).toBe('function');
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

    expect(ep.input?.params?.properties?.id?.type).toBe('integer');
    expect(ep.input?.query?.properties?.include?.type).toBe('string');
    expect(ep.input?.paramsSchema).toBeDefined();
    expect(ep.input?.querySchema).toBeDefined();
  });

  it('supports multiple tags', () => {
    const ep = endpoint('GET', '/test').summary('Test').tags('Auth', 'Admin').handler('test').build();
    expect(ep.meta?.tags).toEqual(['Auth', 'Admin']);
  });
});
