import type { FortressSchema, Infer } from './json-schema';
import type { StandardSchemaV1 } from './standard-schema';
import { describe, expect, it } from 'vitest';
import { anyOf, arr, bool, date, datetime, defineComponents, discriminatedUnion, email, endpoint, enums, ErrorEnvelope, extractJsonSchema, id, int, intersect, isFortressSchema, isStandardSchema, literal, nullable, nullType, num, obj, oneOf, record, recordOf, ref, str, strFormat, strict, time, url, uuid } from './schema-builder';

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

  it('oneOf() composes schemas and requires exactly one runtime match', async () => {
    const left = obj({ left: str() }, 'left');
    const right = obj({ right: str() }, 'right');
    const s = oneOf(left, right);
    expect(s.oneOf).toHaveLength(2);

    expect(await s['~standard'].validate({ left: 'yes' })).toEqual({ value: { left: 'yes' } });
    expectIssues(await s['~standard'].validate({ neither: true }));
    expectIssues(await s['~standard'].validate({ left: 'yes', right: 'yes' }));
  });

  it('anyOf() composes schemas and permits overlapping runtime matches', async () => {
    const s = anyOf(
      obj({ left: str() }, 'left'),
      obj({ right: str() }, 'right'),
    );
    expect(s.anyOf).toHaveLength(2);
    expect((await s['~standard'].validate({ left: 'yes', right: 'yes' }) as any).issues).toBeUndefined();
  });

  it('ref() returns $ref', () => {
    expect(ref('User').$ref).toBe('#/components/schemas/User');
  });

  it('defineComponents refs enforce the referenced component shape', () => {
    const User = strict(obj({ email: email(), age: int({ min: 18 }) }, 'email', 'age'));
    const { ref: componentRef } = defineComponents({ User });
    const schema = componentRef('User');

    expect((schema['~standard'].validate({ email: 'user@example.com', age: 21 }) as any).issues).toBeUndefined();
    expectIssues(schema['~standard'].validate({ email: 'invalid', age: 21 }) as StandardSchemaV1.Result<any>);
    expectIssues(schema['~standard'].validate({ email: 'user@example.com', age: 17 }) as StandardSchemaV1.Result<any>);
    expectIssues(schema['~standard'].validate({ email: 'user@example.com' }) as StandardSchemaV1.Result<any>);
    expectIssues(schema['~standard'].validate({ email: 'user@example.com', age: 21, admin: true }) as StandardSchemaV1.Result<any>);
  });

  it('enforces bound refs nested inside an inline request schema', () => {
    const User = obj({ name: str({ min: 2 }) }, 'name');
    const { ref: componentRef } = defineComponents({ User });
    const schema = obj({ user: componentRef('User') }, 'user');

    expect((schema['~standard'].validate({ user: { name: 'Ada' } }) as any).issues).toBeUndefined();
    expectIssues(schema['~standard'].validate({ user: { name: 'A' } }) as StandardSchemaV1.Result<any>);
  });

  it('resolves transitive and recursive component refs', () => {
    const Address = obj({ city: str({ min: 2 }) }, 'city');
    const User = obj({ address: ref('Address') }, 'address');
    const Node = obj({ name: str(), children: arr(ref('Node')) }, 'name');
    const { ref: componentRef } = defineComponents({ Address, User, Node });

    const user = componentRef('User');
    expect((user['~standard'].validate({ address: { city: 'Oslo' } }) as any).issues).toBeUndefined();
    expectIssues(user['~standard'].validate({ address: { city: 'X' } }) as StandardSchemaV1.Result<any>);

    const node = componentRef('Node');
    expect((node['~standard'].validate({ name: 'root', children: [{ name: 'leaf' }] }) as any).issues).toBeUndefined();
    expectIssues(node['~standard'].validate({ name: 'root', children: [{}] }) as StandardSchemaV1.Result<any>);
  });

  it('isolates same-named components across independent registries', () => {
    const AUser = obj({ kind: literal('a') }, 'kind');
    const BUser = obj({ kind: literal('b') }, 'kind');
    const aRef = defineComponents({ User: AUser }).ref('User');
    const bRef = defineComponents({ User: BUser }).ref('User');

    // Compile lazily only after both registries exist: neither may overwrite
    // the other by global component name.
    expect((aRef['~standard'].validate({ kind: 'a' }) as any).issues).toBeUndefined();
    expectIssues(aRef['~standard'].validate({ kind: 'b' }) as StandardSchemaV1.Result<any>);
    expect((bRef['~standard'].validate({ kind: 'b' }) as any).issues).toBeUndefined();
    expectIssues(bRef['~standard'].validate({ kind: 'a' }) as StandardSchemaV1.Result<any>);
  });

  it('typed refs enforce their supplied schema while bare refs stay permissive', () => {
    const typed = ref('Token', obj({ value: str({ min: 3 }) }, 'value'));
    expect((typed['~standard'].validate({ value: 'abc' }) as any).issues).toBeUndefined();
    expectIssues(typed['~standard'].validate({ value: 'x' }) as StandardSchemaV1.Result<any>);

    const bare = ref('Unknown');
    defineComponents({ Unknown: obj({ required: str() }, 'required') });
    // A later registry declaration must not retroactively bind a bare ref.
    expect((bare['~standard'].validate({ arbitrary: true }) as any).issues).toBeUndefined();
  });

  it('resolves same-named bare and bound refs to one global component', () => {
    const bare = ref('SharedUser');
    const bound = defineComponents({
      SharedUser: obj({ name: str({ min: 2 }) }, 'name'),
    }).ref('SharedUser');
    const schema = obj({ bare, bound }, 'bare', 'bound');

    expect((schema['~standard'].validate({
      bare: { name: 'Ada' },
      bound: { name: 'Lin' },
    }) as any).issues).toBeUndefined();
    expectIssues(schema['~standard'].validate({
      bare: { arbitrary: true },
      bound: { name: 'Lin' },
    }) as StandardSchemaV1.Result<any>);
  });

  it('nullable bound refs accept null and still enforce non-null values', () => {
    const User = obj({ name: str({ min: 2 }) }, 'name');
    const schema = nullable(defineComponents({ User }).ref('User'));

    expect((schema['~standard'].validate(null) as any).issues).toBeUndefined();
    expect((schema['~standard'].validate({ name: 'Ada' }) as any).issues).toBeUndefined();
    expectIssues(schema['~standard'].validate({ name: 'A' }) as StandardSchemaV1.Result<any>);
  });

  it('rejects component names that cannot be represented safely in OpenAPI refs', () => {
    expect(() => ref('Admin/User')).toThrow(/Invalid OpenAPI component name/);
    expect(() => defineComponents({ 'Admin/User': obj({ id: str() }) })).toThrow(/Invalid OpenAPI component name/);
  });

  it('snapshots component bindings before lazy validation', () => {
    const original = obj({ kind: literal('original') }, 'kind');
    const replacement = obj({ kind: literal('replacement') }, 'kind');
    const registry: Record<string, FortressSchema<any>> = { User: original };
    const bound = defineComponents(registry).ref('User');
    registry.User = replacement;

    expect((bound['~standard'].validate({ kind: 'original' }) as any).issues).toBeUndefined();
    expectIssues(bound['~standard'].validate({ kind: 'replacement' }) as StandardSchemaV1.Result<any>);
  });

  it('resolves mutually recursive component refs', () => {
    const A = obj({ name: str(), b: ref('B') }, 'name');
    const B = obj({ name: str(), a: ref('A') }, 'name');
    const schema = defineComponents({ A, B }).ref('A');

    expect((schema['~standard'].validate({ name: 'a', b: { name: 'b' } }) as any).issues).toBeUndefined();
    expectIssues(schema['~standard'].validate({ name: 'a', b: { a: {} } }) as StandardSchemaV1.Result<any>);
  });

  it('fails closed when one schema mixes conflicting same-named registries', () => {
    const a = defineComponents({ User: obj({ kind: literal('a') }, 'kind') }).ref('User');
    const b = defineComponents({ User: obj({ kind: literal('b') }, 'kind') }).ref('User');
    const mixed = obj({ a, b }, 'a', 'b');

    expect(() => mixed['~standard'].validate({ a: { kind: 'a' }, b: { kind: 'b' } }))
      .toThrow(/Conflicting component definitions/);
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

  it('record() returns an honestly typed open object schema', () => {
    const s = record('Some data');
    expect(s.type).toBe('object');
    expect(s.additionalProperties).toBe(true);
    expect(s.description).toBe('Some data');
    void (0 as unknown as Infer<typeof s> satisfies Record<string, unknown>);
    // @ts-expect-error -- record() cannot claim properties it does not validate
    void record<{ id: string }>('unsafe');
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

describe('schema detection (Zod-like Standard Schema)', () => {
  /** Creates a mock external Standard Schema that has a .type property (like Zod). */
  function mockZodSchema(): StandardSchemaV1 & { type: string } {
    const jsonSchema = { type: 'object' as const, properties: { name: { type: 'string' as const } }, required: ['name'] };
    return {
      'type': 'ZodObject', // Zod objects have a .type property
      '~standard': {
        version: 1,
        vendor: 'zod',
        validate: (value: unknown) => ({ value }),
        jsonSchema: {
          input: () => jsonSchema,
        },
      },
    } as any;
  }

  it('does not detect Zod-like schema as FortressSchema', () => {
    const zod = mockZodSchema();
    expect(isStandardSchema(zod)).toBe(true);
    expect(isFortressSchema(zod)).toBe(false);
  });

  it('extractJsonSchema uses ~standard.jsonSchema for external schemas', () => {
    const zod = mockZodSchema();
    const result = extractJsonSchema(zod);
    expect(result).toEqual({
      type: 'object',
      properties: { name: { type: 'string' } },
      required: ['name'],
    });
  });

  it('extractJsonSchema returns fortress schema as-is', () => {
    const s = obj({ name: str() }, 'name');
    const result = extractJsonSchema(s);
    expect(result).toBe(s); // same reference
  });

  /** Mimics fetcher: JSON Schema object with ~standard bolted on, no jsonSchema.input adapter. */
  function mockFetcherObject(): StandardSchemaV1 & { type: 'object'; properties: Record<string, unknown>; required: string[] } {
    return {
      'type': 'object',
      'properties': { name: { type: 'string' } },
      'required': ['name'],
      '~standard': {
        version: 1,
        vendor: 'fetcher',
        validate: (value: unknown) => ({ value }),
      },
    } as any;
  }

  it('extractJsonSchema returns fetcher-shaped schema as-is (non-fortress vendor, no adapter)', () => {
    const f = mockFetcherObject();
    const result = extractJsonSchema(f);
    expect(result).toBe(f);
    expect(result).toMatchObject({
      type: 'object',
      properties: { name: { type: 'string' } },
      required: ['name'],
    });
  });

  it('extractJsonSchema handles $ref-shaped Standard Schema regardless of vendor', () => {
    const r = {
      '$ref': '#/components/schemas/User',
      '~standard': { version: 1, vendor: 'fetcher', validate: (v: unknown) => ({ value: v }) },
    } as any;
    expect(extractJsonSchema(r)).toBe(r);
  });

  it('extractJsonSchema falls back to {} for wrapper-style schema whose type is not a JSON Schema type', () => {
    const fakeZod = {
      'type': 'ZodObject',
      '~standard': { version: 1, vendor: 'zod', validate: (v: unknown) => ({ value: v }) },
    } as any;
    expect(extractJsonSchema(fakeZod)).toEqual({});
  });

  it('endpoint builder extracts JSON Schema from external Standard Schema', () => {
    const zod = mockZodSchema();
    const ep = endpoint('POST', '/test')
      .body(zod)
      .handler('test')
      .build();

    expect(ep.input?.body?.type).toBe('object');
    expect(ep.input?.body?.properties?.name?.type).toBe('string');
    expect(ep.input?.bodySchema).toBeDefined();
  });
});

describe('endpoint builder', () => {
  it('builds a minimal endpoint and rejects unsupported runtime methods', () => {
    const ep = endpoint('GET', '/health').handler('healthCheck').build();
    expect(ep).toEqual({
      method: 'GET',
      path: '/health',
      handler: 'healthCheck',
    });
    expect(() => endpoint('TRACE' as any, '/trace')).toThrow('Unsupported endpoint method: TRACE');
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
      .params(obj({ id: id('User ID') }, 'id'))
      .query(obj({ include: str('Relations to include') }))
      .handler('getUser')
      .build();

    expect(ep.input?.params?.properties?.id?.type).toBe('string');
    expect(ep.input?.query?.properties?.include?.type).toBe('string');
    expect(ep.input?.paramsSchema).toBeDefined();
    expect(ep.input?.querySchema).toBeDefined();
  });

  it('supports multiple tags', () => {
    const ep = endpoint('GET', '/test').summary('Test').tags('Auth', 'Admin').handler('test').build();
    expect(ep.meta?.tags).toEqual(['Auth', 'Admin']);
  });

  it('keeps type-changing builder branches immutable', () => {
    const base = endpoint('POST', '/aliased').security('none');
    const withId = base.body(obj({ id: str() }, 'id'));
    const withName = base.body(obj({ name: str() }, 'name'));
    const handlerA = withId.handler('handlerA');
    const handlerB = withId.handler('handlerB');
    const responseA = handlerA.response(200, 'A', obj({ a: str() }, 'a'));
    const responseB = handlerA.response(200, 'B', obj({ b: str() }, 'b'));

    expect(withId.build().input?.body?.properties).toHaveProperty('id');
    expect(withName.build().input?.body?.properties).toHaveProperty('name');
    expect(handlerA.build().handler).toBe('handlerA');
    expect(handlerB.build().handler).toBe('handlerB');
    expect(responseA.build().responses?.[200]?.schema?.properties).toHaveProperty('a');
    expect(responseB.build().responses?.[200]?.schema?.properties).toHaveProperty('b');
  });
});

describe('errorEnvelope + .errorResponse()', () => {
  it('exports ErrorEnvelope as a fortress schema matching FortressError.toJSON()', () => {
    expect(isFortressSchema(ErrorEnvelope)).toBe(true);
    const json = extractJsonSchema(ErrorEnvelope);
    expect(json.type).toBe('object');
    expect(json.required).toEqual(['code', 'message', 'statusCode']);
    expect(json.properties?.code?.type).toBe('string');
    expect(json.properties?.message?.type).toBe('string');
    expect(json.properties?.statusCode?.type).toBe('integer');
    expect(json.properties?.details).toBeDefined();
  });

  it('validates a canonical error body', () => {
    const ok = ErrorEnvelope['~standard'].validate({
      code: 'NOT_FOUND',
      message: 'gone',
      statusCode: 404,
    });
    expect('issues' in ok && ok.issues !== undefined).toBe(false);
  });

  it('rejects bodies missing required fields', () => {
    const bad = ErrorEnvelope['~standard'].validate({ code: 'NOT_FOUND' }) as StandardSchemaV1.Result<any>;
    expectIssues(bad);
  });

  it('.errorResponse() wires ErrorEnvelope into a response declaration', () => {
    const ep = endpoint('GET', '/schools/:id')
      .summary('Get school')
      .errorResponse(404, 'Not found')
      .errorResponse(403, 'Forbidden')
      .handler('getSchool')
      .build();

    expect(ep.responses?.[404]?.description).toBe('Not found');
    expect(ep.responses?.[404]?.schema?.required).toEqual(['code', 'message', 'statusCode']);
    expect(ep.responses?.[403]?.schema?.properties?.code?.type).toBe('string');
  });
});

describe('tier 1 — richer constraints (fetcher-backed, enforced)', () => {
  it('str({ min, max, pattern }) emits and enforces constraints', () => {
    const s = str({ min: 3, max: 5, pattern: '^[a-z]+$' });
    expect(s.minLength).toBe(3);
    expect(s.maxLength).toBe(5);
    expect(s.pattern).toBe('^[a-z]+$');

    expect(s['~standard'].validate('abc')).toEqual({ value: 'abc' });
    expectIssues(s['~standard'].validate('ab') as StandardSchemaV1.Result<any>); // too short
    expectIssues(s['~standard'].validate('abcdef') as StandardSchemaV1.Result<any>); // too long
    expectIssues(s['~standard'].validate('AB1') as StandardSchemaV1.Result<any>); // pattern
  });

  it('str() still accepts a bare description string', () => {
    expect(str('An email').description).toBe('An email');
  });

  it('int({ min, max }) enforces numeric bounds', () => {
    const s = int({ min: 1, max: 10 });
    expect(s.minimum).toBe(1);
    expect(s.maximum).toBe(10);
    expect(s['~standard'].validate(5)).toEqual({ value: 5 });
    expectIssues(s['~standard'].validate(0) as StandardSchemaV1.Result<any>);
    expectIssues(s['~standard'].validate(11) as StandardSchemaV1.Result<any>);
  });

  it('literal() narrows and enforces a constant', () => {
    const s = literal('admin');
    expect(s.const).toBe('admin');
    void (0 as unknown as Infer<typeof s> satisfies 'admin');
    expect(s['~standard'].validate('admin')).toEqual({ value: 'admin' });
    expectIssues(s['~standard'].validate('user') as StandardSchemaV1.Result<any>);
  });

  it('intersect() requires every schema (allOf)', () => {
    const s = intersect(obj({ a: str() }, 'a'), obj({ b: int() }, 'b'));
    expect(s.allOf).toHaveLength(2);
    expect((s['~standard'].validate({ a: 'x', b: 1 }) as any).issues).toBeUndefined();
    expectIssues(s['~standard'].validate({ a: 'x' }) as StandardSchemaV1.Result<any>);
  });

  it('strict() closes an object against extra keys', () => {
    const s = strict(obj({ a: str() }, 'a'));
    expect(s.additionalProperties).toBe(false);
    expect((s['~standard'].validate({ a: 'x' }) as any).issues).toBeUndefined();
    expectIssues(s['~standard'].validate({ a: 'x', extra: 1 }) as StandardSchemaV1.Result<any>);
  });

  it('discriminatedUnion() dispatches on the tag property', () => {
    const s = discriminatedUnion(
      'kind',
      obj({ kind: literal('a'), x: int() }, 'kind', 'x'),
      obj({ kind: literal('b'), y: str() }, 'kind', 'y'),
    );
    expect(s.oneOf).toHaveLength(2);
    expect(s.discriminator?.propertyName).toBe('kind');
    expect((s['~standard'].validate({ kind: 'a', x: 1 }) as any).issues).toBeUndefined();
    expectIssues(s['~standard'].validate({ kind: 'a', x: 'no' }) as StandardSchemaV1.Result<any>);
  });
});

describe('tier 2 — enforced string formats (lifted from fetcher)', () => {
  it('email() carries format + pattern and enforces at runtime', () => {
    const s = email();
    expect(s.format).toBe('email');
    expect(typeof s.pattern).toBe('string');
    expect(s['~standard'].validate('user@example.com')).toEqual({ value: 'user@example.com' });
    expectIssues(s['~standard'].validate('not-an-email') as StandardSchemaV1.Result<any>);
    expectIssues(s['~standard'].validate('a@b@c') as StandardSchemaV1.Result<any>);
  });

  it('uuid() enforces the RFC 9562 grammar', () => {
    const s = uuid();
    expect(s.format).toBe('uuid');
    expect(s['~standard'].validate('00000000-0000-0000-0000-000000000000')).toEqual({
      value: '00000000-0000-0000-0000-000000000000',
    });
    expectIssues(s['~standard'].validate('not-a-uuid') as StandardSchemaV1.Result<any>);
  });

  it('url() requires an explicit scheme://authority', () => {
    const s = url();
    expect(s.format).toBe('uri');
    expect(s['~standard'].validate('https://example.com')).toEqual({ value: 'https://example.com' });
    expectIssues(s['~standard'].validate('mailto:a@b.com') as StandardSchemaV1.Result<any>);
  });

  it('datetime()/date()/time() enforce RFC 3339 shapes', () => {
    expect(datetime().format).toBe('date-time');
    expect((datetime()['~standard'].validate('2026-01-02T03:04:05Z') as any).issues).toBeUndefined();
    expectIssues(datetime()['~standard'].validate('2026-01-02') as StandardSchemaV1.Result<any>);

    expect(date().format).toBe('date');
    expect((date()['~standard'].validate('2026-01-02') as any).issues).toBeUndefined();

    expect(time().format).toBe('time');
    expect((time()['~standard'].validate('03:04:05') as any).issues).toBeUndefined();
  });
});
