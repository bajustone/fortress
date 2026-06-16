/**
 * Interop: authoring fortress endpoint schemas with `@bajustone/fetcher`'s own
 * builder (re-exported at `@bajustone/fortress/fetcher`). Fetcher schemas are
 * JSON Schema objects that implement Standard Schema V1, so they drop straight
 * into `endpoint().body()/.query()/.params()/.response()`:
 *   - runtime validation uses the fetcher schema's own compiled validator
 *   - OpenAPI emission strips fetcher's internal `~`-prefixed keys, leaving
 *     clean JSON Schema
 *
 * This locks that contract in so neither `extractJsonSchema` (detection) nor
 * `cleanSchema` (OpenAPI serialization) can regress it.
 */
import type { StandardSchemaV1 } from './standard-schema';
import { discriminatedUnion, email as femail, integer, literal, nullable, object, optional, string } from '@bajustone/fetcher/schema';
import { describe, expect, it } from 'vitest';
import { toOpenAPI } from './openapi';
import { endpoint, extractJsonSchema, isStandardSchema } from './schema-builder';
import { validateValue } from './validation';

/** Recursively collect any object key beginning with `~` (fetcher internals). */
function tildeKeys(value: unknown, acc: string[] = []): string[] {
  if (Array.isArray(value)) {
    for (const v of value)
      tildeKeys(v, acc);
  }
  else if (value && typeof value === 'object') {
    for (const [k, v] of Object.entries(value)) {
      if (k.startsWith('~'))
        acc.push(k);
      tildeKeys(v, acc);
    }
  }
  return acc;
}

const Body = object({
  email: femail(),
  name: string({ minLength: 1 }),
  age: optional(integer()),
  nick: nullable(string()),
  kind: discriminatedUnion('t', {
    a: object({ t: literal('a'), x: integer() }),
    b: object({ t: literal('b'), y: string() }),
  }),
});

describe('fetcher builder interop — endpoint authoring', () => {
  it('a fetcher schema is a valid Standard Schema and JSON Schema', () => {
    expect(isStandardSchema(Body)).toBe(true);
    expect((Body as any).type).toBe('object');
    // extractJsonSchema accepts the fetcher-shaped schema (no Zod-style adapter)
    expect((extractJsonSchema(Body as any) as any).type).toBe('object');
  });

  it('validates request data via the fetcher schema validator', async () => {
    const okValue = await validateValue(
      Body as unknown as StandardSchemaV1,
      { email: 'user@example.com', name: 'x', nick: null, kind: { t: 'a', x: 1 } },
      'body',
    );
    expect(okValue).toMatchObject({ email: 'user@example.com', name: 'x' });

    await expect(
      validateValue(
        Body as unknown as StandardSchemaV1,
        { email: 'not-an-email', name: '', nick: 1, kind: { t: 'a', x: 'no' } },
        'body',
      ),
    ).rejects.toMatchObject({ code: 'VALIDATION_ERROR', statusCode: 422 });
  });

  it('stores both JSON Schema (OpenAPI) and the validator on the endpoint', () => {
    const ep = endpoint('POST', '/users')
      .summary('Create user')
      .body(Body as any)
      .response(200, 'Created', object({ id: string() }) as any)
      .handler('createUser')
      .build();

    expect(ep.input?.body?.type).toBe('object');
    expect(typeof (ep.input?.bodySchema as any)?.['~standard'].validate).toBe('function');
  });

  it('emits clean OpenAPI — no fetcher ~ keys, correct shape', () => {
    const ep = endpoint('POST', '/users')
      .summary('Create user')
      .body(Body as any)
      .handler('createUser')
      .build();

    const spec = toOpenAPI([ep], { title: 't', version: '1' });
    expect(tildeKeys(spec)).toEqual([]);

    const schema = (spec as any).paths['/users'].post.requestBody.content['application/json'].schema;
    // optional `age` is excluded from required; required keys present
    expect(schema.required).toEqual(['email', 'name', 'nick', 'kind']);
    // enforced email format surfaces as format + pattern
    expect(schema.properties.email.format).toBe('email');
    expect(typeof schema.properties.email.pattern).toBe('string');
    // nullable → anyOf with a null branch (valid OpenAPI 3.1)
    expect(schema.properties.nick.anyOf).toEqual([{ type: 'string' }, { type: 'null' }]);
    // discriminatedUnion → oneOf + discriminator
    expect(schema.properties.kind.oneOf).toHaveLength(2);
    expect(schema.properties.kind.discriminator.propertyName).toBe('t');
  });
});
