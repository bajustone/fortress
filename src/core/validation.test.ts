import type { JSONSchema } from './json-schema';
import { describe, expect, it } from 'vitest';
import { FortressError } from './errors';
import { iamEndpoints } from './iam/iam-endpoints';
import { int, num, obj, str } from './schema-builder';
import { coerceBySchema, validateRequest } from './validation';

describe('coerceBySchema', () => {
  it('coerces only lossless canonical decimal URL numerics', () => {
    const schema = obj({ integer: int(), number: num() });
    expect(coerceBySchema(schema, { integer: '-12', number: '0.5' })).toEqual({
      integer: -12,
      number: 0.5,
    });
    for (const value of [
      '',
      '0x10',
      '1e3',
      '+1',
      '.5',
      '01',
      '1.0',
      '-0',
      '9007199254740992',
      '0.10000000000000001',
      'Infinity',
    ]) {
      expect(coerceBySchema(schema, { integer: value, number: value })).toEqual({
        integer: value,
        number: value,
      });
    }
  });

  it('leaves unsafe integers uncoerced so validation rejects them', async () => {
    const paramsSchema = obj({ id: int() }, 'id');
    const params = coerceBySchema(paramsSchema, { id: '9007199254740992' });

    expect(params).toEqual({ id: '9007199254740992' });
    await expect(
      validateRequest({ params: paramsSchema, paramsSchema }, { params }),
    ).rejects.toMatchObject({ code: 'VALIDATION_ERROR', statusCode: 422 });
  });

  it('coerces numeric enum and const properties without an explicit type', async () => {
    const schema = {
      type: 'object' as const,
      properties: {
        mode: { enum: [1, 2] },
        version: { const: 3 },
      },
      required: ['mode', 'version'],
    };
    const params = coerceBySchema(schema, { mode: '2', version: '3' });

    expect(params).toEqual({ mode: 2, version: 3 });
    await expect(validateRequest({ params: schema }, { params })).resolves.toEqual({ params });
  });
});

describe('validateRequest', () => {
  it('is a no-op for fully contractless endpoints', async () => {
    await expect(validateRequest(undefined, {
      body: { legacy: true },
      query: { q: 'raw' },
      params: { id: 'raw' },
    })).resolves.toEqual({
      body: { legacy: true },
      query: { q: 'raw' },
      params: { id: 'raw' },
    });
  });

  it('no-op when no schemas are set', async () => {
    await expect(validateRequest({}, {})).resolves.toEqual({});
  });

  it('validates hand-authored JSON Schemas and aggregates locations', async () => {
    const input = {
      body: { type: 'object' as const, properties: { name: { type: 'string' as const } }, required: ['name'] },
      query: { type: 'object' as const, properties: { page: { type: 'integer' as const } }, required: ['page'] },
      params: { type: 'object' as const, properties: { id: { type: 'integer' as const } }, required: ['id'] },
    };

    try {
      await validateRequest(input, { body: {}, query: {}, params: {} });
      expect.unreachable();
    }
    catch (err) {
      expect(err).toMatchObject({ code: 'VALIDATION_ERROR', statusCode: 422 });
      const details = (err as FortressError).details as Array<{ location: string }>;
      expect(details.map(issue => issue.location)).toEqual(['body', 'query', 'params']);
    }
  });

  it('preserves definitions when validating a raw JSON Schema ref', async () => {
    const body = {
      $ref: '#/$defs/AdminBody',
      $defs: {
        AdminBody: {
          type: 'object',
          properties: { name: { type: 'string' } },
          required: ['name'],
        },
      },
    } as unknown as JSONSchema;

    await expect(validateRequest({ body }, { body: { name: 'admin' } })).resolves.toEqual({ body: { name: 'admin' } });
    await expect(
      validateRequest({ body }, { body: {} }),
    ).rejects.toMatchObject({ code: 'VALIDATION_ERROR', statusCode: 422 });
  });

  it('enforces component refs through a real IAM endpoint body', async () => {
    const input = iamEndpoints.createRole.input;
    await expect(validateRequest(input, {
      body: { name: 'editor', permissions: [{ resource: 'posts', action: 'read' }] },
    })).resolves.toEqual({
      body: { name: 'editor', permissions: [{ resource: 'posts', action: 'read' }] },
    });
    await expect(validateRequest(input, {
      body: { name: 'editor', permissions: [{ resource: 'posts' }] },
    })).rejects.toMatchObject({ code: 'VALIDATION_ERROR', statusCode: 422 });
  });

  it('validates body via bodySchema', async () => {
    const body = obj({ name: str() }, 'name');
    const input = {
      body: body as any,
      bodySchema: body,
    };

    await expect(validateRequest(input, { body: { name: 'Alice' } })).resolves.toEqual({ body: { name: 'Alice' } });

    try {
      await validateRequest(input, { body: {} });
      expect.unreachable();
    }
    catch (err) {
      expect(err).toBeInstanceOf(FortressError);
      expect((err as FortressError).code).toBe('VALIDATION_ERROR');
      expect((err as FortressError).statusCode).toBe(422);
      expect((err as FortressError).details).toBeDefined();
    }
  });

  it('validates query via querySchema', async () => {
    const query = obj({ q: str() }, 'q');
    const input = {
      query: query as any,
      querySchema: query,
    };

    await expect(validateRequest(input, { query: { q: 'hello' } })).resolves.toEqual({ query: { q: 'hello' } });

    try {
      await validateRequest(input, { query: {} });
      expect.unreachable();
    }
    catch (err) {
      expect((err as FortressError).code).toBe('VALIDATION_ERROR');
    }
  });

  it('validates params via paramsSchema', async () => {
    const params = obj({ id: int() }, 'id');
    // Note: int() does not coerce strings 2014 a string id rejects.
    const input = {
      params: params as any,
      paramsSchema: params,
    };

    await expect(validateRequest(input, { params: { id: 42 } })).resolves.toEqual({ params: { id: 42 } });

    try {
      await validateRequest(input, { params: {} });
      expect.unreachable();
    }
    catch (err) {
      expect((err as FortressError).code).toBe('VALIDATION_ERROR');
    }
  });

  it('returns transformed Standard Schema outputs and drops undeclared locations', async () => {
    const bodySchema = {
      '~standard': {
        version: 1 as const,
        vendor: 'test',
        validate: (value: unknown) => ({
          value: { normalized: String((value as { raw?: unknown }).raw ?? '').toUpperCase() },
        }),
      },
    };

    await expect(validateRequest({ bodySchema }, {
      body: { raw: 'hello' },
      query: { normalized: 'QUERY' },
      params: { normalized: 'PARAMS' },
    })).resolves.toEqual({
      body: { normalized: 'HELLO' },
    });
  });

  it('rejects a declared location whose validator returns a non-flat value', async () => {
    const bodySchema = {
      '~standard': {
        version: 1 as const,
        vendor: 'test',
        validate: () => ({ value: ['not', 'flat'] }),
      },
    };

    await expect(validateRequest({ bodySchema }, { body: {} })).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      statusCode: 422,
    });
  });

  it('collects errors from multiple inputs', async () => {
    const body = obj({ name: str() }, 'name');
    const query = obj({ q: str() }, 'q');
    const input = {
      body: body as any,
      bodySchema: body,
      query: query as any,
      querySchema: query,
    };

    try {
      await validateRequest(input, { body: {}, query: {} });
      expect.unreachable();
    }
    catch (err) {
      const details = (err as FortressError).details as any[];
      expect(details.length).toBe(2);
      expect(details[0].location).toBe('body');
      expect(details[1].location).toBe('query');
    }
  });
});
