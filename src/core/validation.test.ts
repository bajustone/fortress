import { describe, expect, it } from 'vitest';
import { FortressError } from './errors';
import { int, obj, str } from './schema-builder';
import { validateRequest } from './validation';

describe('validateRequest', () => {
  it('no-op when input is undefined', async () => {
    await expect(validateRequest(undefined, {})).resolves.toBeUndefined();
  });

  it('no-op when no schemas are set', async () => {
    await expect(validateRequest({ body: { type: 'object' } }, {})).resolves.toBeUndefined();
  });

  it('validates body via bodySchema', async () => {
    const body = obj({ name: str() }, 'name');
    const input = {
      body: body as any,
      bodySchema: body,
    };

    await expect(validateRequest(input, { body: { name: 'Alice' } })).resolves.toBeUndefined();

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

    await expect(validateRequest(input, { query: { q: 'hello' } })).resolves.toBeUndefined();

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
    const input = {
      params: params as any,
      paramsSchema: params,
    };

    await expect(validateRequest(input, { params: { id: 42 } })).resolves.toBeUndefined();

    try {
      await validateRequest(input, { params: {} });
      expect.unreachable();
    }
    catch (err) {
      expect((err as FortressError).code).toBe('VALIDATION_ERROR');
    }
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
