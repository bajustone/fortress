import type { ExpressRequestLike, InferOutput } from './validated';
import { describe, expect, expectTypeOf, it } from 'vitest';
import { obj, str } from '../core/schema-builder';
import { vBody, vParam, vQuery } from './validated';

const CreateUserBody = obj({ name: str(), email: str() }, 'name', 'email');
const IdParam = obj({ id: str('User ID') }, 'id');
const SearchQuery = obj({ q: str('Search query'), page: str() }, 'q');

describe('vBody', () => {
  it('returns parsed body when valid', async () => {
    const req: ExpressRequestLike = { body: { name: 'Alice', email: 'alice@test.com' } };
    const data = await vBody(req, CreateUserBody);
    expect(data).toEqual({ name: 'Alice', email: 'alice@test.com' });
  });

  it('throws VALIDATION_ERROR when body is missing required fields', async () => {
    const req: ExpressRequestLike = { body: { name: 'Alice' } };
    await expect(vBody(req, CreateUserBody)).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      statusCode: 422,
    });
  });

  it('throws VALIDATION_ERROR when body is undefined', async () => {
    const req: ExpressRequestLike = {};
    await expect(vBody(req, CreateUserBody)).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      statusCode: 422,
    });
  });
});

describe('vParam', () => {
  it('returns route params when valid', async () => {
    const req: ExpressRequestLike = { params: { id: '42' } };
    const data = await vParam(req, IdParam);
    expect(data.id).toBe('42');
  });

  it('throws VALIDATION_ERROR when required param missing', async () => {
    const req: ExpressRequestLike = { params: {} };
    await expect(vParam(req, IdParam)).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      statusCode: 422,
    });
  });
});

describe('vQuery', () => {
  it('returns query parameters when valid', async () => {
    const req: ExpressRequestLike = { query: { q: 'hello' } };
    const data = await vQuery(req, SearchQuery);
    expect(data.q).toBe('hello');
  });

  it('throws VALIDATION_ERROR when required query field missing', async () => {
    const req: ExpressRequestLike = { query: {} };
    await expect(vQuery(req, SearchQuery)).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      statusCode: 422,
    });
  });
});

describe('type inference', () => {
  it('infers vBody return type from schema', () => {
    const fn = (r: ExpressRequestLike) => vBody(r, CreateUserBody);
    expectTypeOf(fn).returns.resolves.toEqualTypeOf<{ name: string; email: string }>();
  });

  it('infers vParam return type from schema', () => {
    const fn = (r: ExpressRequestLike) => vParam(r, IdParam);
    expectTypeOf(fn).returns.resolves.toEqualTypeOf<{ id: string }>();
  });

  it('infers vQuery return type from schema', () => {
    const fn = (r: ExpressRequestLike) => vQuery(r, SearchQuery);
    expectTypeOf(fn).returns.resolves.toEqualTypeOf<{ q: string; page?: string }>();
  });

  it('exports InferOutput utility type', () => {
    type Expected = InferOutput<typeof CreateUserBody>;
    expectTypeOf<Expected>().toEqualTypeOf<{ name: string; email: string }>();
  });
});
