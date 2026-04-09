import type { InferOutput } from './validated';
import { Hono } from 'hono';
import { describe, expect, expectTypeOf, it } from 'vitest';
import { obj, str } from '../core/schema-builder';
import { createErrorHandler } from './middleware/error-handler';
import { vBody, vParam, vQuery } from './validated';

const CreateUserBody = obj({ name: str(), email: str() }, 'name', 'email');
const IdParam = obj({ id: str('User ID') }, 'id');
const SearchQuery = obj({ q: str('Search query'), page: str() }, 'q');

function createApp(): Hono {
  const app = new Hono();
  app.onError(createErrorHandler());

  app.post('/users', async (c) => {
    const body = await vBody(c, CreateUserBody);
    return c.json(body);
  });

  app.get('/users/:id', async (c) => {
    const params = await vParam(c, IdParam);
    return c.json(params);
  });

  app.get('/search', async (c) => {
    const query = await vQuery(c, SearchQuery);
    return c.json(query);
  });

  return app;
}

describe('vBody', () => {
  it('returns parsed JSON body when valid', async () => {
    const app = createApp();
    const res = await app.request('/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Alice', email: 'alice@test.com' }),
    });
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data).toEqual({ name: 'Alice', email: 'alice@test.com' });
  });

  it('returns 422 VALIDATION_ERROR when body is missing required fields', async () => {
    const app = createApp();
    const res = await app.request('/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Alice' }),
    });
    expect(res.status).toBe(422);
    const data = await res.json();
    expect(data.code).toBe('VALIDATION_ERROR');
    expect(Array.isArray(data.details)).toBe(true);
    expect(data.details.some((i: { location: string }) => i.location === 'body')).toBe(true);
  });

  it('returns 422 when body is not parseable JSON', async () => {
    const app = createApp();
    const res = await app.request('/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json',
    });
    expect(res.status).toBe(422);
    const data = await res.json();
    expect(data.code).toBe('VALIDATION_ERROR');
  });
});

describe('vParam', () => {
  it('returns route params when valid', async () => {
    const app = createApp();
    const res = await app.request('/users/42');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.id).toBe('42');
  });
});

describe('vQuery', () => {
  it('returns query parameters when valid', async () => {
    const app = createApp();
    const res = await app.request('/search?q=hello');
    expect(res.status).toBe(200);
    const data = await res.json();
    expect(data.q).toBe('hello');
  });

  it('returns 422 when required query field is missing', async () => {
    const app = createApp();
    const res = await app.request('/search');
    expect(res.status).toBe(422);
    const data = await res.json();
    expect(data.code).toBe('VALIDATION_ERROR');
    expect(data.details.some((i: { location: string }) => i.location === 'query')).toBe(true);
  });
});

describe('type inference', () => {
  it('infers vBody return type from schema', () => {
    const fn = (c: any) => vBody(c, CreateUserBody);
    expectTypeOf(fn).returns.resolves.toEqualTypeOf<{ name: string; email: string }>();
  });

  it('infers vParam return type from schema', () => {
    const fn = (c: any) => vParam(c, IdParam);
    expectTypeOf(fn).returns.resolves.toEqualTypeOf<{ id: string }>();
  });

  it('infers vQuery return type from schema', () => {
    const fn = (c: any) => vQuery(c, SearchQuery);
    expectTypeOf(fn).returns.resolves.toEqualTypeOf<{ q: string; page?: string }>();
  });

  it('exports InferOutput utility type', () => {
    type Expected = InferOutput<typeof CreateUserBody>;
    expectTypeOf<Expected>().toEqualTypeOf<{ name: string; email: string }>();
  });
});
