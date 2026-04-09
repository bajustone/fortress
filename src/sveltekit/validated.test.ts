import type { SvelteKitRequestEvent } from './types';
import type { InferOutput } from './validated';
import { describe, expect, expectTypeOf, it } from 'vitest';
import { FortressError } from '../core/errors';
import { obj, str } from '../core/schema-builder';
import { vBody, vParam, vQuery } from './validated';

const CreateUserBody = obj({ name: str(), email: str() }, 'name', 'email');
const IdParam = obj({ id: str('User ID') }, 'id');
const SearchQuery = obj({ q: str('Search query'), page: str() }, 'q');

function fakeEvent(opts: {
  body?: unknown;
  params?: Record<string, string>;
  url?: string;
}): SvelteKitRequestEvent {
  const url = new URL(opts.url ?? 'http://localhost/');
  const request = new Request(url, {
    method: opts.body !== undefined ? 'POST' : 'GET',
    headers: opts.body !== undefined ? { 'Content-Type': 'application/json' } : {},
    body: opts.body !== undefined ? JSON.stringify(opts.body) : undefined,
  });
  return {
    request,
    url,
    cookies: { get: () => undefined, set: () => {}, delete: () => {} },
    locals: {} as any,
    params: opts.params ?? {},
  };
}

describe('vBody', () => {
  it('returns parsed JSON body when valid', async () => {
    const event = fakeEvent({ body: { name: 'Alice', email: 'alice@test.com' } });
    const data = await vBody(event, CreateUserBody);
    expect(data).toEqual({ name: 'Alice', email: 'alice@test.com' });
  });

  it('throws VALIDATION_ERROR when body is missing required fields', async () => {
    const event = fakeEvent({ body: { name: 'Alice' } });
    await expect(vBody(event, CreateUserBody)).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      statusCode: 422,
    });
  });

  it('throws VALIDATION_ERROR when body is unparseable', async () => {
    const url = new URL('http://localhost/');
    const request = new Request(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: 'not json',
    });
    const event: SvelteKitRequestEvent = {
      request,
      url,
      cookies: { get: () => undefined, set: () => {}, delete: () => {} },
      locals: {} as any,
      params: {},
    };
    await expect(vBody(event, CreateUserBody)).rejects.toBeInstanceOf(FortressError);
  });
});

describe('vParam', () => {
  it('returns route params when valid', async () => {
    const event = fakeEvent({ params: { id: '42' } });
    const data = await vParam(event, IdParam);
    expect(data.id).toBe('42');
  });

  it('throws VALIDATION_ERROR when required param missing', async () => {
    const event = fakeEvent({ params: {} });
    await expect(vParam(event, IdParam)).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      statusCode: 422,
    });
  });
});

describe('vQuery', () => {
  it('returns query parameters when valid', async () => {
    const event = fakeEvent({ url: 'http://localhost/?q=hello' });
    const data = await vQuery(event, SearchQuery);
    expect(data.q).toBe('hello');
  });

  it('throws VALIDATION_ERROR when required query field missing', async () => {
    const event = fakeEvent({ url: 'http://localhost/' });
    await expect(vQuery(event, SearchQuery)).rejects.toMatchObject({
      code: 'VALIDATION_ERROR',
      statusCode: 422,
    });
  });
});

describe('type inference', () => {
  it('infers vBody return type from schema', () => {
    const fn = (e: SvelteKitRequestEvent) => vBody(e, CreateUserBody);
    expectTypeOf(fn).returns.resolves.toEqualTypeOf<{ name: string; email: string }>();
  });

  it('infers vParam return type from schema', () => {
    const fn = (e: SvelteKitRequestEvent) => vParam(e, IdParam);
    expectTypeOf(fn).returns.resolves.toEqualTypeOf<{ id: string }>();
  });

  it('infers vQuery return type from schema', () => {
    const fn = (e: SvelteKitRequestEvent) => vQuery(e, SearchQuery);
    expectTypeOf(fn).returns.resolves.toEqualTypeOf<{ q: string; page?: string }>();
  });

  it('exports InferOutput utility type', () => {
    type Expected = InferOutput<typeof CreateUserBody>;
    expectTypeOf<Expected>().toEqualTypeOf<{ name: string; email: string }>();
  });
});
