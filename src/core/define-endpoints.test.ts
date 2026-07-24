import type { CallClient } from './call-tree';
import type { CallOptions } from './http/call';
import { describe, expect, expectTypeOf, it } from 'vitest';
import { defineEndpoints } from './define-endpoints';
import { endpoint, obj, str } from './schema-builder';

const collection = defineEndpoints({
  greet: endpoint('POST', '/demo/greet')
    .body(obj({ name: str() }, 'name'))
    .response(200, 'Greeting', obj({ greeting: str() }, 'greeting'))
    .handler('greet')
    .build(),
  ping: endpoint('GET', '/demo/ping')
    .response(200, 'Pong', obj({ pong: str() }, 'pong'))
    .handler('ping')
    .build(),
});

describe('defineEndpoints', () => {
  it('returns the collection unchanged', () => {
    expect(Object.keys(collection)).toEqual(['greet', 'ping']);
    expect(collection.greet.method).toBe('POST');
    expect(collection.greet.handler).toBe('greet');
  });

  it('rejects non-endpoint members at runtime as defense in depth', () => {
    const notAnEndpoint = { summary: 'not an endpoint' };
    expect(() =>
      defineEndpoints({
        // @ts-expect-error -- a non-endpoint member fails on its own property
        broken: notAnEndpoint,
      }),
    ).toThrowError(/property 'broken' is not an endpoint definition/);
  });

  it('preserves exact keys, generics, and handler literals', () => {
    expectTypeOf(collection.greet.handler).toEqualTypeOf<'greet'>();
    // No string index signature is introduced: unknown keys are compile errors.
    // @ts-expect-error -- unknown member of an exact collection
    void collection.missing;
  });

  it('is directly consumable by CallClient without filtering', () => {
    type Client = CallClient<typeof collection>;
    expectTypeOf<Client['greet']>().toEqualTypeOf<
      (input: { name: string }, options?: CallOptions) => Promise<{ greeting: string }>
    >();
    expectTypeOf<Client['ping']>().returns.toEqualTypeOf<Promise<{ pong: string }>>();
    expectTypeOf<keyof Client>().toEqualTypeOf<'greet' | 'ping'>();
  });
});
