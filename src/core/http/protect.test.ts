import type { ApiKeyMethods } from '../../plugins/api-key';
import type { EndpointDefinition } from '../endpoint';
import type { FortressPlugin } from '../plugin';
import type { StandardSchemaV1 } from '../standard-schema';
import type { ProtectedRouteContext } from './protect';
import { describe, expect, it, vi } from 'vitest';
import { apiKey } from '../../plugins/api-key';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';
import { buildRouteManifest } from '../manifest/route-manifest';
import { endpoint, id, int, nullType, obj, str } from '../schema-builder';
import { protect } from './protect';

/** Compile-time assertion that two types are identical. */
type Expect<A, B> = [A] extends [B] ? ([B] extends [A] ? true : false) : false;

const secret = 'test-secret-minimum-32-bytes-long!!';

function testEndpoint(): EndpointDefinition {
  return {
    method: 'POST',
    path: '/host/things/:id',
    handler: 'createHostThing',
    meta: { summary: 'Create host thing', security: ['none'] },
    input: {
      body: obj({ name: str() }, 'name'),
      bodySchema: {
        '~standard': {
          version: 1,
          vendor: 'test',
          validate: (value: unknown) => ({
            value: { name: String((value as { name?: unknown }).name).toUpperCase() },
          }),
        },
      },
      query: obj({ draft: str() }),
      querySchema: obj({ draft: str() }),
      params: obj({ id: id() }, 'id'),
      paramsSchema: obj({ id: id() }, 'id'),
    },
    responses: {
      202: { description: 'Queued', schema: obj({ queued: str() }, 'queued') },
      201: { description: 'Created', schema: obj({ ok: str() }, 'ok') },
    },
  };
}

describe('protect()', () => {
  it('runs the pipeline and aligns the handler body with the lowest numeric success status', async () => {
    const calls: string[] = [];
    const ep = testEndpoint();
    const plugin: FortressPlugin = {
      name: 'host-middleware',
      middleware: [
        {
          path: '/host/things/:id',
          position: 'before-auth',
          handler: async (_ctx, _request, next) => {
            calls.push('before-auth');
            await next();
          },
        },
        {
          path: '/host/things/:id',
          position: 'after-auth',
          handler: async (_ctx, _request, next) => {
            calls.push('after-auth');
            await next();
          },
        },
        {
          path: '/host/things/:id',
          position: 'after-rbac',
          handler: async (_ctx, _request, next) => {
            calls.push('after-rbac');
            await next();
          },
        },
      ],
    };
    const fortress = createFortress({
      database: createTestAdapter(),
      jwt: { key: secret },
      csrf: { enabled: false },
      routes: { createHostThing: ep },
      plugins: [plugin],
    });

    const handler = protect(fortress, 'createHostThing', (ctx) => {
      expect(ctx.manifest.classification).toBe('public');
      expect(ctx.input).toEqual({ name: 'ALPHA', draft: 'true', id: '123' });
      expect(ctx.params).toEqual({ id: '123' });
      return { ok: 'yes' };
    });

    const res = await handler(new Request('http://localhost/host/things/123?draft=true', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'alpha' }),
    }));

    expect(res.status).toBe(201);
    expect(await res.json()).toEqual({ ok: 'yes' });
    expect(calls).toEqual(['before-auth', 'after-auth', 'after-rbac']);
  });

  it('authenticates JWTs and enforces RBAC for permission-only host handlers', async () => {
    const ep = {
      method: 'GET',
      path: '/reports/:id',
      handler: 'readReport',
      meta: {
        summary: 'Read report',
        permission: { resource: 'report', action: 'read' },
      },
      input: {
        params: obj({ id: id() }, 'id'),
        paramsSchema: obj({ id: id() }, 'id'),
      },
      responses: { 200: { description: 'OK' } },
    } as EndpointDefinition;
    const checked: unknown[] = [];
    const fortress = {
      endpoints: [ep],
      config: { plugins: [], csrf: { enabled: false }, database: createTestAdapter() },
      cookies: { accessName: 'fortress_access', refreshName: 'fortress_refresh' },
      get manifest() { return buildRouteManifest(this as any); },
      auth: {
        verifyToken: async () => ({
          sub: '7',
          subjectType: 'USER',
          name: 'User',
          groups: [],
          iss: 'test',
          iat: 1,
          exp: 2,
        }),
      },
      iam: {
        checkPermission: async (...args: unknown[]) => {
          checked.push(args);
          return true;
        },
      },
      extractAccessToken: (request: Request) => request.headers.get('authorization')?.replace('Bearer ', '') ?? null,
      serializeAuthCookies: () => [],
      logger: undefined,
    };

    const handler = protect(fortress as any, ep, ctx => ({ subject: ctx.subject, input: ctx.input }));
    const res = await handler(new Request('http://localhost/reports/42', {
      headers: { Authorization: 'Bearer token' },
    }));

    expect(res.status).toBe(200);
    expect(await res.json()).toEqual({
      subject: { type: 'USER', id: '7' },
      input: { id: '42' },
    });
    expect(checked).toHaveLength(1);
    expect(checked[0]).toEqual([{ type: 'USER', id: '7' }, 'report', 'read', { credentialScopes: undefined }]);
  });

  it('matches handleRequest semantics for API-key-authenticated-only host handlers', async () => {
    const ep = endpoint('GET', '/host/api-key-identity')
      .summary('API key identity')
      .security('apiKey')
      .response(200, 'Identity', obj({ type: str(), id: str() }, 'type', 'id'))
      .handler('apiKeyIdentity')
      .build();
    const fortress = createFortress({
      database: createTestAdapter(),
      jwt: { key: secret },
      csrf: { enabled: false },
      routes: { apiKeyIdentity: ep },
      plugins: [apiKey({ prefix: 'protect' })],
    });
    const user = await fortress.auth.createUser({
      email: 'protect-api-key@example.com',
      name: 'Protect API Key',
      password: 'password-123456',
    });
    const login = await fortress.auth.login('protect-api-key@example.com', 'password-123456');
    if (login.status !== 'success')
      throw new Error('expected login success');
    const apiKeys = fortress.plugins['api-key'] as unknown as ApiKeyMethods;
    const { key } = await apiKeys.createKey({
      subject: { type: 'USER', id: user.id },
      name: 'Protect key',
    });
    const checkPermission = vi.fn(async () => true);
    fortress.iam.checkPermission = checkPermission;
    const callback = vi.fn((ctx: ProtectedRouteContext<typeof ep>) => ({
      type: ctx.subject!.type,
      id: ctx.subject!.id,
    }));
    const handler = protect(fortress, ep, callback);

    const valid = await handler(new Request('http://localhost/host/api-key-identity', {
      headers: { 'x-api-key': key },
    }));
    expect(valid.status).toBe(200);
    await expect(valid.json()).resolves.toEqual({ type: 'USER', id: user.id });
    expect(checkPermission).not.toHaveBeenCalled();

    callback.mockClear();
    const missing = await handler(new Request('http://localhost/host/api-key-identity'));
    const invalid = await handler(new Request('http://localhost/host/api-key-identity', {
      headers: { authorization: 'ApiKey protect_sk_invalid' },
    }));
    const bearer = await handler(new Request('http://localhost/host/api-key-identity', {
      headers: { authorization: `Bearer ${login.accessToken}` },
    }));
    expect(missing.status).toBe(401);
    expect(invalid.status).toBe(401);
    expect(bearer.status).toBe(401);
    expect(callback).not.toHaveBeenCalled();
    expect(checkPermission).not.toHaveBeenCalled();
  });

  it('attaches auth cookies for token-shaped handler results', async () => {
    const ep = testEndpoint();
    const fortress = createFortress({
      database: createTestAdapter(),
      jwt: { key: secret },
      csrf: { enabled: false },
      routes: { createHostThing: ep },
      cookies: { secure: false },
    });

    const handler = protect(fortress, ep, () => ({ accessToken: 'access', refreshToken: 'refresh' }));
    const res = await handler(new Request('http://localhost/host/things/1', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'alpha' }),
    }));

    expect(res.headers.getSetCookie().length).toBeGreaterThanOrEqual(2);
  });

  it('preserves explicit null and emits bodyless 205 responses', async () => {
    const nullable = endpoint('GET', '/host/nullable')
      .security('none')
      .response(200, 'Null', nullType())
      .handler('nullable')
      .build();
    const reset = endpoint('POST', '/host/reset')
      .security('none')
      .response(205, 'Reset content')
      .handler('reset')
      .build();
    const fortress = createFortress({
      database: createTestAdapter(),
      jwt: { key: secret },
      csrf: { enabled: false },
      routes: { nullable, reset },
    });

    const nullResponse = await protect(fortress, nullable, () => null)(
      new Request('http://localhost/host/nullable'),
    );
    expect(nullResponse.status).toBe(200);
    expect(await nullResponse.json()).toBeNull();

    const resetResponse = await protect(fortress, reset, () => undefined)(
      new Request('http://localhost/host/reset', { method: 'POST' }),
    );
    expect(resetResponse.status).toBe(205);
    expect(resetResponse.headers.has('content-type')).toBe(false);
    expect(await resetResponse.text()).toBe('');
  });

  it('exposes ctx.respond for typed non-success status returns', async () => {
    const ep = testEndpoint();
    const fortress = createFortress({
      database: createTestAdapter(),
      jwt: { key: secret },
      csrf: { enabled: false },
      routes: { createHostThing: ep },
      cookies: { secure: false },
    });

    const handler = protect(fortress, ep, (ctx) => {
      return ctx.respond(404, { code: 'NOT_FOUND', message: 'no thing', statusCode: 404 } as any);
    });

    const res = await handler(new Request('http://localhost/host/things/1', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ name: 'alpha' }),
    }));

    expect(res.status).toBe(404);
    expect(await res.json()).toEqual({ code: 'NOT_FOUND', message: 'no thing', statusCode: 404 });
  });

  it('drops undeclared query and params before building protected input', async () => {
    const ep = endpoint('POST', '/host/declared-only/:role')
      .security('none')
      .body(obj({ role: str() }, 'role'))
      .response(200, 'OK', obj({ role: str() }, 'role'))
      .handler('declaredOnly')
      .build();
    const fortress = createFortress({
      database: createTestAdapter(),
      jwt: { key: secret },
      csrf: { enabled: false },
      routes: { declaredOnly: ep },
    });
    let seen: unknown;
    const handler = protect(fortress, ep, (ctx) => {
      seen = { input: ctx.input, query: ctx.query, params: ctx.params };
      return ctx.input;
    });

    const response = await handler(new Request('http://localhost/host/declared-only/path?role=query', {
      method: 'POST',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ role: 'member' }),
    }));

    expect(response.status).toBe(200);
    expect(await response.json()).toEqual({ role: 'member' });
    expect(seen).toEqual({ input: { role: 'member' }, query: {}, params: {} });
  });

  it('types transforming schema call input as wire data and protected context as validated output', () => {
    const transformingSchema: StandardSchemaV1<
      { occurredAt: string },
      { occurredAt: Date }
    > & {
      readonly type: 'object';
      readonly properties: { readonly occurredAt: { readonly type: 'string' } };
    } = {
      'type': 'object',
      'properties': { occurredAt: { type: 'string' } },
      '~standard': {
        version: 1,
        vendor: 'transform-test',
        validate: value => ({
          value: { occurredAt: new Date((value as { occurredAt: string }).occurredAt) },
        }),
        types: undefined,
      },
    };
    const transformed = endpoint('POST', '/transformed')
      .body(transformingSchema)
      .handler('transformed')
      .build();
    type TransformedCtx = ProtectedRouteContext<typeof transformed>;
    const _bodyOutput: Expect<TransformedCtx['body'], { occurredAt: Date }> = true;
    const _inputOutput: Expect<TransformedCtx['input'], { occurredAt: Date }> = true;

    expect(transformed.handler).toBe('transformed');
    expect(_bodyOutput).toBe(true);
    expect(_inputOutput).toBe(true);
  });

  it('narrows ctx.body to non-optional T when a body schema is declared (type-level)', () => {
    const withBody = endpoint('POST', '/things')
      .body(obj({ name: str() }, 'name'))
      .response(201, 'Created', obj({ ok: str() }, 'ok'))
      .handler('createThing')
      .build();
    const noBody = endpoint('GET', '/things/:id')
      .params(obj({ id: int() }, 'id'))
      .response(200, 'OK', obj({ ok: str() }, 'ok'))
      .handler('getThing')
      .build();

    type WithBodyCtx = ProtectedRouteContext<typeof withBody>;
    type NoBodyCtx = ProtectedRouteContext<typeof noBody>;

    // Declared body schema → non-optional `{ name: string }` (no `| undefined`).
    const _bodyNonOptional: Expect<WithBodyCtx['body'], { name: string }> = true;
    // No body schema → loose `unknown`.
    const _bodyLoose: Expect<NoBodyCtx['body'], unknown> = true;

    // Touch the runtime values so they aren't flagged as type-only.
    expect(withBody.handler).toBe('createThing');
    expect(noBody.handler).toBe('getThing');
    expect(_bodyNonOptional).toBe(true);
    expect(_bodyLoose).toBe(true);
  });
});
