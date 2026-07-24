import type { EndpointDefinition } from '../endpoint';
import type { FortressPlugin } from '../plugin';
import type { ProtectedRouteContext } from './protect';
import { describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';
import { buildRouteManifest } from '../manifest/route-manifest';
import { endpoint, id, int, obj, str } from '../schema-builder';
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
