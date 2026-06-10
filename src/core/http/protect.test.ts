import type { EndpointDefinition } from '../endpoint';
import type { FortressPlugin } from '../plugin';
import { describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';
import { buildRouteManifest } from '../manifest/route-manifest';
import { int, obj, str } from '../schema-builder';
import { protect } from './protect';

const secret = 'test-secret-minimum-32-bytes-long!!';

function testEndpoint(): EndpointDefinition {
  return {
    method: 'POST',
    path: '/host/things/:id',
    handler: 'createHostThing',
    meta: { summary: 'Create host thing', security: ['none'] },
    input: {
      body: obj({ name: str() }, 'name'),
      bodySchema: obj({ name: str() }, 'name'),
      query: obj({ draft: str() }),
      querySchema: obj({ draft: str() }),
      params: obj({ id: int() }, 'id'),
      paramsSchema: obj({ id: int() }, 'id'),
    },
    responses: { 201: { description: 'Created', schema: obj({ ok: str() }, 'ok') } },
  };
}

describe('protect()', () => {
  it('runs plugin middleware, validates/coerces input, and calls the host handler', async () => {
    const calls: string[] = [];
    const ep = testEndpoint();
    const plugin: FortressPlugin = {
      name: 'host-routes',
      routes: { createHostThing: ep },
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
      jwt: { secret },
      csrf: { enabled: false },
      plugins: [plugin],
    });

    const handler = protect(fortress, 'createHostThing', (ctx) => {
      expect(ctx.manifest.classification).toBe('public');
      expect(ctx.input).toEqual({ name: 'alpha', draft: 'true', id: 123 });
      expect(ctx.params).toEqual({ id: 123 });
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

  it('enforces bearer auth and RBAC from endpoint metadata on host-owned handlers', async () => {
    const ep = {
      method: 'GET',
      path: '/reports/:id',
      handler: 'readReport',
      meta: {
        summary: 'Read report',
        security: ['bearer'],
        permission: { resource: 'report', action: 'read' },
      },
      input: {
        params: obj({ id: int() }, 'id'),
        paramsSchema: obj({ id: int() }, 'id'),
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
          sub: 7,
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
      subject: { type: 'USER', id: 7 },
      input: { id: 42 },
    });
    expect(checked).toHaveLength(1);
    expect(checked[0]).toEqual([{ type: 'USER', id: 7 }, 'report', 'read', { credentialScopes: undefined }]);
  });

  it('attaches auth cookies for token-shaped handler results', async () => {
    const ep = testEndpoint();
    const fortress = createFortress({
      database: createTestAdapter(),
      jwt: { secret },
      csrf: { enabled: false },
      plugins: [{ name: 'host-routes', routes: { createHostThing: ep } }],
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
      jwt: { secret },
      csrf: { enabled: false },
      plugins: [{ name: 'host-routes', routes: { createHostThing: ep } }],
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
});
