import type { EndpointDefinition } from '../endpoint';
import type { FortressPlugin, PluginRouteContext } from '../plugin';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';
import { definePlugin } from '../plugin';
import { endpoint, nullType, obj, str } from '../schema-builder';

const SECRET = 'fortress-test-secret-at-least-32-bytes-long!';

function makeFortress() {
  return createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
  });
}

interface AuthBody {
  status: string;
  user: { id: string; email: string };
  accessToken: string;
  refreshToken: string;
}

describe('fortress.handleRequest', () => {
  let fortress: ReturnType<typeof makeFortress>;

  beforeEach(() => {
    fortress = makeFortress();
  });

  describe('public endpoints', () => {
    it('creates a user via POST /auth/register (201)', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/auth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'a@b.co', name: 'Alice', password: 'password1234567' }),
      }));
      expect(res.status).toBe(201);
      const body = await res.json() as { id: string; email: string };
      expect(body.email).toBe('a@b.co');
    });

    it('returns tokens AND sets cookies on successful POST /auth/login', async () => {
      // create user via service to skip the http-layer registration above
      await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password1234567' });

      const res = await fortress.handleRequest(new Request('http://localhost/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ identifier: 'a@b.co', password: 'password1234567' }),
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as AuthBody;
      expect(typeof body.accessToken).toBe('string');
      expect(typeof body.refreshToken).toBe('string');

      const setCookies = res.headers.getSetCookie();
      expect(setCookies.length).toBe(2);
      expect(setCookies.some(c => c.startsWith(`${fortress.cookies.accessName}=`))).toBe(true);
      expect(setCookies.some(c => c.startsWith(`${fortress.cookies.refreshName}=`))).toBe(true);
    });

    it('returns 401 from POST /auth/login with bad creds', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ identifier: 'nope@b.co', password: 'wrong' }),
      }));
      expect(res.status).toBe(401);
      const body = await res.json() as { code: string };
      expect(body.code).toBe('UNAUTHORIZED');
      // No cookies on a failed login
      expect(res.headers.getSetCookie().length).toBe(0);
    });

    it('returns 404 for unknown endpoints', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/nope/whatever'));
      expect(res.status).toBe(404);
    });
  });

  describe('bearer-protected endpoints', () => {
    let accessToken: string;

    beforeEach(async () => {
      await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password1234567' });
      const result = await fortress.auth.login('a@b.co', 'password1234567');
      if (result.status !== 'success')
        throw new Error('expected success');
      accessToken = result.accessToken;
    });

    it('returns 401 from GET /auth/me without a token', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/auth/me'));
      expect(res.status).toBe(401);
    });

    it('returns the user from GET /auth/me with Bearer token', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/auth/me', {
        headers: { authorization: `Bearer ${accessToken}` },
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as { email: string };
      expect(body.email).toBe('a@b.co');
    });

    it('reads the token from the configured cookie on GET /auth/me', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/auth/me', {
        headers: { cookie: `${fortress.cookies.accessName}=${accessToken}` },
      }));
      expect(res.status).toBe(200);
    });
  });

  describe('refresh flow', () => {
    it('issues new tokens AND sets new cookies on POST /auth/refresh', async () => {
      await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password1234567' });
      const login = await fortress.auth.login('a@b.co', 'password1234567');
      if (login.status !== 'success')
        throw new Error('expected success');

      const res = await fortress.handleRequest(new Request('http://localhost/auth/refresh', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ refreshToken: login.refreshToken }),
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as { accessToken: string; refreshToken: string };
      expect(typeof body.accessToken).toBe('string');
      expect(typeof body.refreshToken).toBe('string');
      expect(body.refreshToken).not.toBe(login.refreshToken); // rotated

      const setCookies = res.headers.getSetCookie();
      expect(setCookies.length).toBe(2);
    });
  });

  describe('logout flow', () => {
    it('revokes the refresh token and clears both configured auth cookies', async () => {
      await fortress.auth.createUser({ email: 'logout@b.co', name: 'Logout', password: 'password1234567' });
      const login = await fortress.auth.login('logout@b.co', 'password1234567');
      if (login.status !== 'success')
        throw new Error('expected success');

      const res = await fortress.handleRequest(new Request('http://localhost/auth/logout', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ refreshToken: login.refreshToken }),
      }));
      expect(res.status).toBe(200);
      const setCookies = res.headers.getSetCookie();
      expect(setCookies).toHaveLength(2);
      expect(setCookies).toEqual(expect.arrayContaining([
        expect.stringMatching(new RegExp(`^${fortress.cookies.accessName}=;.*Max-Age=0`)),
        expect.stringMatching(new RegExp(`^${fortress.cookies.refreshName}=;.*Max-Age=0`)),
      ]));
      for (const cookie of setCookies) {
        expect(cookie).toMatch(/Expires=[^;]+GMT/);
        expect(cookie).toContain('Path=/');
        expect(cookie).toContain('HttpOnly');
      }
      await expect(fortress.auth.refresh(login.refreshToken)).rejects.toMatchObject({ code: 'TOKEN_REUSE' });
    });
  });

  describe('iam endpoints (bearer + permission)', () => {
    let accessToken: string;

    beforeEach(async () => {
      // (Skipping syncResources here — without resources synced, checkPermission
      // returns false, which is exactly what we want to assert default-deny.)
      await fortress.auth.createUser({ email: 'admin@x.co', name: 'Admin', password: 'password1234567' });
      const result = await fortress.auth.login('admin@x.co', 'password1234567');
      if (result.status !== 'success')
        throw new Error('expected success');
      accessToken = result.accessToken;
    });

    it('returns 403 from POST /iam/roles without permission', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/iam/roles', {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${accessToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: 'editor', permissions: [] }),
      }));
      expect(res.status).toBe(403);
    });
  });

  describe('validation', () => {
    it('returns 422 when required fields are missing', async () => {
      // /auth/login requires identifier + password
      const res = await fortress.handleRequest(new Request('http://localhost/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      }));
      expect(res.status).toBe(422);
      const body = await res.json() as { code: string };
      expect(body.code).toBe('VALIDATION_ERROR');
    });
  });

  describe('plugin success serialization', () => {
    const responseShapes = definePlugin({
      name: 'response-shapes',
      methods: () => ({
        explicitNull: () => null,
        htmlAccepted: () => '<!DOCTYPE html><title>Accepted</title>',
        noContent: () => undefined,
      }),
      routes: {
        explicitNull: endpoint('GET', '/response-shapes/null')
          .security('none')
          .response(200, 'Explicit null', nullType())
          .handler('explicitNull')
          .build(),
        htmlAccepted: endpoint('GET', '/response-shapes/html')
          .security('none')
          .response(202, 'Accepted HTML', str())
          .handler('htmlAccepted')
          .build(),
        noContent: endpoint('GET', '/response-shapes/no-content')
          .security('none')
          .response(204, 'No content')
          .handler('noContent')
          .build(),
      },
    });

    it('preserves explicit null through dispatch and the typed call client', async () => {
      const local = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [responseShapes] as const,
      });

      const result: null = await local.call.plugins['response-shapes'].explicitNull();
      expect(result).toBeNull();
      const response = await local.handleRequest(new Request('http://localhost/response-shapes/null'));
      expect(response.status).toBe(200);
      expect(await response.json()).toBeNull();
    });

    it('uses the declared success status for HTML responses', async () => {
      const local = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [responseShapes] as const,
      });

      const response = await local.handleRequest(new Request('http://localhost/response-shapes/html'));
      expect(response.status).toBe(202);
      expect(response.headers.get('content-type')).toBe('text/html; charset=utf-8');
      expect(await response.text()).toBe('<!DOCTYPE html><title>Accepted</title>');
    });

    it('emits bodyless 204 responses', async () => {
      const local = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [responseShapes] as const,
      });

      const response = await local.handleRequest(new Request('http://localhost/response-shapes/no-content'));
      expect(response.status).toBe(204);
      expect(response.headers.has('content-type')).toBe(false);
      expect(await response.text()).toBe('');
    });
  });

  describe('plugin route context', () => {
    // A spy plugin that records whatever `PluginRouteContext` the dispatcher
    // hands it. Verifies that handlers see the verified caller id, claims,
    // request meta, and the raw Request.
    function makeSpyPlugin(): { plugin: FortressPlugin; received: PluginRouteContext[] } {
      const received: PluginRouteContext[] = [];
      const plugin: FortressPlugin = {
        name: 'spy',
        routes: {
          echo: {
            method: 'POST',
            path: '/spy/echo',
            handler: 'echo',
            meta: { summary: 'Echo caller', tags: ['Test'], security: ['bearer'] },
            responses: { 200: { description: 'ok' } },
          },
          publicEcho: {
            method: 'GET',
            path: '/spy/public',
            handler: 'publicEcho',
            meta: { summary: 'Public echo', tags: ['Test'], security: ['none'] },
            responses: { 200: { description: 'ok' } },
          },
          permissionOnly: {
            method: 'GET',
            path: '/spy/permission-only',
            handler: 'permissionOnly',
            meta: {
              summary: 'Permission only',
              tags: ['Test'],
              permission: { resource: 'spy', action: 'read' },
            },
            responses: { 200: { description: 'ok' } },
          },
        },
        methods: () => ({
          echo(_body: unknown, ctx: PluginRouteContext): { ok: true } {
            received.push(ctx);
            return { ok: true };
          },
          publicEcho(_body: unknown, ctx: PluginRouteContext): { ok: true } {
            received.push(ctx);
            return { ok: true };
          },
          permissionOnly(_body: unknown, ctx: PluginRouteContext): { ok: true } {
            received.push(ctx);
            return { ok: true };
          },
        }),
      };
      return { plugin, received };
    }

    it('passes verified userId, claims, meta, and request to plugin handlers', async () => {
      const { plugin, received } = makeSpyPlugin();
      const spyFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [plugin],
      });

      const user = await spyFortress.auth.createUser({
        email: 'spy@b.co',
        name: 'Spy',
        password: 'password1234567',
      });
      const login = await spyFortress.auth.login('spy@b.co', 'password1234567');
      if (login.status !== 'success')
        throw new Error('expected success');

      const res = await spyFortress.handleRequest(new Request('http://localhost/spy/echo', {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${login.accessToken}`,
          'content-type': 'application/json',
          'x-forwarded-for': '10.0.0.5',
          'user-agent': 'spy-agent/1.0',
        },
        body: JSON.stringify({ hello: 'world' }),
      }));
      expect(res.status).toBe(200);

      expect(received).toHaveLength(1);
      const ctx = received[0]!;
      expect(ctx.userId).toBe(user.id);
      expect(ctx.claims?.sub).toBe(user.id);
      expect(ctx.meta?.ipAddress).toBe('10.0.0.5');
      expect(ctx.meta?.userAgent).toBe('spy-agent/1.0');
      expect(ctx.request).toBeInstanceOf(Request);
      expect(new URL(ctx.request.url).pathname).toBe('/spy/echo');
    });

    it('authenticates JWTs for permission-only routes without explicit bearer metadata', async () => {
      const { plugin, received } = makeSpyPlugin();
      const spyFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [plugin],
      });
      const user = await spyFortress.auth.createUser({
        email: 'permission-only@b.co',
        name: 'Permission Only',
        password: 'password1234567',
      });
      const login = await spyFortress.auth.login('permission-only@b.co', 'password1234567');
      if (login.status !== 'success')
        throw new Error('expected success');

      let checkedSubject: { type: string; id: string } | undefined;
      spyFortress.iam.checkPermission = async (subject) => {
        checkedSubject = subject;
        return true;
      };
      const allowed = await spyFortress.handleRequest(new Request(
        'http://localhost/spy/permission-only',
        { headers: { authorization: `Bearer ${login.accessToken}` } },
      ));
      expect(allowed.status).toBe(200);
      expect(checkedSubject).toEqual({ type: 'USER', id: user.id });
      expect(received[0]?.userId).toBe(user.id);

      const missing = await spyFortress.handleRequest(new Request('http://localhost/spy/permission-only'));
      expect(missing.status).toBe(401);
      spyFortress.iam.checkPermission = async () => false;
      const denied = await spyFortress.handleRequest(new Request(
        'http://localhost/spy/permission-only',
        { headers: { authorization: `Bearer ${login.accessToken}` } },
      ));
      expect(denied.status).toBe(403);
    });

    it('dispatches merged JSON body, query, and schema-coerced params to plugin handlers', async () => {
      let received: Record<string, unknown> | undefined;
      const plugin: FortressPlugin = {
        name: 'merged-input',
        routes: {
          merge: {
            method: 'POST',
            path: '/merged/:count/:enabled',
            handler: 'merge',
            meta: { summary: 'Merged input', security: ['none'] },
            input: {
              body: {
                type: 'object',
                properties: { message: { type: 'string' } },
                required: ['message'],
              },
              bodySchema: {
                '~standard': {
                  version: 1,
                  vendor: 'test',
                  validate: (value: unknown) => ({
                    value: { message: String((value as { message?: unknown }).message).toUpperCase() },
                  }),
                },
              },
              query: {
                type: 'object',
                properties: { limit: { type: 'integer' } },
                required: ['limit'],
              },
              params: {
                type: 'object',
                properties: { count: { type: 'integer' }, enabled: { type: 'boolean' } },
                required: ['count', 'enabled'],
              },
            },
            responses: { 200: { description: 'ok' } },
          },
        },
        methods: () => ({
          merge: async (input: Record<string, unknown>) => {
            received = input;
            return { ok: true };
          },
        }),
      };
      const f = createFortress({ jwt: { key: SECRET }, database: createTestAdapter(), plugins: [plugin] });
      const res = await f.handleRequest(new Request('http://localhost/merged/3/true?limit=2', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ message: 'hello' }),
      }));

      expect(res.status).toBe(200);
      expect(received).toEqual({ message: 'HELLO', limit: 2, count: 3, enabled: true });
    });

    it('does not merge undeclared query or params over a validated body', async () => {
      let received: { role: string } | undefined;
      const plugin = definePlugin({
        name: 'declared-input-only',
        methods: () => ({
          accept: (input: { role: string }) => {
            received = input;
            return { ok: 'yes' };
          },
        }),
        routes: {
          accept: endpoint('POST', '/declared-input-only/:role')
            .security('none')
            .body(obj({ role: str() }, 'role'))
            .response(200, 'Accepted', obj({ ok: str() }))
            .handler('accept')
            .build(),
        },
      });
      const f = createFortress({ jwt: { key: SECRET }, database: createTestAdapter(), plugins: [plugin] });
      const res = await f.handleRequest(new Request('http://localhost/declared-input-only/path?role=query', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ role: 'member' }),
      }));

      expect(res.status).toBe(200);
      expect(received).toEqual({ role: 'member' });
    });

    it('passes request + meta but leaves userId/claims undefined on public routes', async () => {
      const { plugin, received } = makeSpyPlugin();
      const spyFortress = createFortress({
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [plugin],
      });

      const res = await spyFortress.handleRequest(new Request('http://localhost/spy/public', {
        headers: { 'user-agent': 'anon-agent/1.0' },
      }));
      expect(res.status).toBe(200);

      expect(received).toHaveLength(1);
      const ctx = received[0]!;
      expect(ctx.userId).toBeUndefined();
      expect(ctx.claims).toBeUndefined();
      expect(ctx.meta?.userAgent).toBe('anon-agent/1.0');
      expect(ctx.request).toBeInstanceOf(Request);
    });
  });

  // Regression for the host-app shim that TDMP had to ship across the
  // 0.0.42 → 0.1.0 upgrade: a custom route under /oauth/* with
  // `security: ['bearer']` and no `bearerKind` MUST go through fortress's
  // normal auth pipeline (JWT validation), not the OAuth-protocol
  // self-managed bypass. The bypass is now opt-in via
  // `meta.bearerKind: 'oauth'`.
  describe('bearerKind: \'jwt\' default for /oauth/* routes', () => {
    function makeOauthBearerPlugin(includeForbiddenSelfAuth = false): { plugin: FortressPlugin; received: PluginRouteContext[] } {
      const received: PluginRouteContext[] = [];
      const routes: Record<string, EndpointDefinition> = {
        jwtRoute: {
          method: 'POST',
          path: '/oauth/host-app/jwt-route',
          handler: 'jwtRoute',
          // No `bearerKind` — should default to 'jwt' and require auth.
          meta: { summary: 'Host app JWT route under /oauth/*', tags: ['Test'], security: ['bearer'] },
          responses: { 200: { description: 'ok' } },
        },
      };
      if (includeForbiddenSelfAuth) {
        routes.oauthRoute = {
          method: 'POST',
          path: '/oauth/host-app/oauth-route',
          handler: 'oauthRoute',
          // P3.6 hardening: arbitrary plugin routes may no longer opt out of
          // the auth pipeline with bearerKind:'oauth'. Only known OAuth
          // protocol routes are allowed to self-auth.
          meta: { summary: 'Host app OAuth route under /oauth/*', tags: ['Test'], security: ['bearer'], bearerKind: 'oauth' as const },
          responses: { 200: { description: 'ok' } },
        };
      }
      const plugin: FortressPlugin = {
        name: 'oauth-bearer-spy',
        routes,
        methods: () => ({
          jwtRoute(_body: unknown, ctx: PluginRouteContext): { ok: true } {
            received.push(ctx);
            return { ok: true };
          },
          oauthRoute(_body: unknown, ctx: PluginRouteContext): { ok: true } {
            received.push(ctx);
            return { ok: true };
          },
        }),
      };
      return { plugin, received };
    }

    it('rejects /oauth/host-app/jwt-route without a JWT (401)', async () => {
      const { plugin } = makeOauthBearerPlugin();
      const f = createFortress({ jwt: { key: SECRET }, database: createTestAdapter(), plugins: [plugin] });

      const res = await f.handleRequest(new Request('http://localhost/oauth/host-app/jwt-route', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      }));
      expect(res.status).toBe(401);
    });

    it('accepts /oauth/host-app/jwt-route with a valid JWT and populates ctx.userId', async () => {
      const { plugin, received } = makeOauthBearerPlugin();
      const f = createFortress({ jwt: { key: SECRET }, database: createTestAdapter(), plugins: [plugin] });
      const user = await f.auth.createUser({ email: 'jwt@b.co', name: 'J', password: 'password1234567' });
      const login = await f.auth.login('jwt@b.co', 'password1234567');
      if (login.status !== 'success')
        throw new Error('expected success');

      const res = await f.handleRequest(new Request('http://localhost/oauth/host-app/jwt-route', {
        method: 'POST',
        headers: { 'authorization': `Bearer ${login.accessToken}`, 'content-type': 'application/json' },
        body: JSON.stringify({}),
      }));
      expect(res.status).toBe(200);
      expect(received).toHaveLength(1);
      expect(received[0]!.userId).toBe(user.id);
    });

    it('rejects arbitrary plugin routes that set bearerKind="oauth" (P3.6)', async () => {
      const { plugin } = makeOauthBearerPlugin(true);
      expect(() => createFortress({ jwt: { key: SECRET }, database: createTestAdapter(), plugins: [plugin] }))
        .toThrow(/not an approved self-auth OAuth protocol route/);
    });
  });
});
