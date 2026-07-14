import type { ErrorRequestHandler, Express, RequestHandler } from 'express';
import type { PluginRequestContext } from '../core/http/plugin-middleware';
import type { ExpressNextFunction, ExpressRequest, ExpressResponse } from './middleware';
import { once } from 'node:events';
import express from 'express';
import { describe, expect, it } from 'vitest';
import { FortressError } from '../core/errors';
import { createFortress } from '../core/fortress';
import { assertSuccess } from '../core/types';
import { rateLimit } from '../plugins/rate-limit';
import { createTestAdapter } from '../testing';
import { expressToWebRequest } from './handle';
import { createAuthMiddleware, createCsrfMiddleware, createErrorHandler, createExpressMiddleware, createRbacMiddleware, getClaims, getDb, getUserId } from './middleware';

const SECRET = 'express-test-secret-32-chars!!!x';

function mockRes(): ExpressResponse {
  let statusCode = 200;
  let body: unknown;
  return {
    status(code: number) {
      statusCode = code;
      return this;
    },
    json(b: unknown) {
      body = b;
    },
    setHeader() {},
    get _statusCode() { return statusCode; },
    get _body() { return body; },
  } as any;
}

async function withExpressServer(app: Express, run: (baseUrl: string) => Promise<void>): Promise<void> {
  const server = app.listen(0);
  await once(server, 'listening');
  const address = server.address();
  if (!address || typeof address === 'string')
    throw new Error('Express test server did not bind to a TCP port');

  try {
    await run(`http://127.0.0.1:${address.port}`);
  }
  finally {
    await new Promise<void>((resolve, reject) => {
      server.close(error => error ? reject(error) : resolve());
    });
  }
}

describe('express adapter', () => {
  it('preserves parsed form-urlencoded bodies for OAuth dispatch', async () => {
    const request = expressToWebRequest({
      headers: {
        'host': 'example.test',
        'content-type': 'Application/X-WWW-Form-Urlencoded; Charset=UTF-8',
      },
      method: 'POST',
      path: '/oauth/token',
      originalUrl: '/oauth/token?trace=1',
      protocol: 'https',
      body: {
        grant_type: 'client_credentials',
        client_id: 'client id',
        client_secret: 'secret+value',
        scope: ['read', 'write'],
      },
    }, '/oauth/token');

    expect(request.url).toBe('https://example.test/oauth/token?trace=1');
    expect(await request.text()).toBe(
      'grant_type=client_credentials&client_id=client+id&client_secret=secret%2Bvalue&scope=read&scope=write',
    );
  });

  it('createExpressMiddleware returns auth, rbac, csrf, and error handler', () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });

    const { authMiddleware, csrfMiddleware, rbacMiddleware, errorHandler } = createExpressMiddleware(fortress);
    expect(typeof authMiddleware).toBe('function');
    expect(typeof csrfMiddleware).toBe('function');
    expect(typeof rbacMiddleware).toBe('function');
    expect(typeof errorHandler).toBe('function');
  });

  it('auth middleware rejects missing Authorization header', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });

    const middleware = createAuthMiddleware(fortress);
    const req: ExpressRequest = { headers: {}, method: 'GET', path: '/api/test' };
    const res = mockRes();
    let nextError: unknown;

    await middleware(req, res, ((err?: unknown) => {
      nextError = err;
    }) as ExpressNextFunction);

    expect(nextError).toBeDefined();
    expect((nextError as any).code).toBe('UNAUTHORIZED');
  });

  it('auth middleware sets user context on valid token', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });

    const user = await fortress.auth.createUser({
      email: 'test@test.com',
      name: 'Test',
      password: 'password-123456',
    });
    const loginResult = await fortress.auth.login('test@test.com', 'password-123456');
    assertSuccess(loginResult);

    const middleware = createAuthMiddleware(fortress);
    const req: ExpressRequest = {
      headers: { authorization: `Bearer ${loginResult.accessToken}` },
      method: 'GET',
      path: '/api/test',
    };
    const res = mockRes();
    let nextCalled = false;

    await middleware(req, res, (() => {
      nextCalled = true;
    }) as ExpressNextFunction);

    expect(nextCalled).toBe(true);
    expect(req.fortressUserId).toBe(user.id);
    expect(req.fortressClaims).toBeDefined();
    expect(req.fortressDb).toBeDefined();
    expect(getUserId(req)).toBe(user.id);
    expect(getClaims(req)).toBeDefined();
    expect(getDb(req)).toBeDefined();
  });

  it('passes a faithful authenticated PluginRequestContext after auth', async () => {
    let captured: PluginRequestContext | undefined;
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [{
        name: 'context-spy',
        middleware: [{
          path: '/api/*',
          position: 'after-auth',
          handler: async (_ctx, request, next) => {
            captured = request;
            await next();
          },
        }],
      }],
    });
    const user = await fortress.auth.createUser({
      email: 'context@test.com',
      name: 'Context',
      password: 'password-123456',
    });
    const login = await fortress.auth.login('context@test.com', 'password-123456');
    assertSuccess(login);
    const middleware = createExpressMiddleware(fortress);
    const req: ExpressRequest = {
      headers: {
        'authorization': `Bearer ${login.accessToken}`,
        'host': 'example.test',
        'content-type': 'application/json',
      },
      method: 'POST',
      path: '/api/items',
      originalUrl: '/api/items?include=all',
      protocol: 'https',
      body: { name: 'item' },
    };
    await middleware.authMiddleware(req, mockRes(), (() => {}) as ExpressNextFunction);
    await middleware.pluginMiddleware.afterAuth(req, mockRes(), (() => {}) as ExpressNextFunction);

    expect(captured?.request.url).toBe('https://example.test/api/items?include=all');
    expect(captured?.request.method).toBe('POST');
    await expect(captured?.request.json()).resolves.toEqual({ name: 'item' });
    expect(captured?.fortressSubject).toEqual({ type: 'USER', id: user.id });
    expect(captured?.fortressUserId).toBe(user.id);
    expect(captured?.fortressClaims?.sub).toBe(user.id);
  });

  it('normalizes plugin middleware to PluginRequestContext so path rate limits fire', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [rateLimit({
        login: { disabled: true },
        register: { disabled: true },
        paths: [{ match: '/api/*', rule: { maxPerIp: 1, windowSeconds: 60 } }],
      })],
    });
    const middleware = createExpressMiddleware(fortress).pluginMiddleware.beforeAuth;
    const req: ExpressRequest = {
      headers: { 'x-forwarded-for': '192.0.2.1' },
      method: 'GET',
      path: '/api/items',
    };
    const invoke = async (): Promise<unknown> => {
      let nextError: unknown;
      await middleware(req, mockRes(), ((error?: unknown) => {
        nextError = error;
      }) as ExpressNextFunction);
      return nextError;
    };

    await expect(invoke()).resolves.toBeUndefined();
    await expect(invoke()).resolves.toMatchObject({ code: 'RATE_LIMITED' });
  });

  it('standalone CSRF middleware rejects unsafe requests and matches skips at segment boundaries', async () => {
    const middleware = createCsrfMiddleware({ skipPaths: ['/webhook'] });
    const invoke = async (req: ExpressRequest): Promise<unknown> => {
      let nextError: unknown;
      await middleware(req, mockRes(), ((error?: unknown) => {
        nextError = error;
      }) as ExpressNextFunction);
      return nextError;
    };

    await expect(invoke({ headers: {}, method: 'GET', path: '/api/items' })).resolves.toBeUndefined();
    await expect(invoke({ headers: {}, method: 'POST', path: '/api/items' }))
      .resolves
      .toMatchObject({ code: 'FORBIDDEN', statusCode: 403 });
    await expect(invoke({
      headers: { 'x-fortress-csrf': '1' },
      method: 'POST',
      path: '/api/items',
    })).resolves.toBeUndefined();
    await expect(invoke({ headers: {}, method: 'POST', path: '/webhook/delivery' })).resolves.toBeUndefined();
    await expect(invoke({ headers: {}, method: 'POST', path: '/webhook-evil' }))
      .resolves
      .toMatchObject({ code: 'FORBIDDEN' });
    await expect(invoke({
      headers: { 'x-fortress-csrf': '1', 'sec-fetch-site': 'cross-site' },
      method: 'POST',
      path: '/api/items',
    })).resolves.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('propagates custom CSRF factory options including safe methods and wildcard skips', async () => {
    const fortress = createFortress({ jwt: { key: SECRET }, database: createTestAdapter() });
    const middleware = createExpressMiddleware(fortress, {
      csrf: {
        headerName: 'X-Custom-CSRF',
        safeMethods: ['get', 'post'],
        skipPaths: ['/hooks/*'],
      },
    }).csrfMiddleware;
    const invoke = async (req: ExpressRequest): Promise<unknown> => {
      let nextError: unknown;
      await middleware(req, mockRes(), ((error?: unknown) => {
        nextError = error;
      }) as ExpressNextFunction);
      return nextError;
    };

    await expect(invoke({ headers: {}, method: 'POST', path: '/api/items' })).resolves.toBeUndefined();
    await expect(invoke({ headers: {}, method: 'DELETE', path: '/hooks/delivery' })).resolves.toBeUndefined();
    await expect(invoke({
      headers: { 'X-Custom-CSRF': '1' },
      method: 'PUT',
      path: '/api/items',
    })).resolves.toBeUndefined();
    await expect(invoke({
      headers: { 'x-fortress-csrf': '1' },
      method: 'PUT',
      path: '/api/items',
    })).resolves.toMatchObject({ code: 'FORBIDDEN' });
  });

  it('rbac middleware skips when no route mapping matches', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });

    const middleware = createRbacMiddleware(fortress, { routeMap: {} });
    const req: ExpressRequest = {
      headers: {},
      method: 'GET',
      path: '/api/unmapped',
      fortressUserId: '1',
    };
    let nextCalled = false;

    await middleware(req, mockRes(), (() => {
      nextCalled = true;
    }) as ExpressNextFunction);
    expect(nextCalled).toBe(true);
  });

  it('matches routeMap against originalUrl when Express strips a mount path', async () => {
    const fortress = createFortress({ jwt: { key: SECRET }, database: createTestAdapter() });
    const middleware = createRbacMiddleware(fortress, {
      routeMap: { 'GET /api/posts': { resource: 'post', action: 'list' } },
    });
    const req: ExpressRequest = {
      headers: {},
      method: 'GET',
      path: '/posts',
      url: '/posts',
      originalUrl: '/api/posts?limit=10',
    };
    let nextError: unknown;

    await middleware(req, mockRes(), ((error?: unknown) => {
      nextError = error;
    }) as ExpressNextFunction);
    // If req.path were used, this would silently fall through as unmapped.
    expect(nextError).toMatchObject({ code: 'UNAUTHORIZED', statusCode: 401 });
  });

  it('protects Express case and trailing-slash route variants and treats dots literally', async () => {
    const fortress = createFortress({ jwt: { key: SECRET }, database: createTestAdapter() });
    const app = express();
    const router = express.Router();
    const rbac = createRbacMiddleware(fortress, {
      routeMap: {
        'GET /API/Admin/Users/': { resource: 'admin', action: 'list' },
        'GET /API/Report.JSON/': { resource: 'report', action: 'read' },
        'GET /API/Users/:id/': { resource: 'user', action: 'read' },
      },
    });

    router.use(rbac as unknown as RequestHandler);
    router.get('/admin/users', (_req, res) => res.json({ bypassed: true }));
    router.get('/report.json', (_req, res) => res.json({ bypassed: true }));
    router.get('/users/:id', (_req, res) => res.json({ bypassed: true }));
    router.get('/reportXjson', (_req, res) => res.json({ public: true }));
    app.use('/api', router);
    app.use(createErrorHandler() as unknown as ErrorRequestHandler);

    await withExpressServer(app, async (baseUrl) => {
      for (const path of ['/api/Admin/users', '/api/admin/users/']) {
        const response = await fetch(`${baseUrl}${path}`);
        expect(response.status, path).toBe(401);
      }

      const protectedParam = await fetch(`${baseUrl}/api/Users/42/`);
      expect(protectedParam.status).toBe(401);

      const protectedDot = await fetch(`${baseUrl}/api/report.json`);
      expect(protectedDot.status).toBe(401);

      const literalDot = await fetch(`${baseUrl}/api/reportXjson`);
      expect(literalDot.status).toBe(200);
      expect(await literalDot.json()).toEqual({ public: true });
    });
  });

  it('normalizes configured Express skip paths for case and trailing slashes', async () => {
    const fortress = createFortress({ jwt: { key: SECRET }, database: createTestAdapter() });
    const app = express();
    const router = express.Router();
    const rbac = createRbacMiddleware(fortress, {
      routeMap: {},
      skipPaths: ['/API/Health/', '/API/Public/*'],
      unmappedRoutes: 'deny',
    });

    router.use(rbac as unknown as RequestHandler);
    router.get('/health', (_req, res) => res.json({ ok: true }));
    router.get('/public/info', (_req, res) => res.json({ ok: true }));
    app.use('/api', router);
    app.use(createErrorHandler() as unknown as ErrorRequestHandler);

    await withExpressServer(app, async (baseUrl) => {
      for (const path of ['/api/health', '/api/HEALTH/', '/api/Public/Info/']) {
        const response = await fetch(`${baseUrl}${path}`);
        expect(response.status, path).toBe(200);
      }
    });
  });

  it('rbac middleware denies unmapped routes when unmappedRoutes: deny', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });

    const middleware = createRbacMiddleware(fortress, { routeMap: {}, unmappedRoutes: 'deny' });
    const req: ExpressRequest = {
      headers: {},
      method: 'GET',
      path: '/api/unmapped',
      fortressUserId: '1',
    };
    let nextErr: unknown;

    await middleware(req, mockRes(), ((err?: unknown) => {
      nextErr = err;
    }) as ExpressNextFunction);
    expect(nextErr).toBeInstanceOf(FortressError);
    expect((nextErr as FortressError).statusCode).toBe(403);
  });

  it('rbac middleware still allows skipPaths under unmappedRoutes: deny', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });

    const middleware = createRbacMiddleware(fortress, {
      routeMap: {},
      unmappedRoutes: 'deny',
      skipPaths: ['/api/health'],
    });
    const req: ExpressRequest = { headers: {}, method: 'GET', path: '/api/health' };
    let nextErr: unknown;
    let nextCalled = false;

    await middleware(req, mockRes(), ((err?: unknown) => {
      if (err)
        nextErr = err;
      else nextCalled = true;
    }) as ExpressNextFunction);
    expect(nextErr).toBeUndefined();
    expect(nextCalled).toBe(true);
  });

  it('error handler formats FortressError correctly', () => {
    const handler = createErrorHandler();
    const res = mockRes() as any;

    const err = new FortressError('FORBIDDEN', 'No access', 403);

    handler(err, {} as any, res, (() => {}) as ExpressNextFunction);

    expect(res._statusCode).toBe(403);
    expect(res._body).toEqual({ code: 'FORBIDDEN', message: 'No access', statusCode: 403 });
  });
});
