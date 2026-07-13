import type { ExpressNextFunction, ExpressRequest, ExpressResponse } from './middleware';
import { describe, expect, it } from 'vitest';
import { FortressError } from '../core/errors';
import { createFortress } from '../core/fortress';
import { assertSuccess } from '../core/types';
import { createTestAdapter } from '../testing';
import { createAuthMiddleware, createErrorHandler, createExpressMiddleware, createRbacMiddleware, getClaims, getDb, getUserId } from './middleware';

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

describe('express adapter', () => {
  it('createExpressMiddleware returns auth, rbac, and error handler', () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });

    const { authMiddleware, rbacMiddleware, errorHandler } = createExpressMiddleware(fortress);
    expect(typeof authMiddleware).toBe('function');
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
