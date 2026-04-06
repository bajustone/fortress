import type { ExpressNextFunction, ExpressRequest, ExpressResponse } from './middleware';
import { describe, expect, it } from 'vitest';
import { FortressError } from '../core/errors';
import { createFortress } from '../core/fortress';
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
      jwt: { secret: SECRET },
      database: createTestAdapter(),
    });

    const { authMiddleware, rbacMiddleware, errorHandler } = createExpressMiddleware(fortress);
    expect(typeof authMiddleware).toBe('function');
    expect(typeof rbacMiddleware).toBe('function');
    expect(typeof errorHandler).toBe('function');
  });

  it('auth middleware rejects missing Authorization header', async () => {
    const fortress = createFortress({
      jwt: { secret: SECRET },
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
      jwt: { secret: SECRET },
      database: createTestAdapter(),
    });

    const user = await fortress.auth.createUser({
      email: 'test@test.com',
      name: 'Test',
      password: 'password-123',
    });
    const loginResult = await fortress.auth.login('test@test.com', 'password-123');

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
      jwt: { secret: SECRET },
      database: createTestAdapter(),
    });

    const middleware = createRbacMiddleware(fortress, { routeMap: {} });
    const req: ExpressRequest = {
      headers: {},
      method: 'GET',
      path: '/api/unmapped',
      fortressUserId: 1,
    };
    let nextCalled = false;

    await middleware(req, mockRes(), (() => {
      nextCalled = true;
    }) as ExpressNextFunction);
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
