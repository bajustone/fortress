/**
 * Integration tests proving that api-key credentials authenticate user-owned
 * Express routes. Mirror of the Hono api-key user-route tests — drives the
 * middleware directly (no express runtime dependency) the same way
 * `express.test.ts` does.
 */

import type { Fortress } from '../core/fortress';
import type { Subject } from '../core/types';
import type { ExpressNextFunction, ExpressRequest, ExpressResponse } from './middleware';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../core/fortress';
import { apiKey } from '../plugins/api-key';
import { createTestAdapter } from '../testing';
import { createAuthMiddleware, createRbacMiddleware, getSubject, getUserId } from './middleware';

const SECRET = 'express-api-key-user-routes-32-chars!';

function mockRes(): ExpressResponse {
  return {
    status() { return this; },
    json() {},
    setHeader() {},
  } as ExpressResponse;
}

interface Ctx {
  fortress: Fortress<any>;
  userId: string;
  userKey: string;
  saId: string;
  saKey: string;
  saKeyNoPerm: string;
  userAccessToken: string;
}

async function setup(): Promise<Ctx> {
  const fortress = createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
    plugins: [apiKey({ prefix: 'test' })],
  });

  const user = await fortress.auth.createUser({
    email: 'human@example.com',
    name: 'Human',
    password: 'password-123',
  });
  const userLogin = await fortress.auth.login('human@example.com', 'password-123');
  if (userLogin.status !== 'success')
    throw new Error('login should succeed');

  const deployRole = await fortress.iam.createRole('deployer', [
    { resource: 'deploy', action: 'run' },
  ]);
  await fortress.iam.bindRoleToUser(user.id, deployRole.id);

  const sa = await fortress.iam.createServiceAccount({ name: 'ci-deploy-bot' });
  await fortress.iam.bindRoleToServiceAccount(sa.id, deployRole.id);
  const saNoPerm = await fortress.iam.createServiceAccount({ name: 'observer-bot' });

  const { key: userKey } = await fortress.plugins['api-key'].createKey({
    subject: { type: 'USER', id: user.id },
    name: 'user-key',
  });
  const { key: saKey } = await fortress.plugins['api-key'].createKey({
    subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
    name: 'sa-key',
  });
  const { key: saKeyNoPerm } = await fortress.plugins['api-key'].createKey({
    subject: { type: 'SERVICE_ACCOUNT', id: saNoPerm.id },
    name: 'observer-key',
  });

  return {
    fortress,
    userId: user.id,
    userKey,
    saId: sa.id,
    saKey,
    saKeyNoPerm,
    userAccessToken: userLogin.accessToken,
  };
}

/** Run an Express middleware against a fake request and return `{ ran, err }`. */
async function run(
  middleware: ReturnType<typeof createAuthMiddleware>,
  req: ExpressRequest,
): Promise<{ ran: boolean; err: any }> {
  let ran = false;
  let err: any;
  await middleware(req, mockRes(), ((e?: unknown) => {
    if (e)
      err = e;
    else
      ran = true;
  }) as ExpressNextFunction);
  return { ran, err };
}

describe('express user routes: api-key authentication', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await setup();
  });

  it('authorization: ApiKey <key> authenticates a USER and populates fortressSubject', async () => {
    const middleware = createAuthMiddleware(ctx.fortress);
    const req: ExpressRequest = {
      headers: { authorization: `ApiKey ${ctx.userKey}` },
      method: 'GET',
      path: '/me',
    };
    const { ran, err } = await run(middleware, req);
    expect(err).toBeUndefined();
    expect(ran).toBe(true);
    expect(req.fortressSubject).toEqual({ type: 'USER', id: ctx.userId });
    expect(req.fortressUserId).toBe(ctx.userId);
    expect(getSubject(req)).toEqual({ type: 'USER', id: ctx.userId });
    expect(getUserId(req)).toBe(ctx.userId);
  });

  it('x-API-Key authenticates a SERVICE_ACCOUNT; fortressUserId is undefined', async () => {
    const middleware = createAuthMiddleware(ctx.fortress);
    const req: ExpressRequest = {
      headers: { 'x-api-key': ctx.saKey },
      method: 'GET',
      path: '/me',
    };
    const { ran, err } = await run(middleware, req);
    expect(err).toBeUndefined();
    expect(ran).toBe(true);
    expect(req.fortressSubject).toEqual({ type: 'SERVICE_ACCOUNT', id: ctx.saId });
    // fortressUserId is a USER-only alias
    expect(req.fortressUserId).toBeUndefined();
    expect(getSubject(req).type).toBe('SERVICE_ACCOUNT');
  });

  it('getUserId throws 401 for a SERVICE_ACCOUNT principal', async () => {
    const middleware = createAuthMiddleware(ctx.fortress);
    const req: ExpressRequest = {
      headers: { 'x-api-key': ctx.saKey },
      method: 'GET',
      path: '/me',
    };
    await run(middleware, req);
    expect(() => getUserId(req)).toThrow(/User not authenticated/);
  });

  it('falls back to JWT bearer when no api-key header is present', async () => {
    const middleware = createAuthMiddleware(ctx.fortress);
    const req: ExpressRequest = {
      headers: { authorization: `Bearer ${ctx.userAccessToken}` },
      method: 'GET',
      path: '/me',
    };
    const { ran, err } = await run(middleware, req);
    expect(err).toBeUndefined();
    expect(ran).toBe(true);
    expect(req.fortressSubject).toEqual({ type: 'USER', id: ctx.userId });
    expect(req.fortressClaims).toBeDefined();
  });

  it('rejects requests with no credential', async () => {
    const middleware = createAuthMiddleware(ctx.fortress);
    const req: ExpressRequest = { headers: {}, method: 'GET', path: '/me' };
    const { ran, err } = await run(middleware, req);
    expect(ran).toBe(false);
    expect(err?.code).toBe('UNAUTHORIZED');
  });

  it('rejects requests with an unknown api-key', async () => {
    const middleware = createAuthMiddleware(ctx.fortress);
    const req: ExpressRequest = {
      headers: { 'x-api-key': 'test_sk_not-real' },
      method: 'GET',
      path: '/me',
    };
    const { ran, err } = await run(middleware, req);
    expect(ran).toBe(false);
    expect(err?.code).toBe('UNAUTHORIZED');
  });
});

describe('express user routes: api-key + RBAC middleware', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await setup();
  });

  it('allows a SERVICE_ACCOUNT api-key when the bound role grants the permission', async () => {
    const authMw = createAuthMiddleware(ctx.fortress);
    const rbacMw = createRbacMiddleware(ctx.fortress, {
      routeMap: { 'POST /deploy/run': { resource: 'deploy', action: 'run' } },
    });
    const req: ExpressRequest = {
      headers: { authorization: `ApiKey ${ctx.saKey}` },
      method: 'POST',
      path: '/deploy/run',
    };
    const auth = await run(authMw, req);
    expect(auth.err).toBeUndefined();
    const rbac = await run(rbacMw, req);
    expect(rbac.err).toBeUndefined();
    expect(rbac.ran).toBe(true);
    expect((req.fortressSubject as Subject).type).toBe('SERVICE_ACCOUNT');
  });

  it('denies a SERVICE_ACCOUNT api-key that lacks the permission', async () => {
    const authMw = createAuthMiddleware(ctx.fortress);
    const rbacMw = createRbacMiddleware(ctx.fortress, {
      routeMap: { 'POST /deploy/run': { resource: 'deploy', action: 'run' } },
    });
    const req: ExpressRequest = {
      headers: { 'x-api-key': ctx.saKeyNoPerm },
      method: 'POST',
      path: '/deploy/run',
    };
    await run(authMw, req);
    const rbac = await run(rbacMw, req);
    expect(rbac.ran).toBe(false);
    expect(rbac.err?.code).toBe('FORBIDDEN');
  });

  it('allows a USER api-key when the user has the permission', async () => {
    const authMw = createAuthMiddleware(ctx.fortress);
    const rbacMw = createRbacMiddleware(ctx.fortress, {
      routeMap: { 'POST /deploy/run': { resource: 'deploy', action: 'run' } },
    });
    const req: ExpressRequest = {
      headers: { authorization: `ApiKey ${ctx.userKey}` },
      method: 'POST',
      path: '/deploy/run',
    };
    await run(authMw, req);
    const rbac = await run(rbacMw, req);
    expect(rbac.err).toBeUndefined();
    expect(rbac.ran).toBe(true);
  });
});
