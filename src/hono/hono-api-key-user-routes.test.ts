/**
 * Integration tests proving that api-key credentials authenticate user-owned
 * Hono routes — the gap this branch closed. The auth middleware must delegate
 * to `fortress.resolvePrincipal`, populate `fortressSubject` for every
 * principal kind, and the RBAC middleware must check permissions by subject
 * (not by hardcoded USER subject).
 */

import type { Fortress } from '../core/fortress';
import type { Subject } from '../core/types';
import type { FortressEnv } from './middleware/auth';
import { Hono } from 'hono';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../core/fortress';
import { apiKey } from '../plugins/api-key';
import { createTestAdapter } from '../testing';
import { getSubject, getUserId } from './helpers';
import { createHonoMiddleware } from './index';

const SECRET = 'hono-api-key-user-routes-secret-32char!';

interface Ctx {
  fortress: Fortress<any>;
  app: Hono<FortressEnv>;
  userId: string;
  userKey: string;
  saId: string;
  saKey: string;
  saKeyNoPerm: string;
  saNoPermId: string;
  userAccessToken: string;
}

async function setup(): Promise<Ctx> {
  const fortress: Fortress<any> = createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
    plugins: [apiKey({ prefix: 'test' })],
  });

  // Seed: a user, a service account with 'deploy:run' permission, and a
  // second service account with *no* permissions (for the deny case).
  const user = await fortress.auth.createUser({
    email: 'human@example.com',
    name: 'Human',
    password: 'password-123456',
  });
  const userLogin = await fortress.auth.login('human@example.com', 'password-123456');
  if (userLogin.status !== 'success')
    throw new Error('login should succeed');

  // Give the user the same 'deploy:run' permission so shared user routes work.
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

  const { authMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, {
    routeMap: {
      'POST /deploy/run': { resource: 'deploy', action: 'run' },
    },
  });

  const app = new Hono<FortressEnv>();
  app.onError(errorHandler);
  app.use('/deploy/*', authMiddleware, rbacMiddleware);
  app.use('/me/*', authMiddleware); // no rbac

  app.post('/deploy/run', (c) => {
    const subject = getSubject(c);
    return c.json({ startedBy: subject });
  });

  // Endpoint that only USER subjects can reach (tests that getUserId throws
  // for non-USER principals).
  app.get('/me/profile', (c) => {
    const uid = getUserId(c);
    return c.json({ userId: uid });
  });

  // Endpoint that echoes the full subject so we can assert fortressSubject
  // is populated and fortressUserId is USER-only.
  app.get('/me/whoami', (c) => {
    const subject = c.get('fortressSubject') as Subject;
    const userId = c.get('fortressUserId');
    return c.json({ subject, userId });
  });

  return {
    fortress,
    app,
    userId: user.id,
    userKey,
    saId: sa.id,
    saKey,
    saKeyNoPerm,
    saNoPermId: saNoPerm.id,
    userAccessToken: userLogin.accessToken,
  };
}

describe('hono user routes: api-key authentication', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await setup();
  });

  it('authorization: ApiKey <key> authenticates a USER on a custom user route', async () => {
    const res = await ctx.app.request('/me/whoami', {
      headers: { Authorization: `ApiKey ${ctx.userKey}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { subject: Subject; userId: string };
    expect(body.subject).toEqual({ type: 'USER', id: ctx.userId });
    expect(body.userId).toBe(ctx.userId);
  });

  it('x-API-Key authenticates a SERVICE_ACCOUNT on a custom user route', async () => {
    const res = await ctx.app.request('/me/whoami', {
      headers: { 'X-API-Key': ctx.saKey },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { subject: Subject; userId: string | null };
    expect(body.subject).toEqual({ type: 'SERVICE_ACCOUNT', id: ctx.saId });
    // fortressUserId is a USER-only alias — undefined for service accounts
    expect(body.userId).toBeFalsy();
  });

  it('falls back to JWT bearer when no api-key header is present', async () => {
    const res = await ctx.app.request('/me/whoami', {
      headers: { Authorization: `Bearer ${ctx.userAccessToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { subject: Subject; userId: string };
    expect(body.subject).toEqual({ type: 'USER', id: ctx.userId });
    expect(body.userId).toBe(ctx.userId);
  });

  it('returns 401 when no credential is present', async () => {
    const res = await ctx.app.request('/me/whoami');
    expect(res.status).toBe(401);
  });

  it('returns 401 for an unknown api-key', async () => {
    const res = await ctx.app.request('/me/whoami', {
      headers: { 'X-API-Key': 'test_sk_not-real' },
    });
    expect(res.status).toBe(401);
  });

  it('getUserId throws 401 for a SERVICE_ACCOUNT principal (USER-only helper)', async () => {
    const res = await ctx.app.request('/me/profile', {
      headers: { 'X-API-Key': ctx.saKey },
    });
    expect(res.status).toBe(401);
  });

  it('getUserId returns the id for a USER principal', async () => {
    const res = await ctx.app.request('/me/profile', {
      headers: { Authorization: `ApiKey ${ctx.userKey}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { userId: string };
    expect(body.userId).toBe(ctx.userId);
  });
});

describe('hono user routes: api-key + RBAC middleware', () => {
  let ctx: Ctx;
  beforeEach(async () => {
    ctx = await setup();
  });

  it('allows a SERVICE_ACCOUNT api-key when the bound role grants the permission', async () => {
    const res = await ctx.app.request('/deploy/run', {
      method: 'POST',
      headers: { Authorization: `ApiKey ${ctx.saKey}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as { startedBy: Subject };
    expect(body.startedBy).toEqual({ type: 'SERVICE_ACCOUNT', id: ctx.saId });
  });

  it('denies a SERVICE_ACCOUNT api-key that lacks the permission', async () => {
    const res = await ctx.app.request('/deploy/run', {
      method: 'POST',
      headers: { 'X-API-Key': ctx.saKeyNoPerm },
    });
    expect(res.status).toBe(403);
  });

  it('allows a USER api-key when the user has the permission', async () => {
    const res = await ctx.app.request('/deploy/run', {
      method: 'POST',
      headers: { Authorization: `ApiKey ${ctx.userKey}` },
    });
    expect(res.status).toBe(200);
  });

  it('allows the same USER over JWT bearer (control: JWT still works)', async () => {
    const res = await ctx.app.request('/deploy/run', {
      method: 'POST',
      headers: { Authorization: `Bearer ${ctx.userAccessToken}` },
    });
    expect(res.status).toBe(200);
  });
});
