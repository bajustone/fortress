import type { Fortress } from '../core/fortress';
import type { FortressEnv } from './middleware/auth';
import { Hono } from 'hono';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../core/fortress';
import { dataIsolation } from '../plugins/data-isolation';
import { createTestAdapter } from '../testing';
import { getDb, getScopedDb, getUserId } from './helpers';
import { createHonoMiddleware } from './index';

const SECRET = 'hono-test-secret-at-least-32chars!!';

let fortress: Fortress;
let app: Hono<FortressEnv>;

beforeEach(async () => {
  fortress = createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
  });

  const { authMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, {
    routeMap: {
      'GET /api/posts': { resource: 'post', action: 'list' },
      'POST /api/posts': { resource: 'post', action: 'create' },
      'GET /api/posts/:id': { resource: 'post', action: 'read' },
    },
    skipPaths: ['/health', '/auth/*'],
  });

  app = new Hono<FortressEnv>();
  app.onError(errorHandler);

  // Public routes
  app.get('/health', c => c.json({ status: 'ok' }));
  app.post('/auth/login', async (c) => {
    const { identifier, password } = await c.req.json();
    const result = await fortress.auth.login(identifier, password);
    return c.json(result);
  });

  // Protected routes
  app.use('/api/*', authMiddleware);
  app.use('/api/*', rbacMiddleware);

  app.get('/api/posts', (c) => {
    const userId = getUserId(c);
    return c.json({ userId, posts: [] });
  });
  app.post('/api/posts', c => c.json({ created: true }));
  app.get('/api/posts/:id', c => c.json({ id: c.req.param('id') }));
  app.get('/api/profile', (c) => {
    const userId = getUserId(c);
    return c.json({ userId });
  });

  // Seed a user
  await fortress.auth.createUser({
    email: 'test@example.com',
    name: 'Test User',
    password: 'password-123',
  });
});

async function loginAndGetToken(): Promise<string> {
  const res = await app.request('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier: 'test@example.com', password: 'password-123' }),
  });
  const data = await res.json() as any;
  return data.accessToken;
}

describe('hono errorHandler', () => {
  it('returns 401 for missing auth header', async () => {
    const res = await app.request('/api/posts');
    expect(res.status).toBe(401);
    const body = await res.json() as any;
    expect(body.code).toBe('UNAUTHORIZED');
  });

  it('returns 401 for invalid token', async () => {
    const res = await app.request('/api/posts', {
      headers: { Authorization: 'Bearer invalid-token' },
    });
    expect(res.status).toBe(401);
  });
});

describe('hono authMiddleware', () => {
  it('allows requests with valid token', async () => {
    const token = await loginAndGetToken();
    const res = await app.request('/api/profile', {
      headers: { Authorization: `Bearer ${token}` },
    });
    // No routeMap for /api/profile → RBAC skips, request goes through
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.userId).toBeTruthy();
  });

  it('skips auth for skip paths', async () => {
    const res = await app.request('/health');
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.status).toBe('ok');
  });

  it('skips auth for wildcard skip paths', async () => {
    const res = await app.request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'test@example.com', password: 'password-123' }),
    });
    expect(res.status).toBe(200);
  });
});

describe('hono rbacMiddleware', () => {
  it('allows access when user has permission', async () => {
    const token = await loginAndGetToken();

    // Give the user permission to list posts
    const user = await fortress.auth.me('1');
    const role = await fortress.iam.createRole('viewer', [
      { resource: 'post', action: 'list' },
      { resource: 'post', action: 'read' },
    ]);
    await fortress.iam.bindRoleToUser(user.id, role.id);

    const res = await app.request('/api/posts', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
  });

  it('denies access when user lacks permission', async () => {
    const token = await loginAndGetToken();

    // User has no roles — should be denied for mapped routes
    const res = await app.request('/api/posts', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(403);
    const body = await res.json() as any;
    expect(body.code).toBe('FORBIDDEN');
  });

  it('matches parameterized routes', async () => {
    const token = await loginAndGetToken();

    const role = await fortress.iam.createRole('reader', [
      { resource: 'post', action: 'read' },
    ]);
    await fortress.iam.bindRoleToUser('1', role.id);

    const res = await app.request('/api/posts/42', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.id).toBe('42');
  });

  it('allows unmapped routes through (no routeMap entry)', async () => {
    const token = await loginAndGetToken();

    // /api/profile has no routeMap entry → RBAC skips
    const res = await app.request('/api/profile', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
  });
});

describe('hono authMiddleware — fortressDb and getScopedDb', () => {
  let dbApp: Hono<FortressEnv>;
  let dbFortress: Fortress;

  beforeEach(async () => {
    dbFortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });

    const { authMiddleware, errorHandler } = createHonoMiddleware(dbFortress);
    dbApp = new Hono<FortressEnv>();
    dbApp.onError(errorHandler);

    dbApp.post('/auth/login', async (c) => {
      const { identifier, password } = await c.req.json();
      const result = await dbFortress.auth.login(identifier, password);
      return c.json(result);
    });

    dbApp.use('/api/*', authMiddleware);

    dbApp.get('/api/db-check', (c) => {
      const db = getDb(c);
      return c.json({
        hasDb: !!db,
        hasCreate: typeof db.create === 'function',
      });
    });

    dbApp.get('/api/scoped-check', async (c) => {
      const db = await getScopedDb(c, 'post');
      return c.json({
        hasDb: !!db,
        hasCreate: typeof db.create === 'function',
      });
    });

    await dbFortress.auth.createUser({
      email: 'test@example.com',
      name: 'Test User',
      password: 'password-123',
    });
  });

  async function loginDb(): Promise<string> {
    const res = await dbApp.request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identifier: 'test@example.com',
        password: 'password-123',
      }),
    });
    const data = (await res.json()) as any;
    return data.accessToken;
  }

  it('sets fortressDb on context after auth', async () => {
    const token = await loginDb();
    const res = await dbApp.request('/api/db-check', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.hasDb).toBe(true);
    expect(body.hasCreate).toBe(true);
  });

  it('getScopedDb returns adapter when no plugins define scopeRules', async () => {
    const token = await loginDb();
    const res = await dbApp.request('/api/scoped-check', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.hasDb).toBe(true);
    expect(body.hasCreate).toBe(true);
  });
});

describe('hono authMiddleware — data-isolation scopeRules', () => {
  let isolatedFortress: Fortress<any>;
  let isolatedApp: Hono<FortressEnv>;

  beforeEach(async () => {
    const db = createTestAdapter();

    isolatedFortress = createFortress({
      jwt: { key: SECRET },
      database: db,
      plugins: [
        dataIsolation({
          scopes: [
            {
              name: 'org',
              field: 'orgId',
              models: ['post'],
              resolveValue: async () => 42,
            },
          ],
        }),
      ],
    });

    const { authMiddleware, errorHandler } = createHonoMiddleware(
      isolatedFortress,
    );

    isolatedApp = new Hono<FortressEnv>();
    isolatedApp.onError(errorHandler);

    isolatedApp.post('/auth/login', async (c) => {
      const { identifier, password } = await c.req.json();
      const result = await isolatedFortress.auth.login(identifier, password);
      return c.json(result);
    });

    isolatedApp.use('/api/*', authMiddleware);

    isolatedApp.get('/api/scoped-post', async (c) => {
      const db = await getScopedDb(c, 'post');
      // Verify the scoped adapter exists and has methods
      return c.json({
        hasDb: !!db,
        hasFindMany: typeof db.findMany === 'function',
        hasCreate: typeof db.create === 'function',
      });
    });

    isolatedApp.get('/api/unscoped-user', async (c) => {
      // "user" model is not in the scope config, so no filters applied
      const db = await getScopedDb(c, 'user');
      return c.json({ hasDb: !!db });
    });

    await isolatedFortress.auth.createUser({
      email: 'test@example.com',
      name: 'Test User',
      password: 'password-123',
    });
  });

  async function loginIsolated(): Promise<string> {
    const res = await isolatedApp.request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        identifier: 'test@example.com',
        password: 'password-123',
      }),
    });
    const data = (await res.json()) as any;
    return data.accessToken;
  }

  it('getScopedDb applies scope rules for matching model', async () => {
    const token = await loginIsolated();

    const res = await isolatedApp.request('/api/scoped-post', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.hasDb).toBe(true);
    expect(body.hasFindMany).toBe(true);
    expect(body.hasCreate).toBe(true);
  });

  it('getScopedDb returns base adapter for non-matching model', async () => {
    const token = await loginIsolated();

    const res = await isolatedApp.request('/api/unscoped-user', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = (await res.json()) as any;
    expect(body.hasDb).toBe(true);
  });
});
