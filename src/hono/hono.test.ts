import type { Fortress } from '../core/fortress';
import type { FortressEnv } from './middleware/auth';
import { Hono } from 'hono';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../core/fortress';
import { createTestAdapter } from '../testing';
import { getUserId } from './helpers';
import { createHonoMiddleware } from './index';

const SECRET = 'hono-test-secret-at-least-32chars!!';

let fortress: Fortress;
let app: Hono<FortressEnv>;

beforeEach(async () => {
  fortress = createFortress({
    jwt: { secret: SECRET },
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
    expect(body.userId).toBeGreaterThan(0);
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
    const user = await fortress.auth.me(1);
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
    await fortress.iam.bindRoleToUser(1, role.id);

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
