import type { Fortress } from '../core/fortress';
import type { FortressEnv } from './middleware/auth';
import { Hono } from 'hono';
import { beforeEach, describe, expect, it } from 'vitest';
import { FortressError } from '../core/errors';
import { createFortress } from '../core/fortress';
import { oauth } from '../plugins/oauth';
import { openapi } from '../plugins/openapi';
import { createTestAdapter } from '../testing';
import { mountFortress } from './handle';
import { getClaims, getDb, getUserId } from './helpers';
import { createHonoMiddleware } from './index';
import { createCsrfMiddleware } from './middleware/csrf';

const SECRET = 'hono-handler-test-secret-at-least-32!!';

// --- Helper ---

function createApp(fortress: Fortress, options?: Parameters<typeof createHonoMiddleware>[1]): Hono<FortressEnv> {
  const { authMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, options);
  const app = new Hono<FortressEnv>();
  app.onError(errorHandler);

  app.post('/auth/login', async (c) => {
    const { identifier, password } = await c.req.json();
    const result = await fortress.auth.login(identifier, password);
    return c.json(result);
  });

  app.post('/auth/register', async (c) => {
    const data = await c.req.json();
    const user = await fortress.auth.createUser(data);
    return c.json(user);
  });

  app.use('/api/*', authMiddleware);
  if (options?.routeMap) {
    app.use('/api/*', rbacMiddleware);
  }

  return app;
}

async function seedAndLogin(fortress: Fortress, app: Hono<FortressEnv>): Promise<{ token: string; userId: number }> {
  const user = await fortress.auth.createUser({
    email: 'test@example.com',
    name: 'Test User',
    password: 'password-123',
  });

  const res = await app.request('/auth/login', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ identifier: 'test@example.com', password: 'password-123' }),
  });
  const data = await res.json() as any;
  return { token: data.accessToken, userId: user.id };
}

// =====================
// Error Handler
// =====================

describe('error handler', () => {
  let app: Hono<FortressEnv>;

  beforeEach(() => {
    const fortress = createFortress({ jwt: { secret: SECRET }, database: createTestAdapter() });
    app = createApp(fortress);
  });

  it('returns structured JSON for FortressError', async () => {
    const res = await app.request('/api/anything');
    expect(res.status).toBe(401);
    const body = await res.json() as any;
    expect(body.code).toBe('UNAUTHORIZED');
    expect(body.message).toBeDefined();
    expect(body.statusCode).toBe(401);
  });

  it('returns 500 for unknown errors without stack trace', async () => {
    const fortress = createFortress({ jwt: { secret: SECRET }, database: createTestAdapter() });
    const { errorHandler } = createHonoMiddleware(fortress);
    const testApp = new Hono();
    testApp.onError(errorHandler);
    testApp.get('/blow-up', () => {
      throw new Error('internal failure');
    });

    const res = await testApp.request('/blow-up');
    expect(res.status).toBe(500);
    const body = await res.json() as any;
    expect(body.code).toBe('INTERNAL_ERROR');
    expect(body.message).toBe('Internal server error');
    expect(body).not.toHaveProperty('stack');
  });

  it('adds Retry-After header for RATE_LIMITED errors', async () => {
    const fortress = createFortress({ jwt: { secret: SECRET }, database: createTestAdapter() });
    const { errorHandler } = createHonoMiddleware(fortress);
    const testApp = new Hono();
    testApp.onError(errorHandler);
    testApp.get('/rate-limited', () => {
      throw new FortressError('RATE_LIMITED', 'Too many requests', 429, { retryAfter: 60 });
    });

    const res = await testApp.request('/rate-limited');
    expect(res.status).toBe(429);
    expect(res.headers.get('Retry-After')).toBe('60');
  });

  it('maps various error codes to correct status codes', async () => {
    const fortress = createFortress({ jwt: { secret: SECRET }, database: createTestAdapter() });
    const { errorHandler } = createHonoMiddleware(fortress);
    const testApp = new Hono();
    testApp.onError(errorHandler);

    testApp.get('/forbidden', () => {
      throw new FortressError('FORBIDDEN', 'Nope', 403);
    });
    testApp.get('/not-found', () => {
      throw new FortressError('NOT_FOUND', 'Gone', 404);
    });
    testApp.get('/conflict', () => {
      throw new FortressError('CONFLICT', 'Dupe', 409);
    });

    expect((await testApp.request('/forbidden')).status).toBe(403);
    expect((await testApp.request('/not-found')).status).toBe(404);
    expect((await testApp.request('/conflict')).status).toBe(409);
  });
});

// =====================
// Auth Middleware
// =====================

describe('auth middleware', () => {
  let fortress: Fortress;
  let app: Hono<FortressEnv>;

  beforeEach(async () => {
    fortress = createFortress({ jwt: { secret: SECRET }, database: createTestAdapter() });
    app = createApp(fortress);

    app.get('/api/me', (c) => {
      const userId = getUserId(c);
      const claims = getClaims(c);
      return c.json({ userId, name: claims.name, groups: claims.groups });
    });
  });

  it('extracts user ID and claims from valid token', async () => {
    const { token, userId } = await seedAndLogin(fortress, app);

    const res = await app.request('/api/me', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.userId).toBe(userId);
    expect(body.name).toBe('Test User');
    expect(body.groups).toEqual([]);
  });

  it('rejects requests without Authorization header', async () => {
    const res = await app.request('/api/me');
    expect(res.status).toBe(401);
  });

  it('rejects malformed Authorization header', async () => {
    const res = await app.request('/api/me', {
      headers: { Authorization: 'NotBearer token' },
    });
    expect(res.status).toBe(401);
  });

  it('rejects expired/invalid tokens', async () => {
    const res = await app.request('/api/me', {
      headers: { Authorization: 'Bearer totally.invalid.token' },
    });
    expect(res.status).toBe(401);
  });

  it('provides database adapter via getDb()', async () => {
    app.get('/api/db-test', (c) => {
      const db = getDb(c);
      return c.json({ hasCreate: typeof db.create === 'function' });
    });

    const { token } = await seedAndLogin(fortress, app);
    const res = await app.request('/api/db-test', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.hasCreate).toBe(true);
  });
});

// =====================
// RBAC Middleware
// =====================

describe('rbac middleware', () => {
  let fortress: Fortress;
  let app: Hono<FortressEnv>;

  beforeEach(async () => {
    fortress = createFortress({ jwt: { secret: SECRET }, database: createTestAdapter() });
    app = createApp(fortress, {
      routeMap: {
        'GET /api/posts': { resource: 'post', action: 'list' },
        'POST /api/posts': { resource: 'post', action: 'create' },
        'GET /api/posts/:id': { resource: 'post', action: 'read' },
        'PUT /api/posts/:id': { resource: 'post', action: 'update' },
        'DELETE /api/posts/:id': { resource: 'post', action: 'delete' },
      },
      skipPaths: ['/health', '/public/*'],
    });

    app.get('/api/posts', c => c.json({ posts: [] }));
    app.post('/api/posts', c => c.json({ created: true }));
    app.get('/api/posts/:id', c => c.json({ id: c.req.param('id') }));
    app.put('/api/posts/:id', c => c.json({ updated: true }));
    app.delete('/api/posts/:id', c => c.json({ deleted: true }));
    app.get('/api/unmapped', c => c.json({ ok: true }));
  });

  it('denies when user has no permissions', async () => {
    const { token } = await seedAndLogin(fortress, app);

    const res = await app.request('/api/posts', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(403);
    const body = await res.json() as any;
    expect(body.code).toBe('FORBIDDEN');
  });

  it('allows when user has matching permission', async () => {
    const { token, userId } = await seedAndLogin(fortress, app);
    const role = await fortress.iam.createRole('reader', [{ resource: 'post', action: 'list' }]);
    await fortress.iam.bindRoleToUser(userId, role.id);

    const res = await app.request('/api/posts', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
  });

  it('enforces per-action permission: allow read, deny create', async () => {
    const { token, userId } = await seedAndLogin(fortress, app);
    const role = await fortress.iam.createRole('reader', [{ resource: 'post', action: 'list' }]);
    await fortress.iam.bindRoleToUser(userId, role.id);

    const getRes = await app.request('/api/posts', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(getRes.status).toBe(200);

    const postRes = await app.request('/api/posts', {
      method: 'POST',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(postRes.status).toBe(403);
  });

  it('matches PUT and DELETE on parameterized routes', async () => {
    const { token, userId } = await seedAndLogin(fortress, app);
    const role = await fortress.iam.createRole('editor', [
      { resource: 'post', action: 'update' },
      { resource: 'post', action: 'delete' },
    ]);
    await fortress.iam.bindRoleToUser(userId, role.id);

    const putRes = await app.request('/api/posts/42', {
      method: 'PUT',
      headers: { 'Authorization': `Bearer ${token}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({}),
    });
    expect(putRes.status).toBe(200);

    const deleteRes = await app.request('/api/posts/42', {
      method: 'DELETE',
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(deleteRes.status).toBe(200);
  });

  it('passes through unmapped routes without permission check', async () => {
    const { token } = await seedAndLogin(fortress, app);

    const res = await app.request('/api/unmapped', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(res.status).toBe(200);
  });

  it('supports dynamic mapRequest fallback', async () => {
    const mapFortress = createFortress({ jwt: { secret: SECRET }, database: createTestAdapter() });
    // Pass a routeMap (even empty) so rbacMiddleware is applied by createApp
    const mapApp = createApp(mapFortress, {
      routeMap: {},
      mapRequest: (method, path) => {
        if (method === 'GET' && path.startsWith('/api/dynamic/'))
          return { resource: 'dynamic', action: 'read' };
        return null;
      },
    });

    mapApp.get('/api/dynamic/:id', c => c.json({ id: c.req.param('id') }));

    const { token, userId } = await seedAndLogin(mapFortress, mapApp);

    // No permission → denied
    const denied = await mapApp.request('/api/dynamic/1', {
      headers: { Authorization: `Bearer ${token}` },
    });
    expect(denied.status).toBe(403);

    // Grant permission → allowed
    const role = await mapFortress.iam.createRole('dyn-reader', [{ resource: 'dynamic', action: 'read' }]);
    await mapFortress.iam.bindRoleToUser(userId, role.id);

    // Need a fresh token since claims are cached
    const loginRes = await mapApp.request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'test@example.com', password: 'password-123' }),
    });
    const newToken = ((await loginRes.json()) as any).accessToken;

    const allowed = await mapApp.request('/api/dynamic/1', {
      headers: { Authorization: `Bearer ${newToken}` },
    });
    expect(allowed.status).toBe(200);
  });
});

// =====================
// CSRF Middleware
// =====================

describe('csrf middleware', () => {
  let app: Hono;

  beforeEach(() => {
    app = new Hono();
    app.use('*', createCsrfMiddleware());
    app.get('/data', c => c.json({ ok: true }));
    app.post('/data', c => c.json({ ok: true }));
    app.put('/data', c => c.json({ ok: true }));
    app.patch('/data', c => c.json({ ok: true }));
    app.delete('/data', c => c.json({ ok: true }));
  });

  it('allows GET without CSRF header', async () => {
    const res = await app.request('/data');
    expect(res.status).toBe(200);
  });

  it('allows POST with CSRF header', async () => {
    const res = await app.request('/data', {
      method: 'POST',
      headers: { 'X-Fortress-CSRF': '1', 'Content-Type': 'application/json' },
      body: '{}',
    });
    expect(res.status).toBe(200);
  });

  it('rejects POST without CSRF header', async () => {
    const res = await app.request('/data', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    expect(res.status).toBe(403);
    const body = await res.json() as any;
    expect(body.error).toBe('CSRF_MISSING');
  });

  it('rejects PUT without CSRF header', async () => {
    const res = await app.request('/data', {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    expect(res.status).toBe(403);
  });

  it('rejects PATCH without CSRF header', async () => {
    const res = await app.request('/data', {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    expect(res.status).toBe(403);
  });

  it('rejects DELETE without CSRF header', async () => {
    const res = await app.request('/data', { method: 'DELETE' });
    expect(res.status).toBe(403);
  });

  it('allows PUT/PATCH/DELETE with CSRF header', async () => {
    for (const method of ['PUT', 'PATCH', 'DELETE']) {
      const res = await app.request('/data', {
        method,
        headers: { 'X-Fortress-CSRF': '1', 'Content-Type': 'application/json' },
        body: method !== 'DELETE' ? '{}' : undefined,
      });
      expect(res.status).toBe(200);
    }
  });

  it('rejects cross-site requests via Sec-Fetch-Site', async () => {
    const res = await app.request('/data', {
      method: 'POST',
      headers: {
        'X-Fortress-CSRF': '1',
        'Sec-Fetch-Site': 'cross-site',
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
    expect(res.status).toBe(403);
    const body = await res.json() as any;
    expect(body.error).toBe('CSRF_REJECTED');
  });

  it('allows same-origin requests via Sec-Fetch-Site', async () => {
    const res = await app.request('/data', {
      method: 'POST',
      headers: {
        'X-Fortress-CSRF': '1',
        'Sec-Fetch-Site': 'same-origin',
        'Content-Type': 'application/json',
      },
      body: '{}',
    });
    expect(res.status).toBe(200);
  });

  it('supports custom header name', async () => {
    const customApp = new Hono();
    customApp.use('*', createCsrfMiddleware({ headerName: 'X-Custom-CSRF' }));
    customApp.post('/data', c => c.json({ ok: true }));

    // Wrong header name
    const bad = await customApp.request('/data', {
      method: 'POST',
      headers: { 'X-Fortress-CSRF': '1', 'Content-Type': 'application/json' },
      body: '{}',
    });
    expect(bad.status).toBe(403);

    // Correct header name
    const good = await customApp.request('/data', {
      method: 'POST',
      headers: { 'X-Custom-CSRF': '1', 'Content-Type': 'application/json' },
      body: '{}',
    });
    expect(good.status).toBe(200);
  });

  it('supports skip paths (segment-boundary match)', async () => {
    const skipApp = new Hono();
    skipApp.use('*', createCsrfMiddleware({ skipPaths: ['/webhook'] }));
    skipApp.post('/webhook/github', c => c.json({ ok: true }));
    skipApp.post('/api/data', c => c.json({ ok: true }));

    const skipped = await skipApp.request('/webhook/github', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    expect(skipped.status).toBe(200);

    const enforced = await skipApp.request('/api/data', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    expect(enforced.status).toBe(403);
  });

  it('does not skip a sibling route that shares a string prefix with a skip path', async () => {
    // Regression for the fail-open prefix match: skipping `/api/public` must
    // NOT also skip `/api/public-keys`.
    const skipApp = new Hono();
    skipApp.use('*', createCsrfMiddleware({ skipPaths: ['/api/public'] }));
    skipApp.post('/api/public', c => c.json({ ok: true }));
    skipApp.delete('/api/public-keys', c => c.json({ ok: true }));

    const skipped = await skipApp.request('/api/public', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: '{}',
    });
    expect(skipped.status).toBe(200);

    // The sibling is a distinct path segment → CSRF still enforced.
    const enforced = await skipApp.request('/api/public-keys', {
      method: 'DELETE',
      headers: { 'Content-Type': 'application/json' },
    });
    expect(enforced.status).toBe(403);
  });
});

// =====================
// Plugin Route Mounting
// =====================

describe('plugin route mounting: OAuth', () => {
  let fortress: Fortress<any>;
  let app: Hono<FortressEnv>;
  let oauthClient: { clientId: string; clientSecret: string };

  beforeEach(async () => {
    fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
      plugins: [oauth({ issuerUrl: 'https://auth.example.com' })],
    });

    app = new Hono<FortressEnv>();
    const { errorHandler } = createHonoMiddleware(fortress);
    app.onError(errorHandler);

    mountFortress(app, fortress);

    // Create an OAuth client
    const methods = fortress.plugins.oauth as any;
    oauthClient = await methods.createClient({
      name: 'Test App',
      redirectUris: ['https://app.example.com/callback'],
      grantTypes: ['authorization_code', 'client_credentials'],
    });
  });

  it('gET /.well-known/openid-configuration returns discovery document', async () => {
    const res = await app.request('/oauth/.well-known/openid-configuration');
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.issuer).toBe('https://auth.example.com');
    expect(body.token_endpoint).toContain('/oauth/token');
    expect(body.grant_types_supported).toContain('authorization_code');
    expect(body.grant_types_supported).toContain('client_credentials');
  });

  it('pOST /oauth/token with client_credentials grant', async () => {
    const basicAuth = btoa(`${oauthClient.clientId}:${oauthClient.clientSecret}`);

    const res = await app.request('/oauth/token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials&scope=read',
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.access_token).toBeTruthy();
    expect(body.token_type).toBe('Bearer');
    expect(body.expires_in).toBeDefined();
  });

  it('pOST /oauth/token rejects invalid client credentials', async () => {
    const basicAuth = btoa(`${oauthClient.clientId}:wrong-secret`);

    const res = await app.request('/oauth/token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials',
    });

    expect(res.status).toBe(401);
  });

  it('pOST /oauth/token rejects unsupported grant_type', async () => {
    const basicAuth = btoa(`${oauthClient.clientId}:${oauthClient.clientSecret}`);

    const res = await app.request('/oauth/token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=password',
    });

    expect(res.status).toBe(400);
  });

  it('pOST /oauth/introspect validates token', async () => {
    const basicAuth = btoa(`${oauthClient.clientId}:${oauthClient.clientSecret}`);

    // First get a token
    const tokenRes = await app.request('/oauth/token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials',
    });
    const tokenBody = await tokenRes.json() as any;

    // Introspect it
    const introspectRes = await app.request('/oauth/introspect', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `token=${tokenBody.access_token}`,
    });

    expect(introspectRes.status).toBe(200);
    const body = await introspectRes.json() as any;
    expect(body.active).toBe(true);
    expect(body.client_id).toBe(oauthClient.clientId);
    expect(body.token_type).toBe('Bearer');
  });

  it('pOST /oauth/introspect rejects without client auth', async () => {
    const res = await app.request('/oauth/introspect', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: 'token=some-token',
    });

    expect(res.status).toBe(401);
    const body = await res.json() as any;
    expect(body.error).toBe('invalid_client');
  });

  it('pOST /oauth/introspect returns inactive for invalid token', async () => {
    const basicAuth = btoa(`${oauthClient.clientId}:${oauthClient.clientSecret}`);

    const res = await app.request('/oauth/introspect', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'token=nonexistent-token',
    });

    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.active).toBe(false);
  });

  it('pOST /oauth/revoke succeeds for valid token', async () => {
    const basicAuth = btoa(`${oauthClient.clientId}:${oauthClient.clientSecret}`);

    // Get token
    const tokenRes = await app.request('/oauth/token', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: 'grant_type=client_credentials',
    });
    const { access_token } = await tokenRes.json() as any;

    // Revoke
    const revokeRes = await app.request('/oauth/revoke', {
      method: 'POST',
      headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      body: `token=${access_token}`,
    });
    expect(revokeRes.status).toBe(200);

    // Introspect should show inactive
    const introspectRes = await app.request('/oauth/introspect', {
      method: 'POST',
      headers: {
        'Authorization': `Basic ${basicAuth}`,
        'Content-Type': 'application/x-www-form-urlencoded',
      },
      body: `token=${access_token}`,
    });
    const body = await introspectRes.json() as any;
    expect(body.active).toBe(false);
  });

  it('gET /oauth/userinfo requires Bearer token', async () => {
    const res = await app.request('/oauth/userinfo');
    expect(res.status).toBe(401);
    const body = await res.json() as any;
    expect(body.error).toBe('invalid_token');
  });

  it('gET /oauth/userinfo returns user for valid token with userId', async () => {
    // Create user and auth code
    const user = await fortress.auth.createUser({
      email: 'oauth-user@test.com',
      name: 'OAuth User',
      password: 'password-123',
    });

    const methods = fortress.plugins.oauth as any;
    const { code } = await methods.createAuthorizationCode({
      clientId: oauthClient.clientId,
      userId: user.id,
      redirectUri: 'https://app.example.com/callback',
    });

    const tokenResult = await methods.exchangeCode({
      code,
      clientId: oauthClient.clientId,
      clientSecret: oauthClient.clientSecret,
      redirectUri: 'https://app.example.com/callback',
    });

    const res = await app.request('/oauth/userinfo', {
      headers: { Authorization: `Bearer ${tokenResult.accessToken}` },
    });
    expect(res.status).toBe(200);
    const body = await res.json() as any;
    expect(body.sub).toBe(String(user.id));
    expect(body.email).toBe('oauth-user@test.com');
    expect(body.name).toBe('OAuth User');
  });
});

// =====================
// Plugin Route Mounting: OpenAPI with prefix
// =====================

describe('plugin route mounting: OpenAPI with prefix', () => {
  it('scalar UI data-url resolves to prefixed spec path', async () => {
    const fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
      plugins: [openapi()],
    });

    const app = new Hono<FortressEnv>();
    const { errorHandler } = createHonoMiddleware(fortress);
    app.onError(errorHandler);

    mountFortress(app, fortress, { prefix: '/api/v1' });

    // Spec should be served at the prefixed path
    const specRes = await app.request('/api/v1/openapi.json');
    expect(specRes.status).toBe(200);
    const spec = await specRes.json() as any;
    expect(spec.openapi).toBe('3.1.0');

    // UI should be served at the prefixed path
    const uiRes = await app.request('/api/v1/openapi');
    expect(uiRes.status).toBe(200);
    const html = await uiRes.text();
    expect(html).toContain('data-url="./openapi.json"');
    // Must NOT contain the absolute unprefixed path
    expect(html).not.toContain('data-url="/openapi.json"');
  });

  it('unprefixed spec path returns 404', async () => {
    const fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
      plugins: [openapi()],
    });

    const app = new Hono<FortressEnv>();
    mountFortress(app, fortress, { prefix: '/api/v1' });

    const res = await app.request('/openapi.json');
    expect(res.status).toBe(404);
  });
});

// =====================
// Full auth flow via Hono
// =====================

describe('full auth flow via Hono', () => {
  let fortress: Fortress;
  let app: Hono<FortressEnv>;

  beforeEach(async () => {
    fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
    });

    app = createApp(fortress);

    app.post('/auth/refresh', async (c) => {
      const { refreshToken } = await c.req.json();
      const result = await fortress.auth.refresh(refreshToken);
      return c.json(result);
    });

    app.post('/auth/logout', async (c) => {
      const { refreshToken } = await c.req.json();
      await fortress.auth.logout(refreshToken);
      return c.json({ ok: true });
    });

    app.get('/api/me', (c) => {
      const userId = getUserId(c);
      return c.json({ userId });
    });
  });

  it('register → login → access protected → refresh → access again → logout', async () => {
    // Register
    const regRes = await app.request('/auth/register', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ email: 'flow@test.com', name: 'Flow', password: 'password-123' }),
    });
    expect(regRes.status).toBe(200);

    // Login
    const loginRes = await app.request('/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ identifier: 'flow@test.com', password: 'password-123' }),
    });
    expect(loginRes.status).toBe(200);
    const loginData = await loginRes.json() as any;
    expect(loginData.accessToken).toBeTruthy();
    expect(loginData.refreshToken).toBeTruthy();

    // Access protected route
    const meRes = await app.request('/api/me', {
      headers: { Authorization: `Bearer ${loginData.accessToken}` },
    });
    expect(meRes.status).toBe(200);
    const meData = await meRes.json() as any;
    expect(meData.userId).toBe(loginData.user.id);

    // Refresh
    const refreshRes = await app.request('/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: loginData.refreshToken }),
    });
    expect(refreshRes.status).toBe(200);
    const refreshData = await refreshRes.json() as any;
    expect(refreshData.accessToken).toBeTruthy();
    expect(refreshData.refreshToken).toBeTruthy();

    // Access with new token
    const meRes2 = await app.request('/api/me', {
      headers: { Authorization: `Bearer ${refreshData.accessToken}` },
    });
    expect(meRes2.status).toBe(200);

    // Logout
    const logoutRes = await app.request('/auth/logout', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: refreshData.refreshToken }),
    });
    expect(logoutRes.status).toBe(200);

    // Refresh after logout should fail
    const failedRefresh = await app.request('/auth/refresh', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ refreshToken: refreshData.refreshToken }),
    });
    expect(failedRefresh.status).toBe(401);
  });
});
