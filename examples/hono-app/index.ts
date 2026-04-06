/**
 * Example Hono app using Fortress
 *
 * Demonstrates: registration, login, token refresh, RBAC, 2FA, audit log,
 * and OAuth server endpoints.
 *
 * Run: bun run dev
 * Or:  bun run examples/hono-app/index.ts
 */
import { Hono } from 'hono';
import { createFortress } from '../../src';
import { createHonoMiddleware, getUserId, mountPluginRoutes } from '../../src/hono';
import { auditLog } from '../../src/plugins/audit-log';
import { oauth } from '../../src/plugins/oauth';
import { twoFactor } from '../../src/plugins/two-factor';
import { createTestAdapter } from '../../src/testing';

// --- 1. Create Fortress instance ---

const db = createTestAdapter();

const fortress = createFortress({
  jwt: { secret: 'dev-secret-minimum-32-bytes-long!' },
  database: db,
  plugins: [
    twoFactor({ totp: { issuer: 'Fortress Example' } }),
    auditLog({ hashChain: true }),
    oauth({
      issuerUrl: 'http://localhost:3000',
      scopePermissionMap: {
        'read:users': { resource: 'user', action: 'list' },
      },
    }),
  ],
});

// Type-safe plugin access — no casting needed (2A)
// fortress.plugins['two-factor'].enable(userId) ← fully typed

// --- 2. Create Hono app + middleware ---

const app = new Hono();

const { authMiddleware, rbacMiddleware, errorHandler } = createHonoMiddleware(fortress, {
  routeMap: {
    'GET /api/users': { resource: 'user', action: 'list' },
    'POST /api/users': { resource: 'user', action: 'create' },
  },
  skipPaths: ['/health', '/auth/*'],
});

app.onError(errorHandler);

// --- 3. Public routes ---

// curl http://localhost:3000/health
app.get('/health', c => c.json({ status: 'ok' }));

// curl -X POST http://localhost:3000/auth/register -H 'Content-Type: application/json' \
//   -d '{"email":"user@example.com","password":"password-at-least-8","name":"Test User"}'
app.post('/auth/register', async (c) => {
  const { email, password, name } = await c.req.json();
  const user = await fortress.auth.createUser({ email, password, name });
  return c.json({ data: user }, 201);
});

// curl -X POST http://localhost:3000/auth/login -H 'Content-Type: application/json' \
//   -d '{"identifier":"admin@example.com","password":"admin-password-123!"}'
app.post('/auth/login', async (c) => {
  const { identifier, password } = await c.req.json();
  const result = await fortress.auth.login(identifier, password, {
    ipAddress: c.req.header('x-forwarded-for'),
    userAgent: c.req.header('user-agent'),
  });
  return c.json({ data: result });
});

// curl -X POST http://localhost:3000/auth/refresh -H 'Content-Type: application/json' \
//   -d '{"refreshToken":"<token>"}'
app.post('/auth/refresh', async (c) => {
  const { refreshToken } = await c.req.json();
  const result = await fortress.auth.refresh(refreshToken);
  return c.json({ data: result });
});

// --- 4. Protected routes (require JWT) ---

app.use('/auth/me', authMiddleware);
app.use('/auth/2fa/*', authMiddleware);

// curl http://localhost:3000/auth/me -H 'Authorization: Bearer <token>'
app.get('/auth/me', async (c) => {
  const userId = getUserId(c);
  const user = await db.findOne({ model: 'user', where: [{ field: 'id', operator: '=', value: userId }] });
  return c.json({ data: user });
});

// curl -X POST http://localhost:3000/auth/2fa/enable -H 'Authorization: Bearer <token>'
app.post('/auth/2fa/enable', async (c) => {
  const userId = getUserId(c);
  const result = await fortress.plugins['two-factor'].enable(userId);
  return c.json({ data: { otpauthUrl: result.otpauthUrl, backupCodes: result.backupCodes } });
});

// curl -X POST http://localhost:3000/auth/2fa/verify -H 'Authorization: Bearer <token>' \
//   -H 'Content-Type: application/json' -d '{"code":"123456"}'
app.post('/auth/2fa/verify', async (c) => {
  const userId = getUserId(c);
  const { code } = await c.req.json();
  const result = await fortress.plugins['two-factor'].verify(userId, code, {
    userAgent: c.req.header('user-agent'),
  });
  return c.json({ data: result });
});

// --- 5. RBAC-protected routes ---

app.use('/api/*', authMiddleware);
app.use('/api/*', rbacMiddleware);

// curl http://localhost:3000/api/users -H 'Authorization: Bearer <token>'
app.get('/api/users', async (c) => {
  const users = await db.findMany({ model: 'user' });
  return c.json({ data: users });
});

// curl -X POST http://localhost:3000/api/users -H 'Authorization: Bearer <token>' \
//   -H 'Content-Type: application/json' -d '{"email":"new@example.com","name":"New User"}'
app.post('/api/users', async (c) => {
  const body = await c.req.json();
  const user = await fortress.auth.createUser({ ...body, password: 'temp-password-123!' });
  return c.json({ data: user }, 201);
});

// --- 6. Mount OAuth server endpoints ---
// POST /oauth/token, POST /oauth/introspect, POST /oauth/revoke,
// GET /oauth/userinfo, GET /oauth/.well-known/openid-configuration
mountPluginRoutes(app, fortress);

// --- 7. Seed data on startup ---

async function seed(): Promise<void> {
  // Create admin user
  const admin = await fortress.auth.createUser({
    email: 'admin@example.com',
    password: 'admin-password-123!',
    name: 'Admin User',
  });

  // Create role with permissions
  const adminRole = await fortress.iam.createRole('admin', [
    { resource: 'user', action: 'list' },
    { resource: 'user', action: 'create' },
    { resource: 'user', action: 'read' },
  ], 'Full access');

  // Bind role to admin user
  await fortress.iam.bindRole('user', admin.id, adminRole.id);

  console.warn('Seeded admin user: admin@example.com / admin-password-123!');
  console.warn('Fortress example app running on http://localhost:3000');
}

seed().catch(console.error);

export default {
  port: 3000,
  fetch: app.fetch,
};
