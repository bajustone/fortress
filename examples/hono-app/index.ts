/**
 * Example Hono app using Fortress
 *
 * Demonstrates EVERY feature Fortress offers:
 *
 *   Core: registration, login, logout, token refresh, sessions, impersonation,
 *         RBAC (roles, groups, permissions), password policy
 *
 *   Plugins: rate-limit, account-lockout, email-verification, two-factor,
 *            magic-link, api-key, social-login, tenancy, data-isolation,
 *            audit-log, webhook, oauth
 *
 *   Middleware: auth, RBAC, CSRF, security headers
 *
 *   Helpers: getUserId, getClaims, getDb, getScopedDb
 *
 * Run:  bun run dev
 * Or:   bun run examples/hono-app/index.ts
 */
import { Hono } from 'hono';
import { createFortress, obj, str } from '../../src';
import {
  convertRoutes,
  createCsrfMiddleware,
  createHonoMiddleware,
  createSecurityHeadersMiddleware,
  getClaims,
  getDb,
  getScopedDb,
  getUserId,
  mountFortress,
  vBody,
  vParam,
  vQuery,
} from '../../src/hono';
import { accountLockout } from '../../src/plugins/account-lockout';
import { admin } from '../../src/plugins/admin';
import { apiKey } from '../../src/plugins/api-key';
import { auditLog } from '../../src/plugins/audit-log';
import { dataIsolation } from '../../src/plugins/data-isolation';
import { emailVerification } from '../../src/plugins/email-verification';
import { magicLink } from '../../src/plugins/magic-link';
import { oauth } from '../../src/plugins/oauth';
import { openapi } from '../../src/plugins/openapi';
import { rateLimit } from '../../src/plugins/rate-limit';
import { socialLogin } from '../../src/plugins/social-login';
import { tenancy } from '../../src/plugins/tenancy';
import { twoFactor } from '../../src/plugins/two-factor';
import { webhook } from '../../src/plugins/webhook';
import { createTestAdapter } from '../../src/testing';

// ═══════════════════════════════════════════════════════════════════════════
// 1. Create Fortress instance with ALL plugins
// ═══════════════════════════════════════════════════════════════════════════

const db = createTestAdapter();

const fortress = createFortress({
  jwt: {
    secret: 'dev-secret-minimum-32-bytes-long!',
    // secret: ['new-secret-32-bytes-minimum!!!!!!', 'old-secret-32-bytes-minimum!!!!!!'],  // ← secret rotation
    accessTokenExpirySeconds: 900,
    refreshTokenExpirySeconds: 604800,
  },
  database: db,
  passwordPolicy: { minLength: 10 },

  // Plugin order matters — hooks run in array order
  plugins: [
    // ── Admin (IAM route protection + bootstrap) ──
    admin({ apiKeyRoutes: true }),

    // ── Gate plugins (reject early) ──
    rateLimit({
      login: { maxPerIp: 100, maxPerAccount: 10, windowSeconds: 60 },
      register: { maxPerIp: 50, windowSeconds: 60 },
    }),
    accountLockout({
      maxFailedAttempts: 3,
      lockoutDurationSeconds: 60,
      escalation: true,
    }),
    emailVerification({
      requireVerification: false, // set true in production
      onSendVerification: async (email, token, userId) => {
        console.warn(`[email-verification] userId=${userId} email=${email} token=${token}`);
      },
    }),

    // ── Auth enhancement plugins ──
    twoFactor({ totp: { issuer: 'Fortress Example' } }),
    magicLink({
      onSendMagicLink: async (email, token) => {
        console.warn(`[magic-link] email=${email} token=${token}`);
      },
    }),
    apiKey({ prefix: 'fortress', maxKeysPerUser: 5, routes: true }),
    // ^ `routes: true` mounts the self-service HTTP endpoints:
    //   POST   /api-key/keys                   — create a key for the caller
    //   GET    /api-key/keys                   — list the caller's keys
    //   DELETE /api-key/keys/:id               — revoke one of the caller's keys
    //   POST   /api-key/keys/:id/rotate        — rotate one of the caller's keys
    // The admin plugin above adds admin-side routes when `apiKeyRoutes: true`:
    //   GET    /admin/users/:userId/api-keys       — list any user's keys
    //   DELETE /admin/users/:userId/api-keys/:id   — revoke any user's key
    // Both require the `apiKey:manage` permission (auto-registered into
    // `fortress-admin` via `/iam/admin/bootstrap`).
    socialLogin({
      providers: [
        // Placeholder credentials — shows the config API but won't complete real OAuth flows
        { name: 'google', clientId: 'GOOGLE_CLIENT_ID', clientSecret: 'GOOGLE_SECRET' },
        { name: 'github', clientId: 'GITHUB_CLIENT_ID', clientSecret: 'GITHUB_SECRET' },
      ],
    }),

    // ── Multi-tenancy & data isolation ──
    tenancy(),
    dataIsolation({
      scopes: [{
        name: 'org',
        field: 'orgId',
        models: ['document'],
        resolveValue: async (userId, ctx) => {
          const assignment = await ctx.db.findOne<{ scopeValue: string }>({
            model: 'user_scope_assignment',
            where: [
              { field: 'userId', operator: '=', value: userId },
              { field: 'scopeName', operator: '=', value: 'org' },
            ],
          });
          return assignment?.scopeValue ?? null;
        },
      }],
    }),

    // ── Observability plugins (log last) ──
    auditLog({ hashChain: true }),
    webhook({
      deliver: async (url, payload, headers) => {
        console.warn(`[webhook] → ${url}`, JSON.parse(payload), headers);
        return true;
      },
    }),

    // ── OAuth server ──
    oauth({
      issuerUrl: 'http://localhost:3000',
      scopePermissionMap: {
        'read:users': { resource: 'user', action: 'list' },
      },
    }),

    // ── OpenAPI (API docs) ──
    // convertRoutes turns createRoute-style objects into EndpointDefinitions
    // using your own schema converter (Zod, Valibot, TypeBox, etc.)
    openapi({
      title: 'Fortress Example API',
      version: '0.0.15',
      additionalEndpoints: convertRoutes(
        [
          // These would normally be imported from your route modules, e.g.:
          // import { loginRoute, listUsersRoute } from './modules/auth/routes';
          {
            method: 'get',
            path: '/health',
            tags: ['App'],
            summary: 'Health check',
            responses: {
              200: {
                description: 'OK',
                content: { 'application/json': { schema: { type: 'object', properties: { status: { type: 'string' } } } } },
              },
            },
          },
        ],
        {
          // User brings their own converter, e.g. z.toJSONSchema for Zod v4
          // Here we use identity since schemas are already JSON Schema
          schemaConverter: s => s as Record<string, unknown>,
        },
      ),
    }),
  ],
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Create Hono app + middleware
// ═══════════════════════════════════════════════════════════════════════════

const app = new Hono();

const { authMiddleware, rbacMiddleware, errorHandler, pluginMiddleware } = createHonoMiddleware(fortress, {
  routeMap: {
    // User management
    'GET /api/users': { resource: 'user', action: 'list' },
    'POST /api/users': { resource: 'user', action: 'create' },
    // Groups
    'POST /api/groups': { resource: 'group', action: 'create' },
    'POST /api/groups/:id/members': { resource: 'group', action: 'manage' },
    'DELETE /api/groups/:id/members/:userId': { resource: 'group', action: 'manage' },
    // Audit log
    'GET /api/audit-log': { resource: 'audit-log', action: 'read' },
    'POST /api/audit-log/verify-chain': { resource: 'audit-log', action: 'read' },
    // Webhooks
    'POST /api/webhooks': { resource: 'webhook', action: 'manage' },
    'GET /api/webhooks': { resource: 'webhook', action: 'manage' },
    'DELETE /api/webhooks/:id': { resource: 'webhook', action: 'manage' },
    // Admin
    'POST /admin/impersonate': { resource: 'user', action: 'impersonate' },
    'GET /admin/lockout/:identifier': { resource: 'lockout', action: 'read' },
    'POST /admin/lockout/:identifier/reset': { resource: 'lockout', action: 'manage' },
  },
  skipPaths: ['/health', '/auth/*', '/magic-link/*', '/email/*', '/social/*'],
});

// Global middleware
app.use('*', createSecurityHeadersMiddleware());
app.use('*', createCsrfMiddleware({
  skipPaths: ['/auth', '/oauth', '/magic-link', '/email', '/social', '/health'],
}));
app.onError(errorHandler);

// IAM routes: auth + admin plugin middleware (default deny via admin plugin)
app.use('/iam/*', authMiddleware);
app.use('/iam/*', pluginMiddleware.afterAuth);

// ═══════════════════════════════════════════════════════════════════════════
// 3. Public routes
// ═══════════════════════════════════════════════════════════════════════════

// curl http://localhost:3000/health
app.get('/health', c => c.json({ status: 'ok' }));

// ── Validated Request Helpers (vBody / vParam / vQuery) ──
// vBody/vParam/vQuery extract request data AND validate it at runtime against
// the supplied Standard Schema. On failure they throw FortressError with code
// VALIDATION_ERROR (HTTP 422) — the same shape every fortress-managed endpoint
// produces — so the registered Hono error handler formats it identically.

const RegisterBody = obj({ email: str(), password: str(), name: str() }, 'email', 'password');
const LoginBody = obj({ identifier: str(), password: str() }, 'identifier', 'password');

// curl -X POST http://localhost:3000/auth/register -H 'Content-Type: application/json' \
//   -d '{"email":"new@example.com","password":"MyPassword123!","name":"New User"}'
app.post('/auth/register', async (c) => {
  const { email, password, name } = await vBody(c, RegisterBody);
  const user = await fortress.auth.createUser({ email, password, name });
  return c.json({ data: user }, 201);
});

// curl -X POST http://localhost:3000/auth/login -H 'Content-Type: application/json' \
//   -d '{"identifier":"admin@example.com","password":"Password123!"}'
app.post('/auth/login', async (c) => {
  const { identifier, password } = await vBody(c, LoginBody);
  const result = await fortress.auth.login(identifier, password, {
    ipAddress: c.req.header('x-forwarded-for'),
    userAgent: c.req.header('user-agent'),
  });
  return c.json({ data: result });
});

// ── vParam / vQuery demo ──
// curl 'http://localhost:3000/echo/42?greeting=hello'              → 200 { id: '42', greeting: 'hello' }
// curl 'http://localhost:3000/echo/42'                             → 422 VALIDATION_ERROR (missing greeting)
const EchoParam = obj({ id: str('Echo ID') }, 'id');
const EchoQuery = obj({ greeting: str('Greeting') }, 'greeting');
app.get('/echo/:id', async (c) => {
  const { id } = await vParam(c, EchoParam);
  const { greeting } = await vQuery(c, EchoQuery);
  return c.json({ id, greeting });
});

// curl -X POST http://localhost:3000/auth/refresh -H 'Content-Type: application/json' \
//   -d '{"refreshToken":"<token>"}'
app.post('/auth/refresh', async (c) => {
  const { refreshToken } = await c.req.json();
  const result = await fortress.auth.refresh(refreshToken);
  return c.json({ data: result });
});

// curl -X POST http://localhost:3000/auth/logout -H 'Content-Type: application/json' \
//   -d '{"refreshToken":"<token>"}'
app.post('/auth/logout', async (c) => {
  const { refreshToken } = await c.req.json();
  await fortress.auth.logout(refreshToken);
  return c.json({ data: { loggedOut: true } });
});

// ── Magic Link (passwordless login) ──

// curl -X POST http://localhost:3000/magic-link/send -H 'Content-Type: application/json' \
//   -d '{"email":"admin@example.com"}'
// (token is logged to console — copy it for the verify step)
app.post('/magic-link/send', async (c) => {
  const { email } = await c.req.json();
  const result = await fortress.plugins['magic-link'].sendMagicLink(email);
  return c.json({ data: result });
});

// curl -X POST http://localhost:3000/magic-link/verify -H 'Content-Type: application/json' \
//   -d '{"token":"<token-from-console>"}'
app.post('/magic-link/verify', async (c) => {
  const { token } = await c.req.json();
  const result = await fortress.plugins['magic-link'].verifyMagicLink(token);
  return c.json({ data: result });
});

// ── Email Verification ──

// curl -X POST http://localhost:3000/email/verify -H 'Content-Type: application/json' \
//   -d '{"token":"<token-from-console>"}'
app.post('/email/verify', async (c) => {
  const { token } = await c.req.json();
  const result = await fortress.plugins['email-verification'].verify(token);
  return c.json({ data: result });
});

// ── Social Login ──

// curl http://localhost:3000/social/providers
app.get('/social/providers', (c) => {
  const providers = fortress.plugins['social-login'].getProviders();
  return c.json({ data: providers });
});

// curl 'http://localhost:3000/social/authorize/google?redirect_uri=http://localhost:3000/callback'
// (returns authorization URL — in a real app you'd redirect the browser)
app.get('/social/authorize/:provider', async (c) => {
  const provider = c.req.param('provider');
  const redirectUri = c.req.query('redirect_uri') ?? 'http://localhost:3000/callback';
  const result = await fortress.plugins['social-login'].getAuthorizationUrl(provider, redirectUri);
  return c.json({ data: result });
});

// ═══════════════════════════════════════════════════════════════════════════
// 4. Protected auth routes (require JWT)
// ═══════════════════════════════════════════════════════════════════════════

app.use('/auth/me', authMiddleware);
app.use('/auth/sessions/*', authMiddleware);
app.use('/auth/sessions', authMiddleware);
app.use('/auth/2fa/*', authMiddleware);
app.use('/auth/email/*', authMiddleware);
app.use('/auth/api-keys/*', authMiddleware);
app.use('/auth/api-keys', authMiddleware);
app.use('/auth/social/*', authMiddleware);

// curl http://localhost:3000/auth/me -H 'Authorization: Bearer <token>'
app.get('/auth/me', async (c) => {
  const userId = getUserId(c);
  const claims = getClaims(c);
  const user = await fortress.auth.me(userId);
  return c.json({ data: { user, claims } });
});

// ── Sessions ──

// curl http://localhost:3000/auth/sessions -H 'Authorization: Bearer <token>'
app.get('/auth/sessions', async (c) => {
  const userId = getUserId(c);
  const sessions = await fortress.auth.listSessions(userId);
  return c.json({ data: sessions });
});

// curl -X DELETE http://localhost:3000/auth/sessions/1 -H 'Authorization: Bearer <token>'
app.delete('/auth/sessions/:id', async (c) => {
  const userId = getUserId(c);
  const tokenId = Number(c.req.param('id'));
  await fortress.auth.revokeSession(userId, tokenId);
  return c.json({ data: { revoked: true } });
});

// curl -X DELETE http://localhost:3000/auth/sessions -H 'Authorization: Bearer <token>' \
//   -H 'Content-Type: application/json' -d '{"currentTokenId":1}'
app.delete('/auth/sessions', async (c) => {
  const userId = getUserId(c);
  const { currentTokenId } = await c.req.json();
  await fortress.auth.revokeAllOtherSessions(userId, currentTokenId);
  return c.json({ data: { revokedOthers: true } });
});

// ── Two-Factor Auth ──

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

// curl -X POST http://localhost:3000/auth/2fa/disable -H 'Authorization: Bearer <token>'
app.post('/auth/2fa/disable', async (c) => {
  const userId = getUserId(c);
  await fortress.plugins['two-factor'].disable(userId);
  return c.json({ data: { disabled: true } });
});

// ── Email Verification (resend) ──

// curl -X POST http://localhost:3000/auth/email/send-verification -H 'Authorization: Bearer <token>'
// (token is logged to console)
app.post('/auth/email/send-verification', async (c) => {
  const userId = getUserId(c);
  const result = await fortress.plugins['email-verification'].sendVerification(userId);
  return c.json({ data: result });
});

// ── API Keys ──

// curl -X POST http://localhost:3000/auth/api-keys -H 'Authorization: Bearer <token>' \
//   -H 'Content-Type: application/json' -d '{"name":"My CI Key","scopes":["read:users"]}'
app.post('/auth/api-keys', async (c) => {
  const userId = getUserId(c);
  const { name, scopes } = await c.req.json();
  const result = await fortress.plugins['api-key'].createKey(userId, { name, scopes });
  return c.json({ data: result }, 201);
});

// curl http://localhost:3000/auth/api-keys -H 'Authorization: Bearer <token>'
app.get('/auth/api-keys', async (c) => {
  const userId = getUserId(c);
  const keys = await fortress.plugins['api-key'].listKeys(userId);
  return c.json({ data: keys });
});

// curl -X DELETE http://localhost:3000/auth/api-keys/1 -H 'Authorization: Bearer <token>'
app.delete('/auth/api-keys/:id', async (c) => {
  const userId = getUserId(c);
  const keyId = Number(c.req.param('id'));
  await fortress.plugins['api-key'].revokeKey(userId, keyId);
  return c.json({ data: { revoked: true } });
});

// curl -X POST http://localhost:3000/auth/api-keys/1/rotate -H 'Authorization: Bearer <token>'
app.post('/auth/api-keys/:id/rotate', async (c) => {
  const userId = getUserId(c);
  const keyId = Number(c.req.param('id'));
  const result = await fortress.plugins['api-key'].rotateKey(userId, keyId);
  return c.json({ data: result });
});

// ── Social Login (linked accounts) ──

// curl http://localhost:3000/auth/social/accounts -H 'Authorization: Bearer <token>'
app.get('/auth/social/accounts', async (c) => {
  const userId = getUserId(c);
  const accounts = await fortress.plugins['social-login'].getLinkedAccounts(userId);
  return c.json({ data: accounts });
});

// curl -X DELETE http://localhost:3000/auth/social/accounts/google -H 'Authorization: Bearer <token>'
app.delete('/auth/social/accounts/:provider', async (c) => {
  const userId = getUserId(c);
  const provider = c.req.param('provider');
  await fortress.plugins['social-login'].unlinkAccount(userId, provider);
  return c.json({ data: { unlinked: true } });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. Tenant routes (require JWT)
// ═══════════════════════════════════════════════════════════════════════════

app.use('/api/tenants/*', authMiddleware);
app.use('/api/tenants', authMiddleware);

// curl -X POST http://localhost:3000/api/tenants -H 'Authorization: Bearer <token>' \
//   -H 'Content-Type: application/json' -d '{"name":"Acme Corp","taxId":"acme"}'
app.post('/api/tenants', async (c) => {
  const { name, taxId, description } = await c.req.json();
  const tenant = await fortress.plugins.tenancy.createTenant({ name, taxId, description });
  return c.json({ data: tenant }, 201);
});

// curl http://localhost:3000/api/tenants -H 'Authorization: Bearer <token>'
app.get('/api/tenants', async (c) => {
  const userId = getUserId(c);
  const tenants = await fortress.plugins.tenancy.getUserTenants(userId);
  return c.json({ data: tenants });
});

// curl -X POST http://localhost:3000/api/tenants/switch -H 'Authorization: Bearer <token>' \
//   -H 'Content-Type: application/json' -d '{"taxId":"acme"}'
app.post('/api/tenants/switch', async (c) => {
  const userId = getUserId(c);
  const { taxId } = await c.req.json();
  await fortress.plugins.tenancy.switchTenant(userId, taxId);
  return c.json({ data: { switched: true } });
});

// curl -X POST http://localhost:3000/api/tenants/1/members -H 'Authorization: Bearer <token>' \
//   -H 'Content-Type: application/json' -d '{"userId":2}'
app.post('/api/tenants/:id/members', async (c) => {
  const tenantId = Number(c.req.param('id'));
  const { userId } = await c.req.json();
  await fortress.plugins.tenancy.addUserToTenant(userId, tenantId);
  return c.json({ data: { added: true } });
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. RBAC-protected routes (require JWT + permissions)
// ═══════════════════════════════════════════════════════════════════════════

app.use('/api/users', authMiddleware);
app.use('/api/groups/*', authMiddleware);
app.use('/api/groups', authMiddleware);
app.use('/api/users', rbacMiddleware);
app.use('/api/groups/*', rbacMiddleware);
app.use('/api/groups', rbacMiddleware);

// curl http://localhost:3000/api/users -H 'Authorization: Bearer <token>'
app.get('/api/users', async (c) => {
  // getDb() returns the request-scoped adapter (tenant-aware when tenancy plugin is active)
  const reqDb = getDb(c);
  const users = await reqDb.findMany({ model: 'user' });
  return c.json({ data: users });
});

// curl -X POST http://localhost:3000/api/users -H 'Authorization: Bearer <token>' \
//   -H 'Content-Type: application/json' -H 'X-Fortress-CSRF: 1' \
//   -d '{"email":"new@example.com","name":"New User"}'
app.post('/api/users', async (c) => {
  const body = await c.req.json();
  const user = await fortress.auth.createUser({ ...body, password: 'TempPassword123!' });
  return c.json({ data: user }, 201);
});

// ── Groups ──

// curl -X POST http://localhost:3000/api/groups -H 'Authorization: Bearer <token>' \
//   -H 'Content-Type: application/json' -H 'X-Fortress-CSRF: 1' \
//   -d '{"name":"engineering","description":"Engineering team"}'
app.post('/api/groups', async (c) => {
  const { name, description } = await c.req.json();
  const group = await fortress.iam.createGroup(name, description);
  return c.json({ data: group }, 201);
});

// curl -X POST http://localhost:3000/api/groups/1/members -H 'Authorization: Bearer <token>' \
//   -H 'Content-Type: application/json' -H 'X-Fortress-CSRF: 1' -d '{"userId":2}'
app.post('/api/groups/:id/members', async (c) => {
  const groupId = Number(c.req.param('id'));
  const { userId } = await c.req.json();
  await fortress.iam.addUserToGroup(groupId, userId);
  return c.json({ data: { added: true } });
});

// curl -X DELETE http://localhost:3000/api/groups/1/members/2 -H 'Authorization: Bearer <token>'
app.delete('/api/groups/:id/members/:userId', async (c) => {
  const groupId = Number(c.req.param('id'));
  const userId = Number(c.req.param('userId'));
  await fortress.iam.removeUserFromGroup(groupId, userId);
  return c.json({ data: { removed: true } });
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. Admin routes (require JWT + elevated permissions)
// ═══════════════════════════════════════════════════════════════════════════

app.use('/api/audit-log/*', authMiddleware);
app.use('/api/audit-log', authMiddleware);
app.use('/api/webhooks/*', authMiddleware);
app.use('/api/webhooks', authMiddleware);
app.use('/admin/*', authMiddleware);
app.use('/api/audit-log/*', rbacMiddleware);
app.use('/api/audit-log', rbacMiddleware);
app.use('/api/webhooks/*', rbacMiddleware);
app.use('/api/webhooks', rbacMiddleware);
app.use('/admin/*', rbacMiddleware);

// ── Audit Log ──

// curl 'http://localhost:3000/api/audit-log?limit=20' -H 'Authorization: Bearer <token>'
app.get('/api/audit-log', async (c) => {
  const options: Record<string, unknown> = {};
  const userId = c.req.query('userId');
  const eventType = c.req.query('eventType');
  const limit = c.req.query('limit');
  if (userId)
    options.userId = Number(userId);
  if (eventType)
    options.eventType = eventType;
  if (limit)
    options.limit = Number(limit);
  const entries = await fortress.plugins['audit-log'].getAuditLog(options);
  return c.json({ data: entries });
});

// curl -X POST http://localhost:3000/api/audit-log/verify-chain -H 'Authorization: Bearer <token>' \
//   -H 'X-Fortress-CSRF: 1'
app.post('/api/audit-log/verify-chain', async (c) => {
  const result = await fortress.plugins['audit-log'].verifyChain();
  return c.json({ data: result });
});

// ── Impersonation ──

// curl -X POST http://localhost:3000/admin/impersonate -H 'Authorization: Bearer <token>' \
//   -H 'Content-Type: application/json' -H 'X-Fortress-CSRF: 1' -d '{"targetUserId":2}'
app.post('/admin/impersonate', async (c) => {
  const adminId = getUserId(c);
  const { targetUserId, reason } = await c.req.json();
  const result = await fortress.auth.impersonate(adminId, targetUserId, { reason });
  return c.json({ data: result });
});

// ── Account Lockout ──

// curl http://localhost:3000/admin/lockout/user@example.com -H 'Authorization: Bearer <token>'
app.get('/admin/lockout/:identifier', async (c) => {
  const identifier = c.req.param('identifier');
  const status = await fortress.plugins['account-lockout'].getLockoutStatus(identifier);
  return c.json({ data: status });
});

// curl -X POST http://localhost:3000/admin/lockout/user@example.com/reset \
//   -H 'Authorization: Bearer <token>' -H 'X-Fortress-CSRF: 1'
app.post('/admin/lockout/:identifier/reset', async (c) => {
  const identifier = c.req.param('identifier');
  await fortress.plugins['account-lockout'].resetLockout(identifier);
  return c.json({ data: { reset: true } });
});

// ── Webhooks ──

// curl -X POST http://localhost:3000/api/webhooks -H 'Authorization: Bearer <token>' \
//   -H 'Content-Type: application/json' -H 'X-Fortress-CSRF: 1' \
//   -d '{"url":"https://example.com/hook","events":["LOGIN_SUCCESS","REGISTER"],"secret":"wh-secret"}'
app.post('/api/webhooks', async (c) => {
  const { url, events, secret } = await c.req.json();
  const endpoint = await fortress.plugins.webhook.registerEndpoint(url, events, secret);
  return c.json({ data: endpoint }, 201);
});

// curl http://localhost:3000/api/webhooks -H 'Authorization: Bearer <token>'
app.get('/api/webhooks', async (c) => {
  const endpoints = await fortress.plugins.webhook.listEndpoints();
  return c.json({ data: endpoints });
});

// curl -X DELETE http://localhost:3000/api/webhooks/1 -H 'Authorization: Bearer <token>'
app.delete('/api/webhooks/:id', async (c) => {
  const id = Number(c.req.param('id'));
  await fortress.plugins.webhook.removeEndpoint(id);
  return c.json({ data: { removed: true } });
});

// ── Data Isolation (demonstrates getScopedDb) ──

app.use('/api/documents', authMiddleware);

// curl http://localhost:3000/api/documents -H 'Authorization: Bearer <token>'
// getScopedDb() applies row-level isolation — queries are automatically filtered
// by the user's org scope (configured in the dataIsolation plugin above).
app.get('/api/documents', async (c) => {
  const scopedDb = await getScopedDb(c, 'document');
  const docs = await scopedDb.findMany({ model: 'document' });
  return c.json({ data: docs });
});

// ═══════════════════════════════════════════════════════════════════════════
// 8. Mount Fortress routes (auth, IAM, plugins, OAuth, OpenAPI)
// ═══════════════════════════════════════════════════════════════════════════
//
// `mountFortress` registers a single Hono middleware that detects any
// Fortress-managed path (`/auth/*`, `/iam/*`, `/oauth/*`, `/openapi*`,
// plugin routes) and delegates to `fortress.handleRequest`. The custom
// `/auth/*` handlers above are registered FIRST, so Hono's first-match
// routing means they win — `mountFortress` only handles paths the user
// did not handle manually.
//
// Auth issuing endpoints (login/refresh/impersonate) inside core
// dispatch automatically attach `Set-Cookie` headers using
// `FortressConfig.cookies` defaults.
mountFortress(app, fortress);

// ═══════════════════════════════════════════════════════════════════════════
// 9. Seed data on startup
// ═══════════════════════════════════════════════════════════════════════════

async function seed(): Promise<void> {
  // Create users
  const admin = await fortress.auth.createUser({
    email: 'admin@example.com',
    password: 'Password123!',
    name: 'Admin User',
  });
  const user = await fortress.auth.createUser({
    email: 'user@example.com',
    password: 'Password123!',
    name: 'Regular User',
  });

  // Mark emails as verified
  await db.update({ model: 'user', where: [{ field: 'id', operator: '=', value: admin.id }], data: { emailVerified: true } });
  await db.update({ model: 'user', where: [{ field: 'id', operator: '=', value: user.id }], data: { emailVerified: true } });

  // Bootstrap admin user — creates fortress-admin role with all IAM permissions
  await fortress.plugins.admin.bootstrap({ userId: admin.id });

  // Create app-specific roles with permissions
  const adminRole = await fortress.iam.createRole('admin', [
    { resource: 'user', action: 'list' },
    { resource: 'user', action: 'create' },
    { resource: 'user', action: 'read' },
    { resource: 'user', action: 'impersonate' },
    { resource: 'group', action: 'create' },
    { resource: 'group', action: 'manage' },
    { resource: 'audit-log', action: 'read' },
    { resource: 'webhook', action: 'manage' },
    { resource: 'lockout', action: 'read' },
    { resource: 'lockout', action: 'manage' },
  ], 'Full admin access');

  const viewerRole = await fortress.iam.createRole('viewer', [
    { resource: 'user', action: 'list' },
    { resource: 'user', action: 'read' },
  ], 'Read-only access');

  // Bind roles
  await fortress.iam.bindRole('user', admin.id, adminRole.id);
  await fortress.iam.bindRole('user', user.id, viewerRole.id);

  // Create a group and add admin
  const engineering = await fortress.iam.createGroup('engineering', 'Engineering team');
  await fortress.iam.addUserToGroup(engineering.id, admin.id);

  // Create a tenant and add admin
  const tenant = await fortress.plugins.tenancy.createTenant({ name: 'Acme Corp', taxId: 'acme' });
  await fortress.plugins.tenancy.addUserToTenant(admin.id, tenant.id);

  // Register a webhook endpoint
  await fortress.plugins.webhook.registerEndpoint(
    'https://example.com/webhooks',
    ['LOGIN_SUCCESS', 'REGISTER'],
    'webhook-signing-secret',
  );

  console.warn('');
  console.warn('╔══════════════════════════════════════════════╗');
  console.warn('║  Fortress Example App                        ║');
  console.warn('╠══════════════════════════════════════════════╣');
  console.warn('║  Admin:  admin@example.com / Password123!    ║');
  console.warn('║  User:   user@example.com  / Password123!    ║');
  console.warn('║  Tenant: Acme Corp (taxId: acme)             ║');
  console.warn('║  Group:  engineering                          ║');
  console.warn('╠══════════════════════════════════════════════╣');
  console.warn('║  http://localhost:3000                        ║');
  console.warn('╚══════════════════════════════════════════════╝');
  console.warn('');
}

seed().catch(console.error);

export default {
  port: 3000,
  fetch: app.fetch,
};
