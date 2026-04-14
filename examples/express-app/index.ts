#!/usr/bin/env bun
import type { ExpressNextFunction, ExpressRequest, ExpressResponse } from '../../src/express';
/**
 * Example Express app using Fortress
 *
 * Demonstrates EVERY feature Fortress offers with Express:
 *
 *   Core: registration, login, logout, token refresh, sessions, impersonation,
 *         RBAC (roles, groups, permissions), password policy
 *
 *   Plugins: rate-limit, account-lockout, email-verification, two-factor,
 *            magic-link, api-key, social-login, tenancy, data-isolation,
 *            audit-log, webhook, oauth, openapi
 *
 *   Middleware: auth, RBAC, error handler
 *
 *   Helpers: getUserId, getClaims, getDb, getScopedDb
 *
 * Run:  bun run examples/express-app/index.ts
 */
import { createFortress, obj, str } from '../../src';
import {
  convertRoutes,
  createExpressMiddleware,
  getClaims,
  getDb,
  getScopedDb,
  getUserId,
  mountFortress,
  vBody,
  vParam,
  vQuery,
} from '../../src/express';
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
      requireVerification: false,
      onSendVerification: async (email, token, userId) => {
        console.warn(`[email-verification] userId=${userId} email=${email} token=${token}`);
      },
    }),

    // ── Auth enhancement plugins ──
    twoFactor({ totp: { issuer: 'Fortress Express Example' } }),
    magicLink({
      onSendMagicLink: async (email, token) => {
        console.warn(`[magic-link] email=${email} token=${token}`);
      },
    }),
    apiKey({ prefix: 'fortress', maxKeysPerUser: 5, routes: true }),
    // `routes: true` mounts /api-key/keys/* self-service endpoints.
    // `admin({ apiKeyRoutes: true })` above adds /admin/users/:userId/api-keys/*
    // admin routes, gated by the `apiKey:manage` permission.
    socialLogin({
      providers: [
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
      issuerUrl: 'http://localhost:3001',
      scopePermissionMap: {
        'read:users': { resource: 'user', action: 'list' },
      },
    }),

    // ── OpenAPI (API docs) ──
    // convertRoutes turns createRoute-style objects into EndpointDefinitions
    // using your own schema converter — fortress has zero schema deps
    openapi({
      title: 'Fortress Express Example API',
      version: '0.0.15',
      additionalEndpoints: convertRoutes(
        [
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
        { schemaConverter: s => s as Record<string, unknown> },
      ),
    }),
  ],
});

// ═══════════════════════════════════════════════════════════════════════════
// 2. Create Express-like app using Bun.serve + minimal router
// ═══════════════════════════════════════════════════════════════════════════
//
// This example uses a tiny Express-compatible router so it runs with zero
// npm dependencies (just bun). In a real project you'd use Express/Koa/etc.

type Handler = (req: ExpressRequest, res: ExpressResponse, next: ExpressNextFunction) => void | Promise<void>;

interface Route {
  method: string;
  path: string;
  pattern: RegExp;
  paramNames: string[];
  handler: Handler;
}

const routes: Route[] = [];
const middlewares: Array<{ path: string; handler: Handler }> = [];

function pathToRegexAndParams(path: string): { pattern: RegExp; paramNames: string[] } {
  const paramNames: string[] = [];
  const regexStr = path
    .replace(/:(\w+)/g, (_match, name) => {
      paramNames.push(name);
      return '([^/]+)';
    })
    .replace(/\*/g, '.*')
    .replace(/\//g, '\\/');
  return { pattern: new RegExp(`^${regexStr}$`), paramNames };
}

function registerRoute(method: string, path: string, handler: Handler): void {
  const { pattern, paramNames } = pathToRegexAndParams(path);
  routes.push({ method, path, pattern, paramNames, handler });
}

// Express-compatible app interface
const app = {
  get: (path: string, ...handlers: Handler[]) => handlers.forEach(h => registerRoute('GET', path, h)),
  post: (path: string, ...handlers: Handler[]) => handlers.forEach(h => registerRoute('POST', path, h)),
  put: (path: string, ...handlers: Handler[]) => handlers.forEach(h => registerRoute('PUT', path, h)),
  delete: (path: string, ...handlers: Handler[]) => handlers.forEach(h => registerRoute('DELETE', path, h)),
  patch: (path: string, ...handlers: Handler[]) => handlers.forEach(h => registerRoute('PATCH', path, h)),
  use: (pathOrHandler: string | Handler, handler?: Handler) => {
    if (typeof pathOrHandler === 'function') {
      middlewares.push({ path: '/', handler: pathOrHandler });
    }
    else {
      middlewares.push({ path: pathOrHandler, handler: handler! });
    }
  },
};

// ═══════════════════════════════════════════════════════════════════════════
// 3. Fortress middleware
// ═══════════════════════════════════════════════════════════════════════════

const { authMiddleware, rbacMiddleware, errorHandler, pluginMiddleware } = createExpressMiddleware(fortress, {
  routeMap: {
    'GET /api/users': { resource: 'user', action: 'list' },
    'POST /api/users': { resource: 'user', action: 'create' },
    'POST /api/groups': { resource: 'group', action: 'create' },
    'POST /api/groups/:id/members': { resource: 'group', action: 'manage' },
    'DELETE /api/groups/:id/members/:userId': { resource: 'group', action: 'manage' },
    'GET /api/audit-log': { resource: 'audit-log', action: 'read' },
    'POST /admin/impersonate': { resource: 'user', action: 'impersonate' },
  },
  skipPaths: ['/health', '/auth/*', '/magic-link/*', '/email/*', '/social/*'],
});

// IAM routes: auth + admin plugin middleware (default deny via admin plugin)
app.use('/iam', authMiddleware);
app.use('/iam', pluginMiddleware.afterAuth);

// ═══════════════════════════════════════════════════════════════════════════
// 4. Public routes
// ═══════════════════════════════════════════════════════════════════════════

app.get('/health', (_req, res) => res.json({ status: 'ok' }));

// ── vBody / vParam / vQuery demo ──
// curl 'http://localhost:3001/echo/42?greeting=hello'              → 200 { id: '42', greeting: 'hello' }
// curl 'http://localhost:3001/echo/42'                             → 422 VALIDATION_ERROR (missing greeting)
// curl -X POST http://localhost:3001/echo/42 -H 'Content-Type: application/json' -d '{"name":"x"}'  → 200
// curl -X POST http://localhost:3001/echo/42 -H 'Content-Type: application/json' -d '{}'             → 422
const EchoParam = obj({ id: str('Echo ID') }, 'id');
const EchoQuery = obj({ greeting: str('Greeting') }, 'greeting');
const EchoBody = obj({ name: str('Name') }, 'name');
app.get('/echo/:id', async (req, res, next) => {
  try {
    const { id } = await vParam(req, EchoParam);
    const { greeting } = await vQuery(req, EchoQuery);
    res.json({ id, greeting });
  }
  catch (e) { next(e); }
});
app.post('/echo/:id', async (req, res, next) => {
  try {
    const { id } = await vParam(req, EchoParam);
    const { name } = await vBody(req, EchoBody);
    res.json({ id, name });
  }
  catch (e) { next(e); }
});

app.post('/auth/register', async (req, res, next) => {
  try {
    const { email, password, name } = (req as any).body;
    const user = await fortress.auth.createUser({ email, password, name });
    res.status(201).json({ data: user });
  }
  catch (e) { next(e); }
});

app.post('/auth/login', async (req, res, next) => {
  try {
    const { identifier, password } = (req as any).body;
    const result = await fortress.auth.login(identifier, password, {
      ipAddress: typeof req.headers['x-forwarded-for'] === 'string' ? req.headers['x-forwarded-for'] : undefined,
      userAgent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined,
    });
    res.json({ data: result });
  }
  catch (e) { next(e); }
});

app.post('/auth/refresh', async (req, res, next) => {
  try {
    const { refreshToken } = (req as any).body;
    const result = await fortress.auth.refresh(refreshToken);
    res.json({ data: result });
  }
  catch (e) { next(e); }
});

app.post('/auth/logout', async (req, res, next) => {
  try {
    const { refreshToken } = (req as any).body;
    await fortress.auth.logout(refreshToken);
    res.json({ data: { loggedOut: true } });
  }
  catch (e) { next(e); }
});

// ── Magic Link ──

app.post('/magic-link/send', async (req, res, next) => {
  try {
    const { email } = (req as any).body;
    const result = await fortress.plugins['magic-link'].sendMagicLink(email);
    res.json({ data: result });
  }
  catch (e) { next(e); }
});

app.post('/magic-link/verify', async (req, res, next) => {
  try {
    const { token } = (req as any).body;
    const result = await fortress.plugins['magic-link'].verifyMagicLink(token);
    res.json({ data: result });
  }
  catch (e) { next(e); }
});

// ── Social Login ──

app.get('/social/providers', (_req, res) => {
  const providers = fortress.plugins['social-login'].getProviders();
  res.json({ data: providers });
});

// ═══════════════════════════════════════════════════════════════════════════
// 5. Protected routes (require JWT)
// ═══════════════════════════════════════════════════════════════════════════

app.use('/auth/me', authMiddleware);
app.use('/auth/sessions', authMiddleware);
app.use('/auth/2fa', authMiddleware);
app.use('/auth/api-keys', authMiddleware);

app.get('/auth/me', async (req, res, next) => {
  try {
    const userId = getUserId(req);
    const claims = getClaims(req);
    const user = await fortress.auth.me(userId);
    res.json({ data: { user, claims } });
  }
  catch (e) { next(e); }
});

// ── Sessions ──

app.get('/auth/sessions', async (req, res, next) => {
  try {
    const userId = getUserId(req);
    const sessions = await fortress.auth.listSessions(userId);
    res.json({ data: sessions });
  }
  catch (e) { next(e); }
});

app.delete('/auth/sessions/:id', async (req, res, next) => {
  try {
    const userId = getUserId(req);
    const tokenId = Number((req as any).params.id);
    await fortress.auth.revokeSession(userId, tokenId);
    res.json({ data: { revoked: true } });
  }
  catch (e) { next(e); }
});

// ── Two-Factor Auth ──

app.post('/auth/2fa/enable', async (req, res, next) => {
  try {
    const userId = getUserId(req);
    const result = await fortress.plugins['two-factor'].enable(userId);
    res.json({ data: { otpauthUrl: result.otpauthUrl, backupCodes: result.backupCodes } });
  }
  catch (e) { next(e); }
});

app.post('/auth/2fa/verify', async (req, res, next) => {
  try {
    const userId = getUserId(req);
    const { code } = (req as any).body;
    const result = await fortress.plugins['two-factor'].verify(userId, code, {
      userAgent: typeof req.headers['user-agent'] === 'string' ? req.headers['user-agent'] : undefined,
    });
    res.json({ data: result });
  }
  catch (e) { next(e); }
});

// ── API Keys ──

app.post('/auth/api-keys', async (req, res, next) => {
  try {
    const userId = getUserId(req);
    const { name, scopes } = (req as any).body;
    const result = await fortress.plugins['api-key'].createKey(userId, { name, scopes });
    res.status(201).json({ data: result });
  }
  catch (e) { next(e); }
});

app.get('/auth/api-keys', async (req, res, next) => {
  try {
    const userId = getUserId(req);
    const keys = await fortress.plugins['api-key'].listKeys(userId);
    res.json({ data: keys });
  }
  catch (e) { next(e); }
});

app.delete('/auth/api-keys/:id', async (req, res, next) => {
  try {
    const userId = getUserId(req);
    const keyId = Number((req as any).params.id);
    await fortress.plugins['api-key'].revokeKey(userId, keyId);
    res.json({ data: { revoked: true } });
  }
  catch (e) { next(e); }
});

// ═══════════════════════════════════════════════════════════════════════════
// 6. RBAC-protected routes
// ═══════════════════════════════════════════════════════════════════════════

app.use('/api/users', authMiddleware);
app.use('/api/groups', authMiddleware);
app.use('/api/users', rbacMiddleware);
app.use('/api/groups', rbacMiddleware);

app.get('/api/users', async (req, res, next) => {
  try {
    const reqDb = getDb(req);
    const users = await reqDb.findMany({ model: 'user' });
    res.json({ data: users });
  }
  catch (e) { next(e); }
});

app.post('/api/groups', async (req, res, next) => {
  try {
    const { name, description } = (req as any).body;
    const group = await fortress.iam.createGroup(name, description);
    res.status(201).json({ data: group });
  }
  catch (e) { next(e); }
});

app.post('/api/groups/:id/members', async (req, res, next) => {
  try {
    const groupId = Number((req as any).params.id);
    const { userId } = (req as any).body;
    await fortress.iam.addUserToGroup(groupId, userId);
    res.json({ data: { added: true } });
  }
  catch (e) { next(e); }
});

// ═══════════════════════════════════════════════════════════════════════════
// 7. Admin routes
// ═══════════════════════════════════════════════════════════════════════════

app.use('/admin', authMiddleware);
app.use('/admin', rbacMiddleware);
app.use('/api/audit-log', authMiddleware);
app.use('/api/audit-log', rbacMiddleware);

app.get('/api/audit-log', async (req, res, next) => {
  try {
    const entries = await fortress.plugins['audit-log'].getAuditLog({});
    res.json({ data: entries });
  }
  catch (e) { next(e); }
});

app.post('/admin/impersonate', async (req, res, next) => {
  try {
    const adminId = getUserId(req);
    const { targetUserId, reason } = (req as any).body;
    const result = await fortress.auth.impersonate(adminId, targetUserId, { reason });
    res.json({ data: result });
  }
  catch (e) { next(e); }
});

// ── Data Isolation ──

app.use('/api/documents', authMiddleware);

app.get('/api/documents', async (req, res, next) => {
  try {
    const scopedDb = await getScopedDb(req, 'document');
    const docs = await scopedDb.findMany({ model: 'document' });
    res.json({ data: docs });
  }
  catch (e) { next(e); }
});

// ═══════════════════════════════════════════════════════════════════════════
// 8. Mount Fortress routes (auth, IAM, plugins, OAuth, OpenAPI)
// ═══════════════════════════════════════════════════════════════════════════
//
// `mountFortress` registers a single Express middleware that detects any
// Fortress-managed path and delegates to `fortress.handleRequest`. The
// custom `/auth/*` handlers above are registered FIRST, so Express's
// route order means they win — `mountFortress` only handles paths the
// user did not handle manually.
//
// Auth issuing endpoints (login/refresh/impersonate) inside core
// dispatch automatically attach `Set-Cookie` headers using
// `FortressConfig.cookies` defaults.
mountFortress(app, fortress);

// ═══════════════════════════════════════════════════════════════════════════
// 9. Seed data on startup
// ═══════════════════════════════════════════════════════════════════════════

async function seed(): Promise<void> {
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
  ], 'Full admin access');

  const viewerRole = await fortress.iam.createRole('viewer', [
    { resource: 'user', action: 'list' },
    { resource: 'user', action: 'read' },
  ], 'Read-only access');

  await fortress.iam.bindRole('user', admin.id, adminRole.id);
  await fortress.iam.bindRole('user', user.id, viewerRole.id);

  const engineering = await fortress.iam.createGroup('engineering', 'Engineering team');
  await fortress.iam.addUserToGroup(engineering.id, admin.id);

  console.warn('');
  console.warn('╔══════════════════════════════════════════════╗');
  console.warn('║  Fortress Express Example App                ║');
  console.warn('╠══════════════════════════════════════════════╣');
  console.warn('║  Admin:  admin@example.com / Password123!    ║');
  console.warn('║  User:   user@example.com  / Password123!    ║');
  console.warn('╠══════════════════════════════════════════════╣');
  console.warn('║  http://localhost:3001                        ║');
  console.warn('║  http://localhost:3001/openapi   (API docs)   ║');
  console.warn('╚══════════════════════════════════════════════╝');
  console.warn('');
}

// ═══════════════════════════════════════════════════════════════════════════
// 10. Bun.serve — minimal HTTP server that dispatches to our Express router
// ═══════════════════════════════════════════════════════════════════════════

seed().then(() => {
  Bun.serve({
    port: 3001,
    async fetch(request: Request): Promise<Response> {
      const url = new URL(request.url);
      const method = request.method;
      const path = url.pathname;

      // Parse JSON body for non-GET requests
      let body: unknown;
      const contentType = request.headers.get('content-type') ?? '';
      if (method !== 'GET' && method !== 'HEAD') {
        if (contentType.includes('application/json')) {
          body = await request.json().catch(() => ({}));
        }
        else if (contentType.includes('application/x-www-form-urlencoded')) {
          const text = await request.text();
          const params = new URLSearchParams(text);
          body = Object.fromEntries(params);
        }
        else {
          body = {};
        }
      }

      // Build Express-compatible request
      const headers: Record<string, string | undefined> = {};
      request.headers.forEach((value, key) => {
        headers[key] = value;
      });

      const req: ExpressRequest & { body?: unknown; params?: Record<string, string>; query?: Record<string, string> } = {
        headers,
        method,
        path,
        body,
        params: {},
        query: Object.fromEntries(url.searchParams),
      };

      // Build Express-compatible response
      let statusCode = 200;
      let responseBody: unknown;
      const responseHeaders: Record<string, string> = { 'content-type': 'application/json' };
      let sent = false;

      const res: ExpressResponse & { send?: (body: unknown) => void } = {
        status(code: number) {
          statusCode = code;
          return this;
        },
        json(data: unknown) {
          responseBody = data;
          sent = true;
        },
        setHeader(name: string, value: string) {
          responseHeaders[name] = value;
        },
        send(body: unknown) {
          responseBody = body;
          sent = true;
        },
      };

      const next = (err?: unknown): void => {
        if (err) {
          // Run error handler
          (errorHandler as any)(err, req, res, () => {});
        }
      };

      // Run matching middlewares
      for (const mw of middlewares) {
        if (path.startsWith(mw.path) || mw.path === '/') {
          await new Promise<void>((resolve) => {
            const mwNext: ExpressNextFunction = (err?: unknown) => {
              if (err)
                next(err);
              resolve();
            };
            Promise.resolve(mw.handler(req, res, mwNext)).catch((e) => {
              next(e);
              resolve();
            });
          });
          if (sent)
            break;
        }
      }

      // Find and run matching route
      if (!sent) {
        for (const route of routes) {
          if (route.method !== method)
            continue;
          const match = route.pattern.exec(path);
          if (match) {
            // Extract params
            const params: Record<string, string> = {};
            route.paramNames.forEach((name, i) => {
              params[name] = match[i + 1];
            });
            req.params = params;

            await Promise.resolve(route.handler(req, res, next)).catch(e => next(e));
            break;
          }
        }
      }

      if (!sent) {
        statusCode = 404;
        responseBody = { error: 'Not Found', path };
      }

      const isHtml = typeof responseBody === 'string' && responseBody.startsWith('<!DOCTYPE');
      if (isHtml) {
        responseHeaders['content-type'] = 'text/html';
      }

      return new Response(
        isHtml ? (responseBody as string) : JSON.stringify(responseBody),
        { status: statusCode, headers: responseHeaders },
      );
    },
  });
}).catch(console.error);
