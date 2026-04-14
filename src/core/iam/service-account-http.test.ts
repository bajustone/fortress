import type { Fortress } from '../fortress';
import type { Role, ServiceAccount } from '../types';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

/**
 * HTTP-level integration tests for the 10 core IAM service-account
 * endpoints. These round-trip each endpoint via `fortress.handleRequest`
 * to exercise the dispatch switch cases in `src/core/http/dispatch.ts` —
 * the body/param coercion layer that the service-account.test.ts unit
 * tests skip. Runs without the admin plugin so the core `invokeIamHandler`
 * path is exercised directly; the admin plugin's proxy handlers are
 * covered separately in admin-api-key.test.ts.
 */

const SECRET = 'service-account-http-secret-32ch';

interface Ctx {
  fortress: Fortress;
  adminId: number;
  adminToken: string;
  sa: ServiceAccount;
  role: Role;
}

async function setup(): Promise<Ctx> {
  const fortress = createFortress({
    jwt: { secret: SECRET },
    database: createTestAdapter(),
  });

  const admin = await fortress.auth.createUser({
    email: 'admin@example.com',
    name: 'Admin',
    password: 'password-123',
  });
  const login = await fortress.auth.login('admin@example.com', 'password-123');
  if (login.status !== 'success')
    throw new Error('expected admin login success');

  // Grant every fortress permission the service-account endpoints require.
  // With no admin plugin registered, there is no bootstrap — the test
  // binds permissions directly to the admin user.
  const permissions = [
    { resource: 'fortress', action: 'createServiceAccount' },
    { resource: 'fortress', action: 'viewServiceAccounts' },
    { resource: 'fortress', action: 'manageServiceAccount' },
    { resource: 'fortress', action: 'viewPermissions' },
    { resource: 'fortress', action: 'bindRole' },
    { resource: 'fortress', action: 'unbindRole' },
    { resource: 'fortress', action: 'managePermissions' },
  ];
  for (const p of permissions) {
    await fortress.iam.bindPermissionToUser(admin.id, p);
  }

  // A pre-existing service account for tests that need one.
  const sa = await fortress.iam.createServiceAccount({
    name: 'pre-existing',
    displayName: 'Pre-existing SA',
  });

  // A pre-existing role for bind/unbind tests.
  const role = await fortress.iam.createRole('ops-deployer', [
    { resource: 'deploy', action: 'run' },
  ]);

  return { fortress, adminId: admin.id, adminToken: login.accessToken, sa, role };
}

function authHeaders(token: string, contentType?: string): Record<string, string> {
  const headers: Record<string, string> = { authorization: `Bearer ${token}` };
  if (contentType)
    headers['content-type'] = contentType;
  return headers;
}

describe('service-account HTTP endpoints — core dispatch', () => {
  let ctx: Ctx;

  beforeEach(async () => {
    ctx = await setup();
  });

  // ── POST /iam/service-accounts ──────────────────────────────

  describe('post /iam/service-accounts', () => {
    it('creates a service account and returns 201 with the record', async () => {
      const res = await ctx.fortress.handleRequest(new Request('http://localhost/iam/service-accounts', {
        method: 'POST',
        headers: authHeaders(ctx.adminToken, 'application/json'),
        body: JSON.stringify({
          name: 'ci-deploy',
          displayName: 'CI Deploy',
          description: 'Runs production deploys',
        }),
      }));
      expect(res.status).toBe(201);
      const body = await res.json() as ServiceAccount;
      expect(body.name).toBe('ci-deploy');
      expect(body.displayName).toBe('CI Deploy');
      expect(body.description).toBe('Runs production deploys');
      expect(body.isActive).toBe(true);
      expect(body.id).toBeDefined();
    });

    it('returns 422 when name is missing (schema validation)', async () => {
      const res = await ctx.fortress.handleRequest(new Request('http://localhost/iam/service-accounts', {
        method: 'POST',
        headers: authHeaders(ctx.adminToken, 'application/json'),
        body: JSON.stringify({ displayName: 'No Name' }),
      }));
      expect(res.status).toBe(422);
    });

    it('returns 400 when name is a duplicate', async () => {
      const res = await ctx.fortress.handleRequest(new Request('http://localhost/iam/service-accounts', {
        method: 'POST',
        headers: authHeaders(ctx.adminToken, 'application/json'),
        body: JSON.stringify({ name: 'pre-existing' }),
      }));
      expect(res.status).toBe(400);
    });

    it('returns 401 without a bearer token', async () => {
      const res = await ctx.fortress.handleRequest(new Request('http://localhost/iam/service-accounts', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'no-auth' }),
      }));
      expect(res.status).toBe(401);
    });

    it('returns 403 for an authenticated user without the permission', async () => {
      const bob = await ctx.fortress.auth.createUser({
        email: 'bob@example.com',
        name: 'Bob',
        password: 'password-123',
      });
      const bobLogin = await ctx.fortress.auth.login('bob@example.com', 'password-123');
      if (bobLogin.status !== 'success')
        throw new Error('expected bob login success');
      void bob;

      const res = await ctx.fortress.handleRequest(new Request('http://localhost/iam/service-accounts', {
        method: 'POST',
        headers: authHeaders(bobLogin.accessToken, 'application/json'),
        body: JSON.stringify({ name: 'forbidden-sa' }),
      }));
      expect(res.status).toBe(403);
    });
  });

  // ── GET /iam/service-accounts ───────────────────────────────

  describe('get /iam/service-accounts', () => {
    it('lists service accounts with total', async () => {
      // Seed two extra accounts so the list is meaningful.
      await ctx.fortress.iam.createServiceAccount({ name: 'sa-a' });
      await ctx.fortress.iam.createServiceAccount({ name: 'sa-b' });

      const res = await ctx.fortress.handleRequest(new Request('http://localhost/iam/service-accounts', {
        headers: authHeaders(ctx.adminToken),
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as { serviceAccounts: ServiceAccount[]; total: number };
      expect(body.total).toBe(3); // pre-existing + 2 seeded
      expect(body.serviceAccounts.map(s => s.name).sort()).toEqual(['pre-existing', 'sa-a', 'sa-b']);
    });

    it('respects limit and offset query params', async () => {
      for (let i = 0; i < 5; i++)
        await ctx.fortress.iam.createServiceAccount({ name: `paged-${i}` });

      const res = await ctx.fortress.handleRequest(new Request('http://localhost/iam/service-accounts?limit=2&offset=2', {
        headers: authHeaders(ctx.adminToken),
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as { serviceAccounts: ServiceAccount[]; total: number };
      expect(body.serviceAccounts).toHaveLength(2);
      expect(body.total).toBe(6); // pre-existing + 5 seeded
    });
  });

  // ── GET /iam/service-accounts/:id ───────────────────────────

  describe('get /iam/service-accounts/:id', () => {
    it('returns 200 with the record', async () => {
      const res = await ctx.fortress.handleRequest(new Request(`http://localhost/iam/service-accounts/${ctx.sa.id}`, {
        headers: authHeaders(ctx.adminToken),
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as ServiceAccount;
      expect(body.id).toBe(ctx.sa.id);
      expect(body.name).toBe('pre-existing');
    });

    it('returns 404 for a nonexistent id', async () => {
      const res = await ctx.fortress.handleRequest(new Request('http://localhost/iam/service-accounts/999999', {
        headers: authHeaders(ctx.adminToken),
      }));
      expect(res.status).toBe(404);
    });
  });

  // ── PATCH /iam/service-accounts/:id ─────────────────────────

  describe('patch /iam/service-accounts/:id', () => {
    it('updates displayName, description, and isActive', async () => {
      const res = await ctx.fortress.handleRequest(new Request(`http://localhost/iam/service-accounts/${ctx.sa.id}`, {
        method: 'PATCH',
        headers: authHeaders(ctx.adminToken, 'application/json'),
        body: JSON.stringify({
          displayName: 'Renamed SA',
          description: 'New description',
          isActive: false,
        }),
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as ServiceAccount;
      expect(body.displayName).toBe('Renamed SA');
      expect(body.description).toBe('New description');
      expect(body.isActive).toBe(false);
      // Name is immutable.
      expect(body.name).toBe('pre-existing');
    });

    it('returns 404 for a nonexistent id', async () => {
      const res = await ctx.fortress.handleRequest(new Request('http://localhost/iam/service-accounts/999999', {
        method: 'PATCH',
        headers: authHeaders(ctx.adminToken, 'application/json'),
        body: JSON.stringify({ isActive: false }),
      }));
      expect(res.status).toBe(404);
    });
  });

  // ── DELETE /iam/service-accounts/:id ────────────────────────

  describe('delete /iam/service-accounts/:id', () => {
    it('hard-deletes the service account and cascades to bindings', async () => {
      // Bind a role and a direct permission so we can assert the cascade.
      await ctx.fortress.iam.bindRoleToServiceAccount(ctx.sa.id, ctx.role.id);
      await ctx.fortress.iam.bindPermissionToServiceAccount(ctx.sa.id, {
        resource: 'direct',
        action: 'touch',
      });

      const res = await ctx.fortress.handleRequest(new Request(`http://localhost/iam/service-accounts/${ctx.sa.id}`, {
        method: 'DELETE',
        headers: authHeaders(ctx.adminToken),
      }));
      expect(res.status).toBe(200);

      // Account row is gone.
      const stillThere = await ctx.fortress.config.database.findMany({
        model: 'service_account',
        where: [{ field: 'id', operator: '=', value: ctx.sa.id }],
      });
      expect(stillThere).toHaveLength(0);

      // Role bindings for this SA are gone.
      const roleBindings = await ctx.fortress.config.database.findMany({
        model: 'role_binding',
        where: [
          { field: 'subjectType', operator: '=', value: 'SERVICE_ACCOUNT' },
          { field: 'subjectId', operator: '=', value: ctx.sa.id },
        ],
      });
      expect(roleBindings).toHaveLength(0);

      // Direct permission bindings for this SA are gone.
      const directBindings = await ctx.fortress.config.database.findMany({
        model: 'direct_permission_binding',
        where: [
          { field: 'subjectType', operator: '=', value: 'SERVICE_ACCOUNT' },
          { field: 'subjectId', operator: '=', value: ctx.sa.id },
        ],
      });
      expect(directBindings).toHaveLength(0);
    });

    it('returns 404 for a nonexistent id', async () => {
      const res = await ctx.fortress.handleRequest(new Request('http://localhost/iam/service-accounts/999999', {
        method: 'DELETE',
        headers: authHeaders(ctx.adminToken),
      }));
      expect(res.status).toBe(404);
    });
  });

  // ── GET /iam/service-accounts/:id/permissions ───────────────

  describe('get /iam/service-accounts/:id/permissions', () => {
    it('returns the effective permissions for a service account', async () => {
      // Bind a role; the endpoint should return its permissions.
      await ctx.fortress.iam.bindRoleToServiceAccount(ctx.sa.id, ctx.role.id);

      const res = await ctx.fortress.handleRequest(new Request(`http://localhost/iam/service-accounts/${ctx.sa.id}/permissions`, {
        headers: authHeaders(ctx.adminToken),
      }));
      expect(res.status).toBe(200);
      const perms = await res.json() as { resource: string; action: string }[];
      expect(perms).toHaveLength(1);
      expect(perms[0]).toMatchObject({ resource: 'deploy', action: 'run' });
    });

    it('returns an empty array for an inactive service account even with bound roles', async () => {
      await ctx.fortress.iam.bindRoleToServiceAccount(ctx.sa.id, ctx.role.id);
      await ctx.fortress.iam.updateServiceAccount(ctx.sa.id, { isActive: false });

      const res = await ctx.fortress.handleRequest(new Request(`http://localhost/iam/service-accounts/${ctx.sa.id}/permissions`, {
        headers: authHeaders(ctx.adminToken),
      }));
      expect(res.status).toBe(200);
      const perms = await res.json() as unknown[];
      expect(perms).toEqual([]);
    });
  });

  // ── POST /iam/roles/:id/bind/service-account ────────────────

  describe('post /iam/roles/:id/bind/service-account', () => {
    it('binds the role and the permissions resolve through checkPermission', async () => {
      const res = await ctx.fortress.handleRequest(new Request(`http://localhost/iam/roles/${ctx.role.id}/bind/service-account`, {
        method: 'POST',
        headers: authHeaders(ctx.adminToken, 'application/json'),
        body: JSON.stringify({ serviceAccountId: ctx.sa.id }),
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as { ok: boolean };
      expect(body.ok).toBe(true);

      // Verify by direct check.
      const allowed = await ctx.fortress.iam.checkPermission(
        { type: 'SERVICE_ACCOUNT', id: ctx.sa.id },
        'deploy',
        'run',
      );
      expect(allowed).toBe(true);
    });

    it('supports tenant-scoped bindings', async () => {
      const res = await ctx.fortress.handleRequest(new Request(`http://localhost/iam/roles/${ctx.role.id}/bind/service-account`, {
        method: 'POST',
        headers: authHeaders(ctx.adminToken, 'application/json'),
        body: JSON.stringify({ serviceAccountId: ctx.sa.id, tenantId: 'tenant-a' }),
      }));
      expect(res.status).toBe(200);

      const inA = await ctx.fortress.iam.checkPermission(
        { type: 'SERVICE_ACCOUNT', id: ctx.sa.id },
        'deploy',
        'run',
        { tenantId: 'tenant-a' },
      );
      const inB = await ctx.fortress.iam.checkPermission(
        { type: 'SERVICE_ACCOUNT', id: ctx.sa.id },
        'deploy',
        'run',
        { tenantId: 'tenant-b' },
      );
      expect(inA).toBe(true);
      expect(inB).toBe(false);
    });
  });

  // ── DELETE /iam/roles/:id/bind/service-account ──────────────

  describe('delete /iam/roles/:id/bind/service-account', () => {
    it('removes the binding and revokes the permission', async () => {
      await ctx.fortress.iam.bindRoleToServiceAccount(ctx.sa.id, ctx.role.id);
      expect(
        await ctx.fortress.iam.checkPermission({ type: 'SERVICE_ACCOUNT', id: ctx.sa.id }, 'deploy', 'run'),
      ).toBe(true);

      const res = await ctx.fortress.handleRequest(new Request(`http://localhost/iam/roles/${ctx.role.id}/bind/service-account`, {
        method: 'DELETE',
        headers: authHeaders(ctx.adminToken, 'application/json'),
        body: JSON.stringify({ serviceAccountId: ctx.sa.id }),
      }));
      expect(res.status).toBe(200);

      expect(
        await ctx.fortress.iam.checkPermission({ type: 'SERVICE_ACCOUNT', id: ctx.sa.id }, 'deploy', 'run'),
      ).toBe(false);
    });
  });

  // ── POST /iam/permissions/bind/service-account ──────────────

  describe('post /iam/permissions/bind/service-account', () => {
    it('binds a direct permission to a service account', async () => {
      const res = await ctx.fortress.handleRequest(new Request('http://localhost/iam/permissions/bind/service-account', {
        method: 'POST',
        headers: authHeaders(ctx.adminToken, 'application/json'),
        body: JSON.stringify({
          serviceAccountId: ctx.sa.id,
          permission: { resource: 'audit', action: 'read' },
        }),
      }));
      expect(res.status).toBe(200);

      const allowed = await ctx.fortress.iam.checkPermission(
        { type: 'SERVICE_ACCOUNT', id: ctx.sa.id },
        'audit',
        'read',
      );
      expect(allowed).toBe(true);
    });
  });

  // ── DELETE /iam/permissions/bind/service-account ────────────

  describe('delete /iam/permissions/bind/service-account', () => {
    it('removes a direct permission binding', async () => {
      await ctx.fortress.iam.bindPermissionToServiceAccount(ctx.sa.id, {
        resource: 'audit',
        action: 'read',
      });
      expect(
        await ctx.fortress.iam.checkPermission({ type: 'SERVICE_ACCOUNT', id: ctx.sa.id }, 'audit', 'read'),
      ).toBe(true);

      // Look up the permission id so we can unbind by id.
      const perms = await ctx.fortress.iam.getPermissionsForSubject({
        type: 'SERVICE_ACCOUNT',
        id: ctx.sa.id,
      });
      const permId = perms.find(p => p.resource === 'audit' && p.action === 'read')!.id;

      const res = await ctx.fortress.handleRequest(new Request('http://localhost/iam/permissions/bind/service-account', {
        method: 'DELETE',
        headers: authHeaders(ctx.adminToken, 'application/json'),
        body: JSON.stringify({
          serviceAccountId: ctx.sa.id,
          permissionId: permId,
        }),
      }));
      expect(res.status).toBe(200);

      expect(
        await ctx.fortress.iam.checkPermission({ type: 'SERVICE_ACCOUNT', id: ctx.sa.id }, 'audit', 'read'),
      ).toBe(false);
    });
  });

  // ── Unbind via the polymorphic endpoint ─────────────────────

  describe('delete /iam/roles/:id/bind (polymorphic)', () => {
    it('unbinds a SERVICE_ACCOUNT role via the polymorphic endpoint', async () => {
      await ctx.fortress.iam.bindRoleToServiceAccount(ctx.sa.id, ctx.role.id);
      expect(
        await ctx.fortress.iam.checkPermission({ type: 'SERVICE_ACCOUNT', id: ctx.sa.id }, 'deploy', 'run'),
      ).toBe(true);

      const res = await ctx.fortress.handleRequest(new Request(`http://localhost/iam/roles/${ctx.role.id}/bind`, {
        method: 'DELETE',
        headers: authHeaders(ctx.adminToken, 'application/json'),
        body: JSON.stringify({
          subjectType: 'SERVICE_ACCOUNT',
          subjectId: ctx.sa.id,
        }),
      }));
      expect(res.status).toBe(200);

      expect(
        await ctx.fortress.iam.checkPermission({ type: 'SERVICE_ACCOUNT', id: ctx.sa.id }, 'deploy', 'run'),
      ).toBe(false);
    });
  });
});
