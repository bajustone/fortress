import type { Fortress } from '../../core/fortress';
import type { ApiKeyMethods } from '../api-key';
import type { AdminPluginOptions } from './index';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { apiKey } from '../api-key';
import { admin } from './index';

const SECRET = 'admin-api-key-test-secret-at-least-32!';

interface Setup {
  fortress: Fortress<any>;
  apiKeyMethods: ApiKeyMethods;
  adminUserId: number;
  targetUserId: number;
  nonAdminUserId: number;
  adminToken: string;
  nonAdminToken: string;
}

async function setup(adminOptions: AdminPluginOptions = { apiKeyRoutes: true }): Promise<Setup> {
  const fortress = createFortress({
    jwt: { secret: SECRET },
    database: createTestAdapter(),
    plugins: [
      apiKey({ prefix: 'test', maxKeysPerSubject: 5 }),
      admin(adminOptions),
    ],
  });

  const apiKeyMethods = fortress.plugins['api-key'] as unknown as ApiKeyMethods;

  // Three users: the admin-to-be, the target (whose keys get managed),
  // and a plain user who has no permissions.
  const adminUser = await fortress.auth.createUser({
    email: 'admin@example.com',
    name: 'Admin',
    password: 'password-123',
  });
  const target = await fortress.auth.createUser({
    email: 'target@example.com',
    name: 'Target',
    password: 'password-123',
  });
  const plain = await fortress.auth.createUser({
    email: 'plain@example.com',
    name: 'Plain',
    password: 'password-123',
  });

  const adminLogin = await fortress.auth.login('admin@example.com', 'password-123');
  const plainLogin = await fortress.auth.login('plain@example.com', 'password-123');
  if (adminLogin.status !== 'success' || plainLogin.status !== 'success')
    throw new Error('expected login success');

  // Promote the admin user via /iam/admin/bootstrap. Bootstrap auto-discovers
  // every `meta.permission` declared on registered plugin endpoints and binds
  // them all to the `fortress-admin` role — including `apiKey:manage` when
  // the admin plugin's api-key routes are mounted.
  const bootstrapRes = await fortress.handleRequest(new Request('http://localhost/iam/admin/bootstrap', {
    method: 'POST',
    headers: {
      'authorization': `Bearer ${adminLogin.accessToken}`,
      'content-type': 'application/json',
    },
    body: JSON.stringify({}),
  }));
  if (bootstrapRes.status !== 200) {
    const body = await bootstrapRes.text();
    throw new Error(`bootstrap failed: ${bootstrapRes.status} ${body}`);
  }

  return {
    fortress,
    apiKeyMethods,
    adminUserId: adminUser.id,
    targetUserId: target.id,
    nonAdminUserId: plain.id,
    adminToken: adminLogin.accessToken,
    nonAdminToken: plainLogin.accessToken,
  };
}

describe('admin plugin — api-key routes', () => {
  describe('apiKeyRoutes: false (default)', () => {
    let fortress: Fortress<any>;
    let adminToken: string;

    beforeEach(async () => {
      const s = await setup({});
      fortress = s.fortress;
      adminToken = s.adminToken;
    });

    it('does not mount /admin/users/:userId/api-keys — GET returns 404', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/admin/users/1/api-keys', {
        headers: { authorization: `Bearer ${adminToken}` },
      }));
      expect(res.status).toBe(404);
    });

    it('does not mount /admin/users/:userId/api-keys/:id — DELETE returns 404', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/admin/users/1/api-keys/1', {
        method: 'DELETE',
        headers: { authorization: `Bearer ${adminToken}` },
      }));
      expect(res.status).toBe(404);
    });

    it('bootstrap does not register the apiKey:manage permission', async () => {
      // Search directly: no role_permission binding for apiKey:manage should exist.
      const permissions = await fortress.iam.listPermissions({ resource: 'apiKey' });
      expect(permissions.find(p => p.action === 'manage')).toBeUndefined();
    });
  });

  describe('apiKeyRoutes: true', () => {
    let s: Setup;

    beforeEach(async () => {
      s = await setup({ apiKeyRoutes: true });
    });

    it('bootstrap auto-registers the apiKey:manage permission', async () => {
      const permissions = await s.fortress.iam.listPermissions({ resource: 'apiKey' });
      expect(permissions.find(p => p.action === 'manage')).toBeDefined();
    });

    it('non-admin calling GET /admin/users/:userId/api-keys returns 403', async () => {
      const res = await s.fortress.handleRequest(new Request(`http://localhost/admin/users/${s.targetUserId}/api-keys`, {
        headers: { authorization: `Bearer ${s.nonAdminToken}` },
      }));
      expect(res.status).toBe(403);
    });

    it('admin calling GET /admin/users/:userId/api-keys returns the target user\'s keys', async () => {
      await s.apiKeyMethods.createKey({ subject: { type: 'USER', id: s.targetUserId }, name: 'Target Key 1' });
      await s.apiKeyMethods.createKey({ subject: { type: 'USER', id: s.targetUserId }, name: 'Target Key 2' });

      const res = await s.fortress.handleRequest(new Request(`http://localhost/admin/users/${s.targetUserId}/api-keys`, {
        headers: { authorization: `Bearer ${s.adminToken}` },
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as { keys: { id: number; name: string }[] };
      expect(body.keys).toHaveLength(2);
      expect(body.keys.map(k => k.name).sort()).toEqual(['Target Key 1', 'Target Key 2']);
    });

    it('admin can revoke any user\'s key — bypassing the self-service ownership check', async () => {
      const { id } = await s.apiKeyMethods.createKey({ subject: { type: 'USER', id: s.targetUserId }, name: 'Target Key' });

      const res = await s.fortress.handleRequest(new Request(`http://localhost/admin/users/${s.targetUserId}/api-keys/${id}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${s.adminToken}` },
      }));
      expect(res.status).toBe(200);

      // Key no longer shows up in the target's self-service list.
      const keys = await s.apiKeyMethods.listKeys({ subject: { type: 'USER', id: s.targetUserId } });
      expect(keys.find(k => k.id === id)).toBeUndefined();
    });

    it('admin DELETE on a non-existent key returns 404', async () => {
      const res = await s.fortress.handleRequest(new Request(`http://localhost/admin/users/${s.targetUserId}/api-keys/999999`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${s.adminToken}` },
      }));
      expect(res.status).toBe(404);
    });
  });
});
