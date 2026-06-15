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
    jwt: { key: SECRET },
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

    it('admin POST /admin/users/:userId/api-keys mints a key for any user', async () => {
      const res = await s.fortress.handleRequest(new Request(`http://localhost/admin/users/${s.targetUserId}/api-keys`, {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${s.adminToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: 'admin-minted' }),
      }));
      expect(res.status).toBe(201);
      const body = await res.json() as { key: string; id: number };
      expect(body.key).toMatch(/^test_sk_/);
      expect(body.id).toBeDefined();

      // The minted key shows up in the target user's self-service list.
      const targetKeys = await s.apiKeyMethods.listKeys({
        subject: { type: 'USER', id: s.targetUserId },
      });
      expect(targetKeys.map(k => k.id)).toContain(body.id);

      // And resolves back to the target user — not the admin who minted it.
      const resolved = await s.apiKeyMethods.resolveKey(body.key);
      expect(resolved!.subject).toEqual({ type: 'USER', id: s.targetUserId });
    });

    it('admin POST /admin/users/:userId/api-keys returns 404 for a non-existent user', async () => {
      const res = await s.fortress.handleRequest(new Request(`http://localhost/admin/users/999999/api-keys`, {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${s.adminToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: 'orphan' }),
      }));
      expect(res.status).toBe(404);
    });

    it('non-admin POST /admin/users/:userId/api-keys returns 403', async () => {
      const res = await s.fortress.handleRequest(new Request(`http://localhost/admin/users/${s.targetUserId}/api-keys`, {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${s.nonAdminToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: 'nope' }),
      }));
      expect(res.status).toBe(403);
    });
  });

  describe('apiKeyRoutes: true — service accounts', () => {
    let s: Setup;

    beforeEach(async () => {
      s = await setup({ apiKeyRoutes: true });
    });

    it('admin POST /admin/service-accounts/:id/api-keys bootstraps the first key', async () => {
      const sa = await s.fortress.iam.createServiceAccount({
        name: 'ci-deploy',
        displayName: 'CI Deploy',
      });

      // A fresh service account has no way to self-mint — this endpoint
      // is the only path to its first credential.
      const res = await s.fortress.handleRequest(new Request(`http://localhost/admin/service-accounts/${sa.id}/api-keys`, {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${s.adminToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: 'ci-deploy-github-actions' }),
      }));
      expect(res.status).toBe(201);
      const body = await res.json() as { key: string; id: number };
      expect(body.key).toMatch(/^test_sk_/);

      // The minted key resolves back to the service account as the principal.
      const resolved = await s.apiKeyMethods.resolveKey(body.key);
      expect(resolved!.subject).toEqual({ type: 'SERVICE_ACCOUNT', id: sa.id });
    });

    it('admin POST /admin/service-accounts/:id/api-keys returns 404 for a non-existent SA', async () => {
      const res = await s.fortress.handleRequest(new Request(`http://localhost/admin/service-accounts/999999/api-keys`, {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${s.adminToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: 'orphan' }),
      }));
      expect(res.status).toBe(404);
    });

    it('non-admin POST /admin/service-accounts/:id/api-keys returns 403', async () => {
      const sa = await s.fortress.iam.createServiceAccount({ name: 'forbidden-sa' });
      const res = await s.fortress.handleRequest(new Request(`http://localhost/admin/service-accounts/${sa.id}/api-keys`, {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${s.nonAdminToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: 'nope' }),
      }));
      expect(res.status).toBe(403);
    });

    it('admin GET /admin/service-accounts/:id/api-keys lists the SA keys', async () => {
      const sa = await s.fortress.iam.createServiceAccount({ name: 'listable-sa' });
      await s.apiKeyMethods.createKey({
        subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
        name: 'Key A',
      });
      await s.apiKeyMethods.createKey({
        subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
        name: 'Key B',
      });

      const res = await s.fortress.handleRequest(new Request(`http://localhost/admin/service-accounts/${sa.id}/api-keys`, {
        headers: { authorization: `Bearer ${s.adminToken}` },
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as { keys: { id: number; name: string }[] };
      expect(body.keys.map(k => k.name).sort()).toEqual(['Key A', 'Key B']);
    });

    it('admin DELETE /admin/service-accounts/:id/api-keys/:keyId revokes the key', async () => {
      const sa = await s.fortress.iam.createServiceAccount({ name: 'revokable-sa' });
      const { key, id } = await s.apiKeyMethods.createKey({
        subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
        name: 'To Revoke',
      });
      expect(await s.apiKeyMethods.resolveKey(key)).not.toBeNull();

      const res = await s.fortress.handleRequest(new Request(`http://localhost/admin/service-accounts/${sa.id}/api-keys/${id}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${s.adminToken}` },
      }));
      expect(res.status).toBe(200);

      expect(await s.apiKeyMethods.resolveKey(key)).toBeNull();
    });

    it('bootstrap → mint → authenticate: the full lifecycle', async () => {
      // 1. Admin creates a service account.
      const sa = await s.fortress.iam.createServiceAccount({
        name: 'lifecycle-sa',
        displayName: 'Lifecycle SA',
      });

      // 2. Admin binds a role that grants a fortress permission.
      const role = await s.fortress.iam.createRole('sa-viewer', [
        { resource: 'fortress', action: 'viewServiceAccounts' },
      ]);
      await s.fortress.iam.bindRoleToServiceAccount(sa.id, role.id);

      // 3. Admin mints the first api key via the new admin endpoint.
      const mintRes = await s.fortress.handleRequest(new Request(`http://localhost/admin/service-accounts/${sa.id}/api-keys`, {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${s.adminToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: 'lifecycle-key' }),
      }));
      expect(mintRes.status).toBe(201);
      const { key } = await mintRes.json() as { key: string; id: number };

      // 4. The service account uses the minted key to hit a fortress route
      //    that requires the bound permission — the request should succeed.
      const authedRes = await s.fortress.handleRequest(new Request('http://localhost/iam/service-accounts', {
        headers: { authorization: `ApiKey ${key}` },
      }));
      expect(authedRes.status).toBe(200);
    });
  });
});
