import type { Fortress } from '../../core/fortress';
import type { PluginRouteContext } from '../../core/plugin';
import type { Subject } from '../../core/types';
import type { ApiKeyConfig, ApiKeyMethods } from './index';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { bool, endpoint, obj, str } from '../../core/schema-builder';
import { createTestAdapter } from '../../testing';
import { apiKey } from './index';

const SECRET = 'api-key-test-secret-at-least-32!!';

function httpCtx(subject: Subject | undefined): PluginRouteContext {
  return {
    subject,
    userId: subject?.type === 'USER' ? subject.id : undefined,
    claims: undefined,
    meta: undefined,
    request: new Request('http://localhost/api-key/keys'),
  };
}

function userSubject(id: number): Subject {
  return { type: 'USER', id };
}

async function setup(config: ApiKeyConfig = { prefix: 'test', maxKeysPerSubject: 3 }): Promise<{
  fortress: Fortress<any>;
  methods: ApiKeyMethods;
  userId: number;
  otherUserId: number;
  accessToken: string;
}> {
  const fortress = createFortress({
    jwt: { secret: SECRET },
    database: createTestAdapter(),
    plugins: [apiKey(config)],
  });

  const methods = fortress.plugins['api-key'] as unknown as ApiKeyMethods;

  const alice = await fortress.auth.createUser({
    email: 'alice@example.com',
    name: 'Alice',
    password: 'password-123',
  });
  const bob = await fortress.auth.createUser({
    email: 'bob@example.com',
    name: 'Bob',
    password: 'password-123',
  });

  const login = await fortress.auth.login('alice@example.com', 'password-123');
  if (login.status !== 'success')
    throw new Error('expected login success');

  return {
    fortress,
    methods,
    userId: alice.id,
    otherUserId: bob.id,
    accessToken: login.accessToken,
  };
}

describe('api-key plugin — programmatic methods', () => {
  let methods: ApiKeyMethods;
  let userId: number;
  let otherUserId: number;

  beforeEach(async () => {
    ({ methods, userId, otherUserId } = await setup());
  });

  describe('createKey', () => {
    it('returns a key with the configured prefix', async () => {
      const result = await methods.createKey({ subject: userSubject(userId), name: 'My Key' });
      expect(result.key).toMatch(/^test_sk_[a-f0-9]{64}$/);
      expect(result.id).toBeDefined();
    });

    it('enforces maxKeysPerSubject', async () => {
      await methods.createKey({ subject: userSubject(userId), name: 'Key 1' });
      await methods.createKey({ subject: userSubject(userId), name: 'Key 2' });
      await methods.createKey({ subject: userSubject(userId), name: 'Key 3' });

      await expect(methods.createKey({ subject: userSubject(userId), name: 'Key 4' }))
        .rejects
        .toThrow('Maximum of 3 active API keys');
    });

    it('does not count revoked keys toward the limit', async () => {
      const { id } = await methods.createKey({ subject: userSubject(userId), name: 'Key 1' });
      await methods.createKey({ subject: userSubject(userId), name: 'Key 2' });
      await methods.createKey({ subject: userSubject(userId), name: 'Key 3' });

      await methods.revokeKey({ subject: userSubject(userId), id });

      const result = await methods.createKey({ subject: userSubject(userId), name: 'Key 4' });
      expect(result.key).toBeTruthy();
    });

    it('requires subject when called without routeCtx', async () => {
      await expect(methods.createKey({ name: 'Orphan' } as { name: string }))
        .rejects
        .toThrow('subject is required');
    });
  });

  describe('listKeys', () => {
    it('returns only non-revoked keys', async () => {
      const { id } = await methods.createKey({ subject: userSubject(userId), name: 'Key A' });
      await methods.createKey({ subject: userSubject(userId), name: 'Key B' });
      await methods.revokeKey({ subject: userSubject(userId), id });

      const keys = await methods.listKeys({ subject: userSubject(userId) });
      expect(keys).toHaveLength(1);
      expect(keys[0].name).toBe('Key B');
    });

    it('never exposes the full key or hash', async () => {
      await methods.createKey({ subject: userSubject(userId), name: 'Secret Key' });

      const keys = await methods.listKeys({ subject: userSubject(userId) });
      const key = keys[0] as unknown as Record<string, unknown>;

      expect(key.keyPrefix).toBeTruthy();
      expect(key).not.toHaveProperty('keyHash');
      expect(key).not.toHaveProperty('key');
    });

    it('scopes by subject — one user cannot see another user\'s keys', async () => {
      await methods.createKey({ subject: userSubject(userId), name: 'Alice Key' });
      await methods.createKey({ subject: userSubject(otherUserId), name: 'Bob Key' });

      const aliceKeys = await methods.listKeys({ subject: userSubject(userId) });
      const bobKeys = await methods.listKeys({ subject: userSubject(otherUserId) });

      expect(aliceKeys).toHaveLength(1);
      expect(aliceKeys[0].name).toBe('Alice Key');
      expect(bobKeys).toHaveLength(1);
      expect(bobKeys[0].name).toBe('Bob Key');
    });
  });

  describe('revokeKey', () => {
    it('marks a key as revoked', async () => {
      const { key, id } = await methods.createKey({ subject: userSubject(userId), name: 'To Revoke' });
      await methods.revokeKey({ subject: userSubject(userId), id });

      const resolved = await methods.resolveKey(key);
      expect(resolved).toBeNull();
    });

    it('rejects revoking another user\'s key', async () => {
      const { id } = await methods.createKey({ subject: userSubject(otherUserId), name: 'Bob Key' });
      await expect(methods.revokeKey({ subject: userSubject(userId), id }))
        .rejects
        .toThrow('API key not found');
    });
  });

  describe('rotateKey', () => {
    it('revokes the old key and creates a new one', async () => {
      const original = await methods.createKey({ subject: userSubject(userId), name: 'Rotate Me' });
      const rotated = await methods.rotateKey({ subject: userSubject(userId), id: original.id });

      const oldResolved = await methods.resolveKey(original.key);
      expect(oldResolved).toBeNull();

      const newResolved = await methods.resolveKey(rotated.key);
      expect(newResolved).not.toBeNull();
      expect(newResolved!.subject.type).toBe('USER');
      expect(newResolved!.subject.id).toBe(userId);
    });
  });

  describe('resolveKey', () => {
    it('resolves a valid key', async () => {
      const { key } = await methods.createKey({ subject: userSubject(userId), name: 'Valid Key' });
      const result = await methods.resolveKey(key);
      expect(result).not.toBeNull();
      expect(result!.subject).toEqual({ type: 'USER', id: userId });
    });

    it('rejects a revoked key', async () => {
      const { key, id } = await methods.createKey({ subject: userSubject(userId), name: 'Revoked Key' });
      await methods.revokeKey({ subject: userSubject(userId), id });
      const result = await methods.resolveKey(key);
      expect(result).toBeNull();
    });

    it('rejects an expired key', async () => {
      const { key } = await methods.createKey({
        subject: userSubject(userId),
        name: 'Expired Key',
        expiresAt: new Date(Date.now() - 1000),
      });
      const result = await methods.resolveKey(key);
      expect(result).toBeNull();
    });

    it('updates lastUsedAt on resolve', async () => {
      const { key } = await methods.createKey({ subject: userSubject(userId), name: 'Track Usage' });

      let keys = await methods.listKeys({ subject: userSubject(userId) });
      expect(keys[0].lastUsedAt).toBeNull();

      await methods.resolveKey(key);

      keys = await methods.listKeys({ subject: userSubject(userId) });
      expect(keys[0].lastUsedAt).toBeTruthy();
    });

    it('returns null for an unknown key', async () => {
      const result = await methods.resolveKey('nonexistent_sk_key');
      expect(result).toBeNull();
    });
  });

  describe('scoped keys', () => {
    it('returns the correct scopes on resolve', async () => {
      const scopes = ['article:read', 'article:list'];
      const { key } = await methods.createKey({ subject: userSubject(userId), name: 'Scoped Key', scopes });
      const result = await methods.resolveKey(key);
      expect(result!.scopes).toEqual(scopes);
    });

    it('returns null scopes for an unscoped key', async () => {
      const { key } = await methods.createKey({ subject: userSubject(userId), name: 'Unscoped Key' });
      const result = await methods.resolveKey(key);
      expect(result!.scopes).toBeNull();
    });

    it('narrows IAM route permissions to the API-key scopes', async () => {
      const reportsPlugin = {
        name: 'reports',
        routes: {
          deleteReport: endpoint('DELETE', '/reports/:id')
            .security('bearer')
            .permission('report', 'delete')
            .params(obj({ id: str('Report id') }, 'id'))
            .response(200, 'Deleted', obj({ ok: bool() }, 'ok'))
            .handler('deleteReport')
            .build(),
        },
        methods: () => ({ deleteReport: () => ({ ok: true }) }),
      };
      const fortress = createFortress({
        jwt: { secret: SECRET },
        database: createTestAdapter(),
        plugins: [apiKey({ prefix: 'test' }), reportsPlugin],
      });
      const apiKeys = fortress.plugins['api-key'] as unknown as ApiKeyMethods;
      const user = await fortress.auth.createUser({
        email: 'scoped@example.com',
        name: 'Scoped',
        password: 'password-123',
      });
      const role = await fortress.iam.createRole('report-deleter', [{ resource: 'report', action: 'delete' }]);
      await fortress.iam.bindRoleToUser(user.id, role.id);

      const readOnly = await apiKeys.createKey({
        subject: userSubject(user.id),
        name: 'Read only',
        scopes: ['report:read'],
      });
      const denied = await fortress.handleRequest(new Request('http://localhost/reports/r1', {
        method: 'DELETE',
        headers: { Authorization: `ApiKey ${readOnly.key}` },
      }));
      expect(denied.status).toBe(403);

      const wildcard = await apiKeys.createKey({
        subject: userSubject(user.id),
        name: 'Report wildcard',
        scopes: ['report:*'],
      });
      const allowed = await fortress.handleRequest(new Request('http://localhost/reports/r1', {
        method: 'DELETE',
        headers: { Authorization: `ApiKey ${wildcard.key}` },
      }));
      expect(allowed.status).toBe(200);
    });
  });
});

describe('api-key plugin — dual-mode (routeCtx takes precedence over input.subject)', () => {
  it('uses routeCtx.subject and ignores input.subject when routeCtx is present', async () => {
    const { methods, userId, otherUserId } = await setup();

    // Caller tries to forge a key for another subject by passing subject in input.
    // The route-mode invocation must ignore input.subject and trust routeCtx.
    const result = await methods.createKey(
      { subject: userSubject(otherUserId), name: 'Forged' },
      httpCtx(userSubject(userId)),
    );

    // Key should belong to the authenticated caller, not the forged target
    const aliceKeys = await methods.listKeys({ subject: userSubject(userId) });
    const bobKeys = await methods.listKeys({ subject: userSubject(otherUserId) });

    expect(aliceKeys.map(k => k.id)).toContain(result.id);
    expect(bobKeys.map(k => k.id)).not.toContain(result.id);
  });

  it('throws UNAUTHORIZED when routeCtx.subject is missing', async () => {
    const { methods } = await setup();
    await expect(methods.createKey({ name: 'X' } as { name: string }, httpCtx(undefined)))
      .rejects
      .toThrow('Not authenticated');
  });
});

describe('api-key plugin — HTTP routes (opt-in flag)', () => {
  describe('routes: false (default)', () => {
    it('does not mount /api-key/keys — POST returns 404', async () => {
      const { fortress, accessToken } = await setup({ prefix: 'test' });

      const res = await fortress.handleRequest(new Request('http://localhost/api-key/keys', {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${accessToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: 'Unmounted' }),
      }));
      expect(res.status).toBe(404);
    });

    it('programmatic methods still work', async () => {
      const { methods, userId } = await setup({ prefix: 'test' });
      const result = await methods.createKey({ subject: userSubject(userId), name: 'Programmatic' });
      expect(result.key).toMatch(/^test_sk_/);
    });
  });

  describe('routes: true', () => {
    it('rejects unauthenticated POST /api-key/keys with 401', async () => {
      const { fortress } = await setup({ prefix: 'test', routes: true });
      const res = await fortress.handleRequest(new Request('http://localhost/api-key/keys', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ name: 'Key' }),
      }));
      expect(res.status).toBe(401);
    });

    it('denies API-key credentials from minting broader keys via self-service routes', async () => {
      const { fortress, methods, userId } = await setup({
        prefix: 'test',
        routes: true,
      });
      const scoped = await methods.createKey({
        subject: userSubject(userId),
        name: 'Scoped caller',
        scopes: ['report:read'],
      });

      const res = await fortress.handleRequest(new Request('http://localhost/api-key/keys', {
        method: 'POST',
        headers: {
          'authorization': `ApiKey ${scoped.key}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: 'Escalated', scopes: ['*'] }),
      }));

      expect(res.status).toBe(403);
      const keys = await methods.listKeys({ subject: userSubject(userId) });
      expect(keys.some(k => k.name === 'Escalated')).toBe(false);
    });

    it('creates a key for the authenticated subject and ignores body.subject on POST', async () => {
      const { fortress, methods, userId, otherUserId, accessToken } = await setup({
        prefix: 'test',
        routes: true,
      });

      // Caller tries to forge a key for another user via body.subject — should be ignored.
      const res = await fortress.handleRequest(new Request('http://localhost/api-key/keys', {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${accessToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ subject: userSubject(otherUserId), name: 'Forged via HTTP' }),
      }));
      expect(res.status).toBe(201);
      const body = await res.json() as { key: string; id: number };
      expect(body.key).toMatch(/^test_sk_/);

      const aliceKeys = await methods.listKeys({ subject: userSubject(userId) });
      expect(aliceKeys.map(k => k.id)).toContain(body.id);
    });

    it('returns only the caller keys on GET /api-key/keys', async () => {
      const { fortress, methods, userId, otherUserId, accessToken } = await setup({
        prefix: 'test',
        routes: true,
      });

      await methods.createKey({ subject: userSubject(userId), name: 'Alice HTTP' });
      await methods.createKey({ subject: userSubject(otherUserId), name: 'Bob Silent' });

      const res = await fortress.handleRequest(new Request('http://localhost/api-key/keys', {
        headers: { authorization: `Bearer ${accessToken}` },
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as { id: number; name: string }[];
      // Route returns array shape from listKeys method (not wrapped in { keys: [...] })
      expect(Array.isArray(body)).toBe(true);
      expect(body.some(k => k.name === 'Alice HTTP')).toBe(true);
      expect(body.some(k => k.name === 'Bob Silent')).toBe(false);
    });

    it('refuses to revoke another user key on DELETE /api-key/keys/:id', async () => {
      const { fortress, methods, otherUserId, accessToken } = await setup({
        prefix: 'test',
        routes: true,
      });

      const { id } = await methods.createKey({ subject: userSubject(otherUserId), name: 'Bob Key' });

      const res = await fortress.handleRequest(new Request(`http://localhost/api-key/keys/${id}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${accessToken}` },
      }));
      expect(res.status).toBe(404);

      // Key still resolves — not actually revoked
      const bobKeys = await methods.listKeys({ subject: userSubject(otherUserId) });
      expect(bobKeys.some(k => k.id === id)).toBe(true);
    });

    it('rotates a key and revokes the old one on POST /api-key/keys/:id/rotate', async () => {
      const { fortress, methods, userId, accessToken } = await setup({
        prefix: 'test',
        routes: true,
      });

      const original = await methods.createKey({ subject: userSubject(userId), name: 'Rotate Me' });

      const res = await fortress.handleRequest(new Request(`http://localhost/api-key/keys/${original.id}/rotate`, {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${accessToken}`,
          'content-type': 'application/json',
        },
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as { key: string; id: number };
      expect(body.key).toMatch(/^test_sk_/);
      expect(body.id).not.toBe(original.id);

      // Old key no longer resolves
      expect(await methods.resolveKey(original.key)).toBeNull();
      // New key does
      const newResolved = await methods.resolveKey(body.key);
      expect(newResolved!.subject).toEqual({ type: 'USER', id: userId });
    });
  });
});

// ── Service account pipeline ────────────────────────────────────────

describe('api-key plugin — SERVICE_ACCOUNT subjects', () => {
  it('createKey for a SERVICE_ACCOUNT subject works programmatically', async () => {
    const { fortress, methods } = await setup();
    const sa = await fortress.iam.createServiceAccount({ name: 'ci-deploy' });

    const result = await methods.createKey({
      subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
      name: 'CI Deploy Key',
    });
    expect(result.key).toMatch(/^test_sk_/);

    const resolved = await methods.resolveKey(result.key);
    expect(resolved!.subject).toEqual({ type: 'SERVICE_ACCOUNT', id: sa.id });
  });

  it('listKeys scopes by (subjectType, subjectId)', async () => {
    const { fortress, methods, userId } = await setup();
    const sa = await fortress.iam.createServiceAccount({ name: 'iso' });

    // Create a USER key with the same numeric id would require a user with that id.
    // Use the existing user but also create a SA key.
    await methods.createKey({ subject: userSubject(userId), name: 'User Key' });
    await methods.createKey({
      subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
      name: 'SA Key',
    });

    const userKeys = await methods.listKeys({ subject: userSubject(userId) });
    const saKeys = await methods.listKeys({ subject: { type: 'SERVICE_ACCOUNT', id: sa.id } });

    expect(userKeys.map(k => k.name)).toEqual(['User Key']);
    expect(saKeys.map(k => k.name)).toEqual(['SA Key']);
  });

  it('resolveKey returns null for an inactive service account', async () => {
    const { fortress, methods } = await setup();
    const sa = await fortress.iam.createServiceAccount({ name: 'disabled' });

    const { key } = await methods.createKey({
      subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
      name: 'Disabled Key',
    });
    expect(await methods.resolveKey(key)).not.toBeNull();

    await fortress.iam.updateServiceAccount(sa.id, { isActive: false });
    expect(await methods.resolveKey(key)).toBeNull();
  });

  it('cascade: deleting a service account hard-deletes its api keys', async () => {
    const { fortress, methods } = await setup();
    const sa = await fortress.iam.createServiceAccount({ name: 'to-delete' });

    const { key, id } = await methods.createKey({
      subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
      name: 'Cascade Me',
    });

    await fortress.iam.deleteServiceAccount(sa.id);

    // Key is gone entirely — not just revoked.
    const remaining = await fortress.config.database.findMany({
      model: 'api_key',
      where: [{ field: 'id', operator: '=', value: id }],
    });
    expect(remaining).toHaveLength(0);

    // resolveKey returns null for the now-deleted key
    expect(await methods.resolveKey(key)).toBeNull();
  });

  it('authorization: ApiKey header authenticates a service account request', async () => {
    const { fortress, methods } = await setup({ prefix: 'test', routes: true });
    const sa = await fortress.iam.createServiceAccount({ name: 'ci-authed' });

    // Bind the service account to a role that grants fortress:viewServiceAccounts
    // so it can hit a real fortress-managed route.
    const role = await fortress.iam.createRole('ci-viewer', [
      { resource: 'fortress', action: 'viewServiceAccounts' },
    ]);
    await fortress.iam.bindRoleToServiceAccount(sa.id, role.id);

    const { key } = await methods.createKey({
      subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
      name: 'ci-key',
    });

    const res = await fortress.handleRequest(
      new Request('http://localhost/iam/service-accounts', {
        headers: { authorization: `ApiKey ${key}` },
      }),
    );
    expect(res.status).toBe(200);
    const body = await res.json() as { serviceAccounts: unknown[]; total: number };
    expect(body.total).toBeGreaterThanOrEqual(1);
  });

  it('rejects a service account request without the bound role via 403', async () => {
    const { fortress, methods } = await setup({ prefix: 'test', routes: true });
    const sa = await fortress.iam.createServiceAccount({ name: 'unbound' });

    const { key } = await methods.createKey({
      subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
      name: 'unbound-key',
    });

    const res = await fortress.handleRequest(
      new Request('http://localhost/iam/service-accounts', {
        headers: { authorization: `ApiKey ${key}` },
      }),
    );
    expect(res.status).toBe(403);
  });

  it('x-api-key header is accepted as an alternative to Authorization', async () => {
    const { fortress, methods } = await setup();
    const sa = await fortress.iam.createServiceAccount({ name: 'xheader' });
    const role = await fortress.iam.createRole('xh-role', [
      { resource: 'fortress', action: 'viewServiceAccounts' },
    ]);
    await fortress.iam.bindRoleToServiceAccount(sa.id, role.id);

    const { key } = await methods.createKey({
      subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
      name: 'xheader-key',
    });

    const res = await fortress.handleRequest(
      new Request('http://localhost/iam/service-accounts', {
        headers: { 'x-api-key': key },
      }),
    );
    expect(res.status).toBe(200);
  });
});
