import type { Fortress } from '../../core/fortress';
import type { PluginRouteContext } from '../../core/plugin';
import type { ApiKeyConfig, ApiKeyMethods } from './index';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { apiKey } from './index';

const SECRET = 'api-key-test-secret-at-least-32!!';

function httpCtx(uid: number | undefined): PluginRouteContext {
  return {
    userId: uid,
    claims: undefined,
    meta: undefined,
    request: new Request('http://localhost/api-key/keys'),
  };
}

async function setup(config: ApiKeyConfig = { prefix: 'test', maxKeysPerUser: 3 }): Promise<{
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
      const result = await methods.createKey({ userId, name: 'My Key' });
      expect(result.key).toMatch(/^test_sk_[a-f0-9]{64}$/);
      expect(result.id).toBeDefined();
    });

    it('enforces maxKeysPerUser', async () => {
      await methods.createKey({ userId, name: 'Key 1' });
      await methods.createKey({ userId, name: 'Key 2' });
      await methods.createKey({ userId, name: 'Key 3' });

      await expect(methods.createKey({ userId, name: 'Key 4' }))
        .rejects
        .toThrow('Maximum of 3 active API keys');
    });

    it('does not count revoked keys toward the limit', async () => {
      const { id } = await methods.createKey({ userId, name: 'Key 1' });
      await methods.createKey({ userId, name: 'Key 2' });
      await methods.createKey({ userId, name: 'Key 3' });

      await methods.revokeKey({ userId, id });

      const result = await methods.createKey({ userId, name: 'Key 4' });
      expect(result.key).toBeTruthy();
    });

    it('requires userId when called without routeCtx', async () => {
      await expect(methods.createKey({ name: 'Orphan' } as { name: string }))
        .rejects
        .toThrow('userId is required');
    });
  });

  describe('listKeys', () => {
    it('returns only non-revoked keys', async () => {
      const { id } = await methods.createKey({ userId, name: 'Key A' });
      await methods.createKey({ userId, name: 'Key B' });
      await methods.revokeKey({ userId, id });

      const keys = await methods.listKeys({ userId });
      expect(keys).toHaveLength(1);
      expect(keys[0].name).toBe('Key B');
    });

    it('never exposes the full key or hash', async () => {
      await methods.createKey({ userId, name: 'Secret Key' });

      const keys = await methods.listKeys({ userId });
      const key = keys[0] as unknown as Record<string, unknown>;

      expect(key.keyPrefix).toBeTruthy();
      expect(key).not.toHaveProperty('keyHash');
      expect(key).not.toHaveProperty('key');
    });

    it('scopes by userId — one user cannot see another user\'s keys', async () => {
      await methods.createKey({ userId, name: 'Alice Key' });
      await methods.createKey({ userId: otherUserId, name: 'Bob Key' });

      const aliceKeys = await methods.listKeys({ userId });
      const bobKeys = await methods.listKeys({ userId: otherUserId });

      expect(aliceKeys).toHaveLength(1);
      expect(aliceKeys[0].name).toBe('Alice Key');
      expect(bobKeys).toHaveLength(1);
      expect(bobKeys[0].name).toBe('Bob Key');
    });
  });

  describe('revokeKey', () => {
    it('marks a key as revoked', async () => {
      const { key, id } = await methods.createKey({ userId, name: 'To Revoke' });
      await methods.revokeKey({ userId, id });

      const resolved = await methods.resolveKey(key);
      expect(resolved).toBeNull();
    });

    it('rejects revoking another user\'s key', async () => {
      const { id } = await methods.createKey({ userId: otherUserId, name: 'Bob Key' });
      await expect(methods.revokeKey({ userId, id }))
        .rejects
        .toThrow('API key not found');
    });
  });

  describe('rotateKey', () => {
    it('revokes the old key and creates a new one', async () => {
      const original = await methods.createKey({ userId, name: 'Rotate Me' });
      const rotated = await methods.rotateKey({ userId, id: original.id });

      const oldResolved = await methods.resolveKey(original.key);
      expect(oldResolved).toBeNull();

      const newResolved = await methods.resolveKey(rotated.key);
      expect(newResolved).not.toBeNull();
      expect(newResolved!.userId).toBe(userId);
    });
  });

  describe('resolveKey', () => {
    it('resolves a valid key', async () => {
      const { key } = await methods.createKey({ userId, name: 'Valid Key' });
      const result = await methods.resolveKey(key);
      expect(result).not.toBeNull();
      expect(result!.userId).toBe(userId);
    });

    it('rejects a revoked key', async () => {
      const { key, id } = await methods.createKey({ userId, name: 'Revoked Key' });
      await methods.revokeKey({ userId, id });
      const result = await methods.resolveKey(key);
      expect(result).toBeNull();
    });

    it('rejects an expired key', async () => {
      const { key } = await methods.createKey({
        userId,
        name: 'Expired Key',
        expiresAt: new Date(Date.now() - 1000),
      });
      const result = await methods.resolveKey(key);
      expect(result).toBeNull();
    });

    it('updates lastUsedAt on resolve', async () => {
      const { key } = await methods.createKey({ userId, name: 'Track Usage' });

      let keys = await methods.listKeys({ userId });
      expect(keys[0].lastUsedAt).toBeNull();

      await methods.resolveKey(key);

      keys = await methods.listKeys({ userId });
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
      const { key } = await methods.createKey({ userId, name: 'Scoped Key', scopes });
      const result = await methods.resolveKey(key);
      expect(result!.scopes).toEqual(scopes);
    });

    it('returns null scopes for an unscoped key', async () => {
      const { key } = await methods.createKey({ userId, name: 'Unscoped Key' });
      const result = await methods.resolveKey(key);
      expect(result!.scopes).toBeNull();
    });
  });
});

describe('api-key plugin — dual-mode (routeCtx takes precedence over body.userId)', () => {
  it('uses routeCtx.userId and ignores body.userId when routeCtx is present', async () => {
    const { methods, userId, otherUserId } = await setup();

    // Caller tries to forge a key for another user by passing userId in body.
    // The route-mode invocation must ignore body.userId and trust routeCtx.
    const result = await methods.createKey(
      { userId: otherUserId, name: 'Forged' },
      httpCtx(userId),
    );

    // Key should belong to the authenticated caller, not the forged target
    const aliceKeys = await methods.listKeys({ userId });
    const bobKeys = await methods.listKeys({ userId: otherUserId });

    expect(aliceKeys.map(k => k.id)).toContain(result.id);
    expect(bobKeys.map(k => k.id)).not.toContain(result.id);
  });

  it('throws UNAUTHORIZED when routeCtx.userId is missing', async () => {
    const { methods } = await setup();
    await expect(methods.createKey({ name: 'X' } as { name: string }, httpCtx(undefined)))
      .rejects
      .toThrow('User not authenticated');
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
      const result = await methods.createKey({ userId, name: 'Programmatic' });
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

    it('creates a key for claims.sub and ignores body.userId on POST', async () => {
      const { fortress, methods, userId, otherUserId, accessToken } = await setup({
        prefix: 'test',
        routes: true,
      });

      // Caller tries to set userId in the body — should be ignored.
      const res = await fortress.handleRequest(new Request('http://localhost/api-key/keys', {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${accessToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ userId: otherUserId, name: 'Forged via HTTP' }),
      }));
      expect(res.status).toBe(201);
      const body = await res.json() as { key: string; id: number };
      expect(body.key).toMatch(/^test_sk_/);

      const aliceKeys = await methods.listKeys({ userId });
      expect(aliceKeys.map(k => k.id)).toContain(body.id);
    });

    it('returns only the caller keys on GET /api-key/keys', async () => {
      const { fortress, methods, userId, otherUserId, accessToken } = await setup({
        prefix: 'test',
        routes: true,
      });

      await methods.createKey({ userId, name: 'Alice HTTP' });
      await methods.createKey({ userId: otherUserId, name: 'Bob Silent' });

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

      const { id } = await methods.createKey({ userId: otherUserId, name: 'Bob Key' });

      const res = await fortress.handleRequest(new Request(`http://localhost/api-key/keys/${id}`, {
        method: 'DELETE',
        headers: { authorization: `Bearer ${accessToken}` },
      }));
      expect(res.status).toBe(404);

      // Key still resolves — not actually revoked
      const bobKeys = await methods.listKeys({ userId: otherUserId });
      expect(bobKeys.some(k => k.id === id)).toBe(true);
    });

    it('rotates a key and revokes the old one on POST /api-key/keys/:id/rotate', async () => {
      const { fortress, methods, userId, accessToken } = await setup({
        prefix: 'test',
        routes: true,
      });

      const original = await methods.createKey({ userId, name: 'Rotate Me' });

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
      expect(newResolved!.userId).toBe(userId);
    });
  });
});
