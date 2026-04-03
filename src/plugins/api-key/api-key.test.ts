import type { Fortress } from '../../core/fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { apiKey } from './index';

const SECRET = 'api-key-test-secret-at-least-32!!';

// Type helpers for plugin methods
interface ApiKeyMethods {
  createKey: (userId: number, options: { name: string; scopes?: string[]; expiresAt?: Date }) => Promise<{ key: string; id: number }>;
  listKeys: (userId: number) => Promise<{ id: number; name: string; keyPrefix: string; scopes: string[] | null; expiresAt: string | null; lastUsedAt: string | null; createdAt: string }[]>;
  revokeKey: (userId: number, keyId: number) => Promise<void>;
  rotateKey: (userId: number, keyId: number) => Promise<{ key: string; id: number }>;
  resolveKey: (rawKey: string) => Promise<{ userId: number; scopes: string[] | null } | null>;
}

describe('api-key plugin', () => {
  let fortress: Fortress;
  let methods: ApiKeyMethods;
  let userId: number;

  beforeEach(async () => {
    fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
      plugins: [apiKey({ prefix: 'test', maxKeysPerUser: 3 })],
    });

    methods = fortress.plugins['api-key'] as unknown as ApiKeyMethods;

    const user = await fortress.auth.createUser({
      email: 'alice@example.com',
      name: 'Alice',
      password: 'password-123',
    });
    userId = user.id;
  });

  describe('createKey', () => {
    it('returns a key with correct prefix format', async () => {
      const result = await methods.createKey(userId, { name: 'My Key' });

      expect(result.key).toMatch(/^test_sk_[a-f0-9]{64}$/);
      expect(result.id).toBeDefined();
    });

    it('enforces maxKeysPerUser', async () => {
      await methods.createKey(userId, { name: 'Key 1' });
      await methods.createKey(userId, { name: 'Key 2' });
      await methods.createKey(userId, { name: 'Key 3' });

      await expect(
        methods.createKey(userId, { name: 'Key 4' }),
      ).rejects.toThrow('Maximum of 3 active API keys');
    });

    it('does not count revoked keys toward limit', async () => {
      const { id } = await methods.createKey(userId, { name: 'Key 1' });
      await methods.createKey(userId, { name: 'Key 2' });
      await methods.createKey(userId, { name: 'Key 3' });

      await methods.revokeKey(userId, id);

      // Should succeed since we revoked one
      const result = await methods.createKey(userId, { name: 'Key 4' });
      expect(result.key).toBeTruthy();
    });
  });

  describe('listKeys', () => {
    it('returns non-revoked keys only', async () => {
      const { id } = await methods.createKey(userId, { name: 'Key A' });
      await methods.createKey(userId, { name: 'Key B' });

      await methods.revokeKey(userId, id);

      const keys = await methods.listKeys(userId);
      expect(keys).toHaveLength(1);
      expect(keys[0].name).toBe('Key B');
    });

    it('never exposes the full key or hash', async () => {
      await methods.createKey(userId, { name: 'Secret Key' });

      const keys = await methods.listKeys(userId);
      const key = keys[0] as Record<string, unknown>;

      expect(key.keyPrefix).toBeTruthy();
      expect(key).not.toHaveProperty('keyHash');
      expect(key).not.toHaveProperty('key');
    });
  });

  describe('revokeKey', () => {
    it('marks key as revoked', async () => {
      const { key, id } = await methods.createKey(userId, { name: 'To Revoke' });

      await methods.revokeKey(userId, id);

      const resolved = await methods.resolveKey(key);
      expect(resolved).toBeNull();
    });

    it('rejects revoking another user key', async () => {
      const other = await fortress.auth.createUser({
        email: 'bob@example.com',
        name: 'Bob',
        password: 'password-123',
      });

      const { id } = await methods.createKey(other.id, { name: 'Bob Key' });

      await expect(
        methods.revokeKey(userId, id),
      ).rejects.toThrow('API key not found');
    });
  });

  describe('rotateKey', () => {
    it('revokes old key and creates new one', async () => {
      const original = await methods.createKey(userId, { name: 'Rotate Me' });

      const rotated = await methods.rotateKey(userId, original.id);

      // Old key should not resolve
      const oldResolved = await methods.resolveKey(original.key);
      expect(oldResolved).toBeNull();

      // New key should resolve
      const newResolved = await methods.resolveKey(rotated.key);
      expect(newResolved).not.toBeNull();
      expect(newResolved!.userId).toBe(userId);
    });
  });

  describe('resolveKey', () => {
    it('resolves a valid key', async () => {
      const { key } = await methods.createKey(userId, { name: 'Valid Key' });

      const result = await methods.resolveKey(key);

      expect(result).not.toBeNull();
      expect(result!.userId).toBe(userId);
    });

    it('rejects revoked key', async () => {
      const { key, id } = await methods.createKey(userId, { name: 'Revoked Key' });
      await methods.revokeKey(userId, id);

      const result = await methods.resolveKey(key);
      expect(result).toBeNull();
    });

    it('rejects expired key', async () => {
      const { key } = await methods.createKey(userId, {
        name: 'Expired Key',
        expiresAt: new Date(Date.now() - 1000), // already expired
      });

      const result = await methods.resolveKey(key);
      expect(result).toBeNull();
    });

    it('updates lastUsedAt on resolve', async () => {
      const { key } = await methods.createKey(userId, { name: 'Track Usage' });

      // Initially no lastUsedAt
      let keys = await methods.listKeys(userId);
      expect(keys[0].lastUsedAt).toBeNull();

      // Resolve the key
      await methods.resolveKey(key);

      // Now lastUsedAt should be set
      keys = await methods.listKeys(userId);
      expect(keys[0].lastUsedAt).toBeTruthy();
    });

    it('returns null for unknown key', async () => {
      const result = await methods.resolveKey('nonexistent_sk_key');
      expect(result).toBeNull();
    });
  });

  describe('scoped keys', () => {
    it('returns correct scopes on resolve', async () => {
      const scopes = ['article:read', 'article:list'];
      const { key } = await methods.createKey(userId, {
        name: 'Scoped Key',
        scopes,
      });

      const result = await methods.resolveKey(key);
      expect(result!.scopes).toEqual(scopes);
    });

    it('returns null scopes for unscoped key', async () => {
      const { key } = await methods.createKey(userId, { name: 'Unscoped Key' });

      const result = await methods.resolveKey(key);
      expect(result!.scopes).toBeNull();
    });
  });
});
