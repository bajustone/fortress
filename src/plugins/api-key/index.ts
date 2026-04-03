import type { FortressPlugin } from '../../core/plugin';
import { hashToken } from '../../core/auth/refresh-token';
import { Errors } from '../../core/errors';

export interface ApiKeyConfig {
  /** Prefix for generated keys (default: 'fortress') */
  prefix?: string;
  /** Default expiry in seconds. null = never expires (default: null) */
  defaultExpirySeconds?: number | null;
  /** Maximum active (non-revoked) keys per user (default: 10) */
  maxKeysPerUser?: number;
}

export interface ApiKeyInfo {
  id: number;
  name: string;
  keyPrefix: string;
  scopes: string[] | null;
  expiresAt: string | null;
  lastUsedAt: string | null;
  createdAt: string;
}

interface ApiKeyRecord {
  id: number;
  userId: number;
  name: string;
  keyHash: string;
  keyPrefix: string;
  scopes: string | null;
  expiresAt: string | null;
  lastUsedAt: string | null;
  isRevoked: boolean;
  createdAt: string;
}

async function generateApiKey(prefix: string): Promise<{ raw: string; hash: string; keyPrefix: string }> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const random = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  const raw = `${prefix}_sk_${random}`;
  const hash = await hashToken(raw);
  const keyPrefix = raw.slice(0, 12);
  return { raw, hash, keyPrefix };
}

export function apiKey(config: ApiKeyConfig = {}): FortressPlugin {
  const prefix = config.prefix ?? 'fortress';
  const defaultExpirySeconds = config.defaultExpirySeconds ?? null;
  const maxKeysPerUser = config.maxKeysPerUser ?? 10;

  return {
    name: 'api-key',

    models: [{
      name: 'api_key',
      fields: {
        id: { type: 'number', required: true },
        userId: { type: 'number', required: true, references: { model: 'user', field: 'id' } },
        name: { type: 'string', required: true },
        keyHash: { type: 'string', required: true, unique: true },
        keyPrefix: { type: 'string', required: true },
        scopes: { type: 'string' },
        expiresAt: { type: 'date' },
        lastUsedAt: { type: 'date' },
        isRevoked: { type: 'boolean', required: true },
        createdAt: { type: 'date', required: true },
      },
    }],

    methods: ctx => ({
      async createKey(
        userId: number,
        options: { name: string; scopes?: string[]; expiresAt?: Date },
      ): Promise<{ key: string; id: number }> {
        // Check active key count
        const activeCount = await ctx.db.count({
          model: 'api_key',
          where: [
            { field: 'userId', operator: '=', value: userId },
            { field: 'isRevoked', operator: '=', value: false },
          ],
        });

        if (activeCount >= maxKeysPerUser) {
          throw Errors.badRequest(`Maximum of ${maxKeysPerUser} active API keys per user`);
        }

        const { raw, hash, keyPrefix } = await generateApiKey(prefix);

        let expiresAt: string | null = null;
        if (options.expiresAt) {
          expiresAt = options.expiresAt.toISOString();
        }
        else if (defaultExpirySeconds) {
          expiresAt = new Date(Date.now() + defaultExpirySeconds * 1000).toISOString();
        }

        const record = await ctx.db.create<ApiKeyRecord>({
          model: 'api_key',
          data: {
            userId,
            name: options.name,
            keyHash: hash,
            keyPrefix,
            scopes: options.scopes ? JSON.stringify(options.scopes) : null,
            expiresAt,
            lastUsedAt: null,
            isRevoked: false,
          },
        });

        return { key: raw, id: record.id };
      },

      async listKeys(userId: number): Promise<ApiKeyInfo[]> {
        const records = await ctx.db.findMany<ApiKeyRecord>({
          model: 'api_key',
          where: [
            { field: 'userId', operator: '=', value: userId },
            { field: 'isRevoked', operator: '=', value: false },
          ],
        });

        return records.map(r => ({
          id: r.id,
          name: r.name,
          keyPrefix: r.keyPrefix,
          scopes: r.scopes ? JSON.parse(r.scopes) as string[] : null,
          expiresAt: r.expiresAt,
          lastUsedAt: r.lastUsedAt,
          createdAt: r.createdAt,
        }));
      },

      async revokeKey(userId: number, keyId: number): Promise<void> {
        const record = await ctx.db.findOne<ApiKeyRecord>({
          model: 'api_key',
          where: [{ field: 'id', operator: '=', value: keyId }],
        });

        if (!record || record.userId !== userId) {
          throw Errors.notFound('API key not found');
        }

        await ctx.db.update({
          model: 'api_key',
          where: [{ field: 'id', operator: '=', value: keyId }],
          data: { isRevoked: true },
        });
      },

      async rotateKey(userId: number, keyId: number): Promise<{ key: string; id: number }> {
        const record = await ctx.db.findOne<ApiKeyRecord>({
          model: 'api_key',
          where: [{ field: 'id', operator: '=', value: keyId }],
        });

        if (!record || record.userId !== userId) {
          throw Errors.notFound('API key not found');
        }

        // Revoke old key
        await ctx.db.update({
          model: 'api_key',
          where: [{ field: 'id', operator: '=', value: keyId }],
          data: { isRevoked: true },
        });

        // Create new key with same name and scopes
        const { raw, hash, keyPrefix } = await generateApiKey(prefix);

        const newRecord = await ctx.db.create<ApiKeyRecord>({
          model: 'api_key',
          data: {
            userId,
            name: record.name,
            keyHash: hash,
            keyPrefix,
            scopes: record.scopes,
            expiresAt: record.expiresAt,
            lastUsedAt: null,
            isRevoked: false,
          },
        });

        return { key: raw, id: newRecord.id };
      },

      async resolveKey(rawKey: string): Promise<{ userId: number; scopes: string[] | null } | null> {
        const hash = await hashToken(rawKey);

        const record = await ctx.db.findOne<ApiKeyRecord>({
          model: 'api_key',
          where: [{ field: 'keyHash', operator: '=', value: hash }],
        });

        if (!record || record.isRevoked)
          return null;

        if (record.expiresAt && new Date(record.expiresAt) < new Date())
          return null;

        // Update lastUsedAt
        await ctx.db.update({
          model: 'api_key',
          where: [{ field: 'id', operator: '=', value: record.id }],
          data: { lastUsedAt: new Date().toISOString() },
        });

        return {
          userId: record.userId,
          scopes: record.scopes ? JSON.parse(record.scopes) as string[] : null,
        };
      },
    }),
  };
}
