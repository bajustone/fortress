/**
 * Pure key operations for the api-key plugin.
 *
 * Extracted so both the api-key plugin (self-service) and the admin plugin
 * (admin-over-users) can share one implementation without cross-plugin
 * runtime coupling. Functions take a {@link DatabaseAdapter} plus args and
 * throw {@link FortressError} via the existing `Errors` factory on failure.
 *
 * @module
 */

import type { DatabaseAdapter } from '../../adapters/database';
import { hashToken } from '../../core/auth/refresh-token';
import { Errors } from '../../core/errors';

export interface ApiKeyInfo {
  id: number;
  name: string;
  keyPrefix: string;
  scopes: string[] | null;
  expiresAt: Date | null;
  lastUsedAt: Date | null;
  createdAt: Date;
}

export interface ApiKeyRecord {
  id: number;
  userId: number;
  name: string;
  keyHash: string;
  keyPrefix: string;
  scopes: string | null;
  expiresAt: Date | null;
  lastUsedAt: Date | null;
  isRevoked: boolean;
  createdAt: Date;
}

export interface ApiKeyKnobs {
  prefix: string;
  defaultExpirySeconds: number | null;
  maxKeysPerUser: number;
}

export interface CreateKeyOptions {
  name: string;
  scopes?: string[];
  expiresAt?: Date;
}

/** Generate a new random API key and its hash. */
export async function generateApiKey(
  prefix: string,
): Promise<{ raw: string; hash: string; keyPrefix: string }> {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const random = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  const raw = `${prefix}_sk_${random}`;
  const hash = await hashToken(raw);
  const keyPrefix = raw.slice(0, 12);
  return { raw, hash, keyPrefix };
}

function toInfo(r: ApiKeyRecord): ApiKeyInfo {
  return {
    id: r.id,
    name: r.name,
    keyPrefix: r.keyPrefix,
    scopes: r.scopes ? JSON.parse(r.scopes) as string[] : null,
    expiresAt: r.expiresAt,
    lastUsedAt: r.lastUsedAt,
    createdAt: r.createdAt,
  };
}

/**
 * Create a new key for a user. Enforces `maxKeysPerUser`. Caller-neutral —
 * the admin plugin calls this with a target userId, self-service calls with
 * the authenticated caller's id.
 */
export async function createKeyForUser(
  db: DatabaseAdapter,
  userId: number,
  options: CreateKeyOptions,
  knobs: ApiKeyKnobs,
): Promise<{ key: string; id: number }> {
  const activeCount = await db.count({
    model: 'api_key',
    where: [
      { field: 'userId', operator: '=', value: userId },
      { field: 'isRevoked', operator: '=', value: false },
    ],
  });

  if (activeCount >= knobs.maxKeysPerUser) {
    throw Errors.badRequest(`Maximum of ${knobs.maxKeysPerUser} active API keys per user`);
  }

  const { raw, hash, keyPrefix } = await generateApiKey(knobs.prefix);

  let expiresAt: Date | null = null;
  if (options.expiresAt) {
    expiresAt = options.expiresAt;
  }
  else if (knobs.defaultExpirySeconds) {
    expiresAt = new Date(Date.now() + knobs.defaultExpirySeconds * 1000);
  }

  const record = await db.create<ApiKeyRecord>({
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
}

/** List non-revoked keys for a user. Caller-neutral. */
export async function listKeysForUser(
  db: DatabaseAdapter,
  userId: number,
): Promise<ApiKeyInfo[]> {
  const records = await db.findMany<ApiKeyRecord>({
    model: 'api_key',
    where: [
      { field: 'userId', operator: '=', value: userId },
      { field: 'isRevoked', operator: '=', value: false },
    ],
  });
  return records.map(toInfo);
}

/**
 * Revoke a key the caller owns. Throws `notFound` if the key is missing or
 * belongs to another user — self-service ownership enforcement.
 */
export async function revokeKeyForUser(
  db: DatabaseAdapter,
  userId: number,
  keyId: number,
): Promise<void> {
  const record = await db.findOne<ApiKeyRecord>({
    model: 'api_key',
    where: [{ field: 'id', operator: '=', value: keyId }],
  });
  if (!record || record.userId !== userId) {
    throw Errors.notFound('API key not found');
  }
  await db.update({
    model: 'api_key',
    where: [{ field: 'id', operator: '=', value: keyId }],
    data: { isRevoked: true },
  });
}

/**
 * Rotate one of the caller's own keys — revokes the old one and creates a
 * new one with the same name, scopes, and expiry. Same ownership check as
 * {@link revokeKeyForUser}.
 */
export async function rotateKeyForUser(
  db: DatabaseAdapter,
  userId: number,
  keyId: number,
  knobs: { prefix: string },
): Promise<{ key: string; id: number }> {
  const record = await db.findOne<ApiKeyRecord>({
    model: 'api_key',
    where: [{ field: 'id', operator: '=', value: keyId }],
  });
  if (!record || record.userId !== userId) {
    throw Errors.notFound('API key not found');
  }

  await db.update({
    model: 'api_key',
    where: [{ field: 'id', operator: '=', value: keyId }],
    data: { isRevoked: true },
  });

  const { raw, hash, keyPrefix } = await generateApiKey(knobs.prefix);
  const newRecord = await db.create<ApiKeyRecord>({
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
}

/**
 * Resolve a raw API key to its owning user + scopes. Returns `null` for
 * unknown, revoked, or expired keys. Side-effect: updates `lastUsedAt`.
 */
export async function resolveApiKey(
  db: DatabaseAdapter,
  rawKey: string,
): Promise<{ userId: number; scopes: string[] | null } | null> {
  const hash = await hashToken(rawKey);
  const record = await db.findOne<ApiKeyRecord>({
    model: 'api_key',
    where: [{ field: 'keyHash', operator: '=', value: hash }],
  });

  if (!record || record.isRevoked)
    return null;
  if (record.expiresAt && record.expiresAt < new Date())
    return null;

  await db.update({
    model: 'api_key',
    where: [{ field: 'id', operator: '=', value: record.id }],
    data: { lastUsedAt: new Date() },
  });

  return {
    userId: record.userId,
    scopes: record.scopes ? JSON.parse(record.scopes) as string[] : null,
  };
}

// ── Admin-only helpers ───────────────────────────────────────────────

/**
 * Admin variant of {@link revokeKeyForUser} — revokes any key by id without
 * an ownership check. Use only behind an admin-permission gate.
 */
export async function revokeKeyAsAdmin(
  db: DatabaseAdapter,
  keyId: number,
): Promise<void> {
  const record = await db.findOne<ApiKeyRecord>({
    model: 'api_key',
    where: [{ field: 'id', operator: '=', value: keyId }],
  });
  if (!record)
    throw Errors.notFound('API key not found');
  await db.update({
    model: 'api_key',
    where: [{ field: 'id', operator: '=', value: keyId }],
    data: { isRevoked: true },
  });
}
