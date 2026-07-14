/**
 * Pure key operations for the api-key plugin.
 *
 * Extracted so both the api-key plugin (self-service) and the admin plugin
 * (admin-over-users) can share one implementation without cross-plugin
 * runtime coupling. Functions take a {@link DatabaseAdapter} plus args and
 * throw {@link FortressError} via the existing `Errors` factory on failure.
 *
 * Keys are owned by a {@link Subject} — either a USER or a SERVICE_ACCOUNT
 * (and extensible to future subject types). The storage schema uses a
 * polymorphic `(subject_type, subject_id)` pair instead of a hard FK to
 * `users.id`, mirroring `role_binding` / `direct_permission_binding`.
 *
 * @module
 */

import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressUser, ServiceAccount, Subject, SubjectType } from '../../core/types';
import { hashToken } from '../../core/auth/refresh-token';
import { Errors } from '../../core/errors';

export interface ApiKeyInfo {
  id: string;
  name: string;
  keyPrefix: string;
  scopes: string[] | null;
  expiresAt: Date | null;
  lastUsedAt: Date | null;
  createdAt: Date;
}

export interface ApiKeyRecord {
  id: string;
  subjectType: SubjectType;
  subjectId: string;
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
  maxKeysPerSubject: number;
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
  // Include random material even when the configured textual prefix is long
  // (the default `fortress_sk_` alone already occupies 12 characters).
  const keyPrefix = `${prefix}_sk_${random.slice(0, 8)}`;
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

function subjectWhere(subject: Subject): Array<{ field: 'subjectType' | 'subjectId'; operator: '='; value: string | number }> {
  return [
    { field: 'subjectType', operator: '=', value: subject.type },
    { field: 'subjectId', operator: '=', value: subject.id },
  ];
}

/**
 * Create a new key for a subject. Enforces `maxKeysPerSubject`. Caller-neutral —
 * the admin plugin calls this on behalf of a target subject, self-service
 * calls with the authenticated caller's subject.
 */
export async function createKeyForSubject(
  db: DatabaseAdapter,
  subject: Subject,
  options: CreateKeyOptions,
  knobs: ApiKeyKnobs,
): Promise<{ key: string; id: string }> {
  return db.transaction(async (tx) => {
    // SQLite transactions take the writer lock; PostgreSQL needs an explicit
    // subject-scoped advisory lock so count+insert is one atomic quota check
    // across processes.
    if (tx.dialect === 'pg' && tx.rawQuery) {
      await tx.rawQuery('SELECT pg_advisory_xact_lock(hashtext(?), hashtext(?))', [subject.type, subject.id]);
    }

    const activeCount = await tx.count({
      model: 'api_key',
      where: [
        ...subjectWhere(subject),
        { field: 'isRevoked', operator: '=', value: false },
      ],
    });

    if (activeCount >= knobs.maxKeysPerSubject) {
      throw Errors.badRequest(`Maximum of ${knobs.maxKeysPerSubject} active API keys per subject`);
    }

    const { raw, hash, keyPrefix } = await generateApiKey(knobs.prefix);

    let expiresAt: Date | null = null;
    if (options.expiresAt) {
      expiresAt = options.expiresAt;
    }
    else if (knobs.defaultExpirySeconds) {
      expiresAt = new Date(Date.now() + knobs.defaultExpirySeconds * 1000);
    }

    const record = await tx.create<ApiKeyRecord>({
      model: 'api_key',
      data: {
        subjectType: subject.type,
        subjectId: subject.id,
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
  });
}

/** List non-revoked keys owned by a subject. Caller-neutral. */
export async function listKeysForSubject(
  db: DatabaseAdapter,
  subject: Subject,
): Promise<ApiKeyInfo[]> {
  const records = await db.findMany<ApiKeyRecord>({
    model: 'api_key',
    where: [
      ...subjectWhere(subject),
      { field: 'isRevoked', operator: '=', value: false },
    ],
  });
  return records.map(toInfo);
}

/**
 * Revoke a key owned by the given subject. Throws `notFound` if the key is
 * missing or belongs to a different subject — the ownership check enforces
 * self-service semantics.
 */
export async function revokeKeyForSubject(
  db: DatabaseAdapter,
  subject: Subject,
  keyId: string,
): Promise<void> {
  const record = await db.findOne<ApiKeyRecord>({
    model: 'api_key',
    where: [{ field: 'id', operator: '=', value: keyId }],
  });
  if (!record || record.subjectType !== subject.type || record.subjectId !== subject.id) {
    throw Errors.notFound('API key not found');
  }
  await db.update({
    model: 'api_key',
    where: [{ field: 'id', operator: '=', value: keyId }],
    data: { isRevoked: true },
  });
}

/**
 * Rotate a key owned by the given subject — revokes the old one and issues
 * a new one with the same name, scopes, and expiry. Same ownership check as
 * {@link revokeKeyForSubject}.
 */
export async function rotateKeyForSubject(
  db: DatabaseAdapter,
  subject: Subject,
  keyId: string,
  knobs: { prefix: string },
): Promise<{ key: string; id: string }> {
  const record = await db.findOne<ApiKeyRecord>({
    model: 'api_key',
    where: [{ field: 'id', operator: '=', value: keyId }],
  });
  if (!record || record.subjectType !== subject.type || record.subjectId !== subject.id) {
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
      subjectType: record.subjectType,
      subjectId: record.subjectId,
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
 * Resolve a raw API key to its owning subject + scopes. Returns `null` for
 * unknown, revoked, expired, or inactive keys. Side-effect: updates
 * `lastUsedAt` on successful resolution.
 *
 * USER and SERVICE_ACCOUNT owners are additionally checked for existence and
 * `isActive` — this is the first line of defense before the permission
 * resolver enforces the same gate in `internal-adapter.getSubjectPermissions`.
 */
export async function resolveApiKey(
  db: DatabaseAdapter,
  rawKey: string,
): Promise<{ subject: Subject; scopes: string[] | null } | null> {
  const hash = await hashToken(rawKey);
  const record = await db.findOne<ApiKeyRecord>({
    model: 'api_key',
    where: [{ field: 'keyHash', operator: '=', value: hash }],
  });

  if (!record || record.isRevoked)
    return null;
  if (record.expiresAt && record.expiresAt < new Date())
    return null;

  // A credential cannot outlive or bypass deactivation of its owner.
  if (record.subjectType === 'USER') {
    const user = await db.findOne<FortressUser>({
      model: 'user',
      where: [{ field: 'id', operator: '=', value: record.subjectId }],
    });
    if (!user || !user.isActive)
      return null;
  }
  else if (record.subjectType === 'SERVICE_ACCOUNT') {
    const sa = await db.findOne<ServiceAccount>({
      model: 'service_account',
      where: [{ field: 'id', operator: '=', value: record.subjectId }],
    });
    if (!sa || !sa.isActive)
      return null;
  }

  await db.update({
    model: 'api_key',
    where: [{ field: 'id', operator: '=', value: record.id }],
    data: { lastUsedAt: new Date() },
  });

  return {
    subject: { type: record.subjectType, id: record.subjectId },
    scopes: record.scopes ? JSON.parse(record.scopes) as string[] : null,
  };
}

// ── Admin-only helpers ───────────────────────────────────────────────

/**
 * Admin variant of {@link revokeKeyForSubject} — revokes any key by id
 * without an ownership check. Use only behind an admin-permission gate.
 */
export async function revokeKeyAsAdmin(
  db: DatabaseAdapter,
  keyId: string,
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

/**
 * Admin variant of {@link listKeysForSubject} — lists all keys for any
 * subject without an ownership check. Used by the admin plugin's
 * `adminListUserApiKeys` convenience helper.
 */
export async function listKeysForAnySubject(
  db: DatabaseAdapter,
  subject: Subject,
): Promise<ApiKeyInfo[]> {
  return listKeysForSubject(db, subject);
}

/**
 * Hard-delete every api key owned by a subject. Used by the api-key plugin's
 * IAM observer to cascade-delete keys when a service account is deleted.
 */
export async function deleteAllKeysForSubject(
  db: DatabaseAdapter,
  subject: Subject,
): Promise<void> {
  await db.delete({
    model: 'api_key',
    where: subjectWhere(subject),
  });
}
