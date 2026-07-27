/**
 * Migration upgrade fixture — proves the bundled migrations apply
 * end-to-end against a freshly provisioned database, not just against the
 * test adapter (which pre-creates every Fortress table).
 *
 * Uses a bare in-memory SQLite database so the starting state has no
 * Fortress tables at all. As bundled migrations grow beyond the
 * schema-version checkpoint, this fixture doubles as the regression
 * guard that catches a migration that silently fails to install a table.
 */

import type { MigratableDatabaseAdapter } from '../../adapters/database';
import { describe, expect, it } from 'vitest';
import { createSqliteDrizzleAdapter } from '../../drizzle/adapter';
import {
  detectMigrationDrift,
  getMigrationStatus,
  hasMigrationDrift,
  migrateDown,
  migrateUp,
} from './engine';
import { FORTRESS_TABLES } from './migrations';

const isBun = typeof (globalThis as Record<string, unknown>).Bun !== 'undefined';

function createBareSqliteAdapter(): MigratableDatabaseAdapter<'sqlite'> {
  if (isBun) {
    // eslint-disable-next-line ts/no-require-imports
    const { Database } = require('bun:sqlite');
    // eslint-disable-next-line ts/no-require-imports
    const { drizzle } = require('drizzle-orm/bun-sqlite');
    const sqlite = new Database(':memory:');
    sqlite.exec('PRAGMA foreign_keys = ON;');
    return createSqliteDrizzleAdapter(drizzle(sqlite));
  }
  // eslint-disable-next-line ts/no-require-imports
  const BetterSqlite3 = require('better-sqlite3');
  // eslint-disable-next-line ts/no-require-imports
  const { drizzle } = require('drizzle-orm/better-sqlite3');
  const sqlite = new BetterSqlite3(':memory:');
  sqlite.pragma('foreign_keys = ON');
  return createSqliteDrizzleAdapter(drizzle(sqlite));
}

describe('migration upgrade fixture (bare sqlite)', () => {
  it('provisions a bare DB end-to-end from the bundled migrations', async () => {
    const db = createBareSqliteAdapter();

    const initial = await getMigrationStatus(db);
    expect(initial.hasVersionTable).toBe(false);
    expect(initial.currentVersion).toBe(0);

    const initialDrift = await detectMigrationDrift(db);
    expect(hasMigrationDrift(initialDrift)).toBe(true);
    expect(initialDrift.missingVersionTable).toBe(true);
    // A bare DB is missing every Fortress table.
    expect(initialDrift.missingTables.length).toBe(FORTRESS_TABLES.length);

    const up = await migrateUp(db);
    expect(up.fromVersion).toBe(0);
    expect(up.toVersion).toBe(10);
    expect(up.applied.map(migration => migration.name)).toEqual(['schema_version', 'initial_schema', 'auth_continuation', 'tenant_default_unique', 'hot_indexes_timestamptz', 'canonical_email', 'audit_chain_anchor', 'two_factor_hardening', 'encrypt_totp_secrets', 'bigint_append_only_ids']);

    const after = await getMigrationStatus(db);
    expect(after.hasVersionTable).toBe(true);
    expect(after.currentVersion).toBe(10);
    expect(after.upToDate).toBe(true);

    // The full schema is now installed: no missing tables, no missing columns.
    const afterDrift = await detectMigrationDrift(db);
    expect(hasMigrationDrift(afterDrift)).toBe(false);
    expect(afterDrift.missingTables).toEqual([]);
    expect(afterDrift.missingColumns).toEqual([]);
    expect(afterDrift.missingIndexes).toEqual([]);

    // The provisioned schema is actually usable, not just present.
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'fixture@test.com', name: 'Fixture', passwordHash: 'h', isActive: true },
    });
    expect(user.id).toBeTruthy();

    const continuation = await db.create<{ id: string; consumedAt: Date | null }>({
      model: 'auth_continuation',
      data: {
        userId: user.id,
        tokenHash: 'fixture-continuation-hash',
        reason: 'two-factor',
        expiresAt: new Date(Date.now() + 60_000),
        consumedAt: null,
      },
    });
    expect(continuation.id).toBeTruthy();
    expect(continuation.consumedAt).toBeNull();

    // Re-running is idempotent.
    const reapply = await migrateUp(db);
    expect(reapply.applied).toEqual([]);

    // Roll back below 0 drops every Fortress table again.
    const down = await migrateDown(db);
    expect(down.toVersion).toBe(0);
    expect(down.rolledBack.map(migration => migration.name)).toEqual(['bigint_append_only_ids', 'encrypt_totp_secrets', 'two_factor_hardening', 'audit_chain_anchor', 'canonical_email', 'hot_indexes_timestamptz', 'tenant_default_unique', 'auth_continuation', 'initial_schema', 'schema_version']);
    const final = await getMigrationStatus(db);
    expect(final.hasVersionTable).toBe(false);
    const finalDrift = await detectMigrationDrift(db);
    expect(finalDrift.missingTables.length).toBe(FORTRESS_TABLES.length);
  });

  it('migration 0009 removes legacy plaintext TOTP enrolments irreversibly', async () => {
    const db = createBareSqliteAdapter();
    await migrateUp(db, 8);
    await db.rawQuery!('INSERT INTO fortress_user (email, name) VALUES (\'mfa@example.com\', \'MFA\')');
    const [user] = await db.rawQuery!<{ id: string }>('SELECT id FROM fortress_user WHERE email = \'mfa@example.com\'');
    await db.rawQuery!(
      'INSERT INTO fortress_two_factor_secret (user_id, secret, is_enabled) VALUES (?, ?, 1)',
      [user.id, 'PLAINTEXT-TOTP-SEED'],
    );
    await db.rawQuery!(
      'INSERT INTO fortress_backup_code (user_id, code_hash, is_used) VALUES (?, ?, 0)',
      [user.id, 'backup-hash'],
    );
    await db.rawQuery!(
      'INSERT INTO fortress_trusted_device (user_id, device_hash, expires_at, last_used_at) VALUES (?, ?, ?, ?)',
      [user.id, 'device-hash', 1_900_000_000, 1_800_000_000],
    );

    const result = await migrateUp(db);
    expect(result.applied.map(migration => migration.name)).toEqual(['encrypt_totp_secrets', 'bigint_append_only_ids']);
    expect(await db.count({ model: 'two_factor_secret' })).toBe(0);
    expect(await db.count({ model: 'backup_code' })).toBe(0);
    expect(await db.count({ model: 'trusted_device' })).toBe(0);

    await migrateDown(db, 8);
    expect(await db.count({ model: 'two_factor_secret' })).toBe(0);
  });

  it('canonicalizes legacy emails and quarantines duplicate accounts before v6 indexes', async () => {
    const db = createBareSqliteAdapter();
    await migrateUp(db, 5);

    await db.rawQuery!(
      `INSERT INTO fortress_user (email, name, is_active) VALUES (?, ?, 1), (?, ?, 1)`,
      ['É@Example.COM', 'Oldest duplicate', 'E\u0301@example.com', 'Later duplicate'],
    );
    const users = await db.rawQuery!<{ id: string; email: string }>(
      'SELECT id, email FROM fortress_user ORDER BY id',
    );
    await db.rawQuery!(
      `INSERT INTO fortress_user (email, name, is_active) VALUES (?, ?, 1)`,
      [`FORTRESS-DUPLICATE-${users[1].id}@INVALID`, 'Tombstone collision'],
    );
    await db.rawQuery!(
      `INSERT INTO fortress_login_identifier (user_id, type, value)
       VALUES (?, 'email', ?), (?, 'email', 'Alias@Example.COM'), (?, 'email', ?)`,
      [users[0].id, users[0].email, users[0].id, users[1].id, users[1].email],
    );
    await db.rawQuery!(
      `INSERT INTO fortress_login_identifier (user_id, type, value)
       SELECT id, 'email', 'É@EXAMPLE.COM' FROM fortress_user WHERE name = 'Tombstone collision'`,
    );
    await db.rawQuery!(
      `INSERT INTO fortress_login_identifier (user_id, type, value)
       VALUES (?, 'email', 'CROSS@EXAMPLE.COM')`,
      [users[0].id],
    );
    await db.rawQuery!(
      `INSERT INTO fortress_login_identifier (user_id, type, value)
       SELECT id, 'username', 'cross@example.com' FROM fortress_user WHERE name = 'Tombstone collision'`,
    );
    await db.rawQuery!(
      `INSERT INTO fortress_refresh_token (user_id, token_hash, token_family, is_revoked, expires_at)
       VALUES (?, ?, ?, 0, ?)`,
      [users[1].id, 'duplicate-session', 'duplicate-family', 1_900_000_000],
    );
    await db.rawQuery!(
      `INSERT INTO fortress_oauth_refresh_token
        (token, family_id, client_id, user_id, issued_at, expires_at)
       VALUES (?, ?, ?, ?, ?, ?)`,
      ['oauth-duplicate-session', 'oauth-duplicate-family', 'client', users[1].id, 1_700_000_000, 1_900_000_000],
    );

    const upgrade = await migrateUp(db);
    expect(upgrade.applied.map(migration => migration.name)).toEqual(['canonical_email', 'audit_chain_anchor', 'two_factor_hardening', 'encrypt_totp_secrets', 'bigint_append_only_ids']);

    const migrated = await db.rawQuery!<{ id: string; email: string; is_active: number }>(
      'SELECT id, email, is_active FROM fortress_user ORDER BY id',
    );
    expect(migrated[0]).toMatchObject({ email: 'é@example.com', is_active: 1 });
    expect(migrated[1]).toMatchObject({
      email: `fortress-duplicate-${users[1].id}-1@invalid`,
      is_active: 0,
    });
    const identifiers = await db.rawQuery!<{ value: string }>(
      `SELECT value FROM fortress_login_identifier ORDER BY id`,
    );
    expect(identifiers.map(row => row.value)).toEqual([
      'é@example.com',
      'alias@example.com',
      'cross@example.com',
    ]);
    const [session] = await db.rawQuery!<{ is_revoked: number }>(
      'SELECT is_revoked FROM fortress_refresh_token WHERE token_hash = ?',
      ['duplicate-session'],
    );
    expect(session.is_revoked).toBe(1);
    expect(await db.count({ model: 'oauth_refresh_token' })).toBe(0);

    await expect(db.create({
      model: 'user',
      data: { email: 'é@EXAMPLE.COM', name: 'Blocked duplicate', isActive: true },
    })).rejects.toMatchObject({ code: 'CONFLICT', statusCode: 409 });

    const other = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'other@example.com', name: 'Other', isActive: true },
    });
    await expect(db.create({
      model: 'login_identifier',
      data: { userId: other.id, type: 'email', value: 'é@EXAMPLE.COM' },
    })).rejects.toMatchObject({ code: 'CONFLICT', statusCode: 409 });
    const indexes = await db.rawQuery!<{ name: string }>(
      `SELECT name FROM sqlite_master WHERE type = 'index'
       AND name IN ('user_email_ci_unique', 'login_identifier_email_ci_unique') ORDER BY name`,
    );
    expect(indexes.map(row => row.name)).toEqual([
      'login_identifier_email_ci_unique',
      'user_email_ci_unique',
    ]);
  });

  it('rolls back email cleanup atomically when a v6 constraint cannot be installed', async () => {
    const db = createBareSqliteAdapter();
    await migrateUp(db, 5);
    await db.rawQuery!(
      `INSERT INTO fortress_user (email, name, is_active)
       VALUES ('Dup@Example.com', 'Winner', 1), ('dup@example.com', 'Loser', 1)`,
    );
    const users = await db.rawQuery!<{ id: string; email: string }>('SELECT id, email FROM fortress_user ORDER BY id');
    await db.rawQuery!(
      `INSERT INTO fortress_login_identifier (user_id, type, value)
       VALUES (?, 'email', ?), (?, 'email', ?)`,
      [users[0].id, users[0].email, users[1].id, users[1].email],
    );
    // Force the DDL step to fail after cleanup by occupying its index name.
    await db.rawQuery!('CREATE INDEX user_email_ci_unique ON fortress_user (name)');

    await expect(migrateUp(db)).rejects.toThrow();
    const after = await db.rawQuery!<{ email: string; is_active: number }>(
      'SELECT email, is_active FROM fortress_user ORDER BY id',
    );
    expect(after).toEqual([
      { email: 'Dup@Example.com', is_active: 1 },
      { email: 'dup@example.com', is_active: 1 },
    ]);
    expect((await getMigrationStatus(db)).currentVersion).toBe(5);
    const columns = await db.rawQuery!<{ name: string }>('PRAGMA index_info(user_email_ci_unique)');
    expect(columns.map(column => column.name)).toEqual(['name']);
  });

  it('upgrades v2 refresh families without resetting their age', async () => {
    const db = createBareSqliteAdapter();
    await migrateUp(db, 2);

    await db.rawQuery!(
      `INSERT INTO fortress_user (email, name, password_hash, is_active, created_at, updated_at)
       VALUES (?, ?, ?, 1, ?, ?)`,
      ['legacy@test.com', 'Legacy', 'h', 1_700_000_000, 1_700_000_000],
    );
    const [user] = await db.rawQuery!<{ id: string }>(
      'SELECT id FROM fortress_user WHERE email = ?',
      ['legacy@test.com'],
    );
    await db.rawQuery!(
      `INSERT INTO fortress_refresh_token
        (user_id, token_hash, token_family, is_revoked, expires_at, created_at)
       VALUES (?, ?, ?, 0, ?, ?), (?, ?, ?, 1, ?, ?)`,
      [
        user.id,
        'legacy-hash-1',
        'legacy-family',
        1_900_000_000,
        1_700_000_000,
        user.id,
        'legacy-hash-2',
        'legacy-family',
        1_900_000_000,
        1_750_000_000,
      ],
    );

    // Simulate a real pre-v4 database, including duplicate defaults that the
    // new migration must repair before adding its partial unique index.
    await db.rawQuery!('DROP INDEX IF EXISTS fortress_tenant_user_one_default_idx');
    await db.rawQuery!(
      `INSERT INTO fortress_tenant (name, tax_id) VALUES (?, ?), (?, ?)`,
      ['Tenant A', 'tenant-a', 'Tenant B', 'tenant-b'],
    );
    const tenants = await db.rawQuery!<{ id: string }>(
      `SELECT id FROM fortress_tenant WHERE tax_id IN (?, ?) ORDER BY tax_id`,
      ['tenant-a', 'tenant-b'],
    );
    await db.rawQuery!(
      `INSERT INTO fortress_tenant_user (tenant_id, user_id, is_default) VALUES (?, ?, 1), (?, ?, 1)`,
      [tenants[0].id, user.id, tenants[1].id, user.id],
    );

    const upgrade = await migrateUp(db);
    expect(upgrade.applied.map(migration => migration.name)).toEqual(['auth_continuation', 'tenant_default_unique', 'hot_indexes_timestamptz', 'canonical_email', 'audit_chain_anchor', 'two_factor_hardening', 'encrypt_totp_secrets', 'bigint_append_only_ids']);
    const [defaultCount] = await db.rawQuery!<{ count: number }>(
      `SELECT COUNT(*) AS count FROM fortress_tenant_user WHERE user_id = ? AND is_default = 1`,
      [user.id],
    );
    expect(Number(defaultCount.count)).toBe(1);
    const tenantIndexes = await db.rawQuery!<{ name: string }>(
      `SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`,
      ['fortress_tenant_user_one_default_idx'],
    );
    expect(tenantIndexes).toHaveLength(1);

    const tokens = await db.rawQuery!<{
      token_hash: string;
      family_created_at: number;
      successor_token_hash: string | null;
      rotated_at: number | null;
    }>(`SELECT token_hash, family_created_at, successor_token_hash, rotated_at
        FROM fortress_refresh_token WHERE token_family = ? ORDER BY created_at`, ['legacy-family']);
    expect(tokens).toEqual([
      {
        token_hash: 'legacy-hash-1',
        family_created_at: 1_700_000_000,
        successor_token_hash: null,
        rotated_at: null,
      },
      {
        token_hash: 'legacy-hash-2',
        family_created_at: 1_700_000_000,
        successor_token_hash: null,
        rotated_at: null,
      },
    ]);

    const beforeDefaultInsert = Math.floor(Date.now() / 1000) - 5;
    await db.rawQuery!(
      `INSERT INTO fortress_refresh_token
        (user_id, token_hash, token_family, is_revoked, expires_at)
       VALUES (?, ?, ?, 0, ?)`,
      [user.id, 'default-hash', 'default-family', 1_900_000_000],
    );
    const [defaulted] = await db.rawQuery!<{ family_created_at: number }>(
      'SELECT family_created_at FROM fortress_refresh_token WHERE token_hash = ?',
      ['default-hash'],
    );
    expect(defaulted.family_created_at).toBeGreaterThanOrEqual(beforeDefaultInsert);

    const drift = await detectMigrationDrift(db);
    expect(hasMigrationDrift(drift)).toBe(false);

    const rollback = await migrateDown(db, 2);
    expect(rollback.rolledBack.map(migration => migration.name)).toEqual(['bigint_append_only_ids', 'encrypt_totp_secrets', 'two_factor_hardening', 'audit_chain_anchor', 'canonical_email', 'hot_indexes_timestamptz', 'tenant_default_unique', 'auth_continuation']);
    expect(await db.count({ model: 'refresh_token' })).toBe(3);
    const columns = await db.rawQuery!<{ name: string }>('PRAGMA table_info(fortress_refresh_token)');
    expect(columns.map(column => column.name)).not.toEqual(expect.arrayContaining([
      'family_created_at',
      'successor_token_hash',
      'rotated_at',
    ]));
    const continuationTables = await db.rawQuery!<{ name: string }>(
      `SELECT name FROM sqlite_master WHERE type = 'table' AND name = 'fortress_auth_continuation'`,
    );
    expect(continuationTables).toEqual([]);
    const indexesAfterRollback = await db.rawQuery!<{ name: string }>(
      `SELECT name FROM sqlite_master WHERE type = 'index' AND name = ?`,
      ['fortress_tenant_user_one_default_idx'],
    );
    expect(indexesAfterRollback).toEqual([]);
  });
});
