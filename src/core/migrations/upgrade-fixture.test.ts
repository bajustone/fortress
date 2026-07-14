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

import type { DatabaseAdapter } from '../../adapters/database';
import { describe, expect, it } from 'vitest';
import { createDrizzleAdapter } from '../../drizzle/adapter';
import {
  detectMigrationDrift,
  getMigrationStatus,
  hasMigrationDrift,
  migrateDown,
  migrateUp,
} from './engine';
import { FORTRESS_TABLES } from './migrations';

const isBun = typeof (globalThis as Record<string, unknown>).Bun !== 'undefined';

function createBareSqliteAdapter(): DatabaseAdapter {
  if (isBun) {
    // eslint-disable-next-line ts/no-require-imports
    const { Database } = require('bun:sqlite');
    // eslint-disable-next-line ts/no-require-imports
    const { drizzle } = require('drizzle-orm/bun-sqlite');
    const sqlite = new Database(':memory:');
    sqlite.exec('PRAGMA foreign_keys = ON;');
    return createDrizzleAdapter(drizzle(sqlite));
  }
  // eslint-disable-next-line ts/no-require-imports
  const BetterSqlite3 = require('better-sqlite3');
  // eslint-disable-next-line ts/no-require-imports
  const { drizzle } = require('drizzle-orm/better-sqlite3');
  const sqlite = new BetterSqlite3(':memory:');
  sqlite.pragma('foreign_keys = ON');
  return createDrizzleAdapter(drizzle(sqlite));
}

describe('migration upgrade fixture (bare sqlite)', () => {
  it('provisions a bare DB end-to-end from the bundled migrations', async () => {
    const db = createBareSqliteAdapter();

    const initial = await getMigrationStatus(db, 'sqlite');
    expect(initial.hasVersionTable).toBe(false);
    expect(initial.currentVersion).toBe(0);

    const initialDrift = await detectMigrationDrift(db, 'sqlite');
    expect(hasMigrationDrift(initialDrift)).toBe(true);
    expect(initialDrift.missingVersionTable).toBe(true);
    // A bare DB is missing every Fortress table.
    expect(initialDrift.missingTables.length).toBe(FORTRESS_TABLES.length);

    const up = await migrateUp(db, 'sqlite');
    expect(up.fromVersion).toBe(0);
    expect(up.toVersion).toBe(5);
    expect(up.applied.map(migration => migration.name)).toEqual(['schema_version', 'initial_schema', 'auth_continuation', 'tenant_default_unique', 'hot_indexes_timestamptz']);

    const after = await getMigrationStatus(db, 'sqlite');
    expect(after.hasVersionTable).toBe(true);
    expect(after.currentVersion).toBe(5);
    expect(after.upToDate).toBe(true);

    // The full schema is now installed: no missing tables, no missing columns.
    const afterDrift = await detectMigrationDrift(db, 'sqlite');
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
    const reapply = await migrateUp(db, 'sqlite');
    expect(reapply.applied).toEqual([]);

    // Roll back below 0 drops every Fortress table again.
    const down = await migrateDown(db, 'sqlite');
    expect(down.toVersion).toBe(0);
    expect(down.rolledBack.map(migration => migration.name)).toEqual(['hot_indexes_timestamptz', 'tenant_default_unique', 'auth_continuation', 'initial_schema', 'schema_version']);
    const final = await getMigrationStatus(db, 'sqlite');
    expect(final.hasVersionTable).toBe(false);
    const finalDrift = await detectMigrationDrift(db, 'sqlite');
    expect(finalDrift.missingTables.length).toBe(FORTRESS_TABLES.length);
  });

  it('upgrades v2 refresh families without resetting their age', async () => {
    const db = createBareSqliteAdapter();
    await migrateUp(db, 'sqlite', 2);

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

    const upgrade = await migrateUp(db, 'sqlite');
    expect(upgrade.applied.map(migration => migration.name)).toEqual(['auth_continuation', 'tenant_default_unique', 'hot_indexes_timestamptz']);
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

    const drift = await detectMigrationDrift(db, 'sqlite');
    expect(hasMigrationDrift(drift)).toBe(false);

    const rollback = await migrateDown(db, 'sqlite', 2);
    expect(rollback.rolledBack.map(migration => migration.name)).toEqual(['hot_indexes_timestamptz', 'tenant_default_unique', 'auth_continuation']);
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
