import type { DatabaseAdapter } from '../../adapters/database';
import { describe, expect, it } from 'vitest';
import { createDrizzleAdapter } from '../../drizzle/adapter';
import { createTestAdapter } from '../../testing';
import {
  detectMigrationDrift,
  getMigrationStatus,
  hasMigrationDrift,
  migrateDown,
  migrateUp,
} from './engine';
import { FORTRESS_INDEXES, FORTRESS_TABLES, getFortressMigrations } from './migrations';

const dialect = 'sqlite';

function createBareSqliteAdapter(): DatabaseAdapter {
  // eslint-disable-next-line ts/no-require-imports
  const BetterSqlite3 = require('better-sqlite3');
  // eslint-disable-next-line ts/no-require-imports
  const { drizzle } = require('drizzle-orm/better-sqlite3');
  return createDrizzleAdapter(drizzle(new BetterSqlite3(':memory:')));
}

describe('migration engine', () => {
  it('reports pending migrations, applies up, and rolls down', async () => {
    const db = createBareSqliteAdapter();

    const before = await getMigrationStatus(db, dialect);
    expect(before.currentVersion).toBe(0);
    expect(before.latestVersion).toBe(6);
    expect(before.pending.map(migration => migration.version)).toEqual([1, 2, 3, 4, 5, 6]);

    const up = await migrateUp(db, dialect);
    expect(up).toMatchObject({ fromVersion: 0, toVersion: 6 });
    expect(up.applied.map(migration => migration.name)).toEqual(['schema_version', 'initial_schema', 'auth_continuation', 'tenant_default_unique', 'hot_indexes_timestamptz', 'canonical_email']);

    const after = await getMigrationStatus(db, dialect);
    expect(after.currentVersion).toBe(6);
    expect(after.upToDate).toBe(true);
    expect(hasMigrationDrift(await detectMigrationDrift(db, dialect))).toBe(false);

    const down = await migrateDown(db, dialect);
    expect(down).toMatchObject({ fromVersion: 6, toVersion: 0 });
    expect(down.rolledBack.map(migration => migration.name)).toEqual(['canonical_email', 'hot_indexes_timestamptz', 'tenant_default_unique', 'auth_continuation', 'initial_schema', 'schema_version']);

    const final = await getMigrationStatus(db, dialect);
    expect(final.hasVersionTable).toBe(false);
    expect(final.currentVersion).toBe(0);
  });

  it('fails closed when a data migration is applied as SQL without its runtime step', async () => {
    const db = createBareSqliteAdapter();
    await migrateUp(db, dialect, 5);
    const migration = getFortressMigrations(dialect).find(item => item.version === 6)!;
    const sentinelStatement = migration.up
      .split(';')
      .map(statement => statement.split('\n').filter(line => !line.trimStart().startsWith('--')).join('\n').trim())
      .find(Boolean)!;

    await expect(db.rawQuery!(sentinelStatement)).rejects.toThrow();
    expect((await getMigrationStatus(db, dialect)).currentVersion).toBe(5);
  });

  it('reports missing Fortress tables as drift', async () => {
    const db = createTestAdapter();
    // Drop a Fortress-owned table to simulate a partial / stale migration.
    await db.rawQuery!('DROP TABLE fortress_audit_log');

    const drift = await detectMigrationDrift(db, dialect);
    expect(drift.missingTables).toEqual(['fortress_audit_log']);
    expect(hasMigrationDrift(drift)).toBe(true);
  });

  it('every expected Fortress table is created by the test adapter', async () => {
    const db = createTestAdapter();
    const drift = await detectMigrationDrift(db, dialect);
    expect(drift.missingTables).toEqual([]);
    expect(drift.missingColumns).toEqual([]);
    expect(drift.missingIndexes).toEqual([]);
    expect(FORTRESS_TABLES.length).toBeGreaterThan(30);
  });

  it('creates every required hot index with the expected column order', async () => {
    const db = createTestAdapter();
    for (const expected of FORTRESS_INDEXES) {
      const rows = await db.rawQuery!<{ name: string }>(`PRAGMA index_info(${expected.name})`);
      expect(rows.map(row => row.name), expected.name).toEqual(expected.columns);
    }
  });

  it('reports a missing required hot index as drift', async () => {
    const db = createTestAdapter();
    await db.rawQuery!('DROP INDEX refresh_token_family_idx');

    const drift = await detectMigrationDrift(db, dialect);
    expect(drift.missingIndexes).toEqual(['refresh_token_family_idx']);
    expect(hasMigrationDrift(drift)).toBe(true);
  });

  it('reports a present-but-stale table missing a column as drift', async () => {
    const db = createTestAdapter();
    // Recreate fortress_oauth_pending_flow without the H6 `user_id` column to
    // simulate a database provisioned before that migration landed.
    await db.rawQuery!('DROP TABLE fortress_oauth_pending_flow');
    await db.rawQuery!(`CREATE TABLE fortress_oauth_pending_flow (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      flow_id TEXT NOT NULL UNIQUE,
      client_id TEXT NOT NULL,
      redirect_uri TEXT NOT NULL,
      scope TEXT,
      state TEXT NOT NULL,
      code_challenge TEXT,
      code_challenge_method TEXT,
      nonce TEXT,
      expires_at INTEGER NOT NULL,
      created_at INTEGER NOT NULL DEFAULT (unixepoch())
    )`);

    const drift = await detectMigrationDrift(db, dialect);
    expect(drift.missingTables).toEqual([]);
    const flowDrift = drift.missingColumns.find(entry => entry.table === 'fortress_oauth_pending_flow');
    expect(flowDrift?.columns).toEqual(expect.arrayContaining(['user_id', 'used_at']));
    expect(hasMigrationDrift(drift)).toBe(true);
  });
});
