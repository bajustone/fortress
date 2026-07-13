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
import { FORTRESS_TABLES } from './migrations';

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
    expect(before.latestVersion).toBe(3);
    expect(before.pending.map(migration => migration.version)).toEqual([1, 2, 3]);

    const up = await migrateUp(db, dialect);
    expect(up).toMatchObject({ fromVersion: 0, toVersion: 3 });
    expect(up.applied.map(migration => migration.name)).toEqual(['schema_version', 'initial_schema', 'auth_continuation']);

    const after = await getMigrationStatus(db, dialect);
    expect(after.currentVersion).toBe(3);
    expect(after.upToDate).toBe(true);
    expect(hasMigrationDrift(await detectMigrationDrift(db, dialect))).toBe(false);

    const down = await migrateDown(db, dialect);
    expect(down).toMatchObject({ fromVersion: 3, toVersion: 0 });
    expect(down.rolledBack.map(migration => migration.name)).toEqual(['auth_continuation', 'initial_schema', 'schema_version']);

    const final = await getMigrationStatus(db, dialect);
    expect(final.hasVersionTable).toBe(false);
    expect(final.currentVersion).toBe(0);
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
    expect(FORTRESS_TABLES.length).toBeGreaterThan(30);
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
