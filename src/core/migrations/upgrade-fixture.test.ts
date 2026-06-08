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
    expect(up.toVersion).toBe(2);
    expect(up.applied.map(migration => migration.name)).toEqual(['schema_version', 'initial_schema']);

    const after = await getMigrationStatus(db, 'sqlite');
    expect(after.hasVersionTable).toBe(true);
    expect(after.currentVersion).toBe(2);
    expect(after.upToDate).toBe(true);

    // The full schema is now installed: no missing tables, no missing columns.
    const afterDrift = await detectMigrationDrift(db, 'sqlite');
    expect(hasMigrationDrift(afterDrift)).toBe(false);
    expect(afterDrift.missingTables).toEqual([]);
    expect(afterDrift.missingColumns).toEqual([]);

    // The provisioned schema is actually usable, not just present.
    const user = await db.create<{ id: number }>({
      model: 'user',
      data: { email: 'fixture@test.com', name: 'Fixture', passwordHash: 'h', isActive: true },
    });
    expect(user.id).toBeGreaterThan(0);

    // Re-running is idempotent.
    const reapply = await migrateUp(db, 'sqlite');
    expect(reapply.applied).toEqual([]);

    // Roll back below 0 drops every Fortress table again.
    const down = await migrateDown(db, 'sqlite');
    expect(down.toVersion).toBe(0);
    expect(down.rolledBack.map(migration => migration.name)).toEqual(['initial_schema', 'schema_version']);
    const final = await getMigrationStatus(db, 'sqlite');
    expect(final.hasVersionTable).toBe(false);
    const finalDrift = await detectMigrationDrift(db, 'sqlite');
    expect(finalDrift.missingTables.length).toBe(FORTRESS_TABLES.length);
  });
});
