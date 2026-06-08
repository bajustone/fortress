import { describe, expect, it } from 'vitest';
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

describe('migration engine', () => {
  it('reports pending migrations, applies up, and rolls down', async () => {
    const db = createTestAdapter();

    const before = await getMigrationStatus(db, dialect);
    expect(before.currentVersion).toBe(0);
    expect(before.latestVersion).toBe(1);
    expect(before.pending.map(migration => migration.version)).toEqual([1]);

    const up = await migrateUp(db, dialect);
    expect(up).toMatchObject({ fromVersion: 0, toVersion: 1 });
    expect(up.applied.map(migration => migration.name)).toEqual(['schema_version']);

    const after = await getMigrationStatus(db, dialect);
    expect(after.currentVersion).toBe(1);
    expect(after.upToDate).toBe(true);
    expect(hasMigrationDrift(await detectMigrationDrift(db, dialect))).toBe(false);

    const down = await migrateDown(db, dialect);
    expect(down).toMatchObject({ fromVersion: 1, toVersion: 0 });
    expect(down.rolledBack.map(migration => migration.name)).toEqual(['schema_version']);

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
    expect(FORTRESS_TABLES.length).toBeGreaterThan(30);
  });
});
