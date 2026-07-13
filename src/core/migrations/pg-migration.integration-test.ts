/**
 * PostgreSQL migration upgrade fixture (testcontainers).
 *
 * Proves the bundled PG migrations install the entire Fortress schema
 * against a real, bare PostgreSQL server — catching dialect-specific
 * problems (SERIAL, partial unique indexes, JSONB defaults, FK drop
 * ordering) that the in-memory SQLite fixture can't. Mirrors the SQLite
 * `upgrade-fixture.test.ts` but on a real engine.
 */

import type { Sql } from 'postgres';
import type { StartedTestContainer } from 'testcontainers';
import type { DatabaseAdapter } from '../../adapters/database';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { GenericContainer, Wait } from 'testcontainers';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createDrizzleAdapter } from '../../drizzle/adapter';
import {
  detectMigrationDrift,
  getMigrationStatus,
  hasMigrationDrift,
  migrateDown,
  migrateUp,
} from './engine';
import { FORTRESS_TABLES } from './migrations';

let container: StartedTestContainer;
let pgClient: Sql;

function adapter(): DatabaseAdapter {
  return createDrizzleAdapter(drizzle(pgClient) as any, { dialect: 'pg' });
}

beforeAll(async () => {
  container = await new GenericContainer('postgres:16-alpine')
    .withEnvironment({
      POSTGRES_USER: 'test',
      POSTGRES_PASSWORD: 'test',
      POSTGRES_DB: 'fortress_migrate_test',
    })
    .withExposedPorts(5432)
    .withWaitStrategy(Wait.forListeningPorts())
    .start();

  const connectionString = `postgres://test:test@${container.getHost()}:${container.getMappedPort(5432)}/fortress_migrate_test`;
  pgClient = postgres(connectionString);
}, 60_000);

afterAll(async () => {
  if (pgClient)
    await pgClient.end();
  if (container)
    await container.stop();
});

describe('pg: migration upgrade fixture (bare postgres)', () => {
  it('provisions a bare PG database end-to-end from the bundled migrations', async () => {
    const db = adapter();

    const initial = await getMigrationStatus(db, 'pg');
    expect(initial.hasVersionTable).toBe(false);
    expect(initial.currentVersion).toBe(0);

    const initialDrift = await detectMigrationDrift(db, 'pg');
    expect(hasMigrationDrift(initialDrift)).toBe(true);
    expect(initialDrift.missingTables.length).toBe(FORTRESS_TABLES.length);

    const baseline = await migrateUp(db, 'pg', 2);
    expect(baseline.fromVersion).toBe(0);
    expect(baseline.toVersion).toBe(2);
    expect(baseline.applied.map(migration => migration.name)).toEqual(['schema_version', 'initial_schema']);

    await db.rawQuery!(
      `INSERT INTO fortress_user (email, name, password_hash, is_active, created_at, updated_at)
       VALUES ($1, $2, $3, true, $4, $4)`,
      ['legacy-pg@test.com', 'Legacy PG', 'h', '2025-01-01T00:00:00Z'],
    );
    const [legacyUser] = await db.rawQuery!<{ id: string }>(
      'SELECT id FROM fortress_user WHERE email = $1',
      ['legacy-pg@test.com'],
    );
    await db.rawQuery!(
      `INSERT INTO fortress_refresh_token
        (user_id, token_hash, token_family, is_revoked, expires_at, created_at)
       VALUES ($1, $2, $3, false, $4, $5), ($1, $6, $3, true, $4, $7)`,
      [
        legacyUser.id,
        'legacy-pg-hash-1',
        'legacy-pg-family',
        '2030-01-01T00:00:00Z',
        '2025-01-01T00:00:00Z',
        'legacy-pg-hash-2',
        '2025-02-01T00:00:00Z',
      ],
    );

    const up = await migrateUp(db, 'pg');
    expect(up.fromVersion).toBe(2);
    expect(up.toVersion).toBe(3);
    expect(up.applied.map(migration => migration.name)).toEqual(['auth_continuation']);

    const familyRows = await db.rawQuery!<{ tokenHash: string; familyCreatedAt: string }>(
      `SELECT token_hash AS "tokenHash", family_created_at AS "familyCreatedAt"
       FROM fortress_refresh_token WHERE token_family = $1 ORDER BY created_at`,
      ['legacy-pg-family'],
    );
    expect(familyRows.map(row => row.tokenHash)).toEqual([
      'legacy-pg-hash-1',
      'legacy-pg-hash-2',
    ]);
    expect(familyRows[0].familyCreatedAt).toBe(familyRows[1].familyCreatedAt);
    expect(familyRows[0].familyCreatedAt).toContain('2025-01-01');

    await db.rawQuery!(
      `INSERT INTO fortress_refresh_token
        (user_id, token_hash, token_family, is_revoked, expires_at)
       VALUES ($1, $2, $3, false, $4)`,
      [legacyUser.id, 'default-pg-hash', 'default-pg-family', '2030-01-01T00:00:00Z'],
    );
    const [defaulted] = await db.rawQuery!<{ recent: boolean }>(
      `SELECT family_created_at >= now() - interval '5 seconds' AS recent
       FROM fortress_refresh_token WHERE token_hash = $1`,
      ['default-pg-hash'],
    );
    expect(defaulted.recent).toBe(true);

    const after = await getMigrationStatus(db, 'pg');
    expect(after.currentVersion).toBe(3);
    expect(after.upToDate).toBe(true);

    // Real-engine schema check: no missing tables, no missing columns.
    const afterDrift = await detectMigrationDrift(db, 'pg');
    expect(hasMigrationDrift(afterDrift)).toBe(false);
    expect(afterDrift.missingTables).toEqual([]);
    expect(afterDrift.missingColumns).toEqual([]);

    // The provisioned schema is usable: insert a row through the adapter,
    // exercising SERIAL ids (stringified at the adapter boundary, see the
    // v0.2.x `stringifyIds` change in CHANGELOG) and timestamp defaults.
    const user = await db.create<{ id: string; createdAt: Date }>({
      model: 'user',
      data: { email: 'pg-migrate@test.com', name: 'PG Migrate', passwordHash: 'h', isActive: true },
    });
    expect(typeof user.id).toBe('string');
    expect(user.id.length).toBeGreaterThan(0);
    expect(user.createdAt).toBeInstanceOf(Date);

    // Re-running is idempotent.
    const reapply = await migrateUp(db, 'pg');
    expect(reapply.applied).toEqual([]);

    // A targeted rollback preserves refresh rows while removing only v3.
    const rollback = await migrateDown(db, 'pg', 2);
    expect(rollback.rolledBack.map(migration => migration.name)).toEqual(['auth_continuation']);
    expect(await db.count({ model: 'refresh_token' })).toBe(3);
    const v3Columns = await db.rawQuery!<{ columnName: string }>(
      `SELECT column_name AS "columnName" FROM information_schema.columns
       WHERE table_schema = current_schema() AND table_name = 'fortress_refresh_token'
         AND column_name IN ('family_created_at', 'successor_token_hash', 'rotated_at')`,
    );
    expect(v3Columns).toEqual([]);
    const continuationTables = await db.rawQuery!<{ tableName: string }>(
      `SELECT table_name AS "tableName" FROM information_schema.tables
       WHERE table_schema = current_schema() AND table_name = 'fortress_auth_continuation'`,
    );
    expect(continuationTables).toEqual([]);

    const restore = await migrateUp(db, 'pg');
    expect(restore.applied.map(migration => migration.name)).toEqual(['auth_continuation']);

    // Roll back drops every Fortress table (FK-safe via CASCADE ordering).
    const down = await migrateDown(db, 'pg');
    expect(down.toVersion).toBe(0);
    const finalDrift = await detectMigrationDrift(db, 'pg');
    expect(finalDrift.missingTables.length).toBe(FORTRESS_TABLES.length);
  }, 60_000);
});
