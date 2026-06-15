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

    const up = await migrateUp(db, 'pg');
    expect(up.fromVersion).toBe(0);
    expect(up.toVersion).toBe(2);
    expect(up.applied.map(migration => migration.name)).toEqual(['schema_version', 'initial_schema']);

    const after = await getMigrationStatus(db, 'pg');
    expect(after.currentVersion).toBe(2);
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

    // Roll back drops every Fortress table (FK-safe via CASCADE ordering).
    const down = await migrateDown(db, 'pg');
    expect(down.toVersion).toBe(0);
    const finalDrift = await detectMigrationDrift(db, 'pg');
    expect(finalDrift.missingTables.length).toBe(FORTRESS_TABLES.length);
  }, 60_000);
});
