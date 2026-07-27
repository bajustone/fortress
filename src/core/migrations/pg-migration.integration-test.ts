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
import type { MigratableDatabaseAdapter } from '../../adapters/database';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { GenericContainer, Wait } from 'testcontainers';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { createPostgresDrizzleAdapter } from '../../drizzle/adapter';
import {
  computeMigrationChecksum,
  detectMigrationDrift,
  getMigrationStatus,
  hasMigrationDrift,
  migrateDown,
  migrateUp,
} from './engine';
import { FORTRESS_INDEXES, FORTRESS_TABLES, getFortressMigrations } from './migrations';

const SHA256_HEX_RE = /^[a-f0-9]{64}$/;
const INTEGRITY_FAILURE_RE = /integrity check failed/;

let container: StartedTestContainer;
let pgClient: Sql;
let connectionString: string;

function adapterFor(client: Sql): MigratableDatabaseAdapter<'pg'> {
  return createPostgresDrizzleAdapter(drizzle(client) as any);
}

function adapter(): MigratableDatabaseAdapter<'pg'> {
  return adapterFor(pgClient);
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

  connectionString = `postgres://test:test@${container.getHost()}:${container.getMappedPort(5432)}/fortress_migrate_test`;
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

    const initial = await getMigrationStatus(db);
    expect(initial.hasVersionTable).toBe(false);
    expect(initial.currentVersion).toBe(0);

    const initialDrift = await detectMigrationDrift(db);
    expect(hasMigrationDrift(initialDrift)).toBe(true);
    expect(initialDrift.missingTables.length).toBe(FORTRESS_TABLES.length);

    const baseline = await migrateUp(db, 2);
    expect(baseline.fromVersion).toBe(0);
    expect(baseline.toVersion).toBe(2);
    expect(baseline.applied.map(migration => migration.name)).toEqual(['schema_version', 'initial_schema']);

    await db.rawQuery!(
      `INSERT INTO fortress_user (email, name, password_hash, is_active, created_at, updated_at)
       VALUES (?, ?, ?, true, ?, ?)`,
      ['legacy-pg@test.com', 'Legacy PG', 'h', '2025-01-01T00:00:00Z', '2025-01-01T00:00:00Z'],
    );
    const [legacyUser] = await db.rawQuery!<{ id: string }>(
      'SELECT id FROM fortress_user WHERE email = ?',
      ['legacy-pg@test.com'],
    );
    await db.rawQuery!(
      `INSERT INTO fortress_refresh_token
        (user_id, token_hash, token_family, is_revoked, expires_at, created_at)
       VALUES (?, ?, ?, false, ?, ?), (?, ?, ?, true, ?, ?)`,
      [
        legacyUser.id,
        'legacy-pg-hash-1',
        'legacy-pg-family',
        '2030-01-01T00:00:00Z',
        '2025-01-01T00:00:00Z',
        legacyUser.id,
        'legacy-pg-hash-2',
        'legacy-pg-family',
        '2030-01-01T00:00:00Z',
        '2025-02-01T00:00:00Z',
      ],
    );

    // Simulate a real pre-v4 installation: v2 did not originally include the
    // partial index and could contain multiple defaults for one user.
    await db.rawQuery!('DROP INDEX IF EXISTS fortress_tenant_user_one_default_idx');
    await db.rawQuery!(
      `INSERT INTO fortress_tenant (name, tax_id) VALUES (?, ?), (?, ?)`,
      ['Tenant A', 'tenant-a', 'Tenant B', 'tenant-b'],
    );
    const tenantRows = await db.rawQuery!<{ id: string }>(
      `SELECT id FROM fortress_tenant WHERE tax_id IN (?, ?) ORDER BY tax_id`,
      ['tenant-a', 'tenant-b'],
    );
    await db.rawQuery!(
      `INSERT INTO fortress_tenant_user (tenant_id, user_id, is_default) VALUES (?, ?, true), (?, ?, true)`,
      [tenantRows[0].id, legacyUser.id, tenantRows[1].id, legacyUser.id],
    );

    // Legacy case-variants are deterministically quarantined before the
    // case-insensitive unique indexes are installed.
    await db.rawQuery!(
      `INSERT INTO fortress_user (email, name, is_active) VALUES (?, ?, true), (?, ?, true)`,
      ['Duplicate@Example.COM', 'Oldest duplicate', 'duplicate@example.com', 'Later duplicate'],
    );
    const duplicateUsers = await db.rawQuery!<{ id: string; email: string }>(
      `SELECT id, email FROM fortress_user WHERE lower(email) = ? ORDER BY id`,
      ['duplicate@example.com'],
    );
    await db.rawQuery!(
      `INSERT INTO fortress_login_identifier (user_id, type, value) VALUES (?, 'email', ?), (?, 'email', ?)`,
      [duplicateUsers[0].id, duplicateUsers[0].email, duplicateUsers[1].id, duplicateUsers[1].email],
    );
    await db.rawQuery!(
      `INSERT INTO fortress_refresh_token (user_id, token_hash, token_family, is_revoked, expires_at)
       VALUES (?, ?, ?, false, ?)`,
      [duplicateUsers[1].id, 'duplicate-session', 'duplicate-family', '2030-01-01T00:00:00Z'],
    );

    // Conversion must not depend on the session timezone: historical
    // timestamp-without-time-zone values are interpreted as UTC explicitly.
    await db.rawQuery!('SET TIME ZONE \'America/Los_Angeles\'');
    const up = await migrateUp(db);
    await db.rawQuery!('SET TIME ZONE \'UTC\'');
    expect(up.fromVersion).toBe(2);
    expect(up.toVersion).toBe(10);
    expect(up.applied.map(migration => migration.name)).toEqual(['auth_continuation', 'tenant_default_unique', 'hot_indexes_timestamptz', 'canonical_email', 'audit_chain_anchor', 'two_factor_hardening', 'encrypt_totp_secrets', 'bigint_append_only_ids']);
    const defaults = await db.rawQuery!<{ count: string }>(
      `SELECT COUNT(*) AS count FROM fortress_tenant_user WHERE user_id = ? AND is_default = true`,
      [legacyUser.id],
    );
    expect(Number(defaults[0].count)).toBe(1);
    const widened = await db.rawQuery!<{ tableName: string; dataType: string }>(
      `SELECT table_name AS "tableName", data_type AS "dataType"
       FROM information_schema.columns
       WHERE table_schema = current_schema()
         AND column_name = 'id'
         AND table_name IN ('fortress_refresh_token', 'fortress_audit_log', 'fortress_webhook_delivery')
       ORDER BY table_name`,
    );
    expect(widened).toHaveLength(3);
    expect(widened.every(column => column.dataType === 'bigint')).toBe(true);

    const canonicalized = await db.rawQuery!<{ id: string; email: string; isActive: boolean }>(
      `SELECT id, email, is_active AS "isActive" FROM fortress_user
       WHERE id IN (?, ?) ORDER BY id`,
      [duplicateUsers[0].id, duplicateUsers[1].id],
    );
    expect(canonicalized[0]).toMatchObject({
      id: duplicateUsers[0].id,
      email: 'duplicate@example.com',
      isActive: true,
    });
    expect(canonicalized[1].email).toBe(`fortress-duplicate-${duplicateUsers[1].id}@invalid`);
    expect(canonicalized[1].isActive).toBe(false);
    const [duplicateSession] = await db.rawQuery!<{ isRevoked: boolean }>(
      'SELECT is_revoked AS "isRevoked" FROM fortress_refresh_token WHERE token_hash = ?',
      ['duplicate-session'],
    );
    expect(duplicateSession.isRevoked).toBe(true);
    await expect(db.create({
      model: 'user',
      data: { email: 'DUPLICATE@EXAMPLE.COM', name: 'Blocked duplicate', isActive: true },
    })).rejects.toMatchObject({ code: 'CONFLICT', statusCode: 409 });
    const emailIndexes = await db.rawQuery!<{ indexname: string }>(
      `SELECT indexname FROM pg_indexes WHERE schemaname = current_schema()
       AND indexname IN ('user_email_ci_unique', 'login_identifier_email_ci_unique') ORDER BY indexname`,
    );
    expect(emailIndexes.map(row => row.indexname)).toEqual([
      'login_identifier_email_ci_unique',
      'user_email_ci_unique',
    ]);

    const tenantIndexes = await db.rawQuery!<{ indexname: string }>(
      `SELECT indexname FROM pg_indexes WHERE indexname = ?`,
      ['fortress_tenant_user_one_default_idx'],
    );
    expect(tenantIndexes).toHaveLength(1);

    const familyRows = await db.rawQuery!<{ tokenHash: string; familyCreatedAt: string }>(
      `SELECT token_hash AS "tokenHash", family_created_at AS "familyCreatedAt"
       FROM fortress_refresh_token WHERE token_family = ? ORDER BY created_at`,
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
       VALUES (?, ?, ?, false, ?)`,
      [legacyUser.id, 'default-pg-hash', 'default-pg-family', '2030-01-01T00:00:00Z'],
    );
    const [defaulted] = await db.rawQuery!<{ recent: boolean }>(
      `SELECT family_created_at >= now() - interval '5 seconds' AS recent
       FROM fortress_refresh_token WHERE token_hash = ?`,
      ['default-pg-hash'],
    );
    expect(defaulted.recent).toBe(true);

    const after = await getMigrationStatus(db);
    expect(after.currentVersion).toBe(10);
    expect(after.upToDate).toBe(true);

    // Real-engine schema check: no missing tables, no missing columns.
    const afterDrift = await detectMigrationDrift(db);
    expect(hasMigrationDrift(afterDrift)).toBe(false);
    expect(afterDrift.missingTables).toEqual([]);
    expect(afterDrift.missingColumns).toEqual([]);
    expect(afterDrift.missingIndexes).toEqual([]);

    const timestampTypes = await db.rawQuery!<{ dataType: string; count: string }>(
      `SELECT data_type AS "dataType", COUNT(*) AS count
       FROM information_schema.columns
       WHERE table_schema = current_schema()
         AND table_name LIKE 'fortress_%'
         AND table_name NOT IN ('fortress_migration_journal', 'fortress_audit_chain_state')
         AND data_type LIKE 'timestamp%'
       GROUP BY data_type`,
    );
    expect(timestampTypes).toEqual([{ dataType: 'timestamp with time zone', count: '62' }]);

    const allIndexRows = await db.rawQuery!<{ indexname: string; indexdef: string }>(
      `SELECT indexname, indexdef FROM pg_indexes
       WHERE schemaname = current_schema() AND tablename LIKE 'fortress_%'`,
    );
    const requiredNames = new Set(FORTRESS_INDEXES.map(index => index.name));
    const indexRows = allIndexRows.filter(row => requiredNames.has(row.indexname));
    expect(indexRows.map(row => row.indexname).sort()).toEqual(
      FORTRESS_INDEXES.map(index => index.name).sort(),
    );
    for (const expected of FORTRESS_INDEXES) {
      const definition = indexRows.find(row => row.indexname === expected.name)?.indexdef.replaceAll('"', '');
      expect(definition, expected.name).toContain(`(${expected.columns.join(', ')})`);
    }

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
    const reapply = await migrateUp(db);
    expect(reapply.applied).toEqual([]);

    // A targeted rollback preserves refresh rows while removing v5 through v3.
    const rollback = await migrateDown(db, 2);
    expect(rollback.rolledBack.map(migration => migration.name)).toEqual(['bigint_append_only_ids', 'encrypt_totp_secrets', 'two_factor_hardening', 'audit_chain_anchor', 'canonical_email', 'hot_indexes_timestamptz', 'tenant_default_unique', 'auth_continuation']);
    expect(await db.count({ model: 'refresh_token' })).toBe(4);
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

    const restore = await migrateUp(db);
    expect(restore.applied.map(migration => migration.name)).toEqual(['auth_continuation', 'tenant_default_unique', 'hot_indexes_timestamptz', 'canonical_email', 'audit_chain_anchor', 'two_factor_hardening', 'encrypt_totp_secrets', 'bigint_append_only_ids']);

    // Roll back drops every Fortress table (FK-safe via CASCADE ordering).
    const down = await migrateDown(db);
    expect(down.toVersion).toBe(0);
    const finalDrift = await detectMigrationDrift(db);
    expect(finalDrift.missingTables.length).toBe(FORTRESS_TABLES.length);
  }, 60_000);

  it('serializes concurrent migrators and rejects journal tampering', async () => {
    const firstClient = postgres(connectionString);
    const secondClient = postgres(connectionString);
    const first = adapterFor(firstClient);
    const second = adapterFor(secondClient);
    try {
      const upResults = await Promise.all([
        migrateUp(first),
        migrateUp(second),
      ]);
      expect(upResults.map(result => result.applied.length).sort((a, b) => a - b)).toEqual([0, 10]);
      expect(upResults.map(result => result.fromVersion).sort((a, b) => a - b)).toEqual([0, 10]);

      const journal = await first.rawQuery!<{ version: number; checksum: string }>(
        'SELECT version, checksum FROM fortress_migration_journal ORDER BY version',
      );
      expect(journal.map(row => Number(row.version))).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
      expect(journal.every(row => SHA256_HEX_RE.test(row.checksum))).toBe(true);

      const downResults = await Promise.all([
        migrateDown(first, 4),
        migrateDown(second, 4),
      ]);
      expect(downResults.map(result => result.rolledBack.length).sort((a, b) => a - b)).toEqual([0, 6]);
      expect((await getMigrationStatus(first)).currentVersion).toBe(4);

      await first.rawQuery!(
        'UPDATE fortress_migration_journal SET checksum = ? WHERE version = 3',
        ['f'.repeat(64)],
      );
      await expect(migrateUp(second)).rejects.toThrow(INTEGRITY_FAILURE_RE);
      expect((await getMigrationStatus(first)).currentVersion).toBe(4);

      const migration3 = getFortressMigrations('pg').find(migration => migration.version === 3)!;
      await first.rawQuery!(
        'UPDATE fortress_migration_journal SET checksum = ? WHERE version = 3',
        [await computeMigrationChecksum(migration3)],
      );
      await migrateDown(first, 0);
    }
    finally {
      await firstClient.end();
      await secondClient.end();
    }
  }, 60_000);
});
