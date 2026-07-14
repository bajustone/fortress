import type { DatabaseAdapter } from '../../adapters/database';
import { spawn } from 'node:child_process';
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
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

function runMigrationChild(script: string, filename: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const child = spawn(process.env.BUN_EXE ?? 'bun', [script, filename], {
      cwd: process.cwd(),
      stdio: ['ignore', 'pipe', 'pipe'],
    });
    let stderr = '';
    child.stderr.on('data', chunk => stderr += String(chunk));
    child.on('error', reject);
    child.on('exit', code => code === 0 ? resolve() : reject(new Error(`migration child exited ${code}: ${stderr}`)));
  });
}

function createBareSqliteAdapter(): DatabaseAdapter {
  // eslint-disable-next-line ts/no-require-imports
  const BetterSqlite3 = require('better-sqlite3');
  // eslint-disable-next-line ts/no-require-imports
  const { drizzle } = require('drizzle-orm/better-sqlite3');
  return createDrizzleAdapter(drizzle(new BetterSqlite3(':memory:')));
}

function createFileSqliteAdapter(filename: string): { db: DatabaseAdapter; close: () => void } {
  // eslint-disable-next-line ts/no-require-imports
  const BetterSqlite3 = require('better-sqlite3');
  // eslint-disable-next-line ts/no-require-imports
  const { drizzle } = require('drizzle-orm/better-sqlite3');
  const sqlite = new BetterSqlite3(filename);
  sqlite.pragma('busy_timeout = 5000');
  return {
    db: createDrizzleAdapter(drizzle(sqlite)),
    close: () => sqlite.close(),
  };
}

describe('migration engine', () => {
  it('reports pending migrations, applies up, and rolls down', async () => {
    const db = createBareSqliteAdapter();

    const before = await getMigrationStatus(db, dialect);
    expect(before.currentVersion).toBe(0);
    expect(before.latestVersion).toBe(10);
    expect(before.pending.map(migration => migration.version)).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);

    const up = await migrateUp(db, dialect);
    expect(up).toMatchObject({ fromVersion: 0, toVersion: 10 });
    expect(up.applied.map(migration => migration.name)).toEqual(['schema_version', 'initial_schema', 'auth_continuation', 'tenant_default_unique', 'hot_indexes_timestamptz', 'canonical_email', 'audit_chain_anchor', 'two_factor_hardening', 'encrypt_totp_secrets', 'bigint_append_only_ids']);

    const after = await getMigrationStatus(db, dialect);
    expect(after.currentVersion).toBe(10);
    expect(after.upToDate).toBe(true);
    expect(hasMigrationDrift(await detectMigrationDrift(db, dialect))).toBe(false);

    const down = await migrateDown(db, dialect);
    expect(down).toMatchObject({ fromVersion: 10, toVersion: 0 });
    expect(down.rolledBack.map(migration => migration.name)).toEqual(['bigint_append_only_ids', 'encrypt_totp_secrets', 'two_factor_hardening', 'audit_chain_anchor', 'canonical_email', 'hot_indexes_timestamptz', 'tenant_default_unique', 'auth_continuation', 'initial_schema', 'schema_version']);

    const final = await getMigrationStatus(db, dialect);
    expect(final.hasVersionTable).toBe(false);
    expect(final.currentVersion).toBe(0);
    const metadata = await db.rawQuery!<{ name: string }>(
      `SELECT name FROM sqlite_master WHERE type = 'table'
       AND name IN ('fortress_migration_journal', 'fortress_migration_state', 'fortress_migration_lock')`,
    );
    expect(metadata).toEqual([]);
  });

  it('serializes concurrent SQLite migrators and re-reads version after the lock', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortress-migrate-'));
    const filename = join(dir, 'shared.sqlite');
    const first = createFileSqliteAdapter(filename);
    const second = createFileSqliteAdapter(filename);
    try {
      const results = await Promise.all([
        migrateUp(first.db, dialect),
        migrateUp(second.db, dialect),
      ]);
      expect(results.map(result => result.applied.length).sort((a, b) => a - b)).toEqual([0, 10]);
      expect(results.map(result => result.fromVersion).sort((a, b) => a - b)).toEqual([0, 10]);
      expect((await getMigrationStatus(second.db, dialect)).currentVersion).toBe(10);
      const journal = await second.db.rawQuery!<{ version: number }>(
        'SELECT version FROM fortress_migration_journal ORDER BY version',
      );
      expect(journal.map(row => Number(row.version))).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
    }
    finally {
      first.close();
      second.close();
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it('serializes migrations across independent SQLite processes', async () => {
    const dir = mkdtempSync(join(tmpdir(), 'fortress-migrate-process-'));
    const filename = join(dir, 'shared.sqlite');
    const script = join(dir, 'migrate-child.ts');
    const adapterUrl = new URL('../../drizzle/adapter.ts', import.meta.url).href;
    const engineUrl = new URL('./engine.ts', import.meta.url).href;
    writeFileSync(script, `
      import { Database } from 'bun:sqlite';
      import { drizzle } from 'drizzle-orm/bun-sqlite';
      import { createDrizzleAdapter } from ${JSON.stringify(adapterUrl)};
      import { migrateUp } from ${JSON.stringify(engineUrl)};
      const sqlite = new Database(process.argv[2]);
      sqlite.exec('PRAGMA busy_timeout = 10000');
      await migrateUp(createDrizzleAdapter(drizzle(sqlite)), 'sqlite');
      sqlite.close();
    `);

    try {
      await Promise.all([
        runMigrationChild(script, filename),
        runMigrationChild(script, filename),
      ]);
      const database = createFileSqliteAdapter(filename);
      try {
        expect((await getMigrationStatus(database.db, dialect)).currentVersion).toBe(10);
        const journal = await database.db.rawQuery!<{ version: number }>(
          'SELECT version FROM fortress_migration_journal ORDER BY version',
        );
        expect(journal.map(row => Number(row.version))).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
      }
      finally {
        database.close();
      }
    }
    finally {
      rmSync(dir, { recursive: true, force: true });
    }
  }, 30_000);

  it('never advances migrateDown when the requested target is above current', async () => {
    const db = createBareSqliteAdapter();
    await migrateUp(db, dialect, 2);
    await db.rawQuery!('UPDATE fortress_schema_version SET applied_at = 123 WHERE id = 1');

    const result = await migrateDown(db, dialect, 99);
    expect(result).toMatchObject({ fromVersion: 2, toVersion: 2, rolledBack: [] });
    expect((await getMigrationStatus(db, dialect)).currentVersion).toBe(2);
    const [checkpoint] = await db.rawQuery!<{ applied_at: number }>(
      'SELECT applied_at FROM fortress_schema_version WHERE id = 1',
    );
    expect(checkpoint.applied_at).toBe(123);
  });

  it('rejects invalid migration targets without mutation', async () => {
    const db = createBareSqliteAdapter();
    await migrateUp(db, dialect, 2);
    for (const target of [-1, 1.5, Number.NaN])
      await expect(migrateDown(db, dialect, target)).rejects.toThrow(/non-negative safe integer/);
    expect((await getMigrationStatus(db, dialect)).currentVersion).toBe(2);
  });

  it('records deterministic checksums and removes journal rows on rollback', async () => {
    const db = createBareSqliteAdapter();
    await migrateUp(db, dialect);
    const journal = await db.rawQuery!<{ version: number; name: string; checksum: string }>(
      'SELECT version, name, checksum FROM fortress_migration_journal ORDER BY version',
    );
    expect(journal).toHaveLength(10);
    expect(journal.map(row => row.name)).toEqual([
      'schema_version',
      'initial_schema',
      'auth_continuation',
      'tenant_default_unique',
      'hot_indexes_timestamptz',
      'canonical_email',
      'audit_chain_anchor',
      'two_factor_hardening',
      'encrypt_totp_secrets',
      'bigint_append_only_ids',
    ]);
    expect(journal.every(row => /^[a-f0-9]{64}$/.test(row.checksum))).toBe(true);

    await migrateDown(db, dialect, 4);
    const remaining = await db.rawQuery!<{ version: number }>(
      'SELECT version FROM fortress_migration_journal ORDER BY version',
    );
    expect(remaining.map(row => Number(row.version))).toEqual([1, 2, 3, 4]);
  });

  it('fails closed on a corrupted or incomplete migration journal', async () => {
    const db = createBareSqliteAdapter();
    await migrateUp(db, dialect);
    await db.rawQuery!(
      'UPDATE fortress_migration_journal SET checksum = ? WHERE version = 3',
      ['0'.repeat(64)],
    );
    await expect(migrateUp(db, dialect)).rejects.toThrow(/integrity check failed/);
    expect((await getMigrationStatus(db, dialect)).currentVersion).toBe(10);

    await db.rawQuery!('UPDATE fortress_migration_journal SET checksum = (SELECT checksum FROM fortress_migration_journal WHERE version = 2) WHERE version = 3');
    // The copied checksum is still invalid for v3; replace via a fresh legacy
    // database to exercise the separate missing-row path deterministically.
    const legacy = createTestAdapter();
    await migrateUp(legacy, dialect); // backfills the pre-journal fixture
    await legacy.rawQuery!('DELETE FROM fortress_migration_journal WHERE version = 4');
    await expect(migrateUp(legacy, dialect)).rejects.toThrow(/missing version 4/);

    const completeLoss = createTestAdapter();
    await migrateUp(completeLoss, dialect); // legacy backfill sets initialized
    await completeLoss.rawQuery!('DELETE FROM fortress_migration_journal');
    await expect(migrateUp(completeLoss, dialect)).rejects.toThrow(/missing version 1/);
  });

  it('backfills journal rows for a legacy checkpoint without reapplying migrations', async () => {
    const db = createTestAdapter();
    const result = await migrateUp(db, dialect);
    expect(result.applied).toEqual([]);
    const journal = await db.rawQuery!<{ version: number }>(
      'SELECT version FROM fortress_migration_journal ORDER BY version',
    );
    expect(journal.map(row => Number(row.version))).toEqual([1, 2, 3, 4, 5, 6, 7, 8, 9, 10]);
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
