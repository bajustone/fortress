import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressMigration, MigrationDialect } from './migrations';
import { Errors } from '../errors';
import { FORTRESS_TABLES, getFortressMigrations, getLatestMigrationVersion } from './migrations';

export interface MigrationStatus {
  dialect: MigrationDialect;
  currentVersion: number;
  latestVersion: number;
  pending: FortressMigration[];
  applied: FortressMigration[];
  upToDate: boolean;
  hasVersionTable: boolean;
}

export interface MigrationApplyResult {
  dialect: MigrationDialect;
  fromVersion: number;
  toVersion: number;
  applied: FortressMigration[];
}

export interface MigrationDownResult {
  dialect: MigrationDialect;
  fromVersion: number;
  toVersion: number;
  rolledBack: FortressMigration[];
}

export interface MigrationDrift {
  dialect: MigrationDialect;
  currentVersion: number;
  latestVersion: number;
  missingVersionTable: boolean;
  unknownFutureVersion: boolean;
  pendingVersions: number[];
  /**
   * Fortress-owned tables expected by the runtime but missing from the
   * live database. A non-empty list almost always means an upgrade was
   * skipped or the database was provisioned from an out-of-date schema
   * dump. Compared against {@link FORTRESS_TABLES}.
   */
  missingTables: string[];
}

function assertRawQuery(db: DatabaseAdapter): NonNullable<DatabaseAdapter['rawQuery']> {
  if (!db.rawQuery) {
    throw Errors.badRequest('Migration tooling requires a database adapter with rawQuery support');
  }
  return db.rawQuery.bind(db);
}

function splitSqlStatements(sql: string): string[] {
  const withoutLineComments = sql
    .split('\n')
    .filter(line => !line.trimStart().startsWith('--'))
    .join('\n');
  return withoutLineComments
    .split(';')
    .map(statement => statement.trim())
    .filter(statement => statement.length > 0);
}

async function executeSql(db: DatabaseAdapter, sql: string): Promise<void> {
  const rawQuery = assertRawQuery(db);
  for (const statement of splitSqlStatements(sql)) {
    await rawQuery(statement);
  }
}

async function tableExists(db: DatabaseAdapter, dialect: MigrationDialect): Promise<boolean> {
  const rawQuery = assertRawQuery(db);
  if (dialect === 'sqlite') {
    const rows = await rawQuery<{ name: string }>(
      'SELECT name FROM sqlite_master WHERE type = \'table\' AND name = \'fortress_schema_version\'',
    );
    return rows.length > 0;
  }

  const rows = await rawQuery<{ table_name: string }>(
    'SELECT table_name FROM information_schema.tables WHERE table_schema = \'public\' AND table_name = \'fortress_schema_version\'',
  );
  return rows.length > 0;
}

/**
 * Enumerate every Fortress-owned table present in the live database. Used
 * by drift detection to surface missing tables (e.g. an incomplete
 * migration run or a freshly provisioned DB that never had Fortress
 * tables created).
 */
async function listFortressTables(
  db: DatabaseAdapter,
  dialect: MigrationDialect,
): Promise<Set<string>> {
  const rawQuery = assertRawQuery(db);
  if (dialect === 'sqlite') {
    const rows = await rawQuery<{ name: string }>(
      'SELECT name FROM sqlite_master WHERE type = \'table\' AND name LIKE \'fortress_%\'',
    );
    return new Set(rows.map(row => row.name));
  }

  const rows = await rawQuery<{ table_name: string }>(
    'SELECT table_name FROM information_schema.tables WHERE table_schema = \'public\' AND table_name LIKE \'fortress_%\'',
  );
  return new Set(rows.map(row => row.table_name));
}

async function readCurrentVersion(db: DatabaseAdapter, dialect: MigrationDialect): Promise<{ version: number; hasVersionTable: boolean }> {
  const hasVersionTable = await tableExists(db, dialect);
  if (!hasVersionTable)
    return { version: 0, hasVersionTable };

  const rawQuery = assertRawQuery(db);
  const rows = await rawQuery<{ version: number | string }>('SELECT version FROM fortress_schema_version WHERE id = 1');
  return { version: Number(rows[0]?.version ?? 0), hasVersionTable };
}

async function recordVersion(db: DatabaseAdapter, dialect: MigrationDialect, version: number): Promise<void> {
  if (version <= 0)
    return;
  const rawQuery = assertRawQuery(db);
  if (dialect === 'sqlite') {
    await rawQuery(
      'INSERT INTO fortress_schema_version (id, version, applied_at) VALUES (1, ?, unixepoch()) ON CONFLICT(id) DO UPDATE SET version = excluded.version, applied_at = excluded.applied_at',
      [version],
    );
    return;
  }

  await rawQuery(
    'INSERT INTO fortress_schema_version (id, version, applied_at) VALUES (1, $1, now()) ON CONFLICT(id) DO UPDATE SET version = excluded.version, applied_at = excluded.applied_at',
    [version],
  );
}

export async function getMigrationStatus(
  db: DatabaseAdapter,
  dialect: MigrationDialect = db.dialect === 'pg' ? 'pg' : 'sqlite',
): Promise<MigrationStatus> {
  const migrations = getFortressMigrations(dialect);
  const latestVersion = getLatestMigrationVersion(dialect);
  const { version: currentVersion, hasVersionTable } = await readCurrentVersion(db, dialect);
  return {
    dialect,
    currentVersion,
    latestVersion,
    pending: migrations.filter(migration => migration.version > currentVersion),
    applied: migrations.filter(migration => migration.version <= currentVersion),
    upToDate: currentVersion >= latestVersion,
    hasVersionTable,
  };
}

export async function migrateUp(
  db: DatabaseAdapter,
  dialect: MigrationDialect = db.dialect === 'pg' ? 'pg' : 'sqlite',
  targetVersion = getLatestMigrationVersion(dialect),
): Promise<MigrationApplyResult> {
  const before = await getMigrationStatus(db, dialect);
  const toApply = getFortressMigrations(dialect)
    .filter(migration => migration.version > before.currentVersion && migration.version <= targetVersion);

  for (const migration of toApply) {
    await executeSql(db, migration.up);
    await recordVersion(db, dialect, migration.version);
  }

  return {
    dialect,
    fromVersion: before.currentVersion,
    toVersion: toApply.at(-1)?.version ?? before.currentVersion,
    applied: toApply,
  };
}

export async function migrateDown(
  db: DatabaseAdapter,
  dialect: MigrationDialect = db.dialect === 'pg' ? 'pg' : 'sqlite',
  targetVersion = 0,
): Promise<MigrationDownResult> {
  const before = await getMigrationStatus(db, dialect);
  const toRollback = getFortressMigrations(dialect)
    .filter(migration => migration.version <= before.currentVersion && migration.version > targetVersion)
    .sort((a, b) => b.version - a.version);

  for (const migration of toRollback) {
    await executeSql(db, migration.down);
  }
  await recordVersion(db, dialect, targetVersion);

  return {
    dialect,
    fromVersion: before.currentVersion,
    toVersion: targetVersion,
    rolledBack: toRollback,
  };
}

export async function detectMigrationDrift(
  db: DatabaseAdapter,
  dialect: MigrationDialect = db.dialect === 'pg' ? 'pg' : 'sqlite',
): Promise<MigrationDrift> {
  const status = await getMigrationStatus(db, dialect);
  const present = await listFortressTables(db, dialect);
  const missingTables = FORTRESS_TABLES.filter(name => !present.has(name));
  return {
    dialect,
    currentVersion: status.currentVersion,
    latestVersion: status.latestVersion,
    missingVersionTable: !status.hasVersionTable,
    unknownFutureVersion: status.currentVersion > status.latestVersion,
    pendingVersions: status.pending.map(migration => migration.version),
    missingTables,
  };
}

export function hasMigrationDrift(drift: MigrationDrift): boolean {
  return drift.missingVersionTable
    || drift.unknownFutureVersion
    || drift.pendingVersions.length > 0
    || drift.missingTables.length > 0;
}
