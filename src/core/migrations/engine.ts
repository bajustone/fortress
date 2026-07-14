import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressMigration, MigrationDialect } from './migrations';
import { Errors } from '../errors';
import { FORTRESS_INDEXES, FORTRESS_TABLES, getExpectedColumns, getFortressMigrations, getLatestMigrationVersion } from './migrations';

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
  /**
   * Per-table columns that the bundled migration DDL defines but the live
   * database is missing. Surfaces a partially-applied or hand-patched
   * schema where the table exists but is missing a column added by a later
   * migration. Expected columns are parsed from the migration SQL itself
   * (see `getExpectedColumns`), so this works for any adapter. Only tables
   * that are present in the live DB are inspected — fully missing tables are
   * reported via {@link missingTables} instead.
   */
  missingColumns: { table: string; columns: string[] }[];
  /** Required hot-path indexes absent from the live database. */
  missingIndexes: string[];
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

/**
 * List the columns of a single Fortress table from the live database.
 * Returns an empty set if the table does not exist. Uses catalog
 * introspection (`PRAGMA table_info` / `information_schema.columns`) through
 * `rawQuery`, so it stays adapter-agnostic. The table name is sourced from
 * Fortress's own `FORTRESS_TABLES`, never user input.
 */
async function listColumns(
  db: DatabaseAdapter,
  dialect: MigrationDialect,
  table: string,
): Promise<Set<string>> {
  const rawQuery = assertRawQuery(db);
  if (dialect === 'sqlite') {
    const rows = await rawQuery<{ name: string }>(`PRAGMA table_info(${table})`);
    return new Set(rows.map(row => row.name.toLowerCase()));
  }

  const rows = await rawQuery<{ column_name: string }>(
    'SELECT column_name FROM information_schema.columns WHERE table_schema = \'public\' AND table_name = ?',
    [table],
  );
  return new Set(rows.map(row => row.column_name.toLowerCase()));
}

async function listFortressIndexes(
  db: DatabaseAdapter,
  dialect: MigrationDialect,
): Promise<Set<string>> {
  const rawQuery = assertRawQuery(db);
  if (dialect === 'sqlite') {
    const rows = await rawQuery<{ name: string }>(
      'SELECT name FROM sqlite_master WHERE type = \'index\' AND name NOT LIKE \'sqlite_autoindex_%\'',
    );
    return new Set(rows.map(row => row.name));
  }

  const rows = await rawQuery<{ indexname: string }>(
    'SELECT indexname FROM pg_indexes WHERE schemaname = \'public\' AND tablename LIKE \'fortress_%\'',
  );
  return new Set(rows.map(row => row.indexname));
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
    'INSERT INTO fortress_schema_version (id, version, applied_at) VALUES (1, ?, now()) ON CONFLICT(id) DO UPDATE SET version = excluded.version, applied_at = excluded.applied_at',
    [version],
  );
}

interface MigrationJournalRow {
  version: number | string;
  name: string;
  dialect: string;
  checksum: string;
}

/** SHA-256 of every immutable migration input, including runtime data-step identity. */
export async function computeMigrationChecksum(migration: FortressMigration): Promise<string> {
  const payload = JSON.stringify([
    migration.dialect,
    migration.version,
    migration.name,
    migration.up,
    migration.down,
    migration.freshUp ?? null,
    migration.dataStep ?? null,
    migration.beforeUp?.toString() ?? null,
  ]);
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(payload));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

async function ensureMigrationMetadata(db: DatabaseAdapter, dialect: MigrationDialect): Promise<void> {
  const rawQuery = assertRawQuery(db);
  if (dialect === 'sqlite') {
    // The singleton write forces a database-level writer lock even for
    // adapters whose transaction begins deferred. Separate processes then
    // serialize before the checkpoint is re-read.
    await rawQuery(`CREATE TABLE IF NOT EXISTS fortress_migration_lock (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      touched_at INTEGER NOT NULL
    )`);
    await rawQuery(
      `INSERT INTO fortress_migration_lock (id, touched_at) VALUES (1, unixepoch())
       ON CONFLICT(id) DO UPDATE SET touched_at = excluded.touched_at`,
    );
    await rawQuery(`CREATE TABLE IF NOT EXISTS fortress_migration_journal (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      dialect TEXT NOT NULL,
      checksum TEXT NOT NULL,
      applied_at INTEGER NOT NULL DEFAULT (unixepoch())
    )`);
    await rawQuery(`CREATE TABLE IF NOT EXISTS fortress_migration_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      journal_initialized INTEGER NOT NULL DEFAULT 0
    )`);
    await rawQuery(
      `INSERT INTO fortress_migration_state (id, journal_initialized) VALUES (1, 0)
       ON CONFLICT(id) DO NOTHING`,
    );
    return;
  }

  // Transaction-scoped: releases automatically on commit and rollback and
  // stays bound to the transaction adapter's one pooled connection.
  await rawQuery('SELECT pg_advisory_xact_lock(117993, 0)');
  const journalTable = await rawQuery<{ name: string | null }>(
    `SELECT to_regclass('public.fortress_migration_journal') AS name`,
  );
  if (!journalTable[0]?.name) {
    await rawQuery(`CREATE TABLE fortress_migration_journal (
      version INTEGER PRIMARY KEY,
      name TEXT NOT NULL,
      dialect TEXT NOT NULL,
      checksum VARCHAR(64) NOT NULL,
      applied_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
  }
  const stateTable = await rawQuery<{ name: string | null }>(
    `SELECT to_regclass('public.fortress_migration_state') AS name`,
  );
  if (!stateTable[0]?.name) {
    await rawQuery(`CREATE TABLE fortress_migration_state (
      id INTEGER PRIMARY KEY CHECK (id = 1),
      journal_initialized BOOLEAN NOT NULL DEFAULT false
    )`);
  }
  await rawQuery(
    `INSERT INTO fortress_migration_state (id, journal_initialized) VALUES (1, false)
     ON CONFLICT(id) DO NOTHING`,
  );
}

async function readJournal(db: DatabaseAdapter): Promise<MigrationJournalRow[]> {
  return assertRawQuery(db)<MigrationJournalRow>(
    'SELECT version, name, dialect, checksum FROM fortress_migration_journal ORDER BY version',
  );
}

async function isJournalInitialized(db: DatabaseAdapter): Promise<boolean> {
  const rows = await assertRawQuery(db)<{ journal_initialized: boolean | number | string }>(
    'SELECT journal_initialized FROM fortress_migration_state WHERE id = 1',
  );
  const value = rows[0]?.journal_initialized;
  return value === true || value === 1 || value === '1' || value === 'true';
}

async function markJournalInitialized(db: DatabaseAdapter, dialect: MigrationDialect): Promise<void> {
  await assertRawQuery(db)(
    `UPDATE fortress_migration_state SET journal_initialized = ${dialect === 'pg' ? 'true' : '1'} WHERE id = 1`,
  );
}

async function insertJournal(
  db: DatabaseAdapter,
  dialect: MigrationDialect,
  migration: FortressMigration,
): Promise<void> {
  const rawQuery = assertRawQuery(db);
  const checksum = await computeMigrationChecksum(migration);
  if (dialect === 'sqlite') {
    await rawQuery(
      `INSERT INTO fortress_migration_journal (version, name, dialect, checksum, applied_at)
       VALUES (?, ?, ?, ?, unixepoch())`,
      [migration.version, migration.name, dialect, checksum],
    );
    return;
  }
  await rawQuery(
    `INSERT INTO fortress_migration_journal (version, name, dialect, checksum, applied_at)
     VALUES (?, ?, ?, ?, now())`,
    [migration.version, migration.name, dialect, checksum],
  );
}

async function verifyOrBackfillJournal(
  db: DatabaseAdapter,
  dialect: MigrationDialect,
  currentVersion: number,
): Promise<void> {
  const migrations = getFortressMigrations(dialect);
  const latestVersion = getLatestMigrationVersion(dialect);
  if (currentVersion > latestVersion) {
    throw Errors.badRequest(
      `Database schema version ${currentVersion} is newer than bundled version ${latestVersion}`,
    );
  }

  let rows = await readJournal(db);
  const initialized = await isJournalInitialized(db);
  // Compatibility bridge for installations created before the journal. The
  // persistent state marker makes this a one-time transition: once initialized,
  // even complete row loss is corruption and must not be silently re-certified.
  if (!initialized && rows.length === 0 && currentVersion > 0) {
    for (const migration of migrations.filter(item => item.version <= currentVersion))
      await insertJournal(db, dialect, migration);
    rows = await readJournal(db);
  }

  const byVersion = new Map(rows.map(row => [Number(row.version), row]));
  for (const row of rows) {
    const version = Number(row.version);
    const migration = migrations.find(item => item.version === version);
    if (!migration || version > currentVersion) {
      throw Errors.badRequest(`Migration journal contains unexpected version ${version}`);
    }
    const checksum = await computeMigrationChecksum(migration);
    if (row.name !== migration.name || row.dialect !== dialect || row.checksum !== checksum) {
      throw Errors.badRequest(`Migration journal integrity check failed for version ${version}`);
    }
  }
  for (const migration of migrations.filter(item => item.version <= currentVersion)) {
    if (!byVersion.has(migration.version)) {
      throw Errors.badRequest(`Migration journal is missing version ${migration.version}`);
    }
  }
  if (!initialized)
    await markJournalInitialized(db, dialect);
}

async function deleteJournalVersion(db: DatabaseAdapter, version: number): Promise<void> {
  await assertRawQuery(db)(
    'DELETE FROM fortress_migration_journal WHERE version = ?',
    [version],
  );
}

async function dropMigrationMetadata(db: DatabaseAdapter, dialect: MigrationDialect): Promise<void> {
  const rawQuery = assertRawQuery(db);
  await rawQuery('DROP TABLE IF EXISTS fortress_migration_journal');
  await rawQuery('DROP TABLE IF EXISTS fortress_migration_state');
  if (dialect === 'sqlite')
    await rawQuery('DROP TABLE IF EXISTS fortress_migration_lock');
}

function assertTargetVersion(targetVersion: number): void {
  if (!Number.isSafeInteger(targetVersion) || targetVersion < 0)
    throw Errors.badRequest('Migration target version must be a non-negative safe integer');
}

// better-sqlite3 waits synchronously on a cross-connection writer lock, which
// can starve the first transaction's Promise continuation in the same process.
// Serialize local migration callers as well; the database write lock remains
// the cross-process authority.
let sqliteMigrationChain: Promise<void> = Promise.resolve();

function withMigrationTransaction<T>(
  db: DatabaseAdapter,
  dialect: MigrationDialect,
  fn: (tx: DatabaseAdapter) => Promise<T>,
): Promise<T> {
  if (dialect === 'pg')
    return db.transaction(fn);
  const result = sqliteMigrationChain.then(
    () => db.transaction(fn),
    () => db.transaction(fn),
  );
  sqliteMigrationChain = result.then(() => undefined, () => undefined);
  return result;
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
  targetVersion: number = getLatestMigrationVersion(dialect),
): Promise<MigrationApplyResult> {
  assertTargetVersion(targetVersion);
  return withMigrationTransaction(db, dialect, async (tx) => {
    await ensureMigrationMetadata(tx, dialect);
    // Mandatory post-lock read: no plan computed before this point is trusted.
    const { version: currentVersion } = await readCurrentVersion(tx, dialect);
    await verifyOrBackfillJournal(tx, dialect, currentVersion);

    const toApply = getFortressMigrations(dialect)
      .filter(migration => migration.version > currentVersion && migration.version <= targetVersion);
    for (const migration of toApply) {
      await migration.beforeUp?.(tx);
      await executeSql(tx, migration.up);
      await insertJournal(tx, dialect, migration);
      await recordVersion(tx, dialect, migration.version);
    }

    const toVersion = toApply.at(-1)?.version ?? currentVersion;
    if (toVersion === 0)
      await dropMigrationMetadata(tx, dialect);
    return {
      dialect,
      fromVersion: currentVersion,
      toVersion,
      applied: toApply,
    };
  });
}

export async function migrateDown(
  db: DatabaseAdapter,
  dialect: MigrationDialect = db.dialect === 'pg' ? 'pg' : 'sqlite',
  targetVersion: number = 0,
): Promise<MigrationDownResult> {
  assertTargetVersion(targetVersion);
  return withMigrationTransaction(db, dialect, async (tx) => {
    await ensureMigrationMetadata(tx, dialect);
    const { version: currentVersion } = await readCurrentVersion(tx, dialect);
    await verifyOrBackfillJournal(tx, dialect, currentVersion);

    // A target above current is an idempotent no-op, never a version advance.
    const effectiveTarget = Math.min(targetVersion, currentVersion);
    const migrations = getFortressMigrations(dialect);
    if (
      effectiveTarget > 0
      && effectiveTarget < currentVersion
      && !migrations.some(migration => migration.version === effectiveTarget)
    ) {
      throw Errors.badRequest(`Unknown migration target version ${effectiveTarget}`);
    }
    const toRollback = migrations
      .filter(migration => migration.version <= currentVersion && migration.version > effectiveTarget)
      .sort((a, b) => b.version - a.version);

    for (const migration of toRollback) {
      await executeSql(tx, migration.down);
      await deleteJournalVersion(tx, migration.version);
    }
    if (effectiveTarget === 0)
      await dropMigrationMetadata(tx, dialect);
    else if (toRollback.length > 0)
      await recordVersion(tx, dialect, effectiveTarget);

    return {
      dialect,
      fromVersion: currentVersion,
      toVersion: effectiveTarget,
      rolledBack: toRollback,
    };
  });
}

export async function detectMigrationDrift(
  db: DatabaseAdapter,
  dialect: MigrationDialect = db.dialect === 'pg' ? 'pg' : 'sqlite',
): Promise<MigrationDrift> {
  const status = await getMigrationStatus(db, dialect);
  const present = await listFortressTables(db, dialect);
  const missingTables = FORTRESS_TABLES.filter(name => !present.has(name));

  // Column-level drift: inspect only tables that actually exist (fully
  // missing tables are already reported above). Expected columns come from
  // the bundled migration DDL, so this catches a table that was created
  // from an older schema and never got a later migration's new column.
  const expectedColumns = getExpectedColumns(dialect);
  const missingColumns: { table: string; columns: string[] }[] = [];
  for (const [table, columns] of Object.entries(expectedColumns)) {
    if (!present.has(table))
      continue;
    const live = await listColumns(db, dialect, table);
    const missing = columns.filter(column => !live.has(column));
    if (missing.length > 0)
      missingColumns.push({ table, columns: missing });
  }

  const presentIndexes = await listFortressIndexes(db, dialect);
  const missingIndexes = FORTRESS_INDEXES
    .map(index => index.name)
    .filter(name => !presentIndexes.has(name));

  return {
    dialect,
    currentVersion: status.currentVersion,
    latestVersion: status.latestVersion,
    missingVersionTable: !status.hasVersionTable,
    unknownFutureVersion: status.currentVersion > status.latestVersion,
    pendingVersions: status.pending.map(migration => migration.version),
    missingTables,
    missingColumns,
    missingIndexes,
  };
}

export function hasMigrationDrift(drift: MigrationDrift): boolean {
  return drift.missingVersionTable
    || drift.unknownFutureVersion
    || drift.pendingVersions.length > 0
    || drift.missingTables.length > 0
    || drift.missingColumns.length > 0
    || drift.missingIndexes.length > 0;
}
