import type { DatabaseAdapter, MigratableDatabaseAdapter } from '../../adapters/database';
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

async function sha256(value: string): Promise<string> {
  const digest = await globalThis.crypto.subtle.digest('SHA-256', new TextEncoder().encode(value));
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
}

function migrationChecksumPayload(migration: FortressMigration, legacyFunctionSource = false): string {
  if (migration.beforeUp && !migration.dataStep)
    throw new Error(`Migration ${migration.version} (${migration.name}) must name its runtime data step`);
  return JSON.stringify([
    migration.dialect,
    migration.version,
    migration.name,
    migration.up,
    migration.down,
    migration.freshUp ?? null,
    migration.dataStep ?? null,
    legacyFunctionSource
      ? migration.beforeUp?.toString() ?? null
      : migration.beforeUp ? 'runtime-data-step' : null,
  ]);
}

/** SHA-256 of every immutable migration input, using a runtime-stable data-step identity. */
export async function computeMigrationChecksum(migration: FortressMigration): Promise<string> {
  return sha256(migrationChecksumPayload(migration));
}

// v1.0.2 serialized Function#toString into migration 0006's checksum. Its
// output varies across Node, Bun, Deno, ESM, CJS, and source transforms. Keep a
// narrow one-time bridge for hashes emitted by supported v1.0.2 package forms;
// all new and upgraded rows use the runtime-stable checksum above.
const LEGACY_DATA_STEP_CHECKSUMS: Readonly<Record<MigrationDialect, ReadonlySet<string>>> = {
  sqlite: new Set([
    '3b43aeabaf3a2ddab829eb49397288cf4a16fc4c30051a23bc5e8b41a3c70bb4',
    '0b60788f7af52b1280a785aee35b2523998f5841be87b3e88ccdb4072eef3930',
    '4b632501aa22102639d298ede9bcd34ca3f54eda104ac24f019b802c75acf20e',
    'dcd8db709d36a329c4ebae977cf4ad6a4498b3def840cfbc7327aa6fa4306995',
    '44db7e1c6bf979f0a5f499e966ff1a8d273fd8b67c9c6aa543812cde0dbb3077',
    'c5077641e39bc61e6f71a6963bc2001df3dbc0cde720e17145e49ced1f4c584c',
  ]),
  pg: new Set([
    '950057a392a8d3ee0d00ca78a77fff61747e9f223ad53cbcb1b8a43be7a264f7',
    '61d81ba6370693e3ddec1ce7a5d7f5986da08c2f0287dc75bef510d8d31a335f',
    '26a25630a3e641cd5fda47654bf4cea13ad970be8bdfe9de099e8938b952c966',
    '618e67c788691e06cdc9764214d0814c8811bbe0f7f5a456c396648567ae1302',
    'a8145340cec7ef778b69adef5d30bfb985c517d134c913a0114a36f99d9b720a',
    'd26ee6a75b93c1d1fb6e22b316173ecd7b31ebd4ebdeefd7f5b0b45ab5ab8316',
  ]),
};

async function isLegacyDataStepChecksum(
  migration: FortressMigration,
  checksum: string,
): Promise<boolean> {
  if (migration.version !== 6 || migration.name !== 'canonical_email'
    || migration.dataStep !== 'normalize-email-v2' || !migration.beforeUp) {
    return false;
  }
  if (LEGACY_DATA_STEP_CHECKSUMS[migration.dialect].has(checksum))
    return true;
  // Source consumers may use a loader transform not represented by the
  // published npm/JSR forms. Accept only the exact legacy payload produced by
  // this runtime; arbitrary checksums still fail closed.
  return checksum === await sha256(migrationChecksumPayload(migration, true));
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
    if (row.name !== migration.name || row.dialect !== dialect) {
      throw Errors.badRequest(`Migration journal integrity check failed for version ${version}`);
    }
    if (row.checksum !== checksum) {
      if (!await isLegacyDataStepChecksum(migration, row.checksum))
        throw Errors.badRequest(`Migration journal integrity check failed for version ${version}`);
      await updateJournalChecksum(db, version, checksum);
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

async function updateJournalChecksum(
  db: DatabaseAdapter,
  version: number,
  checksum: string,
): Promise<void> {
  await assertRawQuery(db)(
    'UPDATE fortress_migration_journal SET checksum = ? WHERE version = ?',
    [checksum, version],
  );
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

function withMigrationTransaction<T, D extends MigrationDialect>(
  db: MigratableDatabaseAdapter<D>,
  fn: (tx: MigratableDatabaseAdapter<D>) => Promise<T>,
): Promise<T> {
  const run = (): Promise<T> => db.transaction(async (tx) => {
    if (tx.dialect !== db.dialect || typeof tx.rawQuery !== 'function') {
      throw Errors.badRequest(
        'Migration transactions must preserve the adapter dialect and rawQuery capability',
      );
    }
    return fn(tx);
  });
  if (db.dialect === 'pg')
    return run();
  const result = sqliteMigrationChain.then(run, run);
  sqliteMigrationChain = result.then(() => undefined, () => undefined);
  return result;
}

export async function getMigrationStatus(
  db: MigratableDatabaseAdapter,
): Promise<MigrationStatus> {
  const dialect = db.dialect;
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
  db: MigratableDatabaseAdapter,
  targetVersion: number = getLatestMigrationVersion(db.dialect),
): Promise<MigrationApplyResult> {
  assertTargetVersion(targetVersion);
  const dialect = db.dialect;
  return withMigrationTransaction(db, async (tx) => {
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
  db: MigratableDatabaseAdapter,
  targetVersion: number = 0,
): Promise<MigrationDownResult> {
  assertTargetVersion(targetVersion);
  const dialect = db.dialect;
  return withMigrationTransaction(db, async (tx) => {
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
  db: MigratableDatabaseAdapter,
): Promise<MigrationDrift> {
  const dialect = db.dialect;
  const status = await getMigrationStatus(db);
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
