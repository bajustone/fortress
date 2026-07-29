/**
 * In-memory SQLite test adapter for fortress.
 *
 * Spins up a fresh `bun:sqlite` database with the full fortress schema and
 * returns a {@link MigratableDatabaseAdapter} ready to pass into `createFortress` from
 * unit tests. Designed for fast, isolated test runs — every call creates a
 * new database, so tests cannot leak state into each other.
 *
 * @example
 * ```ts
 * import { createTestAdapter } from '@bajustone/fortress/testing';
 *
 * const db = createTestAdapter();
 * const fortress = createFortress({
 *   database: db,
 *   jwt: { key: 'test-only-jwt-secret-at-least-32-bytes' },
 * });
 * ```
 *
 * @module
 */

import type { MigratableDatabaseAdapter } from '../adapters/database';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { getLatestMigrationVersion, getMigrationUpSql } from '../core/migrations/migrations';
import { createSqliteDrizzleAdapter } from '../drizzle/adapter';

export {
  checkMigrationDrift,
  checkPublicRoutes,
  checkRouteManifestDrift,
  runFortressChecks,
  smokeTestAuth,
} from './checks';
export type {
  AuthSmokeTestOptions,
  CheckResult,
  FortressChecksResult,
  PublicRouteCheckOptions,
  RunFortressChecksOptions,
} from './checks';

/**
 * Full SQLite schema for the test adapter, derived from the bundled
 * migrations so the in-memory test database and a production `migrateUp`
 * can never diverge. The migrations are the SQL-first source of truth (see
 * `src/core/migrations/migrations.ts`); this just concatenates their
 * forward SQL.
 */
const CREATE_TABLES_SQL = getMigrationUpSql('sqlite');
const STAMP_SCHEMA_VERSION_SQL = `
  INSERT INTO fortress_schema_version (id, version, applied_at)
  VALUES (1, ${getLatestMigrationVersion('sqlite')}, unixepoch())
  ON CONFLICT(id) DO UPDATE SET
    version = excluded.version,
    applied_at = excluded.applied_at;
`;

const isBun = typeof (globalThis as Record<string, unknown>).Bun !== 'undefined';
const runtimeRequire = (globalThis as typeof globalThis & { require?: NodeRequire }).require
  ?? createRequire(resolve(process.argv[1] ?? '__fortress_testing__.mjs'));

/**
 * Create a test DatabaseAdapter using in-memory SQLite.
 * Automatically detects the runtime:
 * - Bun: uses bun:sqlite
 * - Node/Vitest: uses better-sqlite3
 *
 * Usage:
 *   import { createTestAdapter } from '@bajustone/fortress/testing';
 *   const fortress = createFortress({
 *     database: createTestAdapter(),
 *     jwt: { key: 'test-only-jwt-secret-at-least-32-bytes' },
 *   });
 */
export function createTestAdapter(): MigratableDatabaseAdapter<'sqlite'> {
  if (isBun) {
    return createBunAdapter();
  }
  return createNodeAdapter();
}

function createBunAdapter(): MigratableDatabaseAdapter<'sqlite'> {
  // Dynamic import to avoid loading bun:sqlite in Node
  const { Database } = runtimeRequire('bun:sqlite');
  const { drizzle } = runtimeRequire('drizzle-orm/bun-sqlite');

  const sqlite = new Database(':memory:');
  sqlite.exec('PRAGMA journal_mode = WAL;');
  sqlite.exec('PRAGMA foreign_keys = ON;');
  sqlite.exec(CREATE_TABLES_SQL);
  sqlite.exec(STAMP_SCHEMA_VERSION_SQL);

  const db = drizzle(sqlite);
  return createSqliteDrizzleAdapter(db);
}

function createNodeAdapter(): MigratableDatabaseAdapter<'sqlite'> {
  // runtimeRequire works in both package formats while keeping the native
  // dependency lazy and out of Bun's runtime branch.
  const BetterSqlite3 = runtimeRequire('better-sqlite3');
  const { drizzle } = runtimeRequire('drizzle-orm/better-sqlite3');

  const sqlite = new BetterSqlite3(':memory:');
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');
  sqlite.exec(CREATE_TABLES_SQL);
  sqlite.exec(STAMP_SCHEMA_VERSION_SQL);

  const db = drizzle(sqlite);
  return createSqliteDrizzleAdapter(db);
}
