/**
 * In-memory SQLite test adapter for fortress.
 *
 * Spins up a fresh `bun:sqlite` database with the full fortress schema and
 * returns a {@link DatabaseAdapter} ready to pass into `createFortress` from
 * unit tests. Designed for fast, isolated test runs — every call creates a
 * new database, so tests cannot leak state into each other.
 *
 * @example
 * ```ts
 * import { createTestAdapter } from '@bajustone/fortress/testing';
 *
 * const db = createTestAdapter();
 * const fortress = await createFortress({ db, jwt: { key: 'test' } });
 * ```
 *
 * @module
 */

import type { DatabaseAdapter } from '../adapters/database';
import { getMigrationUpSql } from '../core/migrations/migrations';
import { createDrizzleAdapter } from '../drizzle/adapter';

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

const isBun = typeof (globalThis as Record<string, unknown>).Bun !== 'undefined';

/**
 * Create a test DatabaseAdapter using in-memory SQLite.
 * Automatically detects the runtime:
 * - Bun: uses bun:sqlite
 * - Node/Vitest: uses better-sqlite3
 *
 * Usage:
 *   import { createTestAdapter } from '@bajustone/fortress/testing';
 *   const fortress = createFortress({ database: createTestAdapter(), jwt: { key: 'test' } });
 */
export function createTestAdapter(): DatabaseAdapter {
  if (isBun) {
    return createBunAdapter();
  }
  return createNodeAdapter();
}

function createBunAdapter(): DatabaseAdapter {
  // Dynamic import to avoid loading bun:sqlite in Node
  // eslint-disable-next-line ts/no-require-imports
  const { Database } = require('bun:sqlite');
  // eslint-disable-next-line ts/no-require-imports
  const { drizzle } = require('drizzle-orm/bun-sqlite');

  const sqlite = new Database(':memory:');
  sqlite.exec('PRAGMA journal_mode = WAL;');
  sqlite.exec('PRAGMA foreign_keys = ON;');
  sqlite.exec(CREATE_TABLES_SQL);

  const db = drizzle(sqlite);
  return createDrizzleAdapter(db);
}

function createNodeAdapter(): DatabaseAdapter {
  // Dynamic import to avoid loading better-sqlite3 in Bun
  // eslint-disable-next-line ts/no-require-imports
  const BetterSqlite3 = require('better-sqlite3');
  // eslint-disable-next-line ts/no-require-imports
  const { drizzle } = require('drizzle-orm/better-sqlite3');

  const sqlite = new BetterSqlite3(':memory:');
  sqlite.pragma('journal_mode = WAL');
  sqlite.pragma('foreign_keys = ON');
  sqlite.exec(CREATE_TABLES_SQL);

  const db = drizzle(sqlite);
  return createDrizzleAdapter(db);
}
