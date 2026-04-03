import type { DatabaseAdapter } from '../adapters/database';
import { createDrizzleAdapter } from '../drizzle/adapter';

const CREATE_TABLES_SQL = `
  CREATE TABLE IF NOT EXISTS fortress_user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    password_hash TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_login_identifier (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    type TEXT NOT NULL,
    value TEXT NOT NULL UNIQUE
  );

  CREATE TABLE IF NOT EXISTS fortress_refresh_token (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    token_hash TEXT NOT NULL UNIQUE,
    token_family TEXT NOT NULL,
    is_revoked INTEGER NOT NULL DEFAULT 0,
    expires_at TEXT NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_group (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
  );

  CREATE TABLE IF NOT EXISTS fortress_group_user (
    group_id INTEGER NOT NULL REFERENCES fortress_group(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    PRIMARY KEY (group_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS fortress_resource (
    name TEXT PRIMARY KEY,
    description TEXT
  );

  CREATE TABLE IF NOT EXISTS fortress_permission (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    resource TEXT NOT NULL REFERENCES fortress_resource(name) ON DELETE CASCADE,
    action TEXT NOT NULL,
    effect TEXT NOT NULL DEFAULT 'ALLOW',
    conditions TEXT,
    description TEXT
  );

  CREATE TABLE IF NOT EXISTS fortress_role (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT
  );

  CREATE TABLE IF NOT EXISTS fortress_role_permission (
    role_id INTEGER NOT NULL REFERENCES fortress_role(id) ON DELETE CASCADE,
    permission_id INTEGER NOT NULL REFERENCES fortress_permission(id) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_id)
  );

  CREATE TABLE IF NOT EXISTS fortress_role_binding (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    role_id INTEGER NOT NULL REFERENCES fortress_role(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL,
    subject_id INTEGER NOT NULL
  );
`;

const isBun = typeof (globalThis as Record<string, unknown>).Bun !== 'undefined';

/**
 * Create a test DatabaseAdapter using in-memory SQLite.
 * Automatically detects the runtime:
 * - Bun: uses bun:sqlite
 * - Node/Vitest: uses better-sqlite3
 *
 * Usage:
 *   import { createTestAdapter } from '@bajustone/fortress/testing';
 *   const fortress = createFortress({ database: createTestAdapter(), jwt: { secret: 'test' } });
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
