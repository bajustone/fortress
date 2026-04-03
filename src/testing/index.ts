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

  CREATE TABLE IF NOT EXISTS fortress_email_verification_token (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    email TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_api_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    scopes TEXT,
    expires_at TEXT,
    last_used_at TEXT,
    is_revoked INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_two_factor_secret (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES fortress_user(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    is_enabled INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_backup_code (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    is_used INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_trusted_device (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    device_hash TEXT NOT NULL,
    expires_at TEXT NOT NULL,
    last_used_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_social_account (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_account_id TEXT NOT NULL,
    email TEXT,
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at TEXT,
    profile TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_tenant (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    tax_id TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    updated_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_tenant_user (
    tenant_id INTEGER NOT NULL REFERENCES fortress_tenant(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    is_default INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (tenant_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS fortress_oauth_client (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL UNIQUE,
    client_secret_hash TEXT NOT NULL,
    name TEXT NOT NULL,
    redirect_uris TEXT NOT NULL,
    grant_types TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_oauth_authorization_code (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    code TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    code_challenge TEXT,
    code_challenge_method TEXT,
    expires_at TEXT NOT NULL,
    used_at TEXT,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_oauth_access_token (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    user_id INTEGER,
    scope TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_oauth_pending_flow (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    state TEXT NOT NULL,
    code_challenge TEXT,
    code_challenge_method TEXT,
    expires_at TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS fortress_user_scope_assignment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    scope_name TEXT NOT NULL,
    scope_value TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
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
