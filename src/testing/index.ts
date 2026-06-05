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
 * const fortress = await createFortress({ db, jwt: { secret: 'test' } });
 * ```
 *
 * @module
 */

import type { DatabaseAdapter } from '../adapters/database';
import { createDrizzleAdapter } from '../drizzle/adapter';

const CREATE_TABLES_SQL = `
  CREATE TABLE IF NOT EXISTS fortress_user (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    password_hash TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    email_verified INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
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
    expires_at INTEGER NOT NULL,
    ip_address TEXT,
    user_agent TEXT,
    device_name TEXT,
    last_active_at INTEGER,
    fingerprint_hash TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
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

  CREATE TABLE IF NOT EXISTS fortress_service_account (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    display_name TEXT,
    description TEXT,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
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
    description TEXT,
    UNIQUE (resource, action, effect, conditions)
  );

  CREATE TABLE IF NOT EXISTS fortress_role (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE,
    description TEXT,
    is_system INTEGER NOT NULL DEFAULT 0
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
    subject_id INTEGER NOT NULL,
    tenant_id TEXT,
    UNIQUE (role_id, subject_type, subject_id, tenant_id)
  );
  CREATE UNIQUE INDEX IF NOT EXISTS uniq_role_binding_global
    ON fortress_role_binding (role_id, subject_type, subject_id)
    WHERE tenant_id IS NULL;
  CREATE UNIQUE INDEX IF NOT EXISTS uniq_role_binding_tenant
    ON fortress_role_binding (role_id, subject_type, subject_id, tenant_id)
    WHERE tenant_id IS NOT NULL;

  CREATE TABLE IF NOT EXISTS fortress_direct_permission_binding (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    permission_id INTEGER NOT NULL REFERENCES fortress_permission(id) ON DELETE CASCADE,
    subject_type TEXT NOT NULL,
    subject_id INTEGER NOT NULL,
    tenant_id TEXT,
    UNIQUE (permission_id, subject_type, subject_id, tenant_id)
  );
  CREATE UNIQUE INDEX IF NOT EXISTS uniq_direct_permission_binding_global
    ON fortress_direct_permission_binding (permission_id, subject_type, subject_id)
    WHERE tenant_id IS NULL;
  CREATE UNIQUE INDEX IF NOT EXISTS uniq_direct_permission_binding_tenant
    ON fortress_direct_permission_binding (permission_id, subject_type, subject_id, tenant_id)
    WHERE tenant_id IS NOT NULL;

  CREATE TABLE IF NOT EXISTS fortress_email_verification_token (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    email TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_magic_link_token (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    email TEXT NOT NULL,
    token TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_api_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    subject_type TEXT NOT NULL,
    subject_id INTEGER NOT NULL,
    name TEXT NOT NULL,
    key_hash TEXT NOT NULL UNIQUE,
    key_prefix TEXT NOT NULL,
    scopes TEXT,
    expires_at INTEGER,
    last_used_at INTEGER,
    is_revoked INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );
  CREATE INDEX IF NOT EXISTS api_key_subject_idx ON fortress_api_key (subject_type, subject_id);

  CREATE TABLE IF NOT EXISTS fortress_two_factor_secret (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL UNIQUE REFERENCES fortress_user(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    is_enabled INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_backup_code (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    is_used INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_trusted_device (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    device_hash TEXT NOT NULL,
    expires_at INTEGER NOT NULL,
    last_used_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_social_account (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    provider TEXT NOT NULL,
    provider_account_id TEXT NOT NULL,
    email TEXT,
    access_token TEXT,
    refresh_token TEXT,
    token_expires_at INTEGER,
    profile TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_tenant (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL,
    tax_id TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch()),
    updated_at INTEGER NOT NULL DEFAULT (unixepoch())
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
    -- RFC 6749 §3.3 / RFC 9700 §2.2.1: per-client scope allow-list (JSON array).
    allowed_scopes TEXT,
    -- RFC 6749 §2.1 / OIDC Discovery client authentication method.
    -- 'client_secret_basic' | 'client_secret_post' | 'none' (public client).
    token_endpoint_auth_method TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
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
    -- OIDC Core §3.1.2.1 nonce / auth_time, persisted for id_token issuance.
    nonce TEXT,
    auth_time INTEGER,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_oauth_access_token (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    client_id TEXT NOT NULL,
    user_id INTEGER,
    scope TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  -- RFC 6749 §6 + RFC 9700 §2.2.2 refresh tokens with rotation.
  CREATE TABLE IF NOT EXISTS fortress_oauth_refresh_token (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    token TEXT NOT NULL UNIQUE,
    family_id TEXT NOT NULL,
    client_id TEXT NOT NULL,
    user_id INTEGER NOT NULL,
    scope TEXT,
    issued_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    used_at INTEGER,
    parent_id INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_oauth_pending_flow (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    client_id TEXT NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    state TEXT NOT NULL,
    code_challenge TEXT,
    code_challenge_method TEXT,
    nonce TEXT,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  -- OIDC Core / RFC 7517: id_token signing key persistence (RS256 today).
  CREATE TABLE IF NOT EXISTS fortress_oauth_signing_key (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    kid TEXT NOT NULL UNIQUE,
    alg TEXT NOT NULL,
    public_jwk TEXT NOT NULL,
    private_jwk TEXT NOT NULL,
    rotated_at INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_user_scope_assignment (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    scope_name TEXT NOT NULL,
    scope_value TEXT NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_account_lockout (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    identifier TEXT NOT NULL UNIQUE,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_at INTEGER,
    locked_until INTEGER,
    lockout_count INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp INTEGER NOT NULL DEFAULT (unixepoch()),
    event_type TEXT NOT NULL,
    actor_id INTEGER,
    actor_type TEXT NOT NULL DEFAULT 'USER',
    target_id INTEGER,
    target_type TEXT,
    ip_address TEXT,
    user_agent TEXT,
    outcome TEXT NOT NULL DEFAULT 'SUCCESS',
    metadata TEXT,
    previous_hash TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_webhook_endpoint (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    url TEXT NOT NULL,
    events TEXT NOT NULL,
    secret TEXT NOT NULL,
    is_active INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_webhook_delivery (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    endpoint_id INTEGER NOT NULL REFERENCES fortress_webhook_endpoint(id) ON DELETE CASCADE,
    event_type TEXT NOT NULL,
    payload TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at INTEGER,
    next_retry_at INTEGER,
    response_status INTEGER,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_webauthn_credential (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    credential_id TEXT NOT NULL UNIQUE,
    public_key TEXT NOT NULL,
    counter INTEGER NOT NULL DEFAULT 0,
    device_type TEXT NOT NULL,
    backed_up INTEGER NOT NULL DEFAULT 0,
    transports TEXT,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
  );

  CREATE TABLE IF NOT EXISTS fortress_webauthn_challenge (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    challenge TEXT NOT NULL UNIQUE,
    user_id INTEGER,
    expires_at INTEGER NOT NULL,
    created_at INTEGER NOT NULL DEFAULT (unixepoch())
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
