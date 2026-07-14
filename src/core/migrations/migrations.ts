export type MigrationDialect = 'sqlite' | 'pg';

export interface FortressMigration {
  version: number;
  name: string;
  dialect: MigrationDialect;
  up: string;
  down: string;
}

// NOTE: the version row itself is written by the migration runner
// (`recordVersion` in engine.ts) after each migration applies, so the
// forward SQL only creates the checkpoint table. This keeps a single
// source of version truth and lets `src/testing/index.ts` provision the
// schema from this DDL without pre-stamping a version.
const SQLITE_0001_UP = `
CREATE TABLE IF NOT EXISTS fortress_schema_version (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version INTEGER NOT NULL,
  applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);
`.trim();

const SQLITE_0001_DOWN = `
DROP TABLE IF EXISTS fortress_schema_version;
`.trim();

const PG_0001_UP = `
CREATE TABLE IF NOT EXISTS fortress_schema_version (
  id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version integer NOT NULL,
  applied_at timestamp NOT NULL DEFAULT now()
);
`.trim();

const PG_0001_DOWN = `
DROP TABLE IF EXISTS fortress_schema_version;
`.trim();

// --- 0002: initial Fortress schema ---
//
// Creates every Fortress-owned table (everything except the
// `fortress_schema_version` checkpoint installed by 0001). This is the
// SQL-first source of truth for provisioning a brand-new database: it runs
// through any `DatabaseAdapter.rawQuery`, so a custom (non-Drizzle) adapter
// installs the exact same schema. `src/testing/index.ts` derives its
// in-memory schema from these migrations, and the column-drift checker
// parses expected columns out of this DDL — keep this the canonical copy.

const SQLITE_0002_UP = `
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
  description TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_permission_no_conditions
  ON fortress_permission (resource, action, effect)
  WHERE conditions IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_permission_with_conditions
  ON fortress_permission (resource, action, effect, conditions)
  WHERE conditions IS NOT NULL;

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
  last_used_counter INTEGER,
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
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  UNIQUE (user_id, provider),
  UNIQUE (provider, provider_account_id)
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
CREATE UNIQUE INDEX IF NOT EXISTS fortress_tenant_user_one_default_idx
  ON fortress_tenant_user (user_id) WHERE is_default = 1;

CREATE TABLE IF NOT EXISTS fortress_oauth_client (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  client_id TEXT NOT NULL UNIQUE,
  client_secret_hash TEXT NOT NULL,
  name TEXT NOT NULL,
  redirect_uris TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  allowed_scopes TEXT,
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
  flow_id TEXT NOT NULL UNIQUE,
  client_id TEXT NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT,
  state TEXT NOT NULL,
  code_challenge TEXT,
  code_challenge_method TEXT,
  nonce TEXT,
  user_id INTEGER,
  used_at INTEGER,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

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
  deactivated_reason TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE TABLE IF NOT EXISTS fortress_webhook_delivery (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  endpoint_id INTEGER NOT NULL REFERENCES fortress_webhook_endpoint(id) ON DELETE CASCADE,
  event_type TEXT NOT NULL,
  payload TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  idempotency_key TEXT,
  last_attempt_at INTEGER,
  next_retry_at INTEGER,
  response_status INTEGER,
  response_body TEXT,
  error_kind TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_webhook_delivery_idempotency
  ON fortress_webhook_delivery (endpoint_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

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
`.trim();

// DROP order is the reverse of creation so child tables go before the
// parents they reference (matters for PostgreSQL FK enforcement; SQLite is
// permissive but ordering keeps the two dialects symmetric).
const SQLITE_0002_DOWN = `
DROP TABLE IF EXISTS fortress_webauthn_challenge;
DROP TABLE IF EXISTS fortress_webauthn_credential;
DROP TABLE IF EXISTS fortress_webhook_delivery;
DROP TABLE IF EXISTS fortress_webhook_endpoint;
DROP TABLE IF EXISTS fortress_audit_log;
DROP TABLE IF EXISTS fortress_account_lockout;
DROP TABLE IF EXISTS fortress_user_scope_assignment;
DROP TABLE IF EXISTS fortress_oauth_signing_key;
DROP TABLE IF EXISTS fortress_oauth_pending_flow;
DROP TABLE IF EXISTS fortress_oauth_refresh_token;
DROP TABLE IF EXISTS fortress_oauth_access_token;
DROP TABLE IF EXISTS fortress_oauth_authorization_code;
DROP TABLE IF EXISTS fortress_oauth_client;
DROP TABLE IF EXISTS fortress_tenant_user;
DROP TABLE IF EXISTS fortress_tenant;
DROP TABLE IF EXISTS fortress_social_account;
DROP TABLE IF EXISTS fortress_trusted_device;
DROP TABLE IF EXISTS fortress_backup_code;
DROP TABLE IF EXISTS fortress_two_factor_secret;
DROP TABLE IF EXISTS fortress_api_key;
DROP TABLE IF EXISTS fortress_magic_link_token;
DROP TABLE IF EXISTS fortress_email_verification_token;
DROP TABLE IF EXISTS fortress_direct_permission_binding;
DROP TABLE IF EXISTS fortress_role_binding;
DROP TABLE IF EXISTS fortress_role_permission;
DROP TABLE IF EXISTS fortress_role;
DROP TABLE IF EXISTS fortress_permission;
DROP TABLE IF EXISTS fortress_resource;
DROP TABLE IF EXISTS fortress_service_account;
DROP TABLE IF EXISTS fortress_group_user;
DROP TABLE IF EXISTS fortress_group;
DROP TABLE IF EXISTS fortress_refresh_token;
DROP TABLE IF EXISTS fortress_login_identifier;
DROP TABLE IF EXISTS fortress_user;
`.trim();

const PG_0002_UP = `
CREATE TABLE IF NOT EXISTS fortress_user (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL UNIQUE,
  name VARCHAR(255) NOT NULL,
  password_hash TEXT,
  is_active BOOLEAN NOT NULL DEFAULT true,
  email_verified BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_login_identifier (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  type VARCHAR(20) NOT NULL,
  value VARCHAR(255) NOT NULL UNIQUE
);

CREATE TABLE IF NOT EXISTS fortress_refresh_token (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  token_family VARCHAR(64) NOT NULL,
  is_revoked BOOLEAN NOT NULL DEFAULT false,
  expires_at TIMESTAMP NOT NULL,
  ip_address VARCHAR(45),
  user_agent TEXT,
  device_name TEXT,
  last_active_at TIMESTAMP,
  fingerprint_hash VARCHAR(64),
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_group (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  description TEXT
);

CREATE TABLE IF NOT EXISTS fortress_group_user (
  group_id INTEGER NOT NULL REFERENCES fortress_group(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  PRIMARY KEY (group_id, user_id)
);

CREATE TABLE IF NOT EXISTS fortress_service_account (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  display_name VARCHAR(255),
  description TEXT,
  is_active BOOLEAN NOT NULL DEFAULT true,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_resource (
  name VARCHAR(100) PRIMARY KEY,
  description TEXT
);

CREATE TABLE IF NOT EXISTS fortress_permission (
  id SERIAL PRIMARY KEY,
  resource VARCHAR(100) NOT NULL REFERENCES fortress_resource(name) ON DELETE CASCADE,
  action VARCHAR(100) NOT NULL,
  effect VARCHAR(10) NOT NULL DEFAULT 'ALLOW',
  conditions JSONB,
  description TEXT
);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_permission_no_conditions
  ON fortress_permission (resource, action, effect)
  WHERE conditions IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_permission_with_conditions
  ON fortress_permission (resource, action, effect, conditions)
  WHERE conditions IS NOT NULL;

CREATE TABLE IF NOT EXISTS fortress_role (
  id SERIAL PRIMARY KEY,
  name VARCHAR(100) NOT NULL UNIQUE,
  description TEXT,
  is_system BOOLEAN NOT NULL DEFAULT false
);

CREATE TABLE IF NOT EXISTS fortress_role_permission (
  role_id INTEGER NOT NULL REFERENCES fortress_role(id) ON DELETE CASCADE,
  permission_id INTEGER NOT NULL REFERENCES fortress_permission(id) ON DELETE CASCADE,
  PRIMARY KEY (role_id, permission_id)
);

CREATE TABLE IF NOT EXISTS fortress_role_binding (
  id SERIAL PRIMARY KEY,
  role_id INTEGER NOT NULL REFERENCES fortress_role(id) ON DELETE CASCADE,
  subject_type VARCHAR(20) NOT NULL,
  subject_id INTEGER NOT NULL,
  tenant_id VARCHAR(100),
  UNIQUE (role_id, subject_type, subject_id, tenant_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_role_binding_global
  ON fortress_role_binding (role_id, subject_type, subject_id)
  WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_role_binding_tenant
  ON fortress_role_binding (role_id, subject_type, subject_id, tenant_id)
  WHERE tenant_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS fortress_direct_permission_binding (
  id SERIAL PRIMARY KEY,
  permission_id INTEGER NOT NULL REFERENCES fortress_permission(id) ON DELETE CASCADE,
  subject_type VARCHAR(20) NOT NULL,
  subject_id INTEGER NOT NULL,
  tenant_id VARCHAR(100),
  UNIQUE (permission_id, subject_type, subject_id, tenant_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS uniq_direct_permission_binding_global
  ON fortress_direct_permission_binding (permission_id, subject_type, subject_id)
  WHERE tenant_id IS NULL;
CREATE UNIQUE INDEX IF NOT EXISTS uniq_direct_permission_binding_tenant
  ON fortress_direct_permission_binding (permission_id, subject_type, subject_id, tenant_id)
  WHERE tenant_id IS NOT NULL;

CREATE TABLE IF NOT EXISTS fortress_email_verification_token (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  token TEXT NOT NULL,
  email VARCHAR(255) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_magic_link_token (
  id SERIAL PRIMARY KEY,
  email VARCHAR(255) NOT NULL,
  token VARCHAR(64) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_api_key (
  id SERIAL PRIMARY KEY,
  subject_type VARCHAR(20) NOT NULL,
  subject_id INTEGER NOT NULL,
  name VARCHAR(255) NOT NULL,
  key_hash VARCHAR(64) NOT NULL UNIQUE,
  key_prefix VARCHAR(20) NOT NULL,
  scopes TEXT,
  expires_at TIMESTAMP,
  last_used_at TIMESTAMP,
  is_revoked BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS api_key_subject_idx ON fortress_api_key (subject_type, subject_id);

CREATE TABLE IF NOT EXISTS fortress_two_factor_secret (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL UNIQUE REFERENCES fortress_user(id) ON DELETE CASCADE,
  secret TEXT NOT NULL,
  is_enabled BOOLEAN NOT NULL DEFAULT false,
  last_used_counter INTEGER,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_backup_code (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  code_hash TEXT NOT NULL,
  is_used BOOLEAN NOT NULL DEFAULT false,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_trusted_device (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  device_hash VARCHAR(64) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  last_used_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_social_account (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  provider VARCHAR(50) NOT NULL,
  provider_account_id VARCHAR(255) NOT NULL,
  email VARCHAR(255),
  access_token TEXT,
  refresh_token TEXT,
  token_expires_at TIMESTAMP,
  profile JSONB,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  updated_at TIMESTAMP NOT NULL DEFAULT now(),
  UNIQUE (user_id, provider),
  UNIQUE (provider, provider_account_id)
);

CREATE TABLE IF NOT EXISTS fortress_tenant (
  id SERIAL PRIMARY KEY,
  name VARCHAR(255) NOT NULL,
  tax_id VARCHAR(100) NOT NULL UNIQUE,
  description TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT now(),
  updated_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_tenant_user (
  tenant_id INTEGER NOT NULL REFERENCES fortress_tenant(id) ON DELETE CASCADE,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  is_default BOOLEAN NOT NULL DEFAULT false,
  PRIMARY KEY (tenant_id, user_id)
);
CREATE UNIQUE INDEX IF NOT EXISTS fortress_tenant_user_one_default_idx
  ON fortress_tenant_user (user_id) WHERE is_default = true;

CREATE TABLE IF NOT EXISTS fortress_oauth_client (
  id SERIAL PRIMARY KEY,
  client_id VARCHAR(255) NOT NULL UNIQUE,
  client_secret_hash TEXT NOT NULL,
  name VARCHAR(255) NOT NULL,
  redirect_uris TEXT NOT NULL,
  grant_types TEXT NOT NULL,
  allowed_scopes TEXT,
  token_endpoint_auth_method TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_oauth_authorization_code (
  id SERIAL PRIMARY KEY,
  code VARCHAR(255) NOT NULL UNIQUE,
  client_id VARCHAR(255) NOT NULL,
  user_id INTEGER NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT,
  code_challenge TEXT,
  code_challenge_method VARCHAR(10),
  nonce TEXT,
  auth_time INTEGER,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_oauth_access_token (
  id SERIAL PRIMARY KEY,
  token VARCHAR(255) NOT NULL UNIQUE,
  client_id VARCHAR(255) NOT NULL,
  user_id INTEGER,
  scope TEXT,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_oauth_refresh_token (
  id SERIAL PRIMARY KEY,
  token VARCHAR(255) NOT NULL UNIQUE,
  family_id VARCHAR(64) NOT NULL,
  client_id VARCHAR(255) NOT NULL,
  user_id INTEGER NOT NULL,
  scope TEXT,
  issued_at TIMESTAMP NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  used_at TIMESTAMP,
  parent_id INTEGER,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_oauth_pending_flow (
  id SERIAL PRIMARY KEY,
  flow_id TEXT NOT NULL UNIQUE,
  client_id VARCHAR(255) NOT NULL,
  redirect_uri TEXT NOT NULL,
  scope TEXT,
  state VARCHAR(255) NOT NULL,
  code_challenge TEXT,
  code_challenge_method VARCHAR(10),
  nonce TEXT,
  user_id INTEGER,
  used_at TIMESTAMP,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_oauth_signing_key (
  id SERIAL PRIMARY KEY,
  kid VARCHAR(64) NOT NULL UNIQUE,
  alg VARCHAR(16) NOT NULL,
  public_jwk TEXT NOT NULL,
  private_jwk TEXT NOT NULL,
  rotated_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_user_scope_assignment (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  scope_name VARCHAR(100) NOT NULL,
  scope_value VARCHAR(255) NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_account_lockout (
  id SERIAL PRIMARY KEY,
  identifier VARCHAR(255) NOT NULL UNIQUE,
  failed_attempts INTEGER NOT NULL DEFAULT 0,
  last_failed_at TIMESTAMP,
  locked_until TIMESTAMP,
  lockout_count INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_audit_log (
  id SERIAL PRIMARY KEY,
  timestamp TIMESTAMP NOT NULL DEFAULT now(),
  event_type VARCHAR(100) NOT NULL,
  actor_id INTEGER,
  actor_type VARCHAR(20) NOT NULL DEFAULT 'USER',
  target_id INTEGER,
  target_type VARCHAR(50),
  ip_address VARCHAR(45),
  user_agent TEXT,
  outcome VARCHAR(20) NOT NULL DEFAULT 'SUCCESS',
  metadata JSONB,
  previous_hash TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_webhook_endpoint (
  id SERIAL PRIMARY KEY,
  url TEXT NOT NULL,
  events TEXT NOT NULL,
  secret TEXT NOT NULL,
  is_active BOOLEAN NOT NULL DEFAULT true,
  deactivated_reason TEXT,
  consecutive_failures INTEGER NOT NULL DEFAULT 0,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_webhook_delivery (
  id SERIAL PRIMARY KEY,
  endpoint_id INTEGER NOT NULL REFERENCES fortress_webhook_endpoint(id) ON DELETE CASCADE,
  event_type VARCHAR(100) NOT NULL,
  payload TEXT NOT NULL,
  status VARCHAR(20) NOT NULL DEFAULT 'pending',
  attempts INTEGER NOT NULL DEFAULT 0,
  idempotency_key TEXT,
  last_attempt_at TIMESTAMP,
  next_retry_at TIMESTAMP,
  response_status INTEGER,
  response_body TEXT,
  error_kind TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE UNIQUE INDEX IF NOT EXISTS uniq_webhook_delivery_idempotency
  ON fortress_webhook_delivery (endpoint_id, idempotency_key)
  WHERE idempotency_key IS NOT NULL;

CREATE TABLE IF NOT EXISTS fortress_webauthn_credential (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  credential_id TEXT NOT NULL UNIQUE,
  public_key TEXT NOT NULL,
  counter INTEGER NOT NULL DEFAULT 0,
  device_type VARCHAR(20) NOT NULL,
  backed_up BOOLEAN NOT NULL DEFAULT false,
  transports TEXT,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS fortress_webauthn_challenge (
  id SERIAL PRIMARY KEY,
  challenge TEXT NOT NULL UNIQUE,
  user_id INTEGER,
  expires_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);
`.trim();

const PG_0002_DOWN = `
DROP TABLE IF EXISTS fortress_webauthn_challenge CASCADE;
DROP TABLE IF EXISTS fortress_webauthn_credential CASCADE;
DROP TABLE IF EXISTS fortress_webhook_delivery CASCADE;
DROP TABLE IF EXISTS fortress_webhook_endpoint CASCADE;
DROP TABLE IF EXISTS fortress_audit_log CASCADE;
DROP TABLE IF EXISTS fortress_account_lockout CASCADE;
DROP TABLE IF EXISTS fortress_user_scope_assignment CASCADE;
DROP TABLE IF EXISTS fortress_oauth_signing_key CASCADE;
DROP TABLE IF EXISTS fortress_oauth_pending_flow CASCADE;
DROP TABLE IF EXISTS fortress_oauth_refresh_token CASCADE;
DROP TABLE IF EXISTS fortress_oauth_access_token CASCADE;
DROP TABLE IF EXISTS fortress_oauth_authorization_code CASCADE;
DROP TABLE IF EXISTS fortress_oauth_client CASCADE;
DROP TABLE IF EXISTS fortress_tenant_user CASCADE;
DROP TABLE IF EXISTS fortress_tenant CASCADE;
DROP TABLE IF EXISTS fortress_social_account CASCADE;
DROP TABLE IF EXISTS fortress_trusted_device CASCADE;
DROP TABLE IF EXISTS fortress_backup_code CASCADE;
DROP TABLE IF EXISTS fortress_two_factor_secret CASCADE;
DROP TABLE IF EXISTS fortress_api_key CASCADE;
DROP TABLE IF EXISTS fortress_magic_link_token CASCADE;
DROP TABLE IF EXISTS fortress_email_verification_token CASCADE;
DROP TABLE IF EXISTS fortress_direct_permission_binding CASCADE;
DROP TABLE IF EXISTS fortress_role_binding CASCADE;
DROP TABLE IF EXISTS fortress_role_permission CASCADE;
DROP TABLE IF EXISTS fortress_role CASCADE;
DROP TABLE IF EXISTS fortress_permission CASCADE;
DROP TABLE IF EXISTS fortress_resource CASCADE;
DROP TABLE IF EXISTS fortress_service_account CASCADE;
DROP TABLE IF EXISTS fortress_group_user CASCADE;
DROP TABLE IF EXISTS fortress_group CASCADE;
DROP TABLE IF EXISTS fortress_refresh_token CASCADE;
DROP TABLE IF EXISTS fortress_login_identifier CASCADE;
DROP TABLE IF EXISTS fortress_user CASCADE;
`.trim();

// --- 0003: auth continuation + refresh-session metadata ---
//
// Adds the single-use state carrier used by the post-auth gate and the
// refresh-family metadata needed by grace-window rotation and session caps.
// Existing refresh families are backfilled from their original row creation
// time so an upgrade does not reset their absolute age.

const SQLITE_0003_UP = `
CREATE TABLE fortress_refresh_token_v3 (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  token_family TEXT NOT NULL,
  family_created_at INTEGER NOT NULL DEFAULT (unixepoch()),
  successor_token_hash TEXT,
  rotated_at INTEGER,
  is_revoked INTEGER NOT NULL DEFAULT 0,
  expires_at INTEGER NOT NULL,
  ip_address TEXT,
  user_agent TEXT,
  device_name TEXT,
  last_active_at INTEGER,
  fingerprint_hash TEXT,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
INSERT INTO fortress_refresh_token_v3 (
  id, user_id, token_hash, token_family, family_created_at,
  successor_token_hash, rotated_at, is_revoked, expires_at, ip_address,
  user_agent, device_name, last_active_at, fingerprint_hash, created_at
)
SELECT
  token.id, token.user_id, token.token_hash, token.token_family,
  (SELECT MIN(family.created_at)
   FROM fortress_refresh_token AS family
   WHERE family.token_family = token.token_family),
  NULL, NULL, token.is_revoked, token.expires_at, token.ip_address,
  token.user_agent, token.device_name, token.last_active_at,
  token.fingerprint_hash, token.created_at
FROM fortress_refresh_token AS token;
DROP TABLE fortress_refresh_token;
ALTER TABLE fortress_refresh_token_v3 RENAME TO fortress_refresh_token;

CREATE TABLE fortress_auth_continuation (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  token_hash TEXT NOT NULL UNIQUE,
  reason TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  consumed_at INTEGER,
  created_at INTEGER NOT NULL DEFAULT (unixepoch())
);
`.trim();

const SQLITE_0003_DOWN = `
DROP TABLE IF EXISTS fortress_auth_continuation;
CREATE TABLE fortress_refresh_token_v2 (
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
INSERT INTO fortress_refresh_token_v2 (
  id, user_id, token_hash, token_family, is_revoked, expires_at,
  ip_address, user_agent, device_name, last_active_at, fingerprint_hash, created_at
)
SELECT
  id, user_id, token_hash, token_family, is_revoked, expires_at,
  ip_address, user_agent, device_name, last_active_at, fingerprint_hash, created_at
FROM fortress_refresh_token;
DROP TABLE fortress_refresh_token;
ALTER TABLE fortress_refresh_token_v2 RENAME TO fortress_refresh_token;
`.trim();

const PG_0003_UP = `
ALTER TABLE fortress_refresh_token
  ADD COLUMN family_created_at TIMESTAMP;
UPDATE fortress_refresh_token AS token
  SET family_created_at = family.created_at
  FROM (
    SELECT token_family, MIN(created_at) AS created_at
    FROM fortress_refresh_token
    GROUP BY token_family
  ) AS family
  WHERE token.token_family = family.token_family;
ALTER TABLE fortress_refresh_token
  ALTER COLUMN family_created_at SET NOT NULL;
ALTER TABLE fortress_refresh_token
  ALTER COLUMN family_created_at SET DEFAULT now();
ALTER TABLE fortress_refresh_token
  ADD COLUMN successor_token_hash VARCHAR(64);
ALTER TABLE fortress_refresh_token
  ADD COLUMN rotated_at TIMESTAMP;

CREATE TABLE fortress_auth_continuation (
  id SERIAL PRIMARY KEY,
  user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
  token_hash VARCHAR(64) NOT NULL UNIQUE,
  reason VARCHAR(32) NOT NULL,
  expires_at TIMESTAMP NOT NULL,
  consumed_at TIMESTAMP,
  created_at TIMESTAMP NOT NULL DEFAULT now()
);
`.trim();

const PG_0003_DOWN = `
DROP TABLE IF EXISTS fortress_auth_continuation CASCADE;
ALTER TABLE fortress_refresh_token DROP COLUMN rotated_at;
ALTER TABLE fortress_refresh_token DROP COLUMN successor_token_hash;
ALTER TABLE fortress_refresh_token DROP COLUMN family_created_at;
`.trim();

const SQLITE_0004_UP = `
UPDATE fortress_tenant_user
SET is_default = 0
WHERE is_default = 1
  AND rowid NOT IN (
    SELECT MIN(rowid)
    FROM fortress_tenant_user
    WHERE is_default = 1
    GROUP BY user_id
  );
CREATE UNIQUE INDEX IF NOT EXISTS fortress_tenant_user_one_default_idx
  ON fortress_tenant_user (user_id)
  WHERE is_default = 1;
`.trim();

const SQLITE_0004_DOWN = `
DROP INDEX IF EXISTS fortress_tenant_user_one_default_idx;
`.trim();

const PG_0004_UP = `
WITH ranked_defaults AS (
  SELECT ctid, ROW_NUMBER() OVER (PARTITION BY user_id ORDER BY tenant_id) AS position
  FROM fortress_tenant_user
  WHERE is_default = true
)
UPDATE fortress_tenant_user AS membership
SET is_default = false
FROM ranked_defaults
WHERE membership.ctid = ranked_defaults.ctid
  AND ranked_defaults.position > 1;
CREATE UNIQUE INDEX IF NOT EXISTS fortress_tenant_user_one_default_idx
  ON fortress_tenant_user (user_id)
  WHERE is_default = true;
`.trim();

const PG_0004_DOWN = `
DROP INDEX IF EXISTS fortress_tenant_user_one_default_idx;
`.trim();

// --- 0005: hot-path indexes and timezone-safe PostgreSQL timestamps ---

const SQLITE_0005_UP = `
CREATE INDEX refresh_token_family_idx ON fortress_refresh_token (token_family);
CREATE INDEX refresh_token_user_idx ON fortress_refresh_token (user_id);
CREATE INDEX email_verification_token_token_idx ON fortress_email_verification_token (token);
CREATE INDEX magic_link_token_token_idx ON fortress_magic_link_token (token);
CREATE INDEX role_binding_subject_idx ON fortress_role_binding (subject_type, subject_id);
CREATE INDEX direct_permission_binding_subject_idx ON fortress_direct_permission_binding (subject_type, subject_id);
CREATE INDEX backup_code_user_idx ON fortress_backup_code (user_id);
CREATE INDEX trusted_device_user_idx ON fortress_trusted_device (user_id);
CREATE INDEX webhook_delivery_retry_idx ON fortress_webhook_delivery (status, next_retry_at);
CREATE INDEX audit_log_timestamp_idx ON fortress_audit_log (timestamp);
`.trim();

const SQLITE_0005_DOWN = `
DROP INDEX IF EXISTS audit_log_timestamp_idx;
DROP INDEX IF EXISTS webhook_delivery_retry_idx;
DROP INDEX IF EXISTS trusted_device_user_idx;
DROP INDEX IF EXISTS backup_code_user_idx;
DROP INDEX IF EXISTS direct_permission_binding_subject_idx;
DROP INDEX IF EXISTS role_binding_subject_idx;
DROP INDEX IF EXISTS magic_link_token_token_idx;
DROP INDEX IF EXISTS email_verification_token_token_idx;
DROP INDEX IF EXISTS refresh_token_user_idx;
DROP INDEX IF EXISTS refresh_token_family_idx;
`.trim();

const PG_0005_UP = `
CREATE INDEX refresh_token_family_idx ON fortress_refresh_token (token_family);
CREATE INDEX refresh_token_user_idx ON fortress_refresh_token (user_id);
CREATE INDEX email_verification_token_token_idx ON fortress_email_verification_token (token);
CREATE INDEX magic_link_token_token_idx ON fortress_magic_link_token (token);
CREATE INDEX role_binding_subject_idx ON fortress_role_binding (subject_type, subject_id);
CREATE INDEX direct_permission_binding_subject_idx ON fortress_direct_permission_binding (subject_type, subject_id);
CREATE INDEX backup_code_user_idx ON fortress_backup_code (user_id);
CREATE INDEX trusted_device_user_idx ON fortress_trusted_device (user_id);
CREATE INDEX webhook_delivery_retry_idx ON fortress_webhook_delivery (status, next_retry_at);
CREATE INDEX audit_log_timestamp_idx ON fortress_audit_log (timestamp);

ALTER TABLE fortress_schema_version ALTER COLUMN applied_at TYPE TIMESTAMPTZ USING applied_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_user ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_user ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN family_created_at TYPE TIMESTAMPTZ USING family_created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN rotated_at TYPE TIMESTAMPTZ USING rotated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN last_active_at TYPE TIMESTAMPTZ USING last_active_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_auth_continuation ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_auth_continuation ALTER COLUMN consumed_at TYPE TIMESTAMPTZ USING consumed_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_auth_continuation ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_service_account ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_service_account ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_email_verification_token ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_email_verification_token ALTER COLUMN used_at TYPE TIMESTAMPTZ USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_email_verification_token ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_magic_link_token ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_magic_link_token ALTER COLUMN used_at TYPE TIMESTAMPTZ USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_magic_link_token ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_api_key ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_api_key ALTER COLUMN last_used_at TYPE TIMESTAMPTZ USING last_used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_api_key ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_two_factor_secret ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_backup_code ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_trusted_device ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_trusted_device ALTER COLUMN last_used_at TYPE TIMESTAMPTZ USING last_used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_trusted_device ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_social_account ALTER COLUMN token_expires_at TYPE TIMESTAMPTZ USING token_expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_social_account ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_social_account ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_tenant ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_tenant ALTER COLUMN updated_at TYPE TIMESTAMPTZ USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_client ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN used_at TYPE TIMESTAMPTZ USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_access_token ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_access_token ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN issued_at TYPE TIMESTAMPTZ USING issued_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN used_at TYPE TIMESTAMPTZ USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN used_at TYPE TIMESTAMPTZ USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_signing_key ALTER COLUMN rotated_at TYPE TIMESTAMPTZ USING rotated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_signing_key ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_user_scope_assignment ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_account_lockout ALTER COLUMN last_failed_at TYPE TIMESTAMPTZ USING last_failed_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_account_lockout ALTER COLUMN locked_until TYPE TIMESTAMPTZ USING locked_until AT TIME ZONE 'UTC';
ALTER TABLE fortress_account_lockout ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_audit_log ALTER COLUMN timestamp TYPE TIMESTAMPTZ USING timestamp AT TIME ZONE 'UTC';
ALTER TABLE fortress_audit_log ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_endpoint ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_delivery ALTER COLUMN last_attempt_at TYPE TIMESTAMPTZ USING last_attempt_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_delivery ALTER COLUMN next_retry_at TYPE TIMESTAMPTZ USING next_retry_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_delivery ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webauthn_credential ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webauthn_challenge ALTER COLUMN expires_at TYPE TIMESTAMPTZ USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webauthn_challenge ALTER COLUMN created_at TYPE TIMESTAMPTZ USING created_at AT TIME ZONE 'UTC';
`.trim();

const PG_0005_DOWN = `
ALTER TABLE fortress_schema_version ALTER COLUMN applied_at TYPE TIMESTAMP USING applied_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_user ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_user ALTER COLUMN updated_at TYPE TIMESTAMP USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN family_created_at TYPE TIMESTAMP USING family_created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN rotated_at TYPE TIMESTAMP USING rotated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN last_active_at TYPE TIMESTAMP USING last_active_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_refresh_token ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_auth_continuation ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_auth_continuation ALTER COLUMN consumed_at TYPE TIMESTAMP USING consumed_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_auth_continuation ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_service_account ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_service_account ALTER COLUMN updated_at TYPE TIMESTAMP USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_email_verification_token ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_email_verification_token ALTER COLUMN used_at TYPE TIMESTAMP USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_email_verification_token ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_magic_link_token ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_magic_link_token ALTER COLUMN used_at TYPE TIMESTAMP USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_magic_link_token ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_api_key ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_api_key ALTER COLUMN last_used_at TYPE TIMESTAMP USING last_used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_api_key ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_two_factor_secret ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_backup_code ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_trusted_device ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_trusted_device ALTER COLUMN last_used_at TYPE TIMESTAMP USING last_used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_trusted_device ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_social_account ALTER COLUMN token_expires_at TYPE TIMESTAMP USING token_expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_social_account ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_social_account ALTER COLUMN updated_at TYPE TIMESTAMP USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_tenant ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_tenant ALTER COLUMN updated_at TYPE TIMESTAMP USING updated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_client ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN used_at TYPE TIMESTAMP USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_authorization_code ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_access_token ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_access_token ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN issued_at TYPE TIMESTAMP USING issued_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN used_at TYPE TIMESTAMP USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_refresh_token ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN used_at TYPE TIMESTAMP USING used_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_pending_flow ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_signing_key ALTER COLUMN rotated_at TYPE TIMESTAMP USING rotated_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_oauth_signing_key ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_user_scope_assignment ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_account_lockout ALTER COLUMN last_failed_at TYPE TIMESTAMP USING last_failed_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_account_lockout ALTER COLUMN locked_until TYPE TIMESTAMP USING locked_until AT TIME ZONE 'UTC';
ALTER TABLE fortress_account_lockout ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_audit_log ALTER COLUMN timestamp TYPE TIMESTAMP USING timestamp AT TIME ZONE 'UTC';
ALTER TABLE fortress_audit_log ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_endpoint ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_delivery ALTER COLUMN last_attempt_at TYPE TIMESTAMP USING last_attempt_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_delivery ALTER COLUMN next_retry_at TYPE TIMESTAMP USING next_retry_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webhook_delivery ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webauthn_credential ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webauthn_challenge ALTER COLUMN expires_at TYPE TIMESTAMP USING expires_at AT TIME ZONE 'UTC';
ALTER TABLE fortress_webauthn_challenge ALTER COLUMN created_at TYPE TIMESTAMP USING created_at AT TIME ZONE 'UTC';

DROP INDEX IF EXISTS audit_log_timestamp_idx;
DROP INDEX IF EXISTS webhook_delivery_retry_idx;
DROP INDEX IF EXISTS trusted_device_user_idx;
DROP INDEX IF EXISTS backup_code_user_idx;
DROP INDEX IF EXISTS direct_permission_binding_subject_idx;
DROP INDEX IF EXISTS role_binding_subject_idx;
DROP INDEX IF EXISTS magic_link_token_token_idx;
DROP INDEX IF EXISTS email_verification_token_token_idx;
DROP INDEX IF EXISTS refresh_token_user_idx;
DROP INDEX IF EXISTS refresh_token_family_idx;
`.trim();

export const fortressMigrations: Record<MigrationDialect, FortressMigration[]> = {
  sqlite: [
    { version: 1, name: 'schema_version', dialect: 'sqlite', up: SQLITE_0001_UP, down: SQLITE_0001_DOWN },
    { version: 2, name: 'initial_schema', dialect: 'sqlite', up: SQLITE_0002_UP, down: SQLITE_0002_DOWN },
    { version: 3, name: 'auth_continuation', dialect: 'sqlite', up: SQLITE_0003_UP, down: SQLITE_0003_DOWN },
    { version: 4, name: 'tenant_default_unique', dialect: 'sqlite', up: SQLITE_0004_UP, down: SQLITE_0004_DOWN },
    { version: 5, name: 'hot_indexes_timestamptz', dialect: 'sqlite', up: SQLITE_0005_UP, down: SQLITE_0005_DOWN },
  ],
  pg: [
    { version: 1, name: 'schema_version', dialect: 'pg', up: PG_0001_UP, down: PG_0001_DOWN },
    { version: 2, name: 'initial_schema', dialect: 'pg', up: PG_0002_UP, down: PG_0002_DOWN },
    { version: 3, name: 'auth_continuation', dialect: 'pg', up: PG_0003_UP, down: PG_0003_DOWN },
    { version: 4, name: 'tenant_default_unique', dialect: 'pg', up: PG_0004_UP, down: PG_0004_DOWN },
    { version: 5, name: 'hot_indexes_timestamptz', dialect: 'pg', up: PG_0005_UP, down: PG_0005_DOWN },
  ],
};

export function getFortressMigrations(dialect: MigrationDialect): FortressMigration[] {
  return [...fortressMigrations[dialect]].sort((a, b) => a.version - b.version);
}

export function getLatestMigrationVersion(dialect: MigrationDialect): number {
  return getFortressMigrations(dialect).at(-1)?.version ?? 0;
}

/**
 * Concatenated forward SQL for every bundled migration of a dialect, in
 * version order. `src/testing/index.ts` provisions its in-memory schema
 * from this so the test adapter and production migrations can never drift.
 */
export function getMigrationUpSql(dialect: MigrationDialect): string {
  return getFortressMigrations(dialect).map(migration => migration.up).join('\n\n');
}

/**
 * Canonical list of every Fortress-owned table. Used by
 * {@link detectMigrationDrift} to surface live-DB drift beyond just the
 * `fortress_schema_version` checkpoint — any of these tables missing in
 * the target database signals an incomplete or stale migration state.
 *
 * Keep in sync with `src/drizzle/{schema,pg/schema}.ts` and the bundled
 * migrations. The list is asserted by `src/core/migrations/engine.test.ts`
 * against the test adapter so an accidental drop/add is caught at test time.
 */
export const FORTRESS_TABLES: readonly string[] = [
  'fortress_schema_version',
  'fortress_user',
  'fortress_login_identifier',
  'fortress_refresh_token',
  'fortress_auth_continuation',
  'fortress_group',
  'fortress_group_user',
  'fortress_service_account',
  'fortress_resource',
  'fortress_permission',
  'fortress_role',
  'fortress_role_permission',
  'fortress_role_binding',
  'fortress_direct_permission_binding',
  'fortress_email_verification_token',
  'fortress_magic_link_token',
  'fortress_api_key',
  'fortress_two_factor_secret',
  'fortress_backup_code',
  'fortress_trusted_device',
  'fortress_social_account',
  'fortress_tenant',
  'fortress_tenant_user',
  'fortress_oauth_client',
  'fortress_oauth_authorization_code',
  'fortress_oauth_access_token',
  'fortress_oauth_refresh_token',
  'fortress_oauth_pending_flow',
  'fortress_oauth_signing_key',
  'fortress_user_scope_assignment',
  'fortress_account_lockout',
  'fortress_audit_log',
  'fortress_webhook_endpoint',
  'fortress_webhook_delivery',
  'fortress_webauthn_credential',
  'fortress_webauthn_challenge',
] as const;

/** Hot-path indexes whose presence is part of the runtime schema contract. */
export const FORTRESS_INDEXES: ReadonlyArray<{
  name: string;
  table: string;
  columns: readonly string[];
}> = [
  { name: 'refresh_token_family_idx', table: 'fortress_refresh_token', columns: ['token_family'] },
  { name: 'refresh_token_user_idx', table: 'fortress_refresh_token', columns: ['user_id'] },
  { name: 'email_verification_token_token_idx', table: 'fortress_email_verification_token', columns: ['token'] },
  { name: 'magic_link_token_token_idx', table: 'fortress_magic_link_token', columns: ['token'] },
  { name: 'role_binding_subject_idx', table: 'fortress_role_binding', columns: ['subject_type', 'subject_id'] },
  { name: 'direct_permission_binding_subject_idx', table: 'fortress_direct_permission_binding', columns: ['subject_type', 'subject_id'] },
  { name: 'backup_code_user_idx', table: 'fortress_backup_code', columns: ['user_id'] },
  { name: 'trusted_device_user_idx', table: 'fortress_trusted_device', columns: ['user_id'] },
  { name: 'webhook_delivery_retry_idx', table: 'fortress_webhook_delivery', columns: ['status', 'next_retry_at'] },
  { name: 'audit_log_timestamp_idx', table: 'fortress_audit_log', columns: ['timestamp'] },
] as const;

const CONSTRAINT_KEYWORDS = new Set(['primary', 'unique', 'foreign', 'constraint', 'check']);

const CREATE_TABLE_RE = /create\s+table\s+(?:if\s+not\s+exists\s+)?(\w+)\s*\(/gi;
const ADD_COLUMN_RE = /alter\s+table\s+(\w+)\s+add\s+column\s+(\w+)/gi;
const RENAME_TABLE_RE = /alter\s+table\s+(\w+)\s+rename\s+to\s+(\w+)/gi;
const WHITESPACE_RE = /\s+/;
const QUOTE_CHARS_RE = /["'`]/g;

/**
 * Parse the expected column set of every Fortress table directly out of the
 * bundled migration DDL. Because the migrations are the SQL-first source of
 * truth, this needs no schema description maintained on the side and no
 * Drizzle-specific tooling — it works for any adapter. Powers the
 * column-level half of {@link detectMigrationDrift}.
 *
 * The parser is intentionally narrow: it understands the controlled DDL
 * Fortress emits (`CREATE TABLE [IF NOT EXISTS] name ( ... );` with
 * comma-separated definitions, plus the controlled `ALTER TABLE` add-column
 * and rename forms used by incremental migrations). Constraint-only lines
 * (PRIMARY KEY (...), UNIQUE (...), etc.) and
 * standalone CREATE INDEX statements are skipped.
 */
export function getExpectedColumns(dialect: MigrationDialect): Record<string, string[]> {
  const sql = getMigrationUpSql(dialect)
    // Strip line comments so `-- ...` never leaks into a column name.
    .split('\n')
    .filter(line => !line.trimStart().startsWith('--'))
    .join('\n');

  const result: Record<string, string[]> = {};
  // CREATE_TABLE_RE carries the global flag (stateful lastIndex); reset it so
  // repeated calls always scan from the start.
  CREATE_TABLE_RE.lastIndex = 0;

  let match = CREATE_TABLE_RE.exec(sql);
  while (match !== null) {
    const tableName = match[1];
    const bodyStart = match.index + match[0].length;

    // Walk forward tracking paren depth to find the matching close paren.
    let depth = 1;
    let i = bodyStart;
    for (; i < sql.length && depth > 0; i++) {
      if (sql[i] === '(')
        depth++;
      else if (sql[i] === ')')
        depth--;
    }
    const body = sql.slice(bodyStart, i - 1);

    result[tableName] = extractColumnNames(body);
    CREATE_TABLE_RE.lastIndex = i;
    match = CREATE_TABLE_RE.exec(sql);
  }

  // Later migrations add columns to tables created by an earlier version.
  // Include those additions in drift expectations without rewriting the
  // immutable baseline migration.
  ADD_COLUMN_RE.lastIndex = 0;
  let addMatch = ADD_COLUMN_RE.exec(sql);
  while (addMatch !== null) {
    const [, tableName, columnName] = addMatch;
    const columns = result[tableName] ?? (result[tableName] = []);
    const normalized = columnName.toLowerCase();
    if (!columns.includes(normalized))
      columns.push(normalized);
    addMatch = ADD_COLUMN_RE.exec(sql);
  }

  // SQLite table rebuilds create a versioned replacement and rename it over
  // the prior table. Reflect that final name/shape in drift expectations.
  RENAME_TABLE_RE.lastIndex = 0;
  let renameMatch = RENAME_TABLE_RE.exec(sql);
  while (renameMatch !== null) {
    const [, fromName, toName] = renameMatch;
    if (result[fromName]) {
      result[toName] = result[fromName];
      delete result[fromName];
    }
    renameMatch = RENAME_TABLE_RE.exec(sql);
  }

  return result;
}

function extractColumnNames(body: string): string[] {
  const columns: string[] = [];
  let depth = 0;
  let current = '';

  const flush = (): void => {
    const trimmed = current.trim();
    current = '';
    if (!trimmed)
      return;
    const firstWord = trimmed.split(WHITESPACE_RE)[0].replace(QUOTE_CHARS_RE, '').toLowerCase();
    if (!firstWord || CONSTRAINT_KEYWORDS.has(firstWord))
      return;
    columns.push(firstWord);
  };

  for (const char of body) {
    if (char === '(') {
      depth++;
      current += char;
    }
    else if (char === ')') {
      depth--;
      current += char;
    }
    else if (char === ',' && depth === 0) {
      flush();
    }
    else {
      current += char;
    }
  }
  flush();

  return columns;
}
