import type { Sql } from 'postgres';
import type { StartedTestContainer } from 'testcontainers';
import type { DatabaseAdapter } from '../../adapters/database';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { GenericContainer, Wait } from 'testcontainers';

import { afterAll, beforeAll, beforeEach, describe } from 'vitest';
import { runAdapterTests } from '../../testing/adapter-conformance.test';
import { createDrizzleAdapter } from '../adapter';

const CREATE_TABLES_SQL = `
  CREATE TABLE IF NOT EXISTS fortress_user (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    password_hash TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
    email_verified BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
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
    family_created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    successor_token_hash VARCHAR(64),
    rotated_at TIMESTAMP,
    is_revoked BOOLEAN NOT NULL DEFAULT false,
    expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_name TEXT,
    last_active_at TIMESTAMP,
    fingerprint_hash VARCHAR(64),
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_auth_continuation (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    token_hash VARCHAR(64) NOT NULL UNIQUE,
    reason VARCHAR(32) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    consumed_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
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
    subject_id INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS fortress_email_verification_token (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    token TEXT NOT NULL,
    email VARCHAR(255) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_magic_link_token (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );
  CREATE INDEX IF NOT EXISTS api_key_subject_idx ON fortress_api_key (subject_type, subject_id);

  CREATE TABLE IF NOT EXISTS fortress_two_factor_secret (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL UNIQUE REFERENCES fortress_user(id) ON DELETE CASCADE,
    secret TEXT NOT NULL,
    is_enabled BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_backup_code (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    code_hash TEXT NOT NULL,
    is_used BOOLEAN NOT NULL DEFAULT false,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_trusted_device (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    device_hash VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    last_used_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_tenant (
    id SERIAL PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    tax_id VARCHAR(100) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMP NOT NULL DEFAULT NOW()
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_oauth_access_token (
    id SERIAL PRIMARY KEY,
    token VARCHAR(255) NOT NULL UNIQUE,
    client_id VARCHAR(255) NOT NULL,
    user_id INTEGER,
    scope TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_oauth_pending_flow (
    id SERIAL PRIMARY KEY,
    client_id VARCHAR(255) NOT NULL,
    redirect_uri TEXT NOT NULL,
    scope TEXT,
    state VARCHAR(255) NOT NULL,
    code_challenge TEXT,
    code_challenge_method VARCHAR(10),
    nonce TEXT,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_oauth_signing_key (
    id SERIAL PRIMARY KEY,
    kid VARCHAR(64) NOT NULL UNIQUE,
    alg VARCHAR(16) NOT NULL,
    public_jwk TEXT NOT NULL,
    private_jwk TEXT NOT NULL,
    rotated_at TIMESTAMP,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_user_scope_assignment (
    id SERIAL PRIMARY KEY,
    user_id INTEGER NOT NULL REFERENCES fortress_user(id) ON DELETE CASCADE,
    scope_name VARCHAR(100) NOT NULL,
    scope_value VARCHAR(255) NOT NULL,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_account_lockout (
    id SERIAL PRIMARY KEY,
    identifier VARCHAR(255) NOT NULL UNIQUE,
    failed_attempts INTEGER NOT NULL DEFAULT 0,
    last_failed_at TIMESTAMP,
    locked_until TIMESTAMP,
    lockout_count INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_audit_log (
    id SERIAL PRIMARY KEY,
    timestamp TIMESTAMP NOT NULL DEFAULT NOW(),
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_webhook_endpoint (
    id SERIAL PRIMARY KEY,
    url TEXT NOT NULL,
    events TEXT NOT NULL,
    secret TEXT NOT NULL,
    is_active BOOLEAN NOT NULL DEFAULT true,
    deactivated_reason TEXT,
    consecutive_failures INTEGER NOT NULL DEFAULT 0,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE UNIQUE INDEX IF NOT EXISTS uniq_webhook_delivery_idempotency
    ON fortress_webhook_delivery (endpoint_id, idempotency_key)
    WHERE idempotency_key IS NOT NULL;
`;

const TRUNCATE_SQL = `
  TRUNCATE
    fortress_webhook_delivery,
    fortress_webhook_endpoint,
    fortress_audit_log,
    fortress_account_lockout,
    fortress_user_scope_assignment,
    fortress_oauth_signing_key,
    fortress_oauth_pending_flow,
    fortress_oauth_refresh_token,
    fortress_oauth_access_token,
    fortress_oauth_authorization_code,
    fortress_oauth_client,
    fortress_tenant_user,
    fortress_tenant,
    fortress_social_account,
    fortress_trusted_device,
    fortress_backup_code,
    fortress_two_factor_secret,
    fortress_api_key,
    fortress_magic_link_token,
    fortress_email_verification_token,
    fortress_role_binding,
    fortress_role_permission,
    fortress_permission,
    fortress_resource,
    fortress_role,
    fortress_service_account,
    fortress_group_user,
    fortress_group,
    fortress_auth_continuation,
    fortress_refresh_token,
    fortress_login_identifier,
    fortress_user
  CASCADE;
`;

let container: StartedTestContainer;
let pgClient: Sql;
let db: ReturnType<typeof drizzle>;

beforeAll(async () => {
  container = await new GenericContainer('postgres:16-alpine')
    .withEnvironment({
      POSTGRES_USER: 'test',
      POSTGRES_PASSWORD: 'test',
      POSTGRES_DB: 'fortress_test',
    })
    .withExposedPorts(5432)
    .withWaitStrategy(Wait.forListeningPorts())
    .start();

  const connectionString = `postgres://test:test@${container.getHost()}:${container.getMappedPort(5432)}/fortress_test`;
  pgClient = postgres(connectionString);
  db = drizzle(pgClient);

  await pgClient.unsafe(CREATE_TABLES_SQL);
}, 60_000);

afterAll(async () => {
  if (pgClient)
    await pgClient.end();
  if (container)
    await container.stop();
});

beforeEach(async () => {
  await pgClient.unsafe(TRUNCATE_SQL);
});

function createPgTestAdapter(): DatabaseAdapter {
  return createDrizzleAdapter(db as any, { dialect: 'pg' });
}

describe('adapter conformance: PostgreSQL (drizzle)', () => {
  runAdapterTests(createPgTestAdapter);
});
