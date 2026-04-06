import type { Sql } from 'postgres';
import type { StartedTestContainer } from 'testcontainers';
import type { DatabaseAdapter } from '../../adapters/database';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { GenericContainer, Wait } from 'testcontainers';

import { afterAll, beforeAll, beforeEach, describe } from 'vitest';
import { runAdapterTests } from '../../testing/adapter-conformance.test';
import { createDrizzleAdapter } from '../adapter';
import { fortressPgSchema } from './schema';

const PG_TABLE_MAP = {
  user: fortressPgSchema.users,
  login_identifier: fortressPgSchema.loginIdentifiers,
  refresh_token: fortressPgSchema.refreshTokens,
  group: fortressPgSchema.groups,
  group_user: fortressPgSchema.groupUsers,
  resource: fortressPgSchema.resources,
  permission: fortressPgSchema.permissions,
  role: fortressPgSchema.roles,
  role_permission: fortressPgSchema.rolePermissions,
  role_binding: fortressPgSchema.roleBindings,
  magic_link_token: fortressPgSchema.magicLinkTokens,
  account_lockout: fortressPgSchema.accountLockouts,
  audit_log: fortressPgSchema.auditLogs,
  webhook_endpoint: fortressPgSchema.webhookEndpoints,
  webhook_delivery: fortressPgSchema.webhookDeliveries,
};

const CREATE_TABLES_SQL = `
  CREATE TABLE IF NOT EXISTS fortress_user (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL UNIQUE,
    name VARCHAR(255) NOT NULL,
    password_hash TEXT,
    is_active BOOLEAN NOT NULL DEFAULT true,
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
    is_revoked BOOLEAN NOT NULL DEFAULT false,
    expires_at TIMESTAMP NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    device_name TEXT,
    last_active_at TIMESTAMP,
    fingerprint_hash VARCHAR(64),
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

  CREATE TABLE IF NOT EXISTS fortress_magic_link_token (
    id SERIAL PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token VARCHAR(64) NOT NULL,
    expires_at TIMESTAMP NOT NULL,
    used_at TIMESTAMP,
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
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );

  CREATE TABLE IF NOT EXISTS fortress_webhook_delivery (
    id SERIAL PRIMARY KEY,
    endpoint_id INTEGER NOT NULL REFERENCES fortress_webhook_endpoint(id) ON DELETE CASCADE,
    event_type VARCHAR(100) NOT NULL,
    payload TEXT NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'pending',
    attempts INTEGER NOT NULL DEFAULT 0,
    last_attempt_at TIMESTAMP,
    next_retry_at TIMESTAMP,
    response_status INTEGER,
    created_at TIMESTAMP NOT NULL DEFAULT NOW()
  );
`;

const TRUNCATE_SQL = `
  TRUNCATE
    fortress_webhook_delivery,
    fortress_webhook_endpoint,
    fortress_audit_log,
    fortress_account_lockout,
    fortress_magic_link_token,
    fortress_role_binding,
    fortress_role_permission,
    fortress_permission,
    fortress_resource,
    fortress_role,
    fortress_group_user,
    fortress_group,
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
    .withWaitStrategy(Wait.forLogMessage('database system is ready to accept connections'))
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
  return createDrizzleAdapter(db as any, {
    dialect: 'pg',
    tables: PG_TABLE_MAP,
  });
}

describe('adapter conformance: PostgreSQL (drizzle)', () => {
  runAdapterTests(createPgTestAdapter);
});
