import type { Sql } from 'postgres';
import type { StartedTestContainer } from 'testcontainers';
import type { DatabaseAdapter } from '../../adapters/database';
import type { Fortress } from '../../core/fortress';
import type { FortressUser } from '../../core/types';
import { drizzle } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';
import { GenericContainer, Wait } from 'testcontainers';

import { afterAll, beforeAll, beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { accountLockout } from '../../plugins/account-lockout';
import { apiKey } from '../../plugins/api-key';
import { auditLog } from '../../plugins/audit-log';
import { dataIsolation } from '../../plugins/data-isolation';
import { emailVerification } from '../../plugins/email-verification';
import { magicLink } from '../../plugins/magic-link';
import { oauth } from '../../plugins/oauth';
import { socialLogin } from '../../plugins/social-login';
import { tenancy } from '../../plugins/tenancy';
import { generateTOTP, twoFactor } from '../../plugins/two-factor';
import { webhook } from '../../plugins/webhook';
import { createDrizzleAdapter } from '../adapter';

const WEBHOOK_SECRET_PREFIX = /^whsec_/;

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
    subject_id INTEGER NOT NULL,
    tenant_id VARCHAR(100)
  );

  CREATE TABLE IF NOT EXISTS fortress_direct_permission_binding (
    id SERIAL PRIMARY KEY,
    permission_id INTEGER NOT NULL REFERENCES fortress_permission(id) ON DELETE CASCADE,
    subject_type VARCHAR(20) NOT NULL,
    subject_id INTEGER NOT NULL,
    tenant_id VARCHAR(100)
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
    last_used_counter INTEGER,
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
    fortress_direct_permission_binding,
    fortress_role_binding,
    fortress_role_permission,
    fortress_permission,
    fortress_resource,
    fortress_role,
    fortress_service_account,
    fortress_group_user,
    fortress_group,
    fortress_refresh_token,
    fortress_login_identifier,
    fortress_user
  CASCADE;
`;

const SECRET = 'pg-integration-test-secret-at-least-32!!';

let container: StartedTestContainer;
let pgClient: Sql;
let db: ReturnType<typeof drizzle>;

function createPgAdapter(): DatabaseAdapter {
  return createDrizzleAdapter(db as any, { dialect: 'pg' });
}

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

// --- PG-specific date handling ---

describe('pg: date handling', () => {
  it('returns Date objects for timestamp columns', async () => {
    const adapter = createPgAdapter();
    const user = await adapter.create<{ id: string; createdAt: Date; updatedAt: Date }>({
      model: 'user',
      data: { email: 'dates@test.com', name: 'Dates', passwordHash: 'h', isActive: true },
    });

    expect(user.createdAt).toBeInstanceOf(Date);
    expect(user.updatedAt).toBeInstanceOf(Date);
  });

  it('round-trips Date objects through create and findOne', async () => {
    const adapter = createPgAdapter();
    const user = await adapter.create<{ id: string }>({
      model: 'user',
      data: { email: 'rt@test.com', name: 'RT', passwordHash: 'h', isActive: true },
    });

    const expiresAt = new Date('2099-06-15T12:00:00.000Z');
    await adapter.create({
      model: 'refresh_token',
      data: {
        userId: user.id,
        tokenHash: 'pg-date-test',
        tokenFamily: 'fam-pg',
        isRevoked: false,
        expiresAt,
      },
    });

    const found = await adapter.findOne<{ expiresAt: Date }>({
      model: 'refresh_token',
      where: [{ field: 'tokenHash', operator: '=', value: 'pg-date-test' }],
    });

    expect(found).not.toBeNull();
    expect(found!.expiresAt).toBeInstanceOf(Date);
    expect(found!.expiresAt.getTime()).toBe(expiresAt.getTime());
  });

  it('supports date comparison operators (gt, lt)', async () => {
    const adapter = createPgAdapter();
    const user = await adapter.create<{ id: string }>({
      model: 'user',
      data: { email: 'cmp@test.com', name: 'Cmp', passwordHash: 'h', isActive: true },
    });

    const past = new Date('2020-01-01T00:00:00.000Z');
    const future = new Date('2099-01-01T00:00:00.000Z');

    await adapter.create({
      model: 'refresh_token',
      data: { userId: user.id, tokenHash: 'expired', tokenFamily: 'f1', isRevoked: false, expiresAt: past },
    });
    await adapter.create({
      model: 'refresh_token',
      data: { userId: user.id, tokenHash: 'valid', tokenFamily: 'f2', isRevoked: false, expiresAt: future },
    });

    const validTokens = await adapter.findMany<{ tokenHash: string }>({
      model: 'refresh_token',
      where: [{ field: 'expiresAt', operator: 'gt', value: new Date() }],
    });

    expect(validTokens).toHaveLength(1);
    expect(validTokens[0].tokenHash).toBe('valid');
  });

  it('handles nullable timestamp columns', async () => {
    const adapter = createPgAdapter();
    const user = await adapter.create<{ id: string }>({
      model: 'user',
      data: { email: 'null-ts@test.com', name: 'NullTs', passwordHash: 'h', isActive: true },
    });

    await adapter.create({
      model: 'refresh_token',
      data: {
        userId: user.id,
        tokenHash: 'null-ts-test',
        tokenFamily: 'fam',
        isRevoked: false,
        expiresAt: new Date('2099-01-01'),
        lastActiveAt: null,
      },
    });

    const found = await adapter.findOne<{ lastActiveAt: Date | null }>({
      model: 'refresh_token',
      where: [{ field: 'tokenHash', operator: '=', value: 'null-ts-test' }],
    });

    expect(found!.lastActiveAt).toBeNull();

    // Update with a Date
    await adapter.update({
      model: 'refresh_token',
      where: [{ field: 'tokenHash', operator: '=', value: 'null-ts-test' }],
      data: { lastActiveAt: new Date() },
    });

    const updated = await adapter.findOne<{ lastActiveAt: Date | null }>({
      model: 'refresh_token',
      where: [{ field: 'tokenHash', operator: '=', value: 'null-ts-test' }],
    });

    expect(updated!.lastActiveAt).toBeInstanceOf(Date);
  });

  it('handles boolean values natively', async () => {
    const adapter = createPgAdapter();
    const user = await adapter.create<{ id: string; isActive: boolean }>({
      model: 'user',
      data: { email: 'bool@test.com', name: 'Bool', passwordHash: 'h', isActive: false },
    });

    expect(user.isActive).toBe(false);

    const found = await adapter.findOne<{ isActive: boolean }>({
      model: 'user',
      where: [{ field: 'isActive', operator: '=', value: false }],
    });

    expect(found).not.toBeNull();
    expect(found!.isActive).toBe(false);
  });
});

// --- Full auth lifecycle on PG ---

describe('pg: auth lifecycle', () => {
  let fortress: Fortress;

  beforeEach(() => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
    });
  });

  it('creates user and logs in', async () => {
    const user = await fortress.auth.createUser({
      email: 'alice@test.com',
      name: 'Alice',
      password: 'password-123',
    });

    expect(user.id).toBeDefined();
    expect(user.email).toBe('alice@test.com');
    expect(user.createdAt).toBeInstanceOf(Date);

    const result = await fortress.auth.login('alice@test.com', 'password-123');
    expect(result.accessToken).toBeTruthy();
    expect(result.refreshToken).toBeTruthy();
    expect(result.user.email).toBe('alice@test.com');
  });

  it('rejects invalid credentials', async () => {
    await fortress.auth.createUser({
      email: 'bob@test.com',
      name: 'Bob',
      password: 'password-123',
    });

    await expect(
      fortress.auth.login('bob@test.com', 'wrong-password'),
    ).rejects.toThrow('Invalid credentials');
  });

  it('refreshes tokens', async () => {
    await fortress.auth.createUser({
      email: 'refresh@test.com',
      name: 'Refresh',
      password: 'password-123',
    });

    const login = await fortress.auth.login('refresh@test.com', 'password-123');
    // Wait 1s so the new JWT has a different iat/exp (JWT timestamps are in seconds)
    await new Promise(r => setTimeout(r, 1100));
    const refreshed = await fortress.auth.refresh(login.refreshToken as string);

    expect(refreshed.accessToken).toBeTruthy();
    expect(refreshed.refreshToken).toBeTruthy();
    expect(refreshed.accessToken).not.toBe(login.accessToken as string);
    expect(refreshed.refreshToken).not.toBe(login.refreshToken as string);
  });

  it('detects token reuse after refresh', async () => {
    await fortress.auth.createUser({
      email: 'reuse@test.com',
      name: 'Reuse',
      password: 'password-123',
    });

    const login = await fortress.auth.login('reuse@test.com', 'password-123');
    await fortress.auth.refresh(login.refreshToken as string);

    // Using the old refresh token again should fail
    await expect(
      fortress.auth.refresh(login.refreshToken as string),
    ).rejects.toThrow();
  });

  it('logs out by revoking refresh token', async () => {
    await fortress.auth.createUser({
      email: 'logout@test.com',
      name: 'Logout',
      password: 'password-123',
    });

    const login = await fortress.auth.login('logout@test.com', 'password-123');
    await fortress.auth.logout(login.refreshToken as string);

    await expect(
      fortress.auth.refresh(login.refreshToken as string),
    ).rejects.toThrow();
  });

  it('verifies access tokens', async () => {
    await fortress.auth.createUser({
      email: 'verify@test.com',
      name: 'Verify',
      password: 'password-123',
    });

    const login = await fortress.auth.login('verify@test.com', 'password-123');
    const claims = await fortress.auth.verifyToken(login.accessToken as string);

    expect(claims.sub).toBe(login.user.id);
    expect(claims.name).toBe('Verify');
  });

  it('lists active sessions', async () => {
    await fortress.auth.createUser({
      email: 'sessions@test.com',
      name: 'Sessions',
      password: 'password-123',
    });

    const login1 = await fortress.auth.login('sessions@test.com', 'password-123');
    await fortress.auth.login('sessions@test.com', 'password-123');

    const sessions = await fortress.auth.listSessions(login1.user.id);
    expect(sessions.length).toBeGreaterThanOrEqual(2);
    expect(sessions[0].createdAt).toBeInstanceOf(Date);
  });

  it('prevents duplicate user creation', async () => {
    await fortress.auth.createUser({
      email: 'dupe@test.com',
      name: 'Dupe',
      password: 'password-123',
    });

    await expect(
      fortress.auth.createUser({ email: 'dupe@test.com', name: 'Dupe 2', password: 'pass' }),
    ).rejects.toThrow('already exists');
  });
});

// --- IAM on PG ---

describe('pg: IAM', () => {
  let fortress: Fortress;
  let user: FortressUser;

  beforeEach(async () => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
    });

    user = await fortress.auth.createUser({
      email: 'iam@test.com',
      name: 'IAM User',
      password: 'password-123',
    });
  });

  it('creates roles with permissions and checks access', async () => {
    const role = await fortress.iam.createRole('editor', [
      { resource: 'post', action: 'read' },
      { resource: 'post', action: 'write' },
    ]);

    await fortress.iam.bindRoleToUser(user.id, role.id);

    const canRead = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'read');
    const canWrite = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'write');
    const canDelete = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'delete');

    expect(canRead).toBe(true);
    expect(canWrite).toBe(true);
    expect(canDelete).toBe(false);
  });

  it('resolves permissions through group bindings', async () => {
    const group = await fortress.iam.createGroup('admins');
    await fortress.iam.addUserToGroup(group.id, user.id);

    const role = await fortress.iam.createRole('admin', [
      { resource: 'user', action: 'manage' },
    ]);
    await fortress.iam.bindRoleToGroup(group.id, role.id);

    const allowed = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'user', 'manage');
    expect(allowed).toBe(true);
  });
});

// --- Plugins on PG ---

describe('pg: plugins', () => {
  it('api-key plugin works with PG dates', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [apiKey({ prefix: 'test' })],
    });

    const user = await fortress.auth.createUser({
      email: 'apikey@test.com',
      name: 'ApiKey',
      password: 'password-123',
    });

    const methods = fortress.plugins['api-key'] as any;
    const userSubject = { type: 'USER' as const, id: user.id };
    const { key } = await methods.createKey({
      subject: userSubject,
      name: 'Test Key',
      expiresAt: new Date(Date.now() + 3600000),
    });

    expect(key).toBeTruthy();

    const resolved = await methods.resolveKey(key);
    expect(resolved).not.toBeNull();
    expect(resolved.subject.type).toBe('USER');
    expect(resolved.subject.id).toBe(user.id);

    const keys = await methods.listKeys({ subject: userSubject });
    expect(keys).toHaveLength(1);
    expect(keys[0].expiresAt).toBeInstanceOf(Date);
    expect(keys[0].createdAt).toBeInstanceOf(Date);
  });

  it('email-verification plugin works with PG dates', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [emailVerification({
        requireVerification: false,
        onSendVerification: async () => {},
      })],
    });

    const user = await fortress.auth.createUser({
      email: 'verify@test.com',
      name: 'Verify',
      password: 'password-123',
    });

    const methods = fortress.plugins['email-verification'] as any;
    const { token } = await methods.sendVerification(user.id);
    expect(token).toBeTruthy();

    const result = await methods.verify(token);
    expect(result.userId).toBe(user.id);
    expect(result.email).toBe('verify@test.com');
  });

  it('audit-log plugin records events with PG timestamps', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [auditLog()],
    });

    await fortress.auth.createUser({
      email: 'audit@test.com',
      name: 'Audit',
      password: 'password-123',
    });

    await fortress.auth.login('audit@test.com', 'password-123');

    const methods = fortress.plugins['audit-log'] as any;
    const entries = await methods.getAuditLog();

    expect(entries.length).toBeGreaterThanOrEqual(1);
    expect(entries[0].timestamp).toBeInstanceOf(Date);
    expect(entries[0].createdAt).toBeInstanceOf(Date);
    expect(entries[0].eventType).toBe('LOGIN_SUCCESS');
  });
});

// --- PG transactions ---

describe('pg: transactions', () => {
  it('commits on success with async PG transactions', async () => {
    const adapter = createPgAdapter();

    await adapter.transaction(async (tx) => {
      await tx.create({ model: 'user', data: { email: 'tx1@test.com', name: 'TX1', passwordHash: 'h', isActive: true } });
      await tx.create({ model: 'user', data: { email: 'tx2@test.com', name: 'TX2', passwordHash: 'h', isActive: true } });
    });

    const count = await adapter.count({ model: 'user' });
    expect(count).toBe(2);
  });

  it('rolls back on error with async PG transactions', async () => {
    const adapter = createPgAdapter();

    await expect(
      adapter.transaction(async (tx) => {
        await tx.create({ model: 'user', data: { email: 'rollback@test.com', name: 'RB', passwordHash: 'h', isActive: true } });
        throw new Error('forced rollback');
      }),
    ).rejects.toThrow('forced rollback');

    const count = await adapter.count({ model: 'user' });
    expect(count).toBe(0);
  });
});

// --- Sorting ---

describe('pg: sorting', () => {
  it('sorts by date field', async () => {
    const adapter = createPgAdapter();

    await adapter.create({ model: 'user', data: { email: 'z@test.com', name: 'Z', passwordHash: 'h', isActive: true } });
    await adapter.create({ model: 'user', data: { email: 'a@test.com', name: 'A', passwordHash: 'h', isActive: true } });

    const ascending = await adapter.findMany<{ email: string }>({
      model: 'user',
      sortBy: { field: 'email', direction: 'asc' },
    });

    expect(ascending[0].email).toBe('a@test.com');
    expect(ascending[1].email).toBe('z@test.com');

    const descending = await adapter.findMany<{ email: string }>({
      model: 'user',
      sortBy: { field: 'email', direction: 'desc' },
    });

    expect(descending[0].email).toBe('z@test.com');
    expect(descending[1].email).toBe('a@test.com');
  });
});

// --- Tenancy plugin on PG ---

describe('pg: tenancy plugin', () => {
  it('creates tenants and manages membership with PG dates', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [tenancy()],
    });

    const user = await fortress.auth.createUser({
      email: 'tenant@test.com',
      name: 'Tenant User',
      password: 'password-123',
    });

    const tenant = await fortress.plugins.tenancy.createTenant({
      name: 'Acme Corp',
      taxId: 'acme',
    });

    expect(tenant.id).toBeDefined();
    expect(tenant.name).toBe('Acme Corp');
    expect(tenant.createdAt).toBeInstanceOf(Date);
    expect(tenant.updatedAt).toBeInstanceOf(Date);

    await fortress.plugins.tenancy.addUserToTenant(user.id, tenant.id);

    const tenants = await fortress.plugins.tenancy.getUserTenants(user.id);
    expect(tenants).toHaveLength(1);
    expect(tenants[0].taxId).toBe('acme');
    expect(tenants[0].createdAt).toBeInstanceOf(Date);
  });

  it('enriches JWT claims with tenant info after login', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [tenancy()],
    });

    const user = await fortress.auth.createUser({
      email: 'claims@test.com',
      name: 'Claims User',
      password: 'password-123',
    });

    const tenant = await fortress.plugins.tenancy.createTenant({
      name: 'Beta Inc',
      taxId: 'beta',
    });
    await fortress.plugins.tenancy.addUserToTenant(user.id, tenant.id);

    const login = await fortress.auth.login('claims@test.com', 'password-123');
    const claims = await fortress.auth.verifyToken(login.accessToken as string);

    expect(claims.customClaims?.tenantId).toBe(tenant.id);
    expect(claims.customClaims?.tenantCode).toBe('beta');
  });

  it('switches default tenant', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [tenancy()],
    });

    const user = await fortress.auth.createUser({
      email: 'switch@test.com',
      name: 'Switch User',
      password: 'password-123',
    });

    const t1 = await fortress.plugins.tenancy.createTenant({ name: 'T1', taxId: 't1' });
    const t2 = await fortress.plugins.tenancy.createTenant({ name: 'T2', taxId: 't2' });
    await fortress.plugins.tenancy.addUserToTenant(user.id, t1.id);
    await fortress.plugins.tenancy.addUserToTenant(user.id, t2.id);

    await fortress.plugins.tenancy.switchTenant({ taxId: 't2', userId: user.id });

    const login = await fortress.auth.login('switch@test.com', 'password-123');
    const claims = await fortress.auth.verifyToken(login.accessToken as string);
    expect(claims.customClaims?.tenantCode).toBe('t2');
  });

  it('isolates tenant data via the transaction-pinned search_path (H2/H3)', async () => {
    // Each tenant gets an `items` table in its own schema via onSchemaCreated.
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [
        tenancy({
          onSchemaCreated: async (schemaName, rawQuery) => {
            await rawQuery(`CREATE TABLE IF NOT EXISTS ${schemaName}.items (id SERIAL PRIMARY KEY, name TEXT NOT NULL)`);
          },
        }),
      ],
    });

    const tenantPlugin = fortress.config.plugins![0];
    const base = fortress.config.database;

    const tA = await fortress.plugins.tenancy.createTenant({ name: 'A', taxId: 'iso-a' });
    const tB = await fortress.plugins.tenancy.createTenant({ name: 'B', taxId: 'iso-b' });

    const dbA = tenantPlugin.wrapAdapter!(base, { tenantId: tA.id });
    const dbB = tenantPlugin.wrapAdapter!(base, { tenantId: tB.id });

    // Writes route to each tenant's schema because the wrapped transaction pins
    // `search_path` on the same connection before the unqualified INSERT runs.
    await dbA.transaction(async tx => tx.rawQuery!(`INSERT INTO items (name) VALUES ('a-only')`));
    await dbB.transaction(async tx => tx.rawQuery!(`INSERT INTO items (name) VALUES ('b-only')`));

    const rowsA = await dbA.transaction(async tx => tx.rawQuery!<{ name: string }>(`SELECT name FROM items`));
    const rowsB = await dbB.transaction(async tx => tx.rawQuery!<{ name: string }>(`SELECT name FROM items`));

    // The load-bearing assertion: A cannot see B's rows and vice versa.
    expect(rowsA.map(r => r.name)).toEqual(['a-only']);
    expect(rowsB.map(r => r.name)).toEqual(['b-only']);

    // Fail closed: with no tenant claim, wrapAdapter is a pass-through. The
    // unqualified `items` table is not on the public search_path → it errors
    // rather than silently reading another tenant's schema.
    const dbNone = tenantPlugin.wrapAdapter!(base, {});
    expect(dbNone).toBe(base);
    await expect(
      dbNone.transaction(async tx => tx.rawQuery!(`SELECT name FROM items`)),
    ).rejects.toThrow();
  });

  it('drops the tenant schema on delete only when opted in', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [
        tenancy({
          dropSchemaOnDelete: true,
          onSchemaCreated: async (schemaName, rawQuery) => {
            await rawQuery(`CREATE TABLE IF NOT EXISTS ${schemaName}.items (id SERIAL PRIMARY KEY)`);
          },
        }),
      ],
    });

    const tenant = await fortress.plugins.tenancy.createTenant({ name: 'Drop', taxId: 'drop-me' });
    const schemaName = `tenant_${tenant.id}`;

    const before = await pgClient.unsafe(
      `SELECT 1 FROM information_schema.schemata WHERE schema_name = '${schemaName}'`,
    );
    expect(before).toHaveLength(1);

    await fortress.plugins.tenancy.deleteTenant({ id: tenant.id });

    const after = await pgClient.unsafe(
      `SELECT 1 FROM information_schema.schemata WHERE schema_name = '${schemaName}'`,
    );
    expect(after).toHaveLength(0);
  });
});

// --- Two-Factor plugin on PG ---

describe('pg: two-factor plugin', () => {
  it('enables, verifies, and disables 2FA with PG dates', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [twoFactor({ totp: { issuer: 'PGTest' }, backupCodes: { count: 5 } })],
    });

    const user = await fortress.auth.createUser({
      email: '2fa@test.com',
      name: '2FA User',
      password: 'password-123',
    });

    const methods = fortress.plugins['two-factor'] as any;
    const setup = await methods.enable(user.id);

    expect(setup.secret).toBeTruthy();
    expect(setup.otpauthUrl).toContain('otpauth://totp/');
    expect(setup.backupCodes).toHaveLength(5);

    // Verify with a real TOTP code
    const code = await generateTOTP(setup.secret, 30, 6);
    const result = await methods.verify(user.id, code);
    expect(result.verified).toBe(true);

    // Disable 2FA
    await methods.disable(user.id);

    // Should be able to enable again after disable
    const setup2 = await methods.enable(user.id);
    expect(setup2.secret).toBeTruthy();
  });
});

// --- Magic Link plugin on PG ---

describe('pg: magic-link plugin', () => {
  it('sends and verifies magic link with PG timestamps', async () => {
    let capturedToken = '';
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [magicLink({
        onSendMagicLink: async (_email, token) => { capturedToken = token; },
      })],
    });

    // Create user so magic link can find them
    await fortress.auth.createUser({
      email: 'magic@test.com',
      name: 'Magic User',
      password: 'password-123',
    });

    const methods = fortress.plugins['magic-link'] as any;
    const sendResult = await methods.sendMagicLink('magic@test.com');
    expect(sendResult.sent).toBe(true);
    expect(capturedToken).toBeTruthy();

    const verifyResult = await methods.verifyMagicLink(capturedToken);
    expect(verifyResult.email).toBe('magic@test.com');
    expect(verifyResult.accessToken).toBeTruthy();
  });
});

// --- OAuth plugin on PG ---

describe('pg: oauth plugin', () => {
  it('creates client, issues auth code, and exchanges for token', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [oauth({ issuerUrl: 'http://localhost:3000' })],
    });

    const user = await fortress.auth.createUser({
      email: 'oauth@test.com',
      name: 'OAuth User',
      password: 'password-123',
    });

    const methods = fortress.plugins.oauth as any;

    // Create client
    const client = await methods.createClient({
      name: 'Test App',
      redirectUris: ['http://localhost:3000/callback'],
      grantTypes: ['authorization_code'],
    });
    expect(client.clientId).toBeTruthy();
    expect(client.clientSecret).toBeTruthy();

    // Create auth code
    const { code } = await methods.createAuthorizationCode({
      clientId: client.clientId,
      userId: user.id,
      redirectUri: 'http://localhost:3000/callback',
      scope: 'read:users',
    });
    expect(code).toBeTruthy();

    // Exchange code for token
    const tokenResult = await methods.exchangeCode({
      code,
      clientId: client.clientId,
      clientSecret: client.clientSecret,
      redirectUri: 'http://localhost:3000/callback',
    });
    expect(tokenResult.accessToken).toBeTruthy();
    expect(tokenResult.tokenType).toBe('Bearer');
    expect(tokenResult.expiresIn).toBeGreaterThan(0);

    // Introspect token
    const introspection = await methods.introspectToken(tokenResult.accessToken);
    expect(introspection.active).toBe(true);
    expect(introspection.clientId).toBe(client.clientId);
  });
});

// --- Social Login plugin on PG ---

describe('pg: social-login plugin', () => {
  it('round-trips JSONB profile data through PG', async () => {
    const adapter = createPgAdapter();

    const user = await adapter.create<{ id: string }>({
      model: 'user',
      data: { email: 'social@test.com', name: 'Social', passwordHash: 'h', isActive: true },
    });

    // Insert social account with JSONB profile
    const profile = { displayName: 'Social User', avatar: 'https://example.com/avatar.png', locale: 'en' };
    await adapter.create({
      model: 'social_account',
      data: {
        userId: user.id,
        provider: 'google',
        providerAccountId: 'google-123',
        email: 'social@test.com',
        accessToken: 'at',
        refreshToken: 'rt',
        tokenExpiresAt: new Date('2099-01-01'),
        profile: JSON.stringify(profile),
      },
    });

    // Read back and verify JSONB round-trip
    const found = await adapter.findOne<{
      provider: string;
      profile: Record<string, unknown>;
      tokenExpiresAt: Date;
      createdAt: Date;
    }>({
      model: 'social_account',
      where: [{ field: 'userId', operator: '=', value: user.id }],
    });

    expect(found).not.toBeNull();
    expect(found!.provider).toBe('google');
    expect(found!.tokenExpiresAt).toBeInstanceOf(Date);
    expect(found!.createdAt).toBeInstanceOf(Date);
    // PG returns JSONB as a parsed object, not a string
    expect(found!.profile).toEqual(profile);
  });

  it('getLinkedAccounts works with PG adapter', async () => {
    const adapter = createPgAdapter();

    const plugin = socialLogin({
      providers: [
        { name: 'google', clientId: 'id', clientSecret: 'secret' },
      ],
    });

    const methods = plugin.methods!({
      db: adapter,
      config: { jwt: { key: SECRET }, database: adapter },
    }) as any;

    const user = await adapter.create<{ id: string }>({
      model: 'user',
      data: { email: 'linked@test.com', name: 'Linked', passwordHash: 'h', isActive: true },
    });

    await adapter.create({
      model: 'social_account',
      data: {
        userId: user.id,
        provider: 'google',
        providerAccountId: 'g-456',
        email: 'linked@test.com',
        profile: null,
      },
    });

    const accounts = await methods.getLinkedAccounts(user.id);
    expect(accounts).toHaveLength(1);
    expect(accounts[0].provider).toBe('google');
    expect(accounts[0].providerAccountId).toBe('g-456');
  });
});

// --- Account Lockout plugin on PG ---

describe('pg: account-lockout plugin', () => {
  it('locks out after failed attempts and returns PG timestamps', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [accountLockout({ maxFailedAttempts: 2, lockoutDurationSeconds: 60 })],
    });

    await fortress.auth.createUser({
      email: 'lockout@test.com',
      name: 'Lockout',
      password: 'password-123',
    });

    // Trigger failed logins
    await fortress.auth.login('lockout@test.com', 'wrong').catch(() => {});
    await fortress.auth.login('lockout@test.com', 'wrong').catch(() => {});

    const methods = fortress.plugins['account-lockout'] as any;
    const status = await methods.getLockoutStatus('lockout@test.com');

    expect(status.isLocked).toBe(true);
    expect(status.failedAttempts).toBe(2);
    expect(status.lockedUntil).toBeInstanceOf(Date);
    expect(status.lastFailedAt).toBeInstanceOf(Date);

    // Login should be blocked
    await expect(
      fortress.auth.login('lockout@test.com', 'password-123'),
    ).rejects.toThrow();

    // Reset lockout
    await methods.resetLockout('lockout@test.com');
    const cleared = await methods.getLockoutStatus('lockout@test.com');
    expect(cleared.isLocked).toBe(false);
  });
});

// --- Webhook plugin on PG ---

describe('pg: webhook plugin', () => {
  it('registers endpoint and records delivery with PG timestamps', async () => {
    const delivered: string[] = [];
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createPgAdapter(),
      plugins: [webhook({
        delivery: {
          fetch: async (req) => {
            delivered.push(await req.text());
            return new Response(null, { status: 200 });
          },
        },
      })],
    });

    const methods = fortress.plugins.webhook as any;

    const endpoint = await methods.registerEndpoint(
      'https://example.com/hook',
      ['auth.login.success'],
    );
    expect(endpoint.id).toBeDefined();
    expect(endpoint.secret).toMatch(WEBHOOK_SECRET_PREFIX);
    expect(endpoint.createdAt).toBeInstanceOf(Date);

    const endpoints = await methods.listEndpoints();
    expect(endpoints).toHaveLength(1);
    expect(endpoints[0].createdAt).toBeInstanceOf(Date);
    expect(endpoints[0].secret).toBeUndefined(); // redacted

    // Trigger a webhook delivery via login
    await fortress.auth.createUser({
      email: 'wh@test.com',
      name: 'WH',
      password: 'password-123',
    });
    await fortress.auth.login('wh@test.com', 'password-123');

    // Delivery is queued out-of-band; wait for it.
    for (let i = 0; i < 100 && delivered.length < 1; i++)
      await new Promise(resolve => setTimeout(resolve, 10));

    expect(delivered.length).toBeGreaterThanOrEqual(1);
    const payload = JSON.parse(delivered[0]);
    expect(payload.event).toBe('auth.login.success');

    await methods.stop();
  });
});

// --- Data Isolation plugin on PG ---

describe('pg: data-isolation plugin', () => {
  it('generates scope rules that filter queries on PG', async () => {
    const adapter = createPgAdapter();

    const plugin = dataIsolation({
      scopes: [{
        name: 'active-only',
        field: 'isActive',
        models: ['user'],
        resolveValue: async () => true,
      }],
    });

    // Create users with different isActive values
    await adapter.create({ model: 'user', data: { email: 'active@test.com', name: 'Active', passwordHash: 'h', isActive: true } });
    await adapter.create({ model: 'user', data: { email: 'inactive@test.com', name: 'Inactive', passwordHash: 'h', isActive: false } });

    // Get scope rules
    const rules = await plugin.scopeRules!('1', 'user', { db: adapter, config: { jwt: { key: SECRET }, database: adapter } });

    expect(rules).not.toBeNull();
    expect(rules!.filters).toHaveLength(1);
    expect(rules!.filters[0]).toEqual({ field: 'isActive', operator: '=', value: true });
    expect(rules!.defaults).toEqual({ isActive: true });
  });
});
