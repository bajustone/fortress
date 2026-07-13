import type { AnyPgTable } from 'drizzle-orm/pg-core';

import { sql } from 'drizzle-orm';
import { boolean, index, integer, jsonb, pgTable, primaryKey, serial, text, timestamp, unique, uniqueIndex, varchar } from 'drizzle-orm/pg-core';

// --- Schema Versioning ---

const schemaVersion = pgTable('fortress_schema_version', {
  id: integer('id').primaryKey().default(1),
  version: integer('version').notNull(),
  appliedAt: timestamp('applied_at').notNull().defaultNow(),
});

// --- Core Identity ---

const users = pgTable('fortress_user', {
  id: serial('id').primaryKey(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  name: varchar('name', { length: 255 }).notNull(),
  passwordHash: text('password_hash'),
  isActive: boolean('is_active').notNull().default(true),
  emailVerified: boolean('email_verified').notNull().default(false),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

// --- Login Identifiers ---

const loginIdentifiers = pgTable('fortress_login_identifier', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  type: varchar('type', { length: 20 }).notNull(), // 'email' | 'phone' | 'username'
  value: varchar('value', { length: 255 }).notNull().unique(),
});

// --- Auth ---

const refreshTokens = pgTable('fortress_refresh_token', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  tokenHash: varchar('token_hash', { length: 64 }).notNull().unique(),
  tokenFamily: varchar('token_family', { length: 64 }).notNull(),
  familyCreatedAt: timestamp('family_created_at').notNull().defaultNow(),
  successorTokenHash: varchar('successor_token_hash', { length: 64 }),
  rotatedAt: timestamp('rotated_at'),
  isRevoked: boolean('is_revoked').notNull().default(false),
  expiresAt: timestamp('expires_at').notNull(),
  ipAddress: varchar('ip_address', { length: 45 }),
  userAgent: text('user_agent'),
  deviceName: text('device_name'),
  lastActiveAt: timestamp('last_active_at'),
  fingerprintHash: varchar('fingerprint_hash', { length: 64 }),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

const authContinuations = pgTable('fortress_auth_continuation', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  tokenHash: varchar('token_hash', { length: 64 }).notNull().unique(),
  reason: varchar('reason', { length: 32 }).notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  consumedAt: timestamp('consumed_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// --- IAM: Groups ---

const groups = pgTable('fortress_group', {
  id: serial('id').primaryKey(),
  name: varchar('name', { length: 100 }).notNull().unique(),
  description: text('description'),
});

const groupUsers = pgTable(
  'fortress_group_user',
  {
    groupId: integer('group_id').notNull().references(() => groups.id, { onDelete: 'cascade' }),
    userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  },
  table => [primaryKey({ columns: [table.groupId, table.userId] })],
);

// --- IAM: Service Accounts ---

const serviceAccounts = pgTable('fortress_service_account', {
  id: serial('id').primaryKey(),
  name: varchar('name', { length: 100 }).notNull().unique(),
  displayName: varchar('display_name', { length: 255 }),
  description: text('description'),
  isActive: boolean('is_active').notNull().default(true),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

// --- IAM: Resources & Permissions ---

const resources = pgTable('fortress_resource', {
  name: varchar('name', { length: 100 }).primaryKey(),
  description: text('description'),
});

const permissions = pgTable('fortress_permission', {
  id: serial('id').primaryKey(),
  resource: varchar('resource', { length: 100 }).notNull().references(() => resources.name, { onDelete: 'cascade' }),
  action: varchar('action', { length: 100 }).notNull(),
  effect: varchar('effect', { length: 10 }).notNull().default('ALLOW'), // 'ALLOW' | 'DENY'
  conditions: jsonb('conditions'), // PermissionCondition[] as JSONB
  description: text('description'),
}, table => [
  // M8 fix — same split-index pattern as role/direct-permission bindings
  // so concurrent findOrCreatePermission can't insert duplicate rows when
  // conditions is NULL (a plain UNIQUE treats NULLs as distinct).
  uniqueIndex('uniq_permission_no_conditions')
    .on(table.resource, table.action, table.effect)
    .where(sql`${table.conditions} is null`),
  uniqueIndex('uniq_permission_with_conditions')
    .on(table.resource, table.action, table.effect, table.conditions)
    .where(sql`${table.conditions} is not null`),
]);

// --- IAM: Roles ---

const roles = pgTable('fortress_role', {
  id: serial('id').primaryKey(),
  name: varchar('name', { length: 100 }).notNull().unique(),
  description: text('description'),
  isSystem: boolean('is_system').notNull().default(false),
});

const rolePermissions = pgTable(
  'fortress_role_permission',
  {
    roleId: integer('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
    permissionId: integer('permission_id').notNull().references(() => permissions.id, { onDelete: 'cascade' }),
  },
  table => [primaryKey({ columns: [table.roleId, table.permissionId] })],
);

// --- IAM: Role Bindings ---

const roleBindings = pgTable('fortress_role_binding', {
  id: serial('id').primaryKey(),
  roleId: integer('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
  subjectType: varchar('subject_type', { length: 20 }).notNull(), // 'USER' | 'GROUP' | 'SERVICE_ACCOUNT'
  subjectId: integer('subject_id').notNull(),
  tenantId: varchar('tenant_id', { length: 100 }),
}, table => [
  unique().on(table.roleId, table.subjectType, table.subjectId, table.tenantId),
  uniqueIndex('uniq_role_binding_global').on(table.roleId, table.subjectType, table.subjectId).where(sql`${table.tenantId} is null`),
  uniqueIndex('uniq_role_binding_tenant').on(table.roleId, table.subjectType, table.subjectId, table.tenantId).where(sql`${table.tenantId} is not null`),
]);

// --- IAM: Direct Permission Bindings ---

const directPermissionBindings = pgTable('fortress_direct_permission_binding', {
  id: serial('id').primaryKey(),
  permissionId: integer('permission_id').notNull().references(() => permissions.id, { onDelete: 'cascade' }),
  subjectType: varchar('subject_type', { length: 20 }).notNull(), // 'USER' | 'GROUP' | 'SERVICE_ACCOUNT'
  subjectId: integer('subject_id').notNull(),
  tenantId: varchar('tenant_id', { length: 100 }),
}, table => [
  unique().on(table.permissionId, table.subjectType, table.subjectId, table.tenantId),
  uniqueIndex('uniq_direct_permission_binding_global').on(table.permissionId, table.subjectType, table.subjectId).where(sql`${table.tenantId} is null`),
  uniqueIndex('uniq_direct_permission_binding_tenant').on(table.permissionId, table.subjectType, table.subjectId, table.tenantId).where(sql`${table.tenantId} is not null`),
]);

// --- Plugins: Email Verification ---

const emailVerificationTokens = pgTable('fortress_email_verification_token', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  token: text('token').notNull(),
  email: varchar('email', { length: 255 }).notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  usedAt: timestamp('used_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// --- Plugins: Magic Link ---

const magicLinkTokens = pgTable('fortress_magic_link_token', {
  id: serial('id').primaryKey(),
  email: varchar('email', { length: 255 }).notNull(),
  token: varchar('token', { length: 64 }).notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  usedAt: timestamp('used_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// --- Plugins: API Key ---

const apiKeys = pgTable('fortress_api_key', {
  id: serial('id').primaryKey(),
  subjectType: varchar('subject_type', { length: 20 }).notNull(), // 'USER' | 'SERVICE_ACCOUNT' — polymorphic owner
  subjectId: integer('subject_id').notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  keyHash: varchar('key_hash', { length: 64 }).notNull().unique(),
  keyPrefix: varchar('key_prefix', { length: 20 }).notNull(),
  scopes: text('scopes'), // JSON array of "resource:action" strings
  expiresAt: timestamp('expires_at'),
  lastUsedAt: timestamp('last_used_at'),
  isRevoked: boolean('is_revoked').notNull().default(false),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, table => [index('api_key_subject_idx').on(table.subjectType, table.subjectId)]);

// --- Plugins: Two-Factor ---

const twoFactorSecrets = pgTable('fortress_two_factor_secret', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull().unique().references(() => users.id, { onDelete: 'cascade' }),
  secret: text('secret').notNull(), // Base32-encoded TOTP secret
  isEnabled: boolean('is_enabled').notNull().default(false),
  lastUsedCounter: integer('last_used_counter'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

const backupCodes = pgTable('fortress_backup_code', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  codeHash: text('code_hash').notNull(),
  isUsed: boolean('is_used').notNull().default(false),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

const trustedDevices = pgTable('fortress_trusted_device', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  deviceHash: varchar('device_hash', { length: 64 }).notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  lastUsedAt: timestamp('last_used_at').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// --- Plugins: Social Login ---

const socialAccounts = pgTable('fortress_social_account', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  provider: varchar('provider', { length: 50 }).notNull(),
  providerAccountId: varchar('provider_account_id', { length: 255 }).notNull(),
  email: varchar('email', { length: 255 }),
  accessToken: text('access_token'), // Encrypted
  refreshToken: text('refresh_token'), // Encrypted
  tokenExpiresAt: timestamp('token_expires_at'),
  profile: jsonb('profile'), // JSON
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
}, table => [
  unique().on(table.userId, table.provider),
  unique().on(table.provider, table.providerAccountId),
]);

// --- Plugins: Tenancy ---

const tenants = pgTable('fortress_tenant', {
  id: serial('id').primaryKey(),
  name: varchar('name', { length: 255 }).notNull(),
  taxId: varchar('tax_id', { length: 100 }).notNull().unique(),
  description: text('description'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

const tenantUsers = pgTable(
  'fortress_tenant_user',
  {
    tenantId: integer('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
    userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    isDefault: boolean('is_default').notNull().default(false),
  },
  table => [primaryKey({ columns: [table.tenantId, table.userId] })],
);

// --- Plugins: OAuth ---

const oauthClients = pgTable('fortress_oauth_client', {
  id: serial('id').primaryKey(),
  clientId: varchar('client_id', { length: 255 }).notNull().unique(),
  clientSecretHash: text('client_secret_hash').notNull(),
  name: varchar('name', { length: 255 }).notNull(),
  redirectUris: text('redirect_uris').notNull(), // JSON array
  grantTypes: text('grant_types').notNull(), // JSON array
  // RFC 6749 §3.3 / RFC 9700 §2.2.1 per-client scope allow-list (JSON array,
  // nullable for legacy v0 clients).
  allowedScopes: text('allowed_scopes'),
  // RFC 6749 §2.1 client authentication method ('client_secret_basic' |
  // 'client_secret_post' | 'none' for RFC 8252 public clients).
  tokenEndpointAuthMethod: text('token_endpoint_auth_method'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

const oauthAuthorizationCodes = pgTable('fortress_oauth_authorization_code', {
  id: serial('id').primaryKey(),
  code: varchar('code', { length: 255 }).notNull().unique(),
  clientId: varchar('client_id', { length: 255 }).notNull(),
  userId: integer('user_id').notNull(),
  redirectUri: text('redirect_uri').notNull(),
  scope: text('scope'),
  codeChallenge: text('code_challenge'),
  codeChallengeMethod: varchar('code_challenge_method', { length: 10 }),
  // OIDC Core §3.1.2.1 / §2 — echoed into the id_token if present.
  nonce: text('nonce'),
  authTime: integer('auth_time'),
  expiresAt: timestamp('expires_at').notNull(),
  usedAt: timestamp('used_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

const oauthAccessTokens = pgTable('fortress_oauth_access_token', {
  id: serial('id').primaryKey(),
  token: varchar('token', { length: 255 }).notNull().unique(),
  clientId: varchar('client_id', { length: 255 }).notNull(),
  userId: integer('user_id'),
  scope: text('scope'),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// RFC 6749 §6 + RFC 9700 §2.2.2 refresh tokens with rotation.
const oauthRefreshTokens = pgTable('fortress_oauth_refresh_token', {
  id: serial('id').primaryKey(),
  token: varchar('token', { length: 255 }).notNull().unique(),
  familyId: varchar('family_id', { length: 64 }).notNull(),
  clientId: varchar('client_id', { length: 255 }).notNull(),
  userId: integer('user_id').notNull(),
  scope: text('scope'),
  issuedAt: timestamp('issued_at').notNull(),
  expiresAt: timestamp('expires_at').notNull(),
  usedAt: timestamp('used_at'),
  parentId: integer('parent_id'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

const oauthPendingFlows = pgTable('fortress_oauth_pending_flow', {
  id: serial('id').primaryKey(),
  flowId: text('flow_id').notNull().unique(),
  clientId: varchar('client_id', { length: 255 }).notNull(),
  redirectUri: text('redirect_uri').notNull(),
  scope: text('scope'),
  state: varchar('state', { length: 255 }).notNull(),
  codeChallenge: text('code_challenge'),
  codeChallengeMethod: varchar('code_challenge_method', { length: 10 }),
  nonce: text('nonce'),
  // H6 fix: subject the flow is bound to (TOFU-claimed on first
  // authenticated touch).
  userId: integer('user_id'),
  // Single-use approval/denial claim used by the OAuth consent API.
  usedAt: timestamp('used_at'),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// OIDC Core / RFC 7517: id_token signing keys (RS256).
const oauthSigningKeys = pgTable('fortress_oauth_signing_key', {
  id: serial('id').primaryKey(),
  kid: varchar('kid', { length: 64 }).notNull().unique(),
  alg: varchar('alg', { length: 16 }).notNull(),
  publicJwk: text('public_jwk').notNull(),
  privateJwk: text('private_jwk').notNull(),
  rotatedAt: timestamp('rotated_at'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// --- Plugins: Data Isolation ---

const userScopeAssignments = pgTable('fortress_user_scope_assignment', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  scopeName: varchar('scope_name', { length: 100 }).notNull(),
  scopeValue: varchar('scope_value', { length: 255 }).notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// --- Core: Account Lockout ---

const accountLockouts = pgTable('fortress_account_lockout', {
  id: serial('id').primaryKey(),
  identifier: varchar('identifier', { length: 255 }).notNull().unique(),
  failedAttempts: integer('failed_attempts').notNull().default(0),
  lastFailedAt: timestamp('last_failed_at'),
  lockedUntil: timestamp('locked_until'),
  lockoutCount: integer('lockout_count').notNull().default(0),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// --- Core: Audit Log ---

const auditLogs = pgTable('fortress_audit_log', {
  id: serial('id').primaryKey(),
  timestamp: timestamp('timestamp').notNull().defaultNow(),
  eventType: varchar('event_type', { length: 100 }).notNull(),
  actorId: integer('actor_id'),
  actorType: varchar('actor_type', { length: 20 }).notNull().default('USER'),
  targetId: integer('target_id'),
  targetType: varchar('target_type', { length: 50 }),
  ipAddress: varchar('ip_address', { length: 45 }),
  userAgent: text('user_agent'),
  outcome: varchar('outcome', { length: 20 }).notNull().default('SUCCESS'),
  metadata: jsonb('metadata'),
  previousHash: text('previous_hash'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// --- Plugins: Webhook ---

const webhookEndpoints = pgTable('fortress_webhook_endpoint', {
  id: serial('id').primaryKey(),
  url: text('url').notNull(),
  events: text('events').notNull(), // JSON array
  secret: text('secret').notNull(),
  isActive: boolean('is_active').notNull().default(true),
  deactivatedReason: text('deactivated_reason'),
  consecutiveFailures: integer('consecutive_failures').notNull().default(0),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

const webhookDeliveries = pgTable('fortress_webhook_delivery', {
  id: serial('id').primaryKey(),
  endpointId: integer('endpoint_id').notNull().references(() => webhookEndpoints.id, { onDelete: 'cascade' }),
  eventType: varchar('event_type', { length: 100 }).notNull(),
  payload: text('payload').notNull(), // JSON
  status: varchar('status', { length: 20 }).notNull().default('pending'), // pending | success | failed
  attempts: integer('attempts').notNull().default(0),
  idempotencyKey: text('idempotency_key'),
  lastAttemptAt: timestamp('last_attempt_at'),
  nextRetryAt: timestamp('next_retry_at'),
  responseStatus: integer('response_status'),
  responseBody: text('response_body'),
  errorKind: text('error_kind'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
}, table => [
  uniqueIndex('uniq_webhook_delivery_idempotency').on(table.endpointId, table.idempotencyKey).where(sql`${table.idempotencyKey} is not null`),
]);

// --- Plugins: WebAuthn ---

const webauthnCredentials = pgTable('fortress_webauthn_credential', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  credentialId: text('credential_id').notNull().unique(),
  publicKey: text('public_key').notNull(),
  counter: integer('counter').notNull().default(0),
  deviceType: varchar('device_type', { length: 20 }).notNull(),
  backedUp: boolean('backed_up').notNull().default(false),
  transports: text('transports'), // JSON array
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

const webauthnChallenges = pgTable('fortress_webauthn_challenge', {
  id: serial('id').primaryKey(),
  challenge: text('challenge').notNull().unique(),
  userId: integer('user_id'),
  expiresAt: timestamp('expires_at').notNull(),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// --- All tables for easy iteration ---

/**
 * Aggregate of every Drizzle PostgreSQL table fortress uses.
 *
 * Typed as `Record<string, AnyPgTable>` so JSR can statically resolve
 * the public API without recursing through Drizzle's complex generic
 * column types. The fortress drizzle adapter accesses tables generically,
 * so column-level inference is not needed internally. Consumers who need
 * column-level types should declare their own typed Drizzle schema and
 * pass it via `createDrizzleAdapter(db, { tables })`.
 */
export const fortressPgSchema: Record<string, AnyPgTable> = {
  schemaVersion,
  users,
  loginIdentifiers,
  refreshTokens,
  authContinuations,
  groups,
  groupUsers,
  serviceAccounts,
  resources,
  permissions,
  roles,
  rolePermissions,
  roleBindings,
  directPermissionBindings,
  emailVerificationTokens,
  magicLinkTokens,
  apiKeys,
  twoFactorSecrets,
  backupCodes,
  trustedDevices,
  socialAccounts,
  tenants,
  tenantUsers,
  oauthClients,
  oauthAuthorizationCodes,
  oauthAccessTokens,
  oauthRefreshTokens,
  oauthPendingFlows,
  oauthSigningKeys,
  userScopeAssignments,
  accountLockouts,
  auditLogs,
  webhookEndpoints,
  webhookDeliveries,
  webauthnCredentials,
  webauthnChallenges,
};
