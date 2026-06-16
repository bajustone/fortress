import type { AnySQLiteTable } from 'drizzle-orm/sqlite-core';

import { sql } from 'drizzle-orm';
import { index, integer, primaryKey, sqliteTable, text, unique, uniqueIndex } from 'drizzle-orm/sqlite-core';

// --- Schema Versioning ---

const schemaVersion = sqliteTable('fortress_schema_version', {
  id: integer('id').primaryKey().default(1),
  version: integer('version').notNull(),
  appliedAt: integer('applied_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- Core Identity ---

const users = sqliteTable('fortress_user', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  email: text('email').notNull().unique(),
  name: text('name').notNull(),
  passwordHash: text('password_hash'),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  emailVerified: integer('email_verified', { mode: 'boolean' }).notNull().default(false),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- Login Identifiers ---

const loginIdentifiers = sqliteTable('fortress_login_identifier', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  type: text('type').notNull(), // 'email' | 'phone' | 'username'
  value: text('value').notNull().unique(),
});

// --- Auth ---

const refreshTokens = sqliteTable('fortress_refresh_token', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  tokenHash: text('token_hash').notNull().unique(),
  tokenFamily: text('token_family').notNull(),
  isRevoked: integer('is_revoked', { mode: 'boolean' }).notNull().default(false),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  deviceName: text('device_name'),
  lastActiveAt: integer('last_active_at', { mode: 'timestamp' }),
  fingerprintHash: text('fingerprint_hash'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- IAM: Groups ---

const groups = sqliteTable('fortress_group', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull().unique(),
  description: text('description'),
});

const groupUsers = sqliteTable(
  'fortress_group_user',
  {
    groupId: integer('group_id').notNull().references(() => groups.id, { onDelete: 'cascade' }),
    userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  },
  table => [primaryKey({ columns: [table.groupId, table.userId] })],
);

// --- IAM: Service Accounts ---

const serviceAccounts = sqliteTable('fortress_service_account', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull().unique(),
  displayName: text('display_name'),
  description: text('description'),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- IAM: Resources & Permissions ---

const resources = sqliteTable('fortress_resource', {
  name: text('name').primaryKey(),
  description: text('description'),
});

const permissions = sqliteTable('fortress_permission', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  resource: text('resource').notNull().references(() => resources.name, { onDelete: 'cascade' }),
  action: text('action').notNull(),
  effect: text('effect').notNull().default('ALLOW'), // 'ALLOW' | 'DENY'
  conditions: text('conditions'), // JSON string of PermissionCondition[]
  description: text('description'),
}, table => [
  // M8 fix: SQL UNIQUE treats two NULL `conditions` as distinct, so the
  // plain unique() above lets `findOrCreatePermission` insert duplicate
  // rows for the same (resource, action, effect, conditions=NULL) tuple
  // under concurrency. Mirror the split-index pattern used for role /
  // direct-permission bindings.
  uniqueIndex('uniq_permission_no_conditions')
    .on(table.resource, table.action, table.effect)
    .where(sql`${table.conditions} is null`),
  uniqueIndex('uniq_permission_with_conditions')
    .on(table.resource, table.action, table.effect, table.conditions)
    .where(sql`${table.conditions} is not null`),
]);

// --- IAM: Roles ---

const roles = sqliteTable('fortress_role', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull().unique(),
  description: text('description'),
  isSystem: integer('is_system', { mode: 'boolean' }).notNull().default(false),
});

const rolePermissions = sqliteTable(
  'fortress_role_permission',
  {
    roleId: integer('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
    permissionId: integer('permission_id').notNull().references(() => permissions.id, { onDelete: 'cascade' }),
  },
  table => [primaryKey({ columns: [table.roleId, table.permissionId] })],
);

// --- IAM: Role Bindings ---

const roleBindings = sqliteTable('fortress_role_binding', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  roleId: integer('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
  subjectType: text('subject_type').notNull(), // 'USER' | 'GROUP' | 'SERVICE_ACCOUNT'
  subjectId: integer('subject_id').notNull(),
  tenantId: text('tenant_id'),
}, table => [
  unique().on(table.roleId, table.subjectType, table.subjectId, table.tenantId),
  uniqueIndex('uniq_role_binding_global').on(table.roleId, table.subjectType, table.subjectId).where(sql`${table.tenantId} is null`),
  uniqueIndex('uniq_role_binding_tenant').on(table.roleId, table.subjectType, table.subjectId, table.tenantId).where(sql`${table.tenantId} is not null`),
]);

// --- IAM: Direct Permission Bindings ---

const directPermissionBindings = sqliteTable('fortress_direct_permission_binding', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  permissionId: integer('permission_id').notNull().references(() => permissions.id, { onDelete: 'cascade' }),
  subjectType: text('subject_type').notNull(), // 'USER' | 'GROUP' | 'SERVICE_ACCOUNT'
  subjectId: integer('subject_id').notNull(),
  tenantId: text('tenant_id'),
}, table => [
  unique().on(table.permissionId, table.subjectType, table.subjectId, table.tenantId),
  uniqueIndex('uniq_direct_permission_binding_global').on(table.permissionId, table.subjectType, table.subjectId).where(sql`${table.tenantId} is null`),
  uniqueIndex('uniq_direct_permission_binding_tenant').on(table.permissionId, table.subjectType, table.subjectId, table.tenantId).where(sql`${table.tenantId} is not null`),
]);

// --- Plugins: Email Verification ---

const emailVerificationTokens = sqliteTable('fortress_email_verification_token', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  token: text('token').notNull(),
  email: text('email').notNull(),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  usedAt: integer('used_at', { mode: 'timestamp' }),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- Plugins: Magic Link ---

const magicLinkTokens = sqliteTable('fortress_magic_link_token', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  email: text('email').notNull(),
  token: text('token').notNull(),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  usedAt: integer('used_at', { mode: 'timestamp' }),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- Plugins: API Key ---

const apiKeys = sqliteTable('fortress_api_key', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  subjectType: text('subject_type').notNull(), // 'USER' | 'SERVICE_ACCOUNT' — polymorphic owner
  subjectId: integer('subject_id').notNull(),
  name: text('name').notNull(),
  keyHash: text('key_hash').notNull().unique(),
  keyPrefix: text('key_prefix').notNull(),
  scopes: text('scopes'), // JSON array of "resource:action" strings
  expiresAt: integer('expires_at', { mode: 'timestamp' }),
  lastUsedAt: integer('last_used_at', { mode: 'timestamp' }),
  isRevoked: integer('is_revoked', { mode: 'boolean' }).notNull().default(false),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
}, table => [index('api_key_subject_idx').on(table.subjectType, table.subjectId)]);

// --- Plugins: Two-Factor ---

const twoFactorSecrets = sqliteTable('fortress_two_factor_secret', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().unique().references(() => users.id, { onDelete: 'cascade' }),
  secret: text('secret').notNull(), // Base32-encoded TOTP secret
  isEnabled: integer('is_enabled', { mode: 'boolean' }).notNull().default(false),
  lastUsedCounter: integer('last_used_counter'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

const backupCodes = sqliteTable('fortress_backup_code', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  codeHash: text('code_hash').notNull(),
  isUsed: integer('is_used', { mode: 'boolean' }).notNull().default(false),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

const trustedDevices = sqliteTable('fortress_trusted_device', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  deviceHash: text('device_hash').notNull(), // Hash of device fingerprint
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  lastUsedAt: integer('last_used_at', { mode: 'timestamp' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- Plugins: Social Login ---

const socialAccounts = sqliteTable('fortress_social_account', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  provider: text('provider').notNull(),
  providerAccountId: text('provider_account_id').notNull(),
  email: text('email'),
  accessToken: text('access_token'), // Encrypted
  refreshToken: text('refresh_token'), // Encrypted
  tokenExpiresAt: integer('token_expires_at', { mode: 'timestamp' }),
  profile: text('profile'), // JSON
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
}, table => [
  unique().on(table.userId, table.provider),
  unique().on(table.provider, table.providerAccountId),
]);

// --- Plugins: Tenancy ---

const tenants = sqliteTable('fortress_tenant', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull(),
  taxId: text('tax_id').notNull().unique(),
  description: text('description'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
  updatedAt: integer('updated_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

const tenantUsers = sqliteTable(
  'fortress_tenant_user',
  {
    tenantId: integer('tenant_id').notNull().references(() => tenants.id, { onDelete: 'cascade' }),
    userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
    isDefault: integer('is_default', { mode: 'boolean' }).notNull().default(false),
  },
  table => [primaryKey({ columns: [table.tenantId, table.userId] })],
);

// --- Plugins: OAuth ---

const oauthClients = sqliteTable('fortress_oauth_client', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  clientId: text('client_id').notNull().unique(),
  clientSecretHash: text('client_secret_hash').notNull(),
  name: text('name').notNull(),
  redirectUris: text('redirect_uris').notNull(), // JSON array
  grantTypes: text('grant_types').notNull(), // JSON array
  // RFC 6749 §3.3 / RFC 9700 §2.2.1 per-client scope allow-list (JSON array,
  // nullable for legacy v0 clients).
  allowedScopes: text('allowed_scopes'),
  // RFC 6749 §2.1 client authentication method ('client_secret_basic' |
  // 'client_secret_post' | 'none' for RFC 8252 public clients).
  tokenEndpointAuthMethod: text('token_endpoint_auth_method'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

const oauthAuthorizationCodes = sqliteTable('fortress_oauth_authorization_code', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  code: text('code').notNull().unique(),
  clientId: text('client_id').notNull(),
  userId: integer('user_id').notNull(),
  redirectUri: text('redirect_uri').notNull(),
  scope: text('scope'),
  codeChallenge: text('code_challenge'),
  codeChallengeMethod: text('code_challenge_method'),
  // OIDC Core §3.1.2.1 / §2 — echoed into the id_token if present.
  nonce: text('nonce'),
  authTime: integer('auth_time'),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  usedAt: integer('used_at', { mode: 'timestamp' }),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

const oauthAccessTokens = sqliteTable('fortress_oauth_access_token', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  token: text('token').notNull().unique(),
  clientId: text('client_id').notNull(),
  userId: integer('user_id'),
  scope: text('scope'),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// RFC 6749 §6 + RFC 9700 §2.2.2 refresh tokens with rotation.
const oauthRefreshTokens = sqliteTable('fortress_oauth_refresh_token', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  token: text('token').notNull().unique(),
  familyId: text('family_id').notNull(),
  clientId: text('client_id').notNull(),
  userId: integer('user_id').notNull(),
  scope: text('scope'),
  issuedAt: integer('issued_at', { mode: 'timestamp' }).notNull(),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  usedAt: integer('used_at', { mode: 'timestamp' }),
  parentId: integer('parent_id'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

const oauthPendingFlows = sqliteTable('fortress_oauth_pending_flow', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  flowId: text('flow_id').notNull().unique(),
  clientId: text('client_id').notNull(),
  redirectUri: text('redirect_uri').notNull(),
  scope: text('scope'),
  state: text('state').notNull(),
  codeChallenge: text('code_challenge'),
  codeChallengeMethod: text('code_challenge_method'),
  nonce: text('nonce'),
  // H6 fix: subject the flow is bound to. Nullable for the
  // login-redirect path which can't know the user up front — the
  // first authenticated GetFlow / Approve claims it.
  userId: integer('user_id'),
  // Single-use approval/denial claim used by the OAuth consent API.
  usedAt: integer('used_at', { mode: 'timestamp' }),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// OIDC Core / RFC 7517: id_token signing keys (RS256). Active key has
// rotatedAt == null; rotated keys are kept for the JWKS verification grace
// window.
const oauthSigningKeys = sqliteTable('fortress_oauth_signing_key', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  kid: text('kid').notNull().unique(),
  alg: text('alg').notNull(),
  publicJwk: text('public_jwk').notNull(),
  privateJwk: text('private_jwk').notNull(),
  rotatedAt: integer('rotated_at', { mode: 'timestamp' }),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- Plugins: Data Isolation ---

const userScopeAssignments = sqliteTable('fortress_user_scope_assignment', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  scopeName: text('scope_name').notNull(),
  scopeValue: text('scope_value').notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- Plugins: Account Lockout ---

const accountLockouts = sqliteTable('fortress_account_lockout', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  identifier: text('identifier').notNull().unique(),
  failedAttempts: integer('failed_attempts').notNull().default(0),
  lastFailedAt: integer('last_failed_at', { mode: 'timestamp' }),
  lockedUntil: integer('locked_until', { mode: 'timestamp' }),
  lockoutCount: integer('lockout_count').notNull().default(0),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- Core: Audit Log ---

const auditLogs = sqliteTable('fortress_audit_log', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  timestamp: integer('timestamp', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
  eventType: text('event_type').notNull(),
  actorId: integer('actor_id'),
  actorType: text('actor_type').notNull().default('USER'),
  targetId: integer('target_id'),
  targetType: text('target_type'),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  outcome: text('outcome').notNull().default('SUCCESS'),
  metadata: text('metadata'),
  previousHash: text('previous_hash'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- Plugins: Webhook ---

const webhookEndpoints = sqliteTable('fortress_webhook_endpoint', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  url: text('url').notNull(),
  events: text('events').notNull(), // JSON array
  secret: text('secret').notNull(),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  deactivatedReason: text('deactivated_reason'),
  consecutiveFailures: integer('consecutive_failures').notNull().default(0),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

const webhookDeliveries = sqliteTable('fortress_webhook_delivery', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  endpointId: integer('endpoint_id').notNull().references(() => webhookEndpoints.id, { onDelete: 'cascade' }),
  eventType: text('event_type').notNull(),
  payload: text('payload').notNull(), // JSON
  status: text('status').notNull().default('pending'), // pending | success | failed
  attempts: integer('attempts').notNull().default(0),
  idempotencyKey: text('idempotency_key'),
  lastAttemptAt: integer('last_attempt_at', { mode: 'timestamp' }),
  nextRetryAt: integer('next_retry_at', { mode: 'timestamp' }),
  responseStatus: integer('response_status'),
  responseBody: text('response_body'),
  errorKind: text('error_kind'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
}, table => [
  uniqueIndex('uniq_webhook_delivery_idempotency').on(table.endpointId, table.idempotencyKey).where(sql`${table.idempotencyKey} is not null`),
]);

// --- Plugins: WebAuthn ---

const webauthnCredentials = sqliteTable('fortress_webauthn_credential', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  credentialId: text('credential_id').notNull().unique(),
  publicKey: text('public_key').notNull(),
  counter: integer('counter').notNull().default(0),
  deviceType: text('device_type').notNull(),
  backedUp: integer('backed_up', { mode: 'boolean' }).notNull().default(false),
  transports: text('transports'), // JSON array
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

const webauthnChallenges = sqliteTable('fortress_webauthn_challenge', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  challenge: text('challenge').notNull().unique(),
  userId: integer('user_id'),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- All tables for easy iteration ---

/**
 * Aggregate of every Drizzle SQLite table fortress uses.
 *
 * Typed as `Record<string, AnySQLiteTable>` so JSR can statically resolve
 * the public API without recursing through Drizzle's complex generic
 * column types. The fortress drizzle adapter accesses tables generically,
 * so column-level inference is not needed internally. Consumers who need
 * column-level types should declare their own typed Drizzle schema and
 * pass it via `createDrizzleAdapter(db, { tables })`.
 */
export const fortressSchema: Record<string, AnySQLiteTable> = {
  schemaVersion,
  users,
  loginIdentifiers,
  refreshTokens,
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
