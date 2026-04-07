import { integer, primaryKey, sqliteTable, text, unique } from 'drizzle-orm/sqlite-core';

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
});

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
});

// --- IAM: Direct Permission Bindings ---

const directPermissionBindings = sqliteTable('fortress_direct_permission_binding', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  permissionId: integer('permission_id').notNull().references(() => permissions.id, { onDelete: 'cascade' }),
  subjectType: text('subject_type').notNull(), // 'USER' | 'GROUP'
  subjectId: integer('subject_id').notNull(),
  tenantId: text('tenant_id'),
});

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
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  keyHash: text('key_hash').notNull().unique(),
  keyPrefix: text('key_prefix').notNull(),
  scopes: text('scopes'), // JSON array of "resource:action" strings
  expiresAt: integer('expires_at', { mode: 'timestamp' }),
  lastUsedAt: integer('last_used_at', { mode: 'timestamp' }),
  isRevoked: integer('is_revoked', { mode: 'boolean' }).notNull().default(false),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

// --- Plugins: Two-Factor ---

const twoFactorSecrets = sqliteTable('fortress_two_factor_secret', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().unique().references(() => users.id, { onDelete: 'cascade' }),
  secret: text('secret').notNull(), // Base32-encoded TOTP secret
  isEnabled: integer('is_enabled', { mode: 'boolean' }).notNull().default(false),
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

const oauthPendingFlows = sqliteTable('fortress_oauth_pending_flow', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  clientId: text('client_id').notNull(),
  redirectUri: text('redirect_uri').notNull(),
  scope: text('scope'),
  state: text('state').notNull(),
  codeChallenge: text('code_challenge'),
  codeChallengeMethod: text('code_challenge_method'),
  expiresAt: integer('expires_at', { mode: 'timestamp' }).notNull(),
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
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

const webhookDeliveries = sqliteTable('fortress_webhook_delivery', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  endpointId: integer('endpoint_id').notNull().references(() => webhookEndpoints.id, { onDelete: 'cascade' }),
  eventType: text('event_type').notNull(),
  payload: text('payload').notNull(), // JSON
  status: text('status').notNull().default('pending'), // pending | success | failed
  attempts: integer('attempts').notNull().default(0),
  lastAttemptAt: integer('last_attempt_at', { mode: 'timestamp' }),
  nextRetryAt: integer('next_retry_at', { mode: 'timestamp' }),
  responseStatus: integer('response_status'),
  createdAt: integer('created_at', { mode: 'timestamp' }).notNull().$defaultFn(() => new Date()),
});

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

export const fortressSchema = {
  users,
  loginIdentifiers,
  refreshTokens,
  groups,
  groupUsers,
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
  oauthPendingFlows,
  userScopeAssignments,
  accountLockouts,
  auditLogs,
  webhookEndpoints,
  webhookDeliveries,
  webauthnCredentials,
  webauthnChallenges,
};
