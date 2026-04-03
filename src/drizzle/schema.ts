import { integer, primaryKey, sqliteTable, text } from 'drizzle-orm/sqlite-core';

// --- Core Identity ---

const users = sqliteTable('fortress_user', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  email: text('email').notNull().unique(),
  name: text('name').notNull(),
  passwordHash: text('password_hash'),
  isActive: integer('is_active', { mode: 'boolean' }).notNull().default(true),
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
  updatedAt: text('updated_at').notNull().$defaultFn(() => new Date().toISOString()),
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
  expiresAt: text('expires_at').notNull(),
  ipAddress: text('ip_address'),
  userAgent: text('user_agent'),
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
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
});

// --- Plugins: Email Verification ---

const emailVerificationTokens = sqliteTable('fortress_email_verification_token', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  token: text('token').notNull(),
  email: text('email').notNull(),
  expiresAt: text('expires_at').notNull(),
  usedAt: text('used_at'),
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
});

// --- Plugins: API Key ---

const apiKeys = sqliteTable('fortress_api_key', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  name: text('name').notNull(),
  keyHash: text('key_hash').notNull().unique(),
  keyPrefix: text('key_prefix').notNull(),
  scopes: text('scopes'), // JSON array of "resource:action" strings
  expiresAt: text('expires_at'),
  lastUsedAt: text('last_used_at'),
  isRevoked: integer('is_revoked', { mode: 'boolean' }).notNull().default(false),
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
});

// --- Plugins: Two-Factor ---

const twoFactorSecrets = sqliteTable('fortress_two_factor_secret', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().unique().references(() => users.id, { onDelete: 'cascade' }),
  secret: text('secret').notNull(), // Base32-encoded TOTP secret
  isEnabled: integer('is_enabled', { mode: 'boolean' }).notNull().default(false),
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
});

const backupCodes = sqliteTable('fortress_backup_code', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  codeHash: text('code_hash').notNull(),
  isUsed: integer('is_used', { mode: 'boolean' }).notNull().default(false),
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
});

const trustedDevices = sqliteTable('fortress_trusted_device', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  deviceHash: text('device_hash').notNull(), // Hash of device fingerprint
  expiresAt: text('expires_at').notNull(),
  lastUsedAt: text('last_used_at').notNull(),
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
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
  tokenExpiresAt: text('token_expires_at'),
  profile: text('profile'), // JSON
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
  updatedAt: text('updated_at').notNull().$defaultFn(() => new Date().toISOString()),
});

// --- Plugins: Tenancy ---

const tenants = sqliteTable('fortress_tenant', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  name: text('name').notNull(),
  taxId: text('tax_id').notNull().unique(),
  description: text('description'),
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
  updatedAt: text('updated_at').notNull().$defaultFn(() => new Date().toISOString()),
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
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
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
  expiresAt: text('expires_at').notNull(),
  usedAt: text('used_at'),
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
});

const oauthAccessTokens = sqliteTable('fortress_oauth_access_token', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  token: text('token').notNull().unique(),
  clientId: text('client_id').notNull(),
  userId: integer('user_id'),
  scope: text('scope'),
  expiresAt: text('expires_at').notNull(),
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
});

const oauthPendingFlows = sqliteTable('fortress_oauth_pending_flow', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  clientId: text('client_id').notNull(),
  redirectUri: text('redirect_uri').notNull(),
  scope: text('scope'),
  state: text('state').notNull(),
  codeChallenge: text('code_challenge'),
  codeChallengeMethod: text('code_challenge_method'),
  expiresAt: text('expires_at').notNull(),
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
});

// --- Plugins: Data Isolation ---

const userScopeAssignments = sqliteTable('fortress_user_scope_assignment', {
  id: integer('id').primaryKey({ autoIncrement: true }),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  scopeName: text('scope_name').notNull(),
  scopeValue: text('scope_value').notNull(),
  createdAt: text('created_at').notNull().$defaultFn(() => new Date().toISOString()),
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
  emailVerificationTokens,
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
};
