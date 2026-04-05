import { boolean, integer, jsonb, pgTable, primaryKey, serial, text, timestamp, varchar } from 'drizzle-orm/pg-core';

// --- Core Identity ---

const users = pgTable('fortress_user', {
  id: serial('id').primaryKey(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  name: varchar('name', { length: 255 }).notNull(),
  passwordHash: text('password_hash'),
  isActive: boolean('is_active').notNull().default(true),
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
  isRevoked: boolean('is_revoked').notNull().default(false),
  expiresAt: timestamp('expires_at').notNull(),
  ipAddress: varchar('ip_address', { length: 45 }),
  userAgent: text('user_agent'),
  deviceName: text('device_name'),
  lastActiveAt: timestamp('last_active_at'),
  fingerprintHash: varchar('fingerprint_hash', { length: 64 }),
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
});

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
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

const webhookDeliveries = pgTable('fortress_webhook_delivery', {
  id: serial('id').primaryKey(),
  endpointId: integer('endpoint_id').notNull().references(() => webhookEndpoints.id, { onDelete: 'cascade' }),
  eventType: varchar('event_type', { length: 100 }).notNull(),
  payload: text('payload').notNull(), // JSON
  status: varchar('status', { length: 20 }).notNull().default('pending'), // pending | success | failed
  attempts: integer('attempts').notNull().default(0),
  lastAttemptAt: timestamp('last_attempt_at'),
  nextRetryAt: timestamp('next_retry_at'),
  responseStatus: integer('response_status'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// --- All tables for easy iteration ---

export const fortressPgSchema = {
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
  magicLinkTokens,
  accountLockouts,
  auditLogs,
  webhookEndpoints,
  webhookDeliveries,
};
