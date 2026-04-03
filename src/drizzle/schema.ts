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
};
