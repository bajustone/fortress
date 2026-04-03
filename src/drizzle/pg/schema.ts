import { boolean, integer, jsonb, pgTable, primaryKey, serial, text, timestamp, varchar } from 'drizzle-orm/pg-core';

// --- Core Identity ---

export const users = pgTable('fortress_user', {
  id: serial('id').primaryKey(),
  email: varchar('email', { length: 255 }).notNull().unique(),
  name: varchar('name', { length: 255 }).notNull(),
  passwordHash: text('password_hash'),
  isActive: boolean('is_active').notNull().default(true),
  createdAt: timestamp('created_at').notNull().defaultNow(),
  updatedAt: timestamp('updated_at').notNull().defaultNow(),
});

// --- Login Identifiers ---

export const loginIdentifiers = pgTable('fortress_login_identifier', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  type: varchar('type', { length: 20 }).notNull(), // 'email' | 'phone' | 'username'
  value: varchar('value', { length: 255 }).notNull().unique(),
});

// --- Auth ---

export const refreshTokens = pgTable('fortress_refresh_token', {
  id: serial('id').primaryKey(),
  userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  tokenHash: varchar('token_hash', { length: 64 }).notNull().unique(),
  tokenFamily: varchar('token_family', { length: 64 }).notNull(),
  isRevoked: boolean('is_revoked').notNull().default(false),
  expiresAt: timestamp('expires_at').notNull(),
  ipAddress: varchar('ip_address', { length: 45 }),
  userAgent: text('user_agent'),
  createdAt: timestamp('created_at').notNull().defaultNow(),
});

// --- IAM: Groups ---

export const groups = pgTable('fortress_group', {
  id: serial('id').primaryKey(),
  name: varchar('name', { length: 100 }).notNull().unique(),
  description: text('description'),
});

export const groupUsers = pgTable(
  'fortress_group_user',
  {
    groupId: integer('group_id').notNull().references(() => groups.id, { onDelete: 'cascade' }),
    userId: integer('user_id').notNull().references(() => users.id, { onDelete: 'cascade' }),
  },
  table => [primaryKey({ columns: [table.groupId, table.userId] })],
);

// --- IAM: Resources & Permissions ---

export const resources = pgTable('fortress_resource', {
  name: varchar('name', { length: 100 }).primaryKey(),
  description: text('description'),
});

export const permissions = pgTable('fortress_permission', {
  id: serial('id').primaryKey(),
  resource: varchar('resource', { length: 100 }).notNull().references(() => resources.name, { onDelete: 'cascade' }),
  action: varchar('action', { length: 100 }).notNull(),
  effect: varchar('effect', { length: 10 }).notNull().default('ALLOW'), // 'ALLOW' | 'DENY'
  conditions: jsonb('conditions'), // PermissionCondition[] as JSONB
  description: text('description'),
});

// --- IAM: Roles ---

export const roles = pgTable('fortress_role', {
  id: serial('id').primaryKey(),
  name: varchar('name', { length: 100 }).notNull().unique(),
  description: text('description'),
});

export const rolePermissions = pgTable(
  'fortress_role_permission',
  {
    roleId: integer('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
    permissionId: integer('permission_id').notNull().references(() => permissions.id, { onDelete: 'cascade' }),
  },
  table => [primaryKey({ columns: [table.roleId, table.permissionId] })],
);

// --- IAM: Role Bindings ---

export const roleBindings = pgTable('fortress_role_binding', {
  id: serial('id').primaryKey(),
  roleId: integer('role_id').notNull().references(() => roles.id, { onDelete: 'cascade' }),
  subjectType: varchar('subject_type', { length: 20 }).notNull(), // 'USER' | 'GROUP' | 'SERVICE_ACCOUNT'
  subjectId: integer('subject_id').notNull(),
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
};
