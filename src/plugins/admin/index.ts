/**
 * Admin plugin for fortress.
 *
 * Bootstraps an initial admin user and applies a default-deny policy to the
 * IAM management endpoints, then exposes the full admin CRUD surface
 * (users, groups, roles, permissions, role bindings) as HTTP routes guarded
 * by fortress's own RBAC. Required if you want a self-service IAM admin UI
 * out of the box.
 *
 * @module
 */

import type { EndpointDefinition, EndpointPermission } from '../../core/endpoint';
import type { ResourceFile } from '../../core/iam/resource-sync';
import type { FortressPlugin, PluginContext } from '../../core/plugin';
import type { FortressUser, Group, Permission, PermissionInput, Role, SubjectType } from '../../core/types';
import { authEndpoints } from '../../core/auth/auth-endpoints';
import { Errors } from '../../core/errors';
import { iamEndpoints } from '../../core/iam/iam-endpoints';
import { pullResources } from '../../core/iam/resource-sync';

export interface AdminPluginOptions {
  /** User IDs that bypass all permission checks (superadmins) */
  adminUserIds?: number[];
  /** Resource name for fortress admin permissions. Default: 'fortress'. */
  resource?: string;
}

/**
 * Collect all unique permission declarations from endpoint definitions.
 */
function collectPermissions(endpoints: EndpointDefinition[]): EndpointPermission[] {
  const seen = new Set<string>();
  const result: EndpointPermission[] = [];

  for (const ep of endpoints) {
    const perm = ep.meta?.permission;
    if (!perm)
      continue;
    const key = `${perm.resource}:${perm.action}`;
    if (seen.has(key))
      continue;
    seen.add(key);
    result.push(perm);
  }

  return result;
}

// ── Inline JSON Schema helpers ────────────────────────────────────

const userRef = { $ref: '#/components/schemas/User' };
const permissionRef = { $ref: '#/components/schemas/Permission' };
const permissionInputRef = { $ref: '#/components/schemas/PermissionInput' };
const errorRef = { $ref: '#/components/schemas/ErrorResponse' };

function intSchema(desc: string): { type: 'integer'; description: string } {
  return { type: 'integer', description: desc };
}

function strSchema(desc: string): { type: 'string'; description: string } {
  return { type: 'string', description: desc };
}

function boolSchema(desc: string): { type: 'boolean'; description: string } {
  return { type: 'boolean', description: desc };
}

/** Parse a value to a positive integer, or return undefined. */
function safeInt(v: unknown): number | undefined {
  if (v === undefined || v === null || v === '')
    return undefined;
  const n = Number(v);
  return Number.isInteger(n) && n > 0 ? n : undefined;
}

/** Parse a value to a required positive integer, or throw. */
function requireInt(v: unknown, name: string): number {
  const n = safeInt(v);
  if (n === undefined)
    throw Errors.badRequest(`${name} must be a positive integer`);
  return n;
}

// ── Admin endpoint definitions ────────────────────────────────────

const adminAuthEndpoints: EndpointDefinition[] = [
  // GET /auth/users — list users (paginated, searchable)
  {
    method: 'GET',
    path: '/auth/users',
    handler: 'listUsers',
    meta: {
      summary: 'List users',
      description: 'List all users with pagination and optional search',
      tags: ['Auth', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewUsers' },
    },
    input: {
      query: {
        type: 'object',
        properties: {
          limit: intSchema('Max results (default 50)'),
          offset: intSchema('Skip results (default 0)'),
          search: strSchema('Search by email'),
          sortBy: strSchema('Sort field (default: id)'),
          sortDirection: { type: 'string', enum: ['asc', 'desc'], description: 'Sort direction' },
        },
      },
    },
    responses: {
      200: {
        description: 'User list',
        schema: {
          type: 'object',
          properties: {
            users: { type: 'array', items: userRef, description: 'List of users' },
            total: intSchema('Total number of users'),
          },
          required: ['users', 'total'],
        },
      },
      401: { description: 'Not authenticated' },
      403: { description: 'Insufficient permissions' },
    },
  },

  // GET /auth/users/:id — get user by ID
  {
    method: 'GET',
    path: '/auth/users/:id',
    handler: 'getUserById',
    meta: {
      summary: 'Get user by ID',
      tags: ['Auth', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewUsers' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('User ID') },
        required: ['id'],
      },
    },
    responses: {
      200: { description: 'User details', schema: userRef },
      401: { description: 'Not authenticated' },
      403: { description: 'Insufficient permissions' },
      404: { description: 'User not found', schema: errorRef },
    },
  },

  // PUT /auth/users/:id — update user
  {
    method: 'PUT',
    path: '/auth/users/:id',
    handler: 'updateUser',
    meta: {
      summary: 'Update user',
      tags: ['Auth', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageUsers' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('User ID') },
        required: ['id'],
      },
      body: {
        type: 'object',
        properties: {
          name: strSchema('Display name'),
          email: { type: 'string', format: 'email', description: 'User email' },
          isActive: boolSchema('Account active status'),
          password: strSchema('New password (will be hashed)'),
        },
      },
    },
    responses: {
      200: { description: 'Updated user', schema: userRef },
      401: { description: 'Not authenticated' },
      403: { description: 'Insufficient permissions' },
      404: { description: 'User not found', schema: errorRef },
      409: { description: 'Email already in use', schema: errorRef },
    },
  },

  // DELETE /auth/users/:id — delete user
  {
    method: 'DELETE',
    path: '/auth/users/:id',
    handler: 'deleteUser',
    meta: {
      summary: 'Delete user',
      tags: ['Auth', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageUsers' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('User ID') },
        required: ['id'],
      },
    },
    responses: {
      200: { description: 'User deleted', schema: { type: 'object', properties: { ok: boolSchema('Success') } } },
      401: { description: 'Not authenticated' },
      403: { description: 'Insufficient permissions' },
      404: { description: 'User not found', schema: errorRef },
    },
  },

  // POST /auth/users — admin-initiated user creation
  {
    method: 'POST',
    path: '/auth/users',
    handler: 'createUser',
    meta: {
      summary: 'Create a user (admin)',
      description: 'Admin-initiated user creation. Unlike /auth/register, requires authentication and manageUsers permission.',
      tags: ['Auth', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageUsers' },
    },
    input: {
      body: {
        type: 'object',
        properties: {
          email: { type: 'string', format: 'email', description: 'User email' },
          name: strSchema('Display name'),
          password: strSchema('User password'),
          isActive: boolSchema('Set active status (default true)'),
        },
        required: ['email', 'name'],
      },
    },
    responses: {
      201: { description: 'User created', schema: userRef },
      401: { description: 'Not authenticated' },
      403: { description: 'Insufficient permissions' },
      409: { description: 'Email already exists', schema: errorRef },
    },
  },
];

const adminIamEndpoints: EndpointDefinition[] = [
  // GET /iam/roles/:id — get role with permissions
  {
    method: 'GET',
    path: '/iam/roles/:id',
    handler: 'getRole',
    meta: {
      summary: 'Get role with permissions',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewRoles' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Role ID') },
        required: ['id'],
      },
    },
    responses: {
      200: {
        description: 'Role with permissions',
        schema: {
          type: 'object',
          properties: {
            id: intSchema('Role ID'),
            name: strSchema('Role name'),
            description: { type: 'string', nullable: true, description: 'Role description' },
            isSystem: boolSchema('Whether this is a system role'),
            permissions: { type: 'array', items: permissionRef, description: 'Role permissions' },
          },
          required: ['id', 'name', 'permissions'],
        },
      },
      404: { description: 'Role not found', schema: errorRef },
    },
  },

  // PUT /iam/roles/:id — update role
  {
    method: 'PUT',
    path: '/iam/roles/:id',
    handler: 'updateRole',
    meta: {
      summary: 'Update role',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageRoles' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Role ID') },
        required: ['id'],
      },
      body: {
        type: 'object',
        properties: {
          name: strSchema('Role name'),
          description: strSchema('Role description'),
        },
      },
    },
    responses: {
      200: { description: 'Updated role', schema: { $ref: '#/components/schemas/Role' } },
      400: { description: 'Cannot update system role', schema: errorRef },
      404: { description: 'Role not found', schema: errorRef },
    },
  },

  // GET /iam/groups — list groups (paginated)
  {
    method: 'GET',
    path: '/iam/groups',
    handler: 'listGroups',
    meta: {
      summary: 'List groups',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewGroups' },
    },
    input: {
      query: {
        type: 'object',
        properties: {
          limit: intSchema('Max results (default 50)'),
          offset: intSchema('Skip results (default 0)'),
        },
      },
    },
    responses: {
      200: {
        description: 'Group list',
        schema: {
          type: 'object',
          properties: {
            groups: { type: 'array', items: { $ref: '#/components/schemas/Group' }, description: 'List of groups' },
            total: intSchema('Total number of groups'),
          },
          required: ['groups', 'total'],
        },
      },
    },
  },

  // GET /iam/groups/:id — get group with members
  {
    method: 'GET',
    path: '/iam/groups/:id',
    handler: 'getGroup',
    meta: {
      summary: 'Get group with members',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewGroups' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Group ID') },
        required: ['id'],
      },
    },
    responses: {
      200: {
        description: 'Group with members',
        schema: {
          type: 'object',
          properties: {
            id: intSchema('Group ID'),
            name: strSchema('Group name'),
            description: { type: 'string', nullable: true, description: 'Group description' },
            users: { type: 'array', items: userRef, description: 'Group members' },
          },
          required: ['id', 'name', 'users'],
        },
      },
      404: { description: 'Group not found', schema: errorRef },
    },
  },

  // PUT /iam/groups/:id — update group
  {
    method: 'PUT',
    path: '/iam/groups/:id',
    handler: 'updateGroup',
    meta: {
      summary: 'Update group',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageGroup' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Group ID') },
        required: ['id'],
      },
      body: {
        type: 'object',
        properties: {
          name: strSchema('Group name'),
          description: strSchema('Group description'),
        },
      },
    },
    responses: {
      200: { description: 'Updated group', schema: { $ref: '#/components/schemas/Group' } },
      404: { description: 'Group not found', schema: errorRef },
    },
  },

  // DELETE /iam/groups/:id — delete group
  {
    method: 'DELETE',
    path: '/iam/groups/:id',
    handler: 'deleteGroup',
    meta: {
      summary: 'Delete group',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageGroup' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Group ID') },
        required: ['id'],
      },
    },
    responses: {
      200: { description: 'Group deleted', schema: { type: 'object', properties: { ok: boolSchema('Success') } } },
      404: { description: 'Group not found', schema: errorRef },
    },
  },

  // GET /iam/groups/:id/users — list group members
  {
    method: 'GET',
    path: '/iam/groups/:id/users',
    handler: 'getGroupUsers',
    meta: {
      summary: 'List group members',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewGroups' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Group ID') },
        required: ['id'],
      },
    },
    responses: {
      200: {
        description: 'Group members',
        schema: { type: 'array', items: userRef },
      },
    },
  },

  // GET /iam/permissions — list all permissions
  {
    method: 'GET',
    path: '/iam/permissions',
    handler: 'listPermissions',
    meta: {
      summary: 'List permissions',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewPermissions' },
    },
    input: {
      query: {
        type: 'object',
        properties: {
          resource: strSchema('Filter by resource name'),
        },
      },
    },
    responses: {
      200: {
        description: 'Permission list',
        schema: { type: 'array', items: permissionRef },
      },
    },
  },

  // POST /iam/permissions — create permission
  {
    method: 'POST',
    path: '/iam/permissions',
    handler: 'createPermission',
    meta: {
      summary: 'Create permission',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'managePermissions' },
    },
    input: {
      body: permissionInputRef,
    },
    responses: {
      200: { description: 'Created permission', schema: permissionRef },
    },
  },

  // DELETE /iam/permissions/:id — delete permission
  {
    method: 'DELETE',
    path: '/iam/permissions/:id',
    handler: 'deletePermission',
    meta: {
      summary: 'Delete permission',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'managePermissions' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Permission ID') },
        required: ['id'],
      },
    },
    responses: {
      200: { description: 'Permission deleted', schema: { type: 'object', properties: { ok: boolSchema('Success') } } },
      404: { description: 'Permission not found', schema: errorRef },
    },
  },

  // POST /iam/roles/:id/permissions — add permission to role
  {
    method: 'POST',
    path: '/iam/roles/:id/permissions',
    handler: 'addPermissionToRole',
    meta: {
      summary: 'Add permission to role',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageRoles' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Role ID') },
        required: ['id'],
      },
      body: permissionInputRef,
    },
    responses: {
      200: { description: 'Permission added', schema: { type: 'object', properties: { ok: boolSchema('Success') } } },
      404: { description: 'Role not found', schema: errorRef },
    },
  },
];

// ── Sync endpoint ────────────────────────────────────────────────

const syncEndpoint: EndpointDefinition = {
  method: 'POST',
  path: '/iam/sync',
  handler: 'syncResources',
  meta: {
    summary: 'Sync IAM resources',
    description: 'Push or pull resource definitions to/from the resource file',
    tags: ['IAM', 'Admin'],
    security: ['bearer'],
    permission: { resource: 'fortress', action: 'managePermissions' },
  },
  input: {
    body: {
      type: 'object',
      properties: {
        direction: { type: 'string', enum: ['push', 'pull'], description: 'Sync direction' },
        filePath: strSchema('Resource file path (optional)'),
      },
      required: ['direction'],
    },
  },
  responses: {
    200: { description: 'Sync complete', schema: { type: 'object', properties: { ok: boolSchema('Success') } } },
    401: { description: 'Not authenticated' },
    403: { description: 'Insufficient permissions' },
  },
};

// ── Bootstrap endpoint ────────────────────────────────────────────

const bootstrapEndpoint: EndpointDefinition = {
  method: 'POST',
  path: '/iam/admin/bootstrap',
  handler: 'bootstrap',
  meta: {
    summary: 'Bootstrap admin user',
    description: 'Assigns all fortress admin permissions to a user. Creates the fortress resource and permissions if they do not exist.',
    tags: ['IAM', 'Admin'],
    security: ['bearer'],
  },
  input: {
    body: {
      type: 'object',
      properties: {
        userId: { type: 'integer', description: 'User ID to make admin' },
      },
      required: ['userId'],
    },
  },
  responses: {
    200: { description: 'Admin bootstrapped', schema: { type: 'object', properties: { ok: { type: 'boolean' }, role: { type: 'object' } } } },
    401: { description: 'Not authenticated' },
  },
};

/**
 * Admin plugin — protects fortress routes and provides admin CRUD endpoints.
 *
 * Adds endpoints for:
 * - User management (list, get, update, delete)
 * - Role management (get, update, add permissions)
 * - Group management (list, get, update, delete, members)
 * - Permission management (list, create, delete)
 * - Admin bootstrap
 *
 * Works with the RBAC middleware's security-aware default deny:
 * - All endpoints declare `permission: { resource: 'fortress', action: '...' }`
 * - RBAC middleware enforces these automatically
 * - Admin plugin adds superadmin bypass and bootstrap functionality
 *
 * @example
 * ```ts
 * import { admin } from '@bajustone/fortress/plugins/admin';
 *
 * const fortress = createFortress({
 *   plugins: [
 *     admin({ adminUserIds: [1] }),
 *   ],
 * });
 * ```
 */
export function admin(options: AdminPluginOptions = {}): FortressPlugin {
  const adminUserIds = new Set(options.adminUserIds ?? []);

  const superadminMiddleware = {
    position: 'after-auth' as const,
    handler: async (_ctx: PluginContext, request: unknown, next: () => Promise<void>): Promise<void> => {
      const userId = extractUserId(request);
      // Superadmin bypass — skip all permission checks
      if (userId && adminUserIds.has(userId)) {
        await next();
        return;
      }
      // Non-superadmins: let RBAC middleware handle permission enforcement
      await next();
    },
  };

  return {
    name: 'admin',

    middleware: adminUserIds.size > 0
      ? [
          { path: '/iam/*', ...superadminMiddleware },
          { path: '/auth/users/*', ...superadminMiddleware },
          { path: '/auth/users', ...superadminMiddleware },
        ]
      : undefined,

    routes: [
      bootstrapEndpoint,
      syncEndpoint,
      ...adminAuthEndpoints,
      ...adminIamEndpoints,
      ...iamEndpoints,
    ],

    methods: (ctx: PluginContext) => ({
      async getResources(): Promise<ResourceFile> {
        return pullResources(ctx.db);
      },

      async bootstrap(body: { userId: number }): Promise<{ ok: boolean; role: Role }> {
        const { userId } = body;
        const db = ctx.db;

        // Verify user exists
        const user = await db.findOne<{ id: number }>({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: userId }],
        });
        if (!user) {
          throw Errors.notFound('User not found');
        }

        // Check if already bootstrapped — only superadmins can re-bootstrap
        const existingRole = await db.findOne<Role>({
          model: 'role',
          where: [{ field: 'name', operator: '=', value: 'fortress-admin' }],
        });
        if (existingRole && !adminUserIds.has(userId)) {
          throw Errors.forbidden('Admin already bootstrapped. Only superadmins can re-bootstrap.');
        }

        // Auto-discover all permissions from endpoint definitions
        const plugins = ctx.config.plugins ?? [];
        const pluginEndpoints: EndpointDefinition[] = [];
        for (const plugin of plugins) {
          if (plugin.routes)
            pluginEndpoints.push(...plugin.routes);
        }
        const allEndpoints = [...authEndpoints, ...iamEndpoints, ...pluginEndpoints];
        const declaredPermissions = collectPermissions(allEndpoints);

        // Ensure each resource exists
        const resources = new Set(declaredPermissions.map(p => p.resource));
        for (const resource of resources) {
          const existing = await db.findOne<{ name: string }>({
            model: 'resource',
            where: [{ field: 'name', operator: '=', value: resource }],
          });
          if (!existing) {
            await db.create({ model: 'resource', data: { name: resource, description: `Auto-registered by admin plugin` } });
          }
        }

        // Find or create each permission
        const permissionIds: number[] = [];
        for (const perm of declaredPermissions) {
          let existing = await db.findOne<{ id: number }>({
            model: 'permission',
            where: [
              { field: 'resource', operator: '=', value: perm.resource },
              { field: 'action', operator: '=', value: perm.action },
            ],
          });
          if (!existing) {
            existing = await db.create<{ id: number }>({
              model: 'permission',
              data: {
                resource: perm.resource,
                action: perm.action,
                effect: 'ALLOW',
                description: `${perm.action} ${perm.resource}`,
              },
            });
          }
          permissionIds.push(existing.id);
        }

        // Create or find the fortress-admin role
        let adminRole = existingRole;
        if (!adminRole) {
          adminRole = await db.create<Role>({
            model: 'role',
            data: { name: 'fortress-admin', description: 'Full fortress administration', isSystem: true },
          });
        }

        // Link all permissions to the role
        for (const permId of permissionIds) {
          const existingLink = await db.findOne<{ id: number }>({
            model: 'role_permission',
            where: [
              { field: 'roleId', operator: '=', value: adminRole.id },
              { field: 'permissionId', operator: '=', value: permId },
            ],
          });
          if (!existingLink) {
            await db.create({ model: 'role_permission', data: { roleId: adminRole.id, permissionId: permId } });
          }
        }

        // Bind the role to the user
        const existingBinding = await db.findOne<{ id: number }>({
          model: 'role_binding',
          where: [
            { field: 'roleId', operator: '=', value: adminRole.id },
            { field: 'subjectType', operator: '=', value: 'USER' },
            { field: 'subjectId', operator: '=', value: userId },
          ],
        });
        if (!existingBinding) {
          await db.create({
            model: 'role_binding',
            data: { roleId: adminRole.id, subjectType: 'USER', subjectId: userId, tenantId: null },
          });
        }

        return { ok: true, role: adminRole };
      },

      // ── Auth admin — delegates to core auth service ──────────

      async listUsers(body: Record<string, string>): Promise<{ users: FortressUser[]; total: number }> {
        if (!ctx.auth)
          throw Errors.database('Auth service not available');
        return ctx.auth.listUsers({
          limit: body.limit ? Number(body.limit) : undefined,
          offset: body.offset ? Number(body.offset) : undefined,
          search: body.search,
          sortBy: body.sortBy,
          sortDirection: body.sortDirection as 'asc' | 'desc' | undefined,
        });
      },

      async getUserById(body: Record<string, string>): Promise<FortressUser> {
        if (!ctx.auth)
          throw Errors.database('Auth service not available');
        return ctx.auth.getUserById(requireInt(body.id, 'id'));
      },

      async createUser(body: Record<string, unknown>): Promise<FortressUser> {
        if (!ctx.auth)
          throw Errors.database('Auth service not available');
        return ctx.auth.createUser({
          email: body.email as string,
          name: body.name as string,
          password: body.password as string | undefined,
          isActive: body.isActive as boolean | undefined,
        });
      },

      async updateUser(body: Record<string, unknown>): Promise<FortressUser> {
        if (!ctx.auth)
          throw Errors.database('Auth service not available');
        const { id, ...data } = body;
        return ctx.auth.updateUser(requireInt(id, 'id'), data as { name?: string; email?: string; isActive?: boolean; password?: string });
      },

      async deleteUser(body: Record<string, string>): Promise<{ ok: boolean }> {
        if (!ctx.auth)
          throw Errors.database('Auth service not available');
        await ctx.auth.deleteUser(requireInt(body.id, 'id'));
        return { ok: true };
      },

      // ── IAM admin — delegates to core IAM service ────────────

      async getRole(body: Record<string, string>): Promise<Role & { permissions: Permission[] }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.getRole(requireInt(body.id, 'id'));
      },

      async updateRole(body: Record<string, unknown>): Promise<Role> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        const { id, ...data } = body;
        return ctx.iam.updateRole(requireInt(id, 'id'), data as { name?: string; description?: string });
      },

      async listGroups(body: Record<string, string>): Promise<{ groups: Group[]; total: number }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.listGroups({
          limit: body.limit ? Number(body.limit) : undefined,
          offset: body.offset ? Number(body.offset) : undefined,
        });
      },

      async getGroup(body: Record<string, string>): Promise<Group & { users: FortressUser[] }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.getGroup(requireInt(body.id, 'id'));
      },

      async updateGroup(body: Record<string, unknown>): Promise<Group> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        const { id, ...data } = body;
        return ctx.iam.updateGroup(requireInt(id, 'id'), data as { name?: string; description?: string });
      },

      async deleteGroup(body: Record<string, string>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.deleteGroup(requireInt(body.id, 'id'));
        return { ok: true };
      },

      async getGroupUsers(body: Record<string, string>): Promise<FortressUser[]> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.getGroupUsers(requireInt(body.id, 'id'));
      },

      async listPermissions(body: Record<string, string>): Promise<Permission[]> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.listPermissions({
          resource: body.resource || undefined,
        });
      },

      async createPermission(body: PermissionInput): Promise<Permission> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.createPermission(body);
      },

      async deletePermission(body: Record<string, string>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.deletePermission(requireInt(body.id, 'id'));
        return { ok: true };
      },

      async addPermissionToRole(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        const { id, ...permission } = body;
        await ctx.iam.addPermissionToRole(requireInt(id, 'id'), permission as unknown as PermissionInput);
        return { ok: true };
      },

      // ── Core IAM operations — previously spec-only ─────────────

      async getRoles(): Promise<Role[]> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.getRoles();
      },

      async createRole(body: Record<string, unknown>): Promise<Role> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.createRole(
          body.name as string,
          (body.permissions ?? []) as PermissionInput[],
          body.description as string | undefined,
        );
      },

      async deleteRole(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.deleteRole(requireInt(body.id, 'id'));
        return { ok: true };
      },

      async bindRoleToUser(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.bindRoleToUser(
          requireInt(body.userId, 'userId'),
          requireInt(body.id, 'id'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async bindRoleToGroup(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.bindRoleToGroup(
          requireInt(body.groupId, 'groupId'),
          requireInt(body.id, 'id'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async unbindRole(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.unbindRole(
          body.subjectType as SubjectType,
          requireInt(body.subjectId, 'subjectId'),
          requireInt(body.id, 'id'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async createGroup(body: Record<string, unknown>): Promise<Group> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.createGroup(
          body.name as string,
          body.description as string | undefined,
        );
      },

      async addUserToGroup(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.addUserToGroup(
          requireInt(body.id, 'id'),
          requireInt(body.userId, 'userId'),
        );
        return { ok: true };
      },

      async removeUserFromGroup(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.removeUserFromGroup(
          requireInt(body.id, 'id'),
          requireInt(body.userId, 'userId'),
        );
        return { ok: true };
      },

      async getUserPermissions(body: Record<string, unknown>): Promise<Permission[]> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.getUserPermissions(
          requireInt(body.id, 'id'),
          body.tenantId as string | undefined,
        );
      },

      async checkPermission(body: Record<string, unknown>): Promise<{ allowed: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        const allowed = await ctx.iam.checkPermission(
          requireInt(body.userId, 'userId'),
          body.resource as string,
          body.action as string,
          body.context as Record<string, unknown> | undefined,
        );
        return { allowed };
      },

      async bindPermissionToUser(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.bindPermissionToUser(
          requireInt(body.userId, 'userId'),
          body.permission as PermissionInput,
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async bindPermissionToGroup(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.bindPermissionToGroup(
          requireInt(body.groupId, 'groupId'),
          body.permission as PermissionInput,
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async unbindPermissionFromUser(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.unbindPermissionFromUser(
          requireInt(body.userId, 'userId'),
          requireInt(body.permissionId, 'permissionId'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async unbindPermissionFromGroup(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.unbindPermissionFromGroup(
          requireInt(body.groupId, 'groupId'),
          requireInt(body.permissionId, 'permissionId'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      // ── Resource sync ──────────────────────────────────────────

      async syncResources(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.syncResources(
          body.direction as 'push' | 'pull',
          body.filePath as string | undefined,
        );
        return { ok: true };
      },
    }),
  };
}

// --- Helpers ---

/**
 * Extract userId from a framework-agnostic request object.
 * Supports both Hono Context and Express Request.
 */
function extractUserId(request: unknown): number | undefined {
  if (!request || typeof request !== 'object')
    return undefined;

  // Hono Context: has .get() method
  if ('get' in request && typeof (request as any).get === 'function') {
    return (request as any).get('fortressUserId') as number | undefined;
  }

  // Express Request: has .fortressUserId property
  if ('fortressUserId' in request) {
    return (request as any).fortressUserId as number | undefined;
  }

  return undefined;
}
