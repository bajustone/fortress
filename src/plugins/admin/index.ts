import type { ResourceFile } from '../../core/iam/resource-sync';
import type { FortressPlugin, PluginContext } from '../../core/plugin';
import type { PermissionInput, Role } from '../../core/types';
import { Errors } from '../../core/errors';
import { pullResources } from '../../core/iam/resource-sync';

export interface AdminPluginOptions {
  /** User IDs that bypass all permission checks (superadmins) */
  adminUserIds?: number[];
  /** Resource name for fortress admin permissions. Default: 'fortress'. */
  resource?: string;
}

/** Actions that map to IAM endpoint handlers */
const FORTRESS_ACTIONS: Record<string, string> = {
  getResources: 'viewResources',
  getRoles: 'viewRoles',
  createRole: 'createRole',
  deleteRole: 'deleteRole',
  bindRoleToUser: 'bindRole',
  bindRoleToGroup: 'bindRole',
  unbindRole: 'unbindRole',
  createGroup: 'createGroup',
  addUserToGroup: 'manageGroup',
  removeUserFromGroup: 'manageGroup',
  getUserPermissions: 'viewPermissions',
  checkPermission: 'viewPermissions',
  bindPermissionToUser: 'managePermissions',
  bindPermissionToGroup: 'managePermissions',
  unbindPermissionFromUser: 'managePermissions',
  unbindPermissionFromGroup: 'managePermissions',
  bootstrap: 'bootstrap',
};

/** All unique fortress admin actions */
const ALL_ACTIONS = [...new Set(Object.values(FORTRESS_ACTIONS))];

/**
 * Admin plugin — protects fortress IAM routes and provides admin management endpoints.
 *
 * Injects `after-auth` middleware on `/iam/*` paths that enforces permission checks
 * using the `fortress` resource. Provides bootstrap functionality to assign admin
 * permissions to the first user.
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
  const resourceName = options.resource ?? 'fortress';

  return {
    name: 'admin',

    models: [
      // No additional models needed — uses existing resource/permission/role tables
    ],

    middleware: [
      {
        path: '/iam/*',
        position: 'after-auth',
        handler: async (ctx: PluginContext, request: unknown, next: () => Promise<void>): Promise<void> => {
          // Extract userId from the request context
          // Hono: request is a Hono Context with .get('fortressUserId')
          // Express: request is an ExpressRequest with .fortressUserId
          const userId = extractUserId(request);

          if (!userId) {
            throw Errors.unauthorized('Authentication required for IAM operations');
          }

          // Superadmin bypass
          if (adminUserIds.has(userId)) {
            await next();
            return;
          }

          // Derive the action from the request path + method
          const action = deriveAction(request);

          // Bootstrap endpoint: allow if no fortress-admin role exists yet (first-time setup)
          if (action === 'bootstrap') {
            const existingRole = await ctx.db.findOne<{ id: number }>({
              model: 'role',
              where: [{ field: 'name', operator: '=', value: 'fortress-admin' }],
            });
            if (!existingRole) {
              // First-time bootstrap — allow any authenticated user
              await next();
              return;
            }
            // Role exists — only superadmins can re-bootstrap (already handled above)
            throw Errors.forbidden('Admin already bootstrapped. Only superadmins can re-bootstrap.');
          }

          if (!action) {
            // Unknown IAM endpoint — deny by default
            throw Errors.forbidden('Insufficient permissions for this IAM operation');
          }

          // Check fortress:action permission
          const db = ctx.db;
          // We need to check permissions directly since we don't have access to the IAM service here
          // Use the same approach as the internal adapter
          const permission = await db.findOne<{ id: number }>({
            model: 'permission',
            where: [
              { field: 'resource', operator: '=', value: resourceName },
              { field: 'action', operator: '=', value: action },
            ],
          });

          if (!permission) {
            throw Errors.forbidden(`No '${resourceName}:${action}' permission exists. Run bootstrap first.`);
          }

          // Check if user has this permission (direct or via role)
          const hasPermission = await checkUserHasPermission(db, userId, permission.id);
          if (!hasPermission) {
            throw Errors.forbidden(`Missing '${resourceName}:${action}' permission`);
          }

          await next();
        },
      },
    ],

    routes: [
      {
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
      },
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

        // Ensure the fortress resource exists
        const existingResource = await db.findOne<{ name: string }>({
          model: 'resource',
          where: [{ field: 'name', operator: '=', value: resourceName }],
        });
        if (!existingResource) {
          await db.create({ model: 'resource', data: { name: resourceName, description: 'Fortress IAM administration' } });
        }

        // Create all permissions
        const permissions: PermissionInput[] = ALL_ACTIONS.map(action => ({
          resource: resourceName,
          action,
          effect: 'ALLOW' as const,
        }));

        // Find or create each permission
        const permissionIds: number[] = [];
        for (const perm of permissions) {
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
                effect: perm.effect ?? 'ALLOW',
                description: `${perm.action} ${perm.resource}`,
              },
            });
          }
          permissionIds.push(existing.id);
        }

        // Create or find the fortress-admin role
        let adminRole = await db.findOne<Role>({
          model: 'role',
          where: [{ field: 'name', operator: '=', value: 'fortress-admin' }],
        });
        if (!adminRole) {
          adminRole = await db.create<Role>({
            model: 'role',
            data: { name: 'fortress-admin', description: 'Full fortress IAM administration', isSystem: true },
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

/**
 * Derive the IAM action from the request path and method.
 * Maps endpoint handler names to fortress admin actions.
 */
function deriveAction(request: unknown): string | null {
  if (!request || typeof request !== 'object')
    return null;

  // Get path and method from request
  let path: string;
  let method: string;

  if ('req' in request && typeof (request as any).req === 'object') {
    // Hono Context
    path = (request as any).req.path;
    method = (request as any).req.method;
  }
  else if ('path' in request && 'method' in request) {
    // Express Request
    path = (request as any).path;
    method = (request as any).method;
  }
  else {
    return null;
  }

  // Map path + method to handler name, then to action
  const handlerName = resolveHandlerName(method, path);
  return handlerName ? (FORTRESS_ACTIONS[handlerName] ?? null) : null;
}

/** Core IAM endpoint patterns — module-scoped to avoid regex re-compilation */
const IAM_ENDPOINT_PATTERNS: Array<{ method: string; pattern: RegExp; handler: string }> = [
  { method: 'GET', pattern: /^\/iam\/resources$/, handler: 'getResources' },
  { method: 'GET', pattern: /^\/iam\/roles$/, handler: 'getRoles' },
  { method: 'POST', pattern: /^\/iam\/roles$/, handler: 'createRole' },
  { method: 'DELETE', pattern: /^\/iam\/roles\/[^/]+$/, handler: 'deleteRole' },
  { method: 'POST', pattern: /^\/iam\/roles\/[^/]+\/bind\/user$/, handler: 'bindRoleToUser' },
  { method: 'POST', pattern: /^\/iam\/roles\/[^/]+\/bind\/group$/, handler: 'bindRoleToGroup' },
  { method: 'DELETE', pattern: /^\/iam\/roles\/[^/]+\/bind$/, handler: 'unbindRole' },
  { method: 'POST', pattern: /^\/iam\/groups$/, handler: 'createGroup' },
  { method: 'POST', pattern: /^\/iam\/groups\/[^/]+\/users$/, handler: 'addUserToGroup' },
  { method: 'DELETE', pattern: /^\/iam\/groups\/[^/]+\/users\/[^/]+$/, handler: 'removeUserFromGroup' },
  { method: 'GET', pattern: /^\/iam\/users\/[^/]+\/permissions$/, handler: 'getUserPermissions' },
  { method: 'POST', pattern: /^\/iam\/check$/, handler: 'checkPermission' },
  { method: 'POST', pattern: /^\/iam\/permissions\/bind\/user$/, handler: 'bindPermissionToUser' },
  { method: 'POST', pattern: /^\/iam\/permissions\/bind\/group$/, handler: 'bindPermissionToGroup' },
  { method: 'DELETE', pattern: /^\/iam\/permissions\/bind\/user$/, handler: 'unbindPermissionFromUser' },
  { method: 'DELETE', pattern: /^\/iam\/permissions\/bind\/group$/, handler: 'unbindPermissionFromGroup' },
  { method: 'POST', pattern: /^\/iam\/admin\/bootstrap$/, handler: 'bootstrap' },
];

/**
 * Resolve a handler name from HTTP method + path.
 */
function resolveHandlerName(method: string, path: string): string | null {
  for (const p of IAM_ENDPOINT_PATTERNS) {
    if (p.method === method && p.pattern.test(path)) {
      return p.handler;
    }
  }

  return null;
}

/**
 * Check if a user has a specific permission (via role bindings or direct bindings).
 */
async function checkUserHasPermission(
  db: PluginContext['db'],
  userId: number,
  permissionId: number,
): Promise<boolean> {
  // Check direct permission binding
  const directBinding = await db.findOne<{ id: number }>({
    model: 'direct_permission_binding',
    where: [
      { field: 'permissionId', operator: '=', value: permissionId },
      { field: 'subjectType', operator: '=', value: 'USER' },
      { field: 'subjectId', operator: '=', value: userId },
    ],
  });
  if (directBinding)
    return true;

  // Check role-based permission
  const roleBindings = await db.findMany<{ roleId: number }>({
    model: 'role_binding',
    where: [
      { field: 'subjectType', operator: '=', value: 'USER' },
      { field: 'subjectId', operator: '=', value: userId },
    ],
  });

  if (roleBindings.length === 0) {
    // Check group-based role bindings
    const groupMemberships = await db.findMany<{ groupId: number }>({
      model: 'group_user',
      where: [{ field: 'userId', operator: '=', value: userId }],
    });
    if (groupMemberships.length > 0) {
      const groupIds = groupMemberships.map(m => m.groupId);
      const groupRoleBindings = await db.findMany<{ roleId: number }>({
        model: 'role_binding',
        where: [
          { field: 'subjectType', operator: '=', value: 'GROUP' },
          { field: 'subjectId', operator: 'in', value: groupIds },
        ],
      });
      roleBindings.push(...groupRoleBindings);
    }
  }

  if (roleBindings.length === 0)
    return false;

  const roleIds = [...new Set(roleBindings.map(b => b.roleId))];
  const rolePermission = await db.findOne<{ id: number }>({
    model: 'role_permission',
    where: [
      { field: 'roleId', operator: 'in', value: roleIds },
      { field: 'permissionId', operator: '=', value: permissionId },
    ],
  });

  return rolePermission !== null;
}
