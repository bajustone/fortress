import type { EndpointDefinition, EndpointPermission } from '../../core/endpoint';
import type { ResourceFile } from '../../core/iam/resource-sync';
import type { FortressPlugin, PluginContext } from '../../core/plugin';
import type { Role } from '../../core/types';
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

/**
 * Admin plugin — protects fortress IAM routes and provides admin management endpoints.
 *
 * Works with the RBAC middleware's security-aware default deny:
 * - IAM endpoints declare `permission: { resource: 'fortress', action: '...' }`
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

  return {
    name: 'admin',

    middleware: adminUserIds.size > 0
      ? [
          {
            path: '/iam/*',
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
          },
        ]
      : undefined,

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
