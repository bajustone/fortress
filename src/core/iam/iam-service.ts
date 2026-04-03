import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressConfig } from '../config';
import type {
  Group,
  Permission,
  PermissionContext,
  PermissionInput,
  Role,
  SubjectType,
} from '../types';
import type { EvaluationMode } from './permission-evaluator';
import { Errors } from '../errors';
import { evaluatePermissions } from './permission-evaluator';
import { loadResourceFile, pullResources, pushResources, writeResourceFile } from './resource-sync';

export interface IamService {
  checkPermission: (userId: number, resource: string, action: string, context?: PermissionContext) => Promise<boolean>;
  getUserPermissions: (userId: number) => Promise<Permission[]>;
  createRole: (name: string, permissions: PermissionInput[], description?: string) => Promise<Role>;
  deleteRole: (roleId: number) => Promise<void>;
  bindRole: (subjectType: SubjectType, subjectId: number, roleId: number) => Promise<void>;
  bindRoleToUser: (userId: number, roleId: number) => Promise<void>;
  bindRoleToGroup: (groupId: number, roleId: number) => Promise<void>;
  unbindRole: (subjectType: SubjectType, subjectId: number, roleId: number) => Promise<void>;
  createGroup: (name: string, description?: string) => Promise<Group>;
  addUserToGroup: (groupId: number, userId: number) => Promise<void>;
  removeUserFromGroup: (groupId: number, userId: number) => Promise<void>;
  syncResources: (direction: 'push' | 'pull', filePath?: string) => Promise<void>;
}

export function createIamService(
  db: DatabaseAdapter,
  config: FortressConfig,
): IamService {
  const evaluationMode: EvaluationMode = config.rbac?.evaluationMode ?? 'allow-only';
  const resourceFile = config.rbac?.resourceFile ?? './fortress.resources.json';

  /**
   * Get all permissions for a user through their direct bindings and group memberships.
   * Chain: User → (direct + via Group) → RoleBinding → Role → RolePermission → Permission
   */
  async function getUserPermissions(userId: number): Promise<Permission[]> {
    // 1. Get user's direct role bindings
    const directBindings = await db.findMany<{ roleId: number }>({
      model: 'role_binding',
      where: [
        { field: 'subjectType', operator: '=', value: 'USER' },
        { field: 'subjectId', operator: '=', value: userId },
      ],
    });

    // 2. Get user's group memberships
    const groupMemberships = await db.findMany<{ groupId: number }>({
      model: 'group_user',
      where: [{ field: 'userId', operator: '=', value: userId }],
    });

    // 3. Get role bindings for user's groups
    let groupBindings: { roleId: number }[] = [];
    if (groupMemberships.length > 0) {
      const groupIds = groupMemberships.map(m => m.groupId);
      groupBindings = await db.findMany<{ roleId: number }>({
        model: 'role_binding',
        where: [
          { field: 'subjectType', operator: '=', value: 'GROUP' },
          { field: 'subjectId', operator: 'in', value: groupIds },
        ],
      });
    }

    // 4. Collect unique role IDs
    const roleIds = [...new Set([
      ...directBindings.map(b => b.roleId),
      ...groupBindings.map(b => b.roleId),
    ])];

    if (roleIds.length === 0)
      return [];

    // 5. Get role → permission mappings
    const rolePermissions = await db.findMany<{ permissionId: number }>({
      model: 'role_permission',
      where: [{ field: 'roleId', operator: 'in', value: roleIds }],
    });

    const permissionIds = [...new Set(rolePermissions.map(rp => rp.permissionId))];

    if (permissionIds.length === 0)
      return [];

    // 6. Get actual permissions
    const permissions = await db.findMany<Permission>({
      model: 'permission',
      where: [{ field: 'id', operator: 'in', value: permissionIds }],
    });

    return permissions;
  }

  return {
    async checkPermission(
      userId: number,
      resource: string,
      action: string,
      context?: PermissionContext,
    ): Promise<boolean> {
      const permissions = await getUserPermissions(userId);

      // Enrich context with user info
      const enrichedContext: PermissionContext = {
        ...context,
        user: { id: userId, ...context?.user },
      };

      return evaluatePermissions(permissions, resource, action, evaluationMode, enrichedContext);
    },

    getUserPermissions,

    async createRole(name: string, permissions: PermissionInput[], description?: string): Promise<Role> {
      const role = await db.create<Role>({
        model: 'role',
        data: { name, description: description ?? null },
      });

      for (const perm of permissions) {
        // Ensure the resource exists (auto-create if missing)
        const existingResource = await db.findOne<{ name: string }>({
          model: 'resource',
          where: [{ field: 'name', operator: '=', value: perm.resource }],
        });
        if (!existingResource) {
          await db.create({ model: 'resource', data: { name: perm.resource } });
        }

        // Find or create the permission
        let permission = await db.findOne<Permission>({
          model: 'permission',
          where: [
            { field: 'resource', operator: '=', value: perm.resource },
            { field: 'action', operator: '=', value: perm.action },
          ],
        });

        if (!permission) {
          permission = await db.create<Permission>({
            model: 'permission',
            data: {
              resource: perm.resource,
              action: perm.action,
              effect: perm.effect ?? 'ALLOW',
              conditions: perm.conditions ? JSON.stringify(perm.conditions) : null,
              description: `${perm.action} ${perm.resource}`,
            },
          });
        }

        await db.create({
          model: 'role_permission',
          data: { roleId: role.id, permissionId: permission.id },
        });
      }

      return role;
    },

    async deleteRole(roleId: number): Promise<void> {
      // Remove role bindings and role permissions first
      await db.delete({ model: 'role_permission', where: [{ field: 'roleId', operator: '=', value: roleId }] });
      await db.delete({ model: 'role_binding', where: [{ field: 'roleId', operator: '=', value: roleId }] });
      await db.delete({ model: 'role', where: [{ field: 'id', operator: '=', value: roleId }] });
    },

    async bindRole(subjectType: SubjectType, subjectId: number, roleId: number): Promise<void> {
      await db.create({
        model: 'role_binding',
        data: { roleId, subjectType, subjectId },
      });
    },

    async bindRoleToUser(userId: number, roleId: number): Promise<void> {
      await db.create({
        model: 'role_binding',
        data: { roleId, subjectType: 'USER', subjectId: userId },
      });
    },

    async bindRoleToGroup(groupId: number, roleId: number): Promise<void> {
      await db.create({
        model: 'role_binding',
        data: { roleId, subjectType: 'GROUP', subjectId: groupId },
      });
    },

    async unbindRole(subjectType: SubjectType, subjectId: number, roleId: number): Promise<void> {
      await db.delete({
        model: 'role_binding',
        where: [
          { field: 'roleId', operator: '=', value: roleId },
          { field: 'subjectType', operator: '=', value: subjectType },
          { field: 'subjectId', operator: '=', value: subjectId },
        ],
      });
    },

    async createGroup(name: string, description?: string): Promise<Group> {
      return db.create<Group>({
        model: 'group',
        data: { name, description: description ?? null },
      });
    },

    async addUserToGroup(groupId: number, userId: number): Promise<void> {
      await db.create({
        model: 'group_user',
        data: { groupId, userId },
      });
    },

    async removeUserFromGroup(groupId: number, userId: number): Promise<void> {
      await db.delete({
        model: 'group_user',
        where: [
          { field: 'groupId', operator: '=', value: groupId },
          { field: 'userId', operator: '=', value: userId },
        ],
      });
    },

    async syncResources(direction: 'push' | 'pull', filePath?: string): Promise<void> {
      const path = filePath ?? resourceFile;

      if (direction === 'push') {
        const resources = await loadResourceFile(path);
        if (Object.keys(resources.resources).length === 0) {
          throw Errors.badRequest(`No resources found in ${path}`);
        }
        await pushResources(db, resources);
      }
      else {
        const resources = await pullResources(db);
        await writeResourceFile(path, resources);
      }
    },
  };
}
