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
import { createInternalAdapter } from '../internal-adapter';
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
  const adapter = createInternalAdapter(db);

  return {
    async checkPermission(
      userId: number,
      resource: string,
      action: string,
      context?: PermissionContext,
    ): Promise<boolean> {
      const permissions = await adapter.getUserPermissions(userId);

      // Enrich context with user info
      const enrichedContext: PermissionContext = {
        ...context,
        user: { id: userId, ...context?.user },
      };

      return evaluatePermissions(permissions, resource, action, evaluationMode, enrichedContext);
    },

    getUserPermissions: adapter.getUserPermissions,

    async createRole(name: string, permissions: PermissionInput[], description?: string): Promise<Role> {
      const role = await db.create<Role>({
        model: 'role',
        data: { name, description: description ?? null },
      });

      for (const perm of permissions) {
        await adapter.ensureResource(perm.resource);
        const permission = await adapter.findOrCreatePermission(perm);

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
