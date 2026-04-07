import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressConfig } from '../config';
import type {
  FortressUser,
  Group,
  Permission,
  PermissionContext,
  PermissionInput,
  Role,
  SubjectType,
} from '../types';
import type { EvaluationMode } from './permission-evaluator';
import type { ResourceFile } from './resource-sync';
import { Errors } from '../errors';
import { createInternalAdapter } from '../internal-adapter';
import { createPermissionCache } from './permission-cache';
import { evaluatePermissions } from './permission-evaluator';
import { loadResourceFile, pullResources, pushResources, writeResourceFile } from './resource-sync';

export interface IamEvent {
  eventType: string;
  actorId?: number | null;
  targetId?: number | null;
  targetType?: string | null;
  metadata?: Record<string, unknown>;
}

export type IamEventListener = (event: IamEvent) => Promise<void>;

export interface IamService {
  checkPermission: (userId: number, resource: string, action: string, context?: PermissionContext) => Promise<boolean>;
  getUserPermissions: (userId: number, tenantId?: string) => Promise<Permission[]>;
  createRole: (name: string, permissions: PermissionInput[], description?: string) => Promise<Role>;
  deleteRole: (roleId: number) => Promise<void>;
  bindRole: (subjectType: SubjectType, subjectId: number, roleId: number, tenantId?: string) => Promise<void>;
  bindRoleToUser: (userId: number, roleId: number, tenantId?: string) => Promise<void>;
  bindRoleToGroup: (groupId: number, roleId: number, tenantId?: string) => Promise<void>;
  unbindRole: (subjectType: SubjectType, subjectId: number, roleId: number, tenantId?: string) => Promise<void>;
  bindPermissionToUser: (userId: number, permission: PermissionInput, tenantId?: string) => Promise<void>;
  bindPermissionToGroup: (groupId: number, permission: PermissionInput, tenantId?: string) => Promise<void>;
  unbindPermissionFromUser: (userId: number, permissionId: number, tenantId?: string) => Promise<void>;
  unbindPermissionFromGroup: (groupId: number, permissionId: number, tenantId?: string) => Promise<void>;
  createGroup: (name: string, description?: string) => Promise<Group>;
  addUserToGroup: (groupId: number, userId: number) => Promise<void>;
  removeUserFromGroup: (groupId: number, userId: number) => Promise<void>;
  getResources: () => Promise<ResourceFile>;
  getRoles: () => Promise<Role[]>;
  syncResources: (direction: 'push' | 'pull', filePath?: string) => Promise<void>;
  clearPermissionCache: () => void;
  setIamObserver: (listener: IamEventListener) => void;

  // ── Admin CRUD ─────────────────────────────────────────────────
  getRole: (roleId: number) => Promise<Role & { permissions: Permission[] }>;
  updateRole: (roleId: number, data: { name?: string; description?: string }) => Promise<Role>;
  listGroups: (options?: { limit?: number; offset?: number }) => Promise<{ groups: Group[]; total: number }>;
  getGroup: (groupId: number) => Promise<Group & { users: FortressUser[] }>;
  updateGroup: (groupId: number, data: { name?: string; description?: string }) => Promise<Group>;
  deleteGroup: (groupId: number) => Promise<void>;
  getGroupUsers: (groupId: number) => Promise<FortressUser[]>;
  listPermissions: (options?: { resource?: string }) => Promise<Permission[]>;
  createPermission: (permission: PermissionInput) => Promise<Permission>;
  deletePermission: (permissionId: number) => Promise<void>;
  addPermissionToRole: (roleId: number, permission: PermissionInput) => Promise<void>;
}

export function createIamService(
  db: DatabaseAdapter,
  config: FortressConfig,
): IamService {
  const evaluationMode: EvaluationMode = config.rbac?.evaluationMode ?? 'allow-only';
  const resourceFile = config.rbac?.resourceFile ?? './fortress.resources.json';
  const adapter = createInternalAdapter(db);
  let observer: IamEventListener | null = null;

  function emit(event: IamEvent): void {
    observer?.(event).catch(() => { /* audit log failure should not break IAM operations */ });
  }
  const cacheConfig = config.rbac?.cache;
  const cache = cacheConfig
    ? createPermissionCache(
        (cacheConfig.ttlSeconds ?? 30) * 1000,
        cacheConfig.maxEntries ?? 1000,
      )
    : null;

  return {
    async checkPermission(
      userId: number,
      resource: string,
      action: string,
      context?: PermissionContext,
    ): Promise<boolean> {
      const tenantId = context?.tenantId;
      let permissions: Permission[];

      if (tenantId) {
        // Tenant-scoped: bypass cache (tenant varies per request)
        permissions = await adapter.getUserPermissions(userId, tenantId);
      }
      else {
        // Global: use cache
        permissions = cache?.get(userId) ?? await (async () => {
          const perms = await adapter.getUserPermissions(userId);
          cache?.set(userId, perms);
          return perms;
        })();
      }

      // Enrich context with user info
      const enrichedContext: PermissionContext = {
        ...context,
        user: { id: userId, ...context?.user },
      };

      return evaluatePermissions(permissions, resource, action, evaluationMode, enrichedContext);
    },

    async getUserPermissions(userId: number, tenantId?: string): Promise<Permission[]> {
      return adapter.getUserPermissions(userId, tenantId);
    },

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

      emit({ eventType: 'ROLE_CREATED', targetId: role.id, targetType: 'role', metadata: { name, permissions } });
      return role;
    },

    async deleteRole(roleId: number): Promise<void> {
      const role = await db.findOne<Role & { isSystem?: boolean }>({
        model: 'role',
        where: [{ field: 'id', operator: '=', value: roleId }],
      });
      if (role?.isSystem) {
        throw Errors.badRequest('Cannot delete a system role');
      }

      // Remove role bindings and role permissions first
      await db.delete({ model: 'role_permission', where: [{ field: 'roleId', operator: '=', value: roleId }] });
      await db.delete({ model: 'role_binding', where: [{ field: 'roleId', operator: '=', value: roleId }] });
      await db.delete({ model: 'role', where: [{ field: 'id', operator: '=', value: roleId }] });
      emit({ eventType: 'ROLE_DELETED', targetId: roleId, targetType: 'role' });
    },

    async bindRole(subjectType: SubjectType, subjectId: number, roleId: number, tenantId?: string): Promise<void> {
      await db.create({
        model: 'role_binding',
        data: { roleId, subjectType, subjectId, tenantId: tenantId ?? null },
      });
      emit({ eventType: 'ROLE_BOUND', targetId: roleId, targetType: 'role', metadata: { subjectType, subjectId, tenantId } });
    },

    async bindRoleToUser(userId: number, roleId: number, tenantId?: string): Promise<void> {
      await db.create({
        model: 'role_binding',
        data: { roleId, subjectType: 'USER', subjectId: userId, tenantId: tenantId ?? null },
      });
      cache?.invalidate(userId);
      emit({ eventType: 'ROLE_BOUND', actorId: userId, targetId: roleId, targetType: 'role', metadata: { subjectType: 'USER', tenantId } });
    },

    async bindRoleToGroup(groupId: number, roleId: number, tenantId?: string): Promise<void> {
      await db.create({
        model: 'role_binding',
        data: { roleId, subjectType: 'GROUP', subjectId: groupId, tenantId: tenantId ?? null },
      });
      cache?.invalidateAll();
      emit({ eventType: 'ROLE_BOUND', targetId: roleId, targetType: 'role', metadata: { subjectType: 'GROUP', groupId, tenantId } });
    },

    async unbindRole(subjectType: SubjectType, subjectId: number, roleId: number, tenantId?: string): Promise<void> {
      const where = [
        { field: 'roleId' as const, operator: '=' as const, value: roleId },
        { field: 'subjectType' as const, operator: '=' as const, value: subjectType },
        { field: 'subjectId' as const, operator: '=' as const, value: subjectId },
        ...(tenantId ? [{ field: 'tenantId' as const, operator: '=' as const, value: tenantId }] : []),
      ];
      await db.delete({ model: 'role_binding', where });
      if (subjectType === 'USER')
        cache?.invalidate(subjectId);
      else cache?.invalidateAll();
      emit({ eventType: 'ROLE_UNBOUND', targetId: roleId, targetType: 'role', metadata: { subjectType, subjectId, tenantId } });
    },

    async bindPermissionToUser(userId: number, permission: PermissionInput, tenantId?: string): Promise<void> {
      await adapter.ensureResource(permission.resource);
      const perm = await adapter.findOrCreatePermission(permission);
      await db.create({
        model: 'direct_permission_binding',
        data: { permissionId: perm.id, subjectType: 'USER', subjectId: userId, tenantId: tenantId ?? null },
      });
      cache?.invalidate(userId);
      emit({ eventType: 'PERMISSION_CHANGED', actorId: userId, targetId: perm.id, targetType: 'permission', metadata: { action: 'bind', subjectType: 'USER', tenantId } });
    },

    async bindPermissionToGroup(groupId: number, permission: PermissionInput, tenantId?: string): Promise<void> {
      await adapter.ensureResource(permission.resource);
      const perm = await adapter.findOrCreatePermission(permission);
      await db.create({
        model: 'direct_permission_binding',
        data: { permissionId: perm.id, subjectType: 'GROUP', subjectId: groupId, tenantId: tenantId ?? null },
      });
      cache?.invalidateAll();
      emit({ eventType: 'PERMISSION_CHANGED', targetId: perm.id, targetType: 'permission', metadata: { action: 'bind', subjectType: 'GROUP', groupId, tenantId } });
    },

    async unbindPermissionFromUser(userId: number, permissionId: number, tenantId?: string): Promise<void> {
      const where = [
        { field: 'permissionId' as const, operator: '=' as const, value: permissionId },
        { field: 'subjectType' as const, operator: '=' as const, value: 'USER' },
        { field: 'subjectId' as const, operator: '=' as const, value: userId },
        ...(tenantId ? [{ field: 'tenantId' as const, operator: '=' as const, value: tenantId }] : []),
      ];
      await db.delete({ model: 'direct_permission_binding', where });
      cache?.invalidate(userId);
      emit({ eventType: 'PERMISSION_CHANGED', actorId: userId, targetId: permissionId, targetType: 'permission', metadata: { action: 'unbind', subjectType: 'USER', tenantId } });
    },

    async unbindPermissionFromGroup(groupId: number, permissionId: number, tenantId?: string): Promise<void> {
      const where = [
        { field: 'permissionId' as const, operator: '=' as const, value: permissionId },
        { field: 'subjectType' as const, operator: '=' as const, value: 'GROUP' },
        { field: 'subjectId' as const, operator: '=' as const, value: groupId },
        ...(tenantId ? [{ field: 'tenantId' as const, operator: '=' as const, value: tenantId }] : []),
      ];
      await db.delete({ model: 'direct_permission_binding', where });
      cache?.invalidateAll();
      emit({ eventType: 'PERMISSION_CHANGED', targetId: permissionId, targetType: 'permission', metadata: { action: 'unbind', subjectType: 'GROUP', groupId, tenantId } });
    },

    async createGroup(name: string, description?: string): Promise<Group> {
      const group = await db.create<Group>({
        model: 'group',
        data: { name, description: description ?? null },
      });
      emit({ eventType: 'GROUP_CREATED', targetId: group.id, targetType: 'group', metadata: { name } });
      return group;
    },

    async addUserToGroup(groupId: number, userId: number): Promise<void> {
      await db.create({
        model: 'group_user',
        data: { groupId, userId },
      });
      cache?.invalidate(userId);
      emit({ eventType: 'GROUP_MEMBER_ADDED', actorId: userId, targetId: groupId, targetType: 'group' });
    },

    async removeUserFromGroup(groupId: number, userId: number): Promise<void> {
      await db.delete({
        model: 'group_user',
        where: [
          { field: 'groupId', operator: '=', value: groupId },
          { field: 'userId', operator: '=', value: userId },
        ],
      });
      cache?.invalidate(userId);
      emit({ eventType: 'GROUP_MEMBER_REMOVED', actorId: userId, targetId: groupId, targetType: 'group' });
    },

    async getResources(): Promise<ResourceFile> {
      return pullResources(db);
    },

    async getRoles(): Promise<Role[]> {
      return db.findMany<Role>({ model: 'role' });
    },

    clearPermissionCache(): void {
      cache?.invalidateAll();
    },

    setIamObserver(listener: IamEventListener): void {
      observer = listener;
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

    // ── Admin CRUD ───────────────────────────────────────────────

    async getRole(roleId: number): Promise<Role & { permissions: Permission[] }> {
      const role = await db.findOne<Role>({
        model: 'role',
        where: [{ field: 'id', operator: '=', value: roleId }],
      });
      if (!role) {
        throw Errors.notFound('Role not found');
      }

      const rolePerms = await db.findMany<{ permissionId: number }>({
        model: 'role_permission',
        where: [{ field: 'roleId', operator: '=', value: roleId }],
      });

      let permissions: Permission[] = [];
      if (rolePerms.length > 0) {
        const permIds = rolePerms.map(rp => rp.permissionId);
        permissions = await db.findMany<Permission>({
          model: 'permission',
          where: [{ field: 'id', operator: 'in', value: permIds }],
        });
      }

      return { ...role, permissions };
    },

    async updateRole(roleId: number, data: { name?: string; description?: string }): Promise<Role> {
      const existing = await db.findOne<Role & { isSystem?: boolean }>({
        model: 'role',
        where: [{ field: 'id', operator: '=', value: roleId }],
      });
      if (!existing) {
        throw Errors.notFound('Role not found');
      }
      if (existing.isSystem) {
        throw Errors.badRequest('Cannot update a system role');
      }

      const updateData: Record<string, unknown> = {};
      if (data.name !== undefined)
        updateData.name = data.name;
      if (data.description !== undefined)
        updateData.description = data.description;

      const updated = await db.update<Role>({
        model: 'role',
        where: [{ field: 'id', operator: '=', value: roleId }],
        data: updateData,
      });

      emit({ eventType: 'ROLE_UPDATED', targetId: roleId, targetType: 'role', metadata: data });
      return updated!;
    },

    async listGroups(options?: { limit?: number; offset?: number }): Promise<{ groups: Group[]; total: number }> {
      const [groups, total] = await Promise.all([
        db.findMany<Group>({
          model: 'group',
          limit: options?.limit ?? 50,
          offset: options?.offset ?? 0,
          sortBy: { field: 'id', direction: 'asc' },
        }),
        db.count({ model: 'group' }),
      ]);

      return { groups, total };
    },

    async getGroup(groupId: number): Promise<Group & { users: FortressUser[] }> {
      const group = await db.findOne<Group>({
        model: 'group',
        where: [{ field: 'id', operator: '=', value: groupId }],
      });
      if (!group) {
        throw Errors.notFound('Group not found');
      }

      const memberships = await db.findMany<{ userId: number }>({
        model: 'group_user',
        where: [{ field: 'groupId', operator: '=', value: groupId }],
      });

      let users: FortressUser[] = [];
      if (memberships.length > 0) {
        const userIds = memberships.map(m => m.userId);
        const rawUsers = await db.findMany<FortressUser & { passwordHash?: string }>({
          model: 'user',
          where: [{ field: 'id', operator: 'in', value: userIds }],
        });
        users = rawUsers.map(({ passwordHash: _, ...u }) => u);
      }

      return { ...group, users };
    },

    async updateGroup(groupId: number, data: { name?: string; description?: string }): Promise<Group> {
      const existing = await db.findOne<Group>({
        model: 'group',
        where: [{ field: 'id', operator: '=', value: groupId }],
      });
      if (!existing) {
        throw Errors.notFound('Group not found');
      }

      const updateData: Record<string, unknown> = {};
      if (data.name !== undefined)
        updateData.name = data.name;
      if (data.description !== undefined)
        updateData.description = data.description;

      const updated = await db.update<Group>({
        model: 'group',
        where: [{ field: 'id', operator: '=', value: groupId }],
        data: updateData,
      });

      return updated!;
    },

    async deleteGroup(groupId: number): Promise<void> {
      const existing = await db.findOne<Group>({
        model: 'group',
        where: [{ field: 'id', operator: '=', value: groupId }],
      });
      if (!existing) {
        throw Errors.notFound('Group not found');
      }

      await db.delete({ model: 'group', where: [{ field: 'id', operator: '=', value: groupId }] });
      cache?.invalidateAll();
    },

    async getGroupUsers(groupId: number): Promise<FortressUser[]> {
      const memberships = await db.findMany<{ userId: number }>({
        model: 'group_user',
        where: [{ field: 'groupId', operator: '=', value: groupId }],
      });

      if (memberships.length === 0)
        return [];

      const userIds = memberships.map(m => m.userId);
      const rawUsers = await db.findMany<FortressUser & { passwordHash?: string }>({
        model: 'user',
        where: [{ field: 'id', operator: 'in', value: userIds }],
      });
      return rawUsers.map(({ passwordHash: _, ...u }) => u);
    },

    async listPermissions(options?: { resource?: string }): Promise<Permission[]> {
      const where = options?.resource
        ? [{ field: 'resource' as const, operator: '=' as const, value: options.resource }]
        : undefined;

      return db.findMany<Permission>({ model: 'permission', where });
    },

    async createPermission(permission: PermissionInput): Promise<Permission> {
      await adapter.ensureResource(permission.resource);
      return adapter.findOrCreatePermission(permission);
    },

    async deletePermission(permissionId: number): Promise<void> {
      const existing = await db.findOne<Permission>({
        model: 'permission',
        where: [{ field: 'id', operator: '=', value: permissionId }],
      });
      if (!existing) {
        throw Errors.notFound('Permission not found');
      }

      await db.delete({ model: 'permission', where: [{ field: 'id', operator: '=', value: permissionId }] });
      cache?.invalidateAll();
    },

    async addPermissionToRole(roleId: number, permission: PermissionInput): Promise<void> {
      const role = await db.findOne<Role>({
        model: 'role',
        where: [{ field: 'id', operator: '=', value: roleId }],
      });
      if (!role) {
        throw Errors.notFound('Role not found');
      }

      await adapter.ensureResource(permission.resource);
      const perm = await adapter.findOrCreatePermission(permission);

      // Check if already linked
      const existing = await db.findOne<{ roleId: number }>({
        model: 'role_permission',
        where: [
          { field: 'roleId', operator: '=', value: roleId },
          { field: 'permissionId', operator: '=', value: perm.id },
        ],
      });
      if (!existing) {
        await db.create({ model: 'role_permission', data: { roleId, permissionId: perm.id } });
      }

      cache?.invalidateAll();
      emit({ eventType: 'ROLE_PERMISSION_ADDED', targetId: roleId, targetType: 'role', metadata: { permissionId: perm.id, resource: permission.resource, action: permission.action } });
    },
  };
}
