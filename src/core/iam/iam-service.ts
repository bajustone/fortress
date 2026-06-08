import type { DatabaseAdapter, WhereClause } from '../../adapters/database';
import type { FortressConfig } from '../config';
import type { Unsubscribe } from '../observability/listener-list';
import type { FortressLogger } from '../observability/logger';
import type { TelemetryProvider } from '../observability/types';
import type {
  CreateServiceAccountInput,
  FortressUser,
  Group,
  Permission,
  PermissionContext,
  PermissionInput,
  Role,
  ServiceAccount,
  Subject,
  SubjectType,
} from '../types';
import type { EvaluationMode } from './permission-evaluator';
import type { ResourceFile } from './resource-sync';
import { Errors } from '../errors';
import { createInternalAdapter } from '../internal-adapter';
import { createListenerList } from '../observability/listener-list';
import { SILENT_LOGGER } from '../observability/logger';
import { createPermissionCache, subjectCacheKey } from './permission-cache';
import { evaluatePermissions, withinCredentialScope } from './permission-evaluator';
import { loadResourceFile, pullResources, pushResources, writeResourceFile } from './resource-sync';

export interface IamEvent {
  eventType: string;
  actorId?: number | null;
  targetId?: number | null;
  targetType?: string | null;
  metadata?: Record<string, unknown>;
}

/**
 * Async IAM event listener. May return a Promise — if you `return` it, any
 * rejection is routed to `config.logger.error`. Firing work via
 * `void asyncWork()` inside a sync body is an explicit opt-out of that
 * safety net; rejections will escape to the runtime's unhandled-rejection
 * handler instead.
 */
export type IamEventListener = (event: IamEvent) => void | Promise<void>;

/**
 * High-frequency event fired on every permission check. Emitted by a
 * separate observer list from {@link IamEvent} so audit-log consumers
 * (which subscribe to mutations) aren't spammed with per-check traffic.
 *
 * Listeners are invoked **synchronously**. The type signature intentionally
 * returns `void` (not `Promise<void>`) to discourage awaiting expensive
 * work on the hot path. If an observer needs async work it should fire
 * and forget with `void asyncWork()`.
 */
export interface PermissionCheckEvent {
  subjectType: 'USER' | 'SERVICE_ACCOUNT' | 'GROUP';
  subjectId: number;
  resource: string;
  action: string;
  allowed: boolean;
  cached: boolean;
  /** Pre-divided monotonic duration in seconds; ready to feed into a histogram. */
  durationSeconds: number;
  tenantId?: string;
}

export type PermissionCheckListener = (event: PermissionCheckEvent) => void;

export interface IamService {
  checkPermission: (subject: Subject, resource: string, action: string, context?: PermissionContext) => Promise<boolean>;
  getPermissionsForSubject: (subject: Subject, tenantId?: string) => Promise<Permission[]>;
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
  /**
   * Register a listener for IAM mutation events. Multiple listeners are
   * supported — each is invoked in registration order. Observer failures
   * are routed to the configured logger at `error` level and never break
   * IAM operations. Returns an unsubscribe function.
   */
  addIamObserver: (listener: IamEventListener) => Unsubscribe;

  /**
   * Register a listener for individual permission checks. Fires on every
   * `checkPermission` call with latency and cache-hit information. The
   * listener signature is synchronous — see {@link PermissionCheckEvent}
   * for rationale. Returns an unsubscribe function.
   */
  addPermissionCheckObserver: (listener: PermissionCheckListener) => Unsubscribe;

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
  removePermissionFromRole: (roleId: number, permission: PermissionInput) => Promise<void>;

  // ── Service Accounts ───────────────────────────────────────────
  createServiceAccount: (input: CreateServiceAccountInput) => Promise<ServiceAccount>;
  getServiceAccount: (id: number) => Promise<ServiceAccount>;
  listServiceAccounts: (options?: { limit?: number; offset?: number }) => Promise<{ serviceAccounts: ServiceAccount[]; total: number }>;
  updateServiceAccount: (id: number, data: { displayName?: string | null; description?: string | null; isActive?: boolean }) => Promise<ServiceAccount>;
  deleteServiceAccount: (id: number) => Promise<void>;
  bindRoleToServiceAccount: (serviceAccountId: number, roleId: number, tenantId?: string) => Promise<void>;
  unbindRoleFromServiceAccount: (serviceAccountId: number, roleId: number, tenantId?: string) => Promise<void>;
  bindPermissionToServiceAccount: (serviceAccountId: number, permission: PermissionInput, tenantId?: string) => Promise<void>;
  unbindPermissionFromServiceAccount: (serviceAccountId: number, permissionId: number, tenantId?: string) => Promise<void>;
}

export interface IamServiceDeps {
  logger: FortressLogger;
  telemetry: TelemetryProvider;
}

export function createIamService(
  db: DatabaseAdapter,
  config: FortressConfig,
  deps?: IamServiceDeps,
): IamService {
  const evaluationMode: EvaluationMode = config.rbac?.evaluationMode ?? 'allow-only';
  const resourceFile = config.rbac?.resourceFile ?? './fortress.resources.json';
  const adapter = createInternalAdapter(db);
  const logger = deps?.logger;
  const telemetry = deps?.telemetry;

  const iamEventListeners = createListenerList<IamEvent>({
    kind: 'async',
    eventLabel: 'iam',
    logger: () => logger ?? SILENT_LOGGER,
  });
  const permissionCheckListeners = createListenerList<PermissionCheckEvent>({
    kind: 'sync',
    eventLabel: 'iam.permission_check',
    logger: () => logger ?? SILENT_LOGGER,
  });

  function emit(event: IamEvent): void {
    iamEventListeners.emit(event);
  }
  const cacheConfig = config.rbac?.cache;
  const cache = cacheConfig
    ? createPermissionCache(
        (cacheConfig.ttlSeconds ?? 30) * 1000,
        cacheConfig.maxEntries ?? 1000,
      )
    : null;

  function tenantWhere(tenantId?: string): { field: 'tenantId'; operator: '=' | 'isNull'; value: string | null }[] {
    return tenantId == null
      ? [{ field: 'tenantId', operator: 'isNull', value: null }]
      : [{ field: 'tenantId', operator: '=', value: tenantId }];
  }

  /**
   * Race-safe find-then-create for the idempotency helpers below. The unique
   * indexes guarantee no duplicate row; under genuine concurrency the losing
   * INSERT throws a unique-constraint error, which we treat as "the winner
   * already created it" after re-checking. Returns `true` if THIS call
   * inserted the row, `false` if it already existed (before or via the race).
   */
  async function insertIfMissing(
    model: string,
    where: WhereClause[],
    data: Record<string, unknown>,
  ): Promise<boolean> {
    const existing = await db.findOne<{ id?: number }>({ model, where });
    if (existing)
      return false;
    try {
      await db.create({ model, data });
      return true;
    }
    catch (err) {
      const winner = await db.findOne<{ id?: number }>({ model, where });
      if (winner)
        return false;
      throw err;
    }
  }

  async function createRoleBindingIfMissing(
    subjectType: SubjectType,
    subjectId: number,
    roleId: number,
    tenantId?: string,
  ): Promise<boolean> {
    return insertIfMissing(
      'role_binding',
      [
        { field: 'roleId', operator: '=', value: roleId },
        { field: 'subjectType', operator: '=', value: subjectType },
        { field: 'subjectId', operator: '=', value: subjectId },
        ...tenantWhere(tenantId),
      ],
      { roleId, subjectType, subjectId, tenantId: tenantId ?? null },
    );
  }

  async function createDirectPermissionBindingIfMissing(
    subjectType: SubjectType,
    subjectId: number,
    permissionId: number,
    tenantId?: string,
  ): Promise<boolean> {
    return insertIfMissing(
      'direct_permission_binding',
      [
        { field: 'permissionId', operator: '=', value: permissionId },
        { field: 'subjectType', operator: '=', value: subjectType },
        { field: 'subjectId', operator: '=', value: subjectId },
        ...tenantWhere(tenantId),
      ],
      { permissionId, subjectType, subjectId, tenantId: tenantId ?? null },
    );
  }

  async function addUserToGroupIfMissing(groupId: number, userId: number): Promise<boolean> {
    return insertIfMissing(
      'group_user',
      [
        { field: 'groupId', operator: '=', value: groupId },
        { field: 'userId', operator: '=', value: userId },
      ],
      { groupId, userId },
    );
  }

  return {
    async checkPermission(
      subject: Subject,
      resource: string,
      action: string,
      context?: PermissionContext,
    ): Promise<boolean> {
      const start = performance.now();
      const tenantId = context?.tenantId;
      const cacheKey = subjectCacheKey(subject);
      let permissions: Permission[];
      let cached = false;

      if (tenantId) {
        // Tenant-scoped: bypass cache (tenant varies per request)
        permissions = await adapter.getSubjectPermissions(subject, tenantId);
      }
      else {
        // Global: use cache
        const fromCache = cache?.get(cacheKey);
        if (fromCache !== undefined) {
          permissions = fromCache;
          cached = true;
        }
        else if (cache) {
          // Capture the cache generation before the load so a revocation that
          // invalidates mid-load is not clobbered by this (now stale) write.
          const generationBeforeLoad = cache.generation();
          permissions = await adapter.getSubjectPermissions(subject);
          if (cache.generation() === generationBeforeLoad)
            cache.set(cacheKey, permissions);
        }
        else {
          permissions = await adapter.getSubjectPermissions(subject);
        }
      }

      // Enrich context with subject info. USER subjects still populate
      // `user.id` for backwards-compatible condition expressions; other
      // subject types are exposed under `user.subjectType`/`user.subjectId`.
      const enrichedContext: PermissionContext = {
        ...context,
        user: subject.type === 'USER'
          ? { id: subject.id, ...context?.user }
          : { subjectType: subject.type, subjectId: subject.id, ...context?.user },
      };

      const allowed = withinCredentialScope(context?.credentialScopes, resource, action)
        && evaluatePermissions(permissions, resource, action, evaluationMode, enrichedContext);
      const durationSeconds = (performance.now() - start) / 1000;

      // Span only on deny — allow is metric fodder, deny is security-interesting.
      if (!allowed && telemetry) {
        const span = telemetry.tracer.startSpan('fortress.iam.permission_check.deny', {
          'subject.type': subject.type,
          'subject.id': subject.id,
          'resource': resource,
          'action': action,
          'cached': cached,
        });
        span.end();
      }

      // Observer — only allocate the event object if somebody listens.
      if (permissionCheckListeners.size() > 0) {
        permissionCheckListeners.emit({
          subjectType: subject.type,
          subjectId: subject.id,
          resource,
          action,
          allowed,
          cached,
          durationSeconds,
          tenantId,
        });
      }

      return allowed;
    },

    async getPermissionsForSubject(subject: Subject, tenantId?: string): Promise<Permission[]> {
      return adapter.getSubjectPermissions(subject, tenantId);
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
      // M6 fix: a deleted role can affect any subject via group bindings.
      // We don't know which subjects were bound to it across tenants, so a
      // global cache invalidation is the only safe option — without this,
      // a stale ALLOW could survive in cache for up to `cache.ttlSeconds`.
      cache?.invalidateAll();
      emit({ eventType: 'ROLE_DELETED', targetId: roleId, targetType: 'role' });
    },

    async bindRole(subjectType: SubjectType, subjectId: number, roleId: number, tenantId?: string): Promise<void> {
      const inserted = await createRoleBindingIfMissing(subjectType, subjectId, roleId, tenantId);
      if (!inserted)
        return;
      emit({ eventType: 'ROLE_BOUND', targetId: roleId, targetType: 'role', metadata: { subjectType, subjectId, tenantId } });
    },

    async bindRoleToUser(userId: number, roleId: number, tenantId?: string): Promise<void> {
      const inserted = await createRoleBindingIfMissing('USER', userId, roleId, tenantId);
      if (!inserted)
        return;
      cache?.invalidate(subjectCacheKey({ type: 'USER', id: userId }));
      emit({ eventType: 'ROLE_BOUND', actorId: userId, targetId: roleId, targetType: 'role', metadata: { subjectType: 'USER', tenantId } });
    },

    async bindRoleToGroup(groupId: number, roleId: number, tenantId?: string): Promise<void> {
      const inserted = await createRoleBindingIfMissing('GROUP', groupId, roleId, tenantId);
      if (!inserted)
        return;
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
        cache?.invalidate(subjectCacheKey({ type: 'USER', id: subjectId }));
      else if (subjectType === 'SERVICE_ACCOUNT')
        cache?.invalidate(subjectCacheKey({ type: 'SERVICE_ACCOUNT', id: subjectId }));
      else cache?.invalidateAll();
      emit({ eventType: 'ROLE_UNBOUND', targetId: roleId, targetType: 'role', metadata: { subjectType, subjectId, tenantId } });
    },

    async bindPermissionToUser(userId: number, permission: PermissionInput, tenantId?: string): Promise<void> {
      await adapter.ensureResource(permission.resource);
      const perm = await adapter.findOrCreatePermission(permission);
      const inserted = await createDirectPermissionBindingIfMissing('USER', userId, perm.id, tenantId);
      if (!inserted)
        return;
      cache?.invalidate(subjectCacheKey({ type: 'USER', id: userId }));
      emit({ eventType: 'PERMISSION_CHANGED', actorId: userId, targetId: perm.id, targetType: 'permission', metadata: { action: 'bind', subjectType: 'USER', tenantId } });
    },

    async bindPermissionToGroup(groupId: number, permission: PermissionInput, tenantId?: string): Promise<void> {
      await adapter.ensureResource(permission.resource);
      const perm = await adapter.findOrCreatePermission(permission);
      const inserted = await createDirectPermissionBindingIfMissing('GROUP', groupId, perm.id, tenantId);
      if (!inserted)
        return;
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
      cache?.invalidate(subjectCacheKey({ type: 'USER', id: userId }));
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
      const inserted = await addUserToGroupIfMissing(groupId, userId);
      if (!inserted)
        return;
      cache?.invalidate(subjectCacheKey({ type: 'USER', id: userId }));
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
      cache?.invalidate(subjectCacheKey({ type: 'USER', id: userId }));
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

    addIamObserver(listener: IamEventListener): Unsubscribe {
      return iamEventListeners.add(listener);
    },

    addPermissionCheckObserver(listener: PermissionCheckListener): Unsubscribe {
      return permissionCheckListeners.add(listener);
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

    async removePermissionFromRole(roleId: number, permission: PermissionInput): Promise<void> {
      // Resolve the permission row (must already exist; if not, nothing to
      // unlink). Uses the same uniqueness key as `addPermissionToRole`
      // (resource+action+effect+conditions) so the lookup matches the row
      // that was previously linked.
      const perm = await adapter.findOrCreatePermission(permission);
      await db.delete({
        model: 'role_permission',
        where: [
          { field: 'roleId', operator: '=', value: roleId },
          { field: 'permissionId', operator: '=', value: perm.id },
        ],
      });
      cache?.invalidateAll();
      emit({
        eventType: 'ROLE_PERMISSION_REMOVED',
        targetId: roleId,
        targetType: 'role',
        metadata: { permissionId: perm.id, resource: permission.resource, action: permission.action },
      });
    },

    // ── Service Accounts ─────────────────────────────────────────

    async createServiceAccount(input: CreateServiceAccountInput): Promise<ServiceAccount> {
      if (!input.name || typeof input.name !== 'string') {
        throw Errors.badRequest('Service account name is required');
      }
      const existing = await db.findOne<ServiceAccount>({
        model: 'service_account',
        where: [{ field: 'name', operator: '=', value: input.name }],
      });
      if (existing) {
        throw Errors.badRequest(`Service account with name '${input.name}' already exists`);
      }
      const created = await db.create<ServiceAccount>({
        model: 'service_account',
        data: {
          name: input.name,
          displayName: input.displayName ?? null,
          description: input.description ?? null,
          isActive: true,
        },
      });
      emit({
        eventType: 'SERVICE_ACCOUNT_CREATED',
        targetId: created.id,
        targetType: 'service_account',
        metadata: { name: created.name },
      });
      return created;
    },

    async getServiceAccount(id: number): Promise<ServiceAccount> {
      const sa = await db.findOne<ServiceAccount>({
        model: 'service_account',
        where: [{ field: 'id', operator: '=', value: id }],
      });
      if (!sa) {
        throw Errors.notFound('Service account not found');
      }
      return sa;
    },

    async listServiceAccounts(
      options?: { limit?: number; offset?: number },
    ): Promise<{ serviceAccounts: ServiceAccount[]; total: number }> {
      const [serviceAccounts, total] = await Promise.all([
        db.findMany<ServiceAccount>({
          model: 'service_account',
          limit: options?.limit ?? 50,
          offset: options?.offset ?? 0,
          sortBy: { field: 'id', direction: 'asc' },
        }),
        db.count({ model: 'service_account' }),
      ]);
      return { serviceAccounts, total };
    },

    async updateServiceAccount(
      id: number,
      data: { displayName?: string | null; description?: string | null; isActive?: boolean },
    ): Promise<ServiceAccount> {
      const existing = await db.findOne<ServiceAccount>({
        model: 'service_account',
        where: [{ field: 'id', operator: '=', value: id }],
      });
      if (!existing) {
        throw Errors.notFound('Service account not found');
      }
      // `name` is immutable after creation — matches Kubernetes / IAM conventions.
      const updateData: Record<string, unknown> = { updatedAt: new Date() };
      if (data.displayName !== undefined)
        updateData.displayName = data.displayName;
      if (data.description !== undefined)
        updateData.description = data.description;
      if (data.isActive !== undefined)
        updateData.isActive = data.isActive;

      const updated = await db.update<ServiceAccount>({
        model: 'service_account',
        where: [{ field: 'id', operator: '=', value: id }],
        data: updateData,
      });

      // Flipping isActive affects permission resolution — invalidate the cache.
      cache?.invalidate(subjectCacheKey({ type: 'SERVICE_ACCOUNT', id }));
      emit({
        eventType: 'SERVICE_ACCOUNT_UPDATED',
        targetId: id,
        targetType: 'service_account',
        metadata: data as Record<string, unknown>,
      });
      return updated!;
    },

    async deleteServiceAccount(id: number): Promise<void> {
      const existing = await db.findOne<ServiceAccount>({
        model: 'service_account',
        where: [{ field: 'id', operator: '=', value: id }],
      });
      if (!existing) {
        throw Errors.notFound('Service account not found');
      }

      // Cascade: remove bindings first, then the account itself.
      await db.delete({
        model: 'role_binding',
        where: [
          { field: 'subjectType', operator: '=', value: 'SERVICE_ACCOUNT' },
          { field: 'subjectId', operator: '=', value: id },
        ],
      });
      await db.delete({
        model: 'direct_permission_binding',
        where: [
          { field: 'subjectType', operator: '=', value: 'SERVICE_ACCOUNT' },
          { field: 'subjectId', operator: '=', value: id },
        ],
      });
      await db.delete({
        model: 'service_account',
        where: [{ field: 'id', operator: '=', value: id }],
      });

      cache?.invalidate(subjectCacheKey({ type: 'SERVICE_ACCOUNT', id }));
      // Observers (api-key plugin, audit log, …) react to this. The api-key
      // plugin uses it to hard-delete keys owned by the deleted account.
      emit({
        eventType: 'SERVICE_ACCOUNT_DELETED',
        targetId: id,
        targetType: 'service_account',
        metadata: { name: existing.name },
      });
    },

    async bindRoleToServiceAccount(
      serviceAccountId: number,
      roleId: number,
      tenantId?: string,
    ): Promise<void> {
      const inserted = await createRoleBindingIfMissing('SERVICE_ACCOUNT', serviceAccountId, roleId, tenantId);
      if (!inserted)
        return;
      cache?.invalidate(subjectCacheKey({ type: 'SERVICE_ACCOUNT', id: serviceAccountId }));
      emit({
        eventType: 'ROLE_BOUND',
        targetId: roleId,
        targetType: 'role',
        metadata: { subjectType: 'SERVICE_ACCOUNT', subjectId: serviceAccountId, tenantId },
      });
    },

    async unbindRoleFromServiceAccount(
      serviceAccountId: number,
      roleId: number,
      tenantId?: string,
    ): Promise<void> {
      const where = [
        { field: 'roleId' as const, operator: '=' as const, value: roleId },
        { field: 'subjectType' as const, operator: '=' as const, value: 'SERVICE_ACCOUNT' },
        { field: 'subjectId' as const, operator: '=' as const, value: serviceAccountId },
        ...(tenantId ? [{ field: 'tenantId' as const, operator: '=' as const, value: tenantId }] : []),
      ];
      await db.delete({ model: 'role_binding', where });
      cache?.invalidate(subjectCacheKey({ type: 'SERVICE_ACCOUNT', id: serviceAccountId }));
      emit({
        eventType: 'ROLE_UNBOUND',
        targetId: roleId,
        targetType: 'role',
        metadata: { subjectType: 'SERVICE_ACCOUNT', subjectId: serviceAccountId, tenantId },
      });
    },

    async bindPermissionToServiceAccount(
      serviceAccountId: number,
      permission: PermissionInput,
      tenantId?: string,
    ): Promise<void> {
      await adapter.ensureResource(permission.resource);
      const perm = await adapter.findOrCreatePermission(permission);
      const inserted = await createDirectPermissionBindingIfMissing('SERVICE_ACCOUNT', serviceAccountId, perm.id, tenantId);
      if (!inserted)
        return;
      cache?.invalidate(subjectCacheKey({ type: 'SERVICE_ACCOUNT', id: serviceAccountId }));
      emit({
        eventType: 'PERMISSION_CHANGED',
        targetId: perm.id,
        targetType: 'permission',
        metadata: { action: 'bind', subjectType: 'SERVICE_ACCOUNT', serviceAccountId, tenantId },
      });
    },

    async unbindPermissionFromServiceAccount(
      serviceAccountId: number,
      permissionId: number,
      tenantId?: string,
    ): Promise<void> {
      const where = [
        { field: 'permissionId' as const, operator: '=' as const, value: permissionId },
        { field: 'subjectType' as const, operator: '=' as const, value: 'SERVICE_ACCOUNT' },
        { field: 'subjectId' as const, operator: '=' as const, value: serviceAccountId },
        ...(tenantId ? [{ field: 'tenantId' as const, operator: '=' as const, value: tenantId }] : []),
      ];
      await db.delete({ model: 'direct_permission_binding', where });
      cache?.invalidate(subjectCacheKey({ type: 'SERVICE_ACCOUNT', id: serviceAccountId }));
      emit({
        eventType: 'PERMISSION_CHANGED',
        targetId: permissionId,
        targetType: 'permission',
        metadata: { action: 'unbind', subjectType: 'SERVICE_ACCOUNT', serviceAccountId, tenantId },
      });
    },
  };
}
