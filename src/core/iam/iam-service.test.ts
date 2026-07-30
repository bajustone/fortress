import type { Fortress } from '../fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

const SECRET = 'iam-service-test-secret-32chars!';

describe('iam-service: isSystem flag', () => {
  let fortress: Fortress;

  beforeEach(() => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
  });

  it('creates a role with isSystem flag', async () => {
    const role = await fortress.iam.createRole(
      'super-admin',
      [{ resource: 'users', action: 'read' }],
      'System admin role',
    );

    expect(role.id).toBeDefined();
    expect(role.name).toBe('super-admin');
    // By default isSystem should be false (or falsy in SQLite)
    expect(role.isSystem).toBeFalsy();
  });

  it('deleteRole throws for system roles', async () => {
    // Create a role, then manually set isSystem via raw DB
    const role = await fortress.iam.createRole(
      'built-in-admin',
      [{ resource: 'users', action: 'manage' }],
    );

    // Mark as system role via database update
    await fortress.config.database.update({
      model: 'role',
      where: [{ field: 'id', operator: '=', value: role.id }],
      data: { isSystem: true },
    });

    await expect(fortress.iam.deleteRole(role.id)).rejects.toThrow(
      'Cannot delete a system role',
    );
  });

  it('deleteRole succeeds for non-system roles', async () => {
    const role = await fortress.iam.createRole(
      'temp-role',
      [{ resource: 'reports', action: 'read' }],
    );

    await expect(fortress.iam.deleteRole(role.id)).resolves.toBeUndefined();
  });
});

describe('inline permissions (direct binding)', () => {
  let fortress: Fortress;

  beforeEach(() => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
  });

  it('bindPermissionToUser is idempotent for global bindings', async () => {
    const user = await fortress.auth.createUser({
      email: 'idem-direct@test.com',
      name: 'Idem Direct',
      password: 'password-123456',
    });

    await fortress.iam.bindPermissionToUser(user.id, { resource: 'post', action: 'read' });
    await fortress.iam.bindPermissionToUser(user.id, { resource: 'post', action: 'read' });

    const perms = await fortress.config.database.findMany<{ id: string }>({
      model: 'permission',
      where: [
        { field: 'resource', operator: '=', value: 'post' },
        { field: 'action', operator: '=', value: 'read' },
      ],
    });
    const count = await fortress.config.database.count({
      model: 'direct_permission_binding',
      where: [
        { field: 'permissionId', operator: '=', value: requireAt(perms, 0, 'first permission').id },
        { field: 'subjectType', operator: '=', value: 'USER' },
        { field: 'subjectId', operator: '=', value: user.id },
        { field: 'tenantId', operator: 'isNull', value: null },
      ],
    });
    expect(count).toBe(1);
  });

  it('bindPermissionToUser grants access without a role', async () => {
    const user = await fortress.auth.createUser({
      email: 'alice@test.com',
      name: 'Alice',
      password: 'password-123456',
    });

    await fortress.iam.bindPermissionToUser(user.id, { resource: 'post', action: 'read' });

    const allowed = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'read');
    expect(allowed).toBe(true);

    const denied = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'delete');
    expect(denied).toBe(false);
  });

  it('bindPermissionToGroup grants access to group members', async () => {
    const user = await fortress.auth.createUser({
      email: 'bob@test.com',
      name: 'Bob',
      password: 'password-123456',
    });

    const group = await fortress.iam.createGroup('editors');
    await fortress.iam.addUserToGroup(group.id, user.id);
    await fortress.iam.bindPermissionToGroup(group.id, { resource: 'post', action: 'update' });

    const allowed = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'update');
    expect(allowed).toBe(true);
  });

  it('unbindPermissionFromUser revokes access', async () => {
    const user = await fortress.auth.createUser({
      email: 'carol@test.com',
      name: 'Carol',
      password: 'password-123456',
    });

    await fortress.iam.bindPermissionToUser(user.id, { resource: 'post', action: 'read' });
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'read')).toBe(true);

    const perms = await fortress.iam.getPermissionsForSubject({ type: 'USER', id: user.id });
    const perm = perms.find(p => p.resource === 'post' && p.action === 'read');
    await fortress.iam.unbindPermissionFromUser(user.id, perm!.id);

    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'read')).toBe(false);
  });

  it('bindRoleToUser is idempotent for global bindings', async () => {
    const user = await fortress.auth.createUser({
      email: 'idem-role@test.com',
      name: 'Idem Role',
      password: 'password-123456',
    });
    const role = await fortress.iam.createRole('idem-viewer', [{ resource: 'post', action: 'read' }]);

    await fortress.iam.bindRoleToUser(user.id, role.id);
    await fortress.iam.bindRoleToUser(user.id, role.id);

    const count = await fortress.config.database.count({
      model: 'role_binding',
      where: [
        { field: 'roleId', operator: '=', value: role.id },
        { field: 'subjectType', operator: '=', value: 'USER' },
        { field: 'subjectId', operator: '=', value: user.id },
        { field: 'tenantId', operator: 'isNull', value: null },
      ],
    });
    expect(count).toBe(1);
  });

  it('direct and role-based permissions combine', async () => {
    const user = await fortress.auth.createUser({
      email: 'dave@test.com',
      name: 'Dave',
      password: 'password-123456',
    });

    const role = await fortress.iam.createRole('viewer', [{ resource: 'post', action: 'read' }]);
    await fortress.iam.bindRoleToUser(user.id, role.id);
    await fortress.iam.bindPermissionToUser(user.id, { resource: 'post', action: 'update' });

    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'read')).toBe(true);
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'update')).toBe(true);
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'delete')).toBe(false);
  });
});

describe('tenant-scoped IAM', () => {
  let fortress: Fortress;

  beforeEach(() => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
  });

  it('user can have different roles per tenant', async () => {
    const user = await fortress.auth.createUser({
      email: 'alice@test.com',
      name: 'Alice',
      password: 'password-123456',
    });

    const adminRole = await fortress.iam.createRole('admin', [
      { resource: 'settings', action: 'write' },
    ]);
    const viewerRole = await fortress.iam.createRole('viewer', [
      { resource: 'settings', action: 'read' },
    ]);

    await fortress.iam.bindRoleToUser(user.id, adminRole.id, 'tenant-a');
    await fortress.iam.bindRoleToUser(user.id, viewerRole.id, 'tenant-b');

    // Admin in tenant A
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'settings', 'write', { tenantId: 'tenant-a' })).toBe(true);
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'settings', 'read', { tenantId: 'tenant-a' })).toBe(false);

    // Viewer in tenant B
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'settings', 'write', { tenantId: 'tenant-b' })).toBe(false);
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'settings', 'read', { tenantId: 'tenant-b' })).toBe(true);
  });

  it('unbindRole distinguishes global-only null from omitted all-scopes', async () => {
    const user = await fortress.auth.createUser({
      email: 'tri-state@example.com',
      name: 'Tri State',
      password: 'password-123456',
    });
    const role = await fortress.iam.createRole('tri-state-role', [{ resource: 'reports', action: 'read' }]);
    await fortress.iam.bindRole('USER', user.id, role.id);
    await fortress.iam.bindRole('USER', user.id, role.id, 'tenant-a');

    await fortress.iam.unbindRole('USER', user.id, role.id, null);
    expect(await fortress.config.database.count({
      model: 'role_binding',
      where: [
        { field: 'subjectType', operator: '=', value: 'USER' },
        { field: 'subjectId', operator: '=', value: user.id },
        { field: 'roleId', operator: '=', value: role.id },
      ],
    })).toBe(1);

    await fortress.iam.unbindRole('USER', user.id, role.id);
    expect(await fortress.config.database.count({
      model: 'role_binding',
      where: [
        { field: 'subjectType', operator: '=', value: 'USER' },
        { field: 'subjectId', operator: '=', value: user.id },
        { field: 'roleId', operator: '=', value: role.id },
      ],
    })).toBe(0);
  });

  it('global role bindings apply across all tenants', async () => {
    const user = await fortress.auth.createUser({
      email: 'bob@test.com',
      name: 'Bob',
      password: 'password-123456',
    });

    const globalRole = await fortress.iam.createRole('auditor', [
      { resource: 'audit', action: 'read' },
    ]);

    // Bind without tenantId → global
    await fortress.iam.bindRoleToUser(user.id, globalRole.id);

    // Should be accessible in any tenant context
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'audit', 'read', { tenantId: 'tenant-a' })).toBe(true);
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'audit', 'read', { tenantId: 'tenant-b' })).toBe(true);
    // And without tenant context
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'audit', 'read')).toBe(true);
  });

  it('tenant-scoped direct permission binding', async () => {
    const user = await fortress.auth.createUser({
      email: 'carol@test.com',
      name: 'Carol',
      password: 'password-123456',
    });

    await fortress.iam.bindPermissionToUser(user.id, { resource: 'billing', action: 'manage' }, 'tenant-a');

    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'billing', 'manage', { tenantId: 'tenant-a' })).toBe(true);
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'billing', 'manage', { tenantId: 'tenant-b' })).toBe(false);
  });

  it('getUserPermissions filters by tenant', async () => {
    const user = await fortress.auth.createUser({
      email: 'dave@test.com',
      name: 'Dave',
      password: 'password-123456',
    });

    const roleA = await fortress.iam.createRole('role-a', [{ resource: 'docs', action: 'write' }]);
    const roleB = await fortress.iam.createRole('role-b', [{ resource: 'docs', action: 'read' }]);

    await fortress.iam.bindRoleToUser(user.id, roleA.id, 'tenant-a');
    await fortress.iam.bindRoleToUser(user.id, roleB.id, 'tenant-b');

    const permsA = await fortress.iam.getPermissionsForSubject({ type: 'USER', id: user.id }, 'tenant-a');
    expect(permsA).toHaveLength(1);
    expect(requireAt(permsA, 0, 'first role A permission').action).toBe('write');

    const permsB = await fortress.iam.getPermissionsForSubject({ type: 'USER', id: user.id }, 'tenant-b');
    expect(permsB).toHaveLength(1);
    expect(requireAt(permsB, 0, 'first role B permission').action).toBe('read');
  });
});

// ── Admin CRUD ────────────────────────────────────────────────────

describe('iam-service: admin CRUD', () => {
  let fortress: Fortress;
  let database: ReturnType<typeof createTestAdapter>;

  beforeEach(() => {
    database = createTestAdapter();
    fortress = createFortress({
      jwt: { key: SECRET },
      database,
    });
  });

  // ── getRole ──────────────────────────────────────────────────

  describe('getRole', () => {
    it('returns role with permissions', async () => {
      const role = await fortress.iam.createRole('editor', [
        { resource: 'post', action: 'read' },
        { resource: 'post', action: 'update' },
      ]);

      const result = await fortress.iam.getRole(role.id);

      expect(result.name).toBe('editor');
      expect(result.permissions).toHaveLength(2);
      expect(result.permissions.map(p => p.action).sort()).toEqual(['read', 'update']);
    });

    it('throws NOT_FOUND for missing role', async () => {
      await expect(fortress.iam.getRole('99999')).rejects.toThrow('Role not found');
    });
  });

  // ── updateRole ───────────────────────────────────────────────

  describe('updateRole', () => {
    it('updates role name', async () => {
      const role = await fortress.iam.createRole('old-name', []);

      const updated = await fortress.iam.updateRole(role.id, { name: 'new-name' });

      expect(updated.name).toBe('new-name');
    });

    it('throws for system roles', async () => {
      const role = await fortress.iam.createRole('sys-role', []);
      await fortress.config.database.update({
        model: 'role',
        where: [{ field: 'id', operator: '=', value: role.id }],
        data: { isSystem: true },
      });

      await expect(fortress.iam.updateRole(role.id, { name: 'hacked' })).rejects.toThrow(
        'Cannot update a system role',
      );
    });

    it('throws NOT_FOUND for missing role', async () => {
      await expect(fortress.iam.updateRole('99999', { name: 'x' })).rejects.toThrow('Role not found');
    });
  });

  // ── listGroups ───────────────────────────────────────────────

  describe('listGroups', () => {
    it('returns paginated groups with total', async () => {
      await fortress.iam.createGroup('group-a');
      await fortress.iam.createGroup('group-b');
      await fortress.iam.createGroup('group-c');

      const result = await fortress.iam.listGroups({ limit: 2, offset: 0 });

      expect(result.groups).toHaveLength(2);
      expect(result.total).toBe(3);
    });

    it('returns empty when no groups', async () => {
      const result = await fortress.iam.listGroups();

      expect(result.groups).toEqual([]);
      expect(result.total).toBe(0);
    });
  });

  // ── getGroup ─────────────────────────────────────────────────

  describe('getGroup', () => {
    it('returns group with users', async () => {
      const group = await fortress.iam.createGroup('devs');
      const user = await fortress.auth.createUser({
        email: 'dev@test.com',
        name: 'Dev',
        password: 'password-123456',
      });
      await fortress.iam.addUserToGroup(group.id, user.id);

      const result = await fortress.iam.getGroup(group.id);

      expect(result.name).toBe('devs');
      expect(result.users).toHaveLength(1);
      expect(requireAt(result.users, 0, 'listed user').email).toBe('dev@test.com');
      expect(requireAt(result.users, 0, 'listed user')).not.toHaveProperty('passwordHash');
    });

    it('throws NOT_FOUND for missing group', async () => {
      await expect(fortress.iam.getGroup('99999')).rejects.toThrow('Group not found');
    });
  });

  // ── updateGroup ──────────────────────────────────────────────

  describe('updateGroup', () => {
    it('updates group name and emits GROUP_UPDATED', async () => {
      const group = await fortress.iam.createGroup('old-name');
      const events: string[] = [];
      fortress.iam.addIamObserver((event) => {
        events.push(event.eventType);
      });

      const updated = await fortress.iam.updateGroup(group.id, { name: 'new-name' });

      expect(updated.name).toBe('new-name');
      expect(events).toEqual(['GROUP_UPDATED']);
    });

    it('throws NOT_FOUND for missing group', async () => {
      await expect(fortress.iam.updateGroup('99999', { name: 'x' })).rejects.toThrow('Group not found');
    });
  });

  // ── deleteGroup ──────────────────────────────────────────────

  describe('deleteGroup', () => {
    it('atomically deletes group dependants and emits GROUP_DELETED', async () => {
      const group = await fortress.iam.createGroup('temp');
      const user = await fortress.auth.createUser({
        email: 'group-delete@test.com',
        name: 'Group Delete',
        password: 'password-123456',
      });
      const role = await fortress.iam.createRole('group-role', [{ resource: 'group-test', action: 'read' }]);
      const permission = await fortress.iam.createPermission({ resource: 'group-test', action: 'write' });
      await fortress.iam.addUserToGroup(group.id, user.id);
      await fortress.iam.bindRoleToGroup(group.id, role.id);
      await fortress.iam.bindPermissionToGroup(group.id, permission);
      const events: string[] = [];
      fortress.iam.addIamObserver((event) => {
        events.push(event.eventType);
      });

      await fortress.iam.deleteGroup(group.id);

      const result = await fortress.iam.listGroups();
      expect(result.total).toBe(0);
      await expect(database.count({ model: 'group_user' })).resolves.toBe(0);
      await expect(database.count({ model: 'role_binding' })).resolves.toBe(0);
      await expect(database.count({ model: 'direct_permission_binding' })).resolves.toBe(0);
      expect(events).toEqual(['GROUP_DELETED']);
    });

    it('serializes concurrent GROUP binding so deletion cannot leave an orphan', async () => {
      const raceDatabase = createTestAdapter();
      const originalTransaction = raceDatabase.transaction.bind(raceDatabase);
      let markGroupDeleted!: () => void;
      const groupDeleted = new Promise<void>((resolve) => {
        markGroupDeleted = resolve;
      });
      let releaseDelete!: () => void;
      const deleteGate = new Promise<void>((resolve) => {
        releaseDelete = resolve;
      });
      raceDatabase.transaction = callback => originalTransaction(async (tx) => {
        const wrapped = {
          ...tx,
          async delete(options: Parameters<typeof tx.delete>[0]) {
            const result = await tx.delete(options);
            if (options.model === 'group') {
              markGroupDeleted();
              await deleteGate;
            }
            return result;
          },
        };
        return callback(wrapped);
      });
      const raceFortress = createFortress({ jwt: { key: SECRET }, database: raceDatabase });
      const group = await raceFortress.iam.createGroup('race-group');
      const role = await raceFortress.iam.createRole('race-role', []);

      const deletion = raceFortress.iam.deleteGroup(group.id);
      await groupDeleted;
      const binding = raceFortress.iam.bindRoleToGroup(group.id, role.id);
      releaseDelete();

      await deletion;
      await expect(binding).rejects.toThrow('Group not found');
      await expect(raceDatabase.count({ model: 'role_binding' })).resolves.toBe(0);
    });

    it('emits one deletion event under concurrent duplicate deletes', async () => {
      const group = await fortress.iam.createGroup('duplicate-delete');
      const events: string[] = [];
      fortress.iam.addIamObserver((event) => {
        events.push(event.eventType);
      });

      const results = await Promise.allSettled([
        fortress.iam.deleteGroup(group.id),
        fortress.iam.deleteGroup(group.id),
      ]);
      expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
      expect(events).toEqual(['GROUP_DELETED']);
    });

    it('throws NOT_FOUND for missing group', async () => {
      await expect(fortress.iam.deleteGroup('99999')).rejects.toThrow('Group not found');
    });
  });

  // ── getGroupUsers ────────────────────────────────────────────

  describe('getGroupUsers', () => {
    it('returns group members without passwordHash', async () => {
      const group = await fortress.iam.createGroup('team');
      const user = await fortress.auth.createUser({
        email: 'member@test.com',
        name: 'Member',
        password: 'password-123456',
      });
      await fortress.iam.addUserToGroup(group.id, user.id);

      const users = await fortress.iam.getGroupUsers(group.id);

      expect(users).toHaveLength(1);
      expect(requireAt(users, 0, 'listed group user').email).toBe('member@test.com');
      expect(requireAt(users, 0, 'listed group user')).not.toHaveProperty('passwordHash');
    });

    it('returns empty for group with no members', async () => {
      const group = await fortress.iam.createGroup('empty');

      const users = await fortress.iam.getGroupUsers(group.id);

      expect(users).toEqual([]);
    });
  });

  // ── listPermissions ──────────────────────────────────────────

  describe('listPermissions', () => {
    it('lists all permissions', async () => {
      await fortress.iam.createRole('role1', [
        { resource: 'post', action: 'read' },
        { resource: 'comment', action: 'write' },
      ]);

      const perms = await fortress.iam.listPermissions();

      expect(perms.length).toBeGreaterThanOrEqual(2);
    });

    it('filters by resource', async () => {
      await fortress.iam.createRole('role2', [
        { resource: 'post', action: 'read' },
        { resource: 'comment', action: 'write' },
      ]);

      const perms = await fortress.iam.listPermissions({ resource: 'post' });

      expect(perms.every(p => p.resource === 'post')).toBe(true);
    });
  });

  // ── createPermission ─────────────────────────────────────────

  describe('createPermission', () => {
    it('emits PERMISSION_CREATED only for the inserting call', async () => {
      const events: string[] = [];
      fortress.iam.addIamObserver((event) => {
        events.push(event.eventType);
      });
      const [perm, existing] = await Promise.all([
        fortress.iam.createPermission({ resource: 'invoice', action: 'create' }),
        fortress.iam.createPermission({ resource: 'invoice', action: 'create' }),
      ]);

      expect(perm.id).toBeDefined();
      expect(perm.resource).toBe('invoice');
      expect(perm.action).toBe('create');
      expect(existing.id).toBe(perm.id);
      expect(events).toEqual(['PERMISSION_CREATED']);
    });
  });

  // ── deletePermission ─────────────────────────────────────────

  describe('deletePermission', () => {
    it('deletes a permission and emits PERMISSION_DELETED', async () => {
      const perm = await fortress.iam.createPermission({
        resource: 'invoice',
        action: 'delete',
      });
      const events: string[] = [];
      fortress.iam.addIamObserver((event) => {
        events.push(event.eventType);
      });

      await fortress.iam.deletePermission(perm.id);

      const remaining = await fortress.iam.listPermissions({ resource: 'invoice' });
      expect(remaining.find(p => p.action === 'delete')).toBeUndefined();
      expect(events).toEqual(['PERMISSION_DELETED']);
    });

    it('throws NOT_FOUND for missing permission', async () => {
      await expect(fortress.iam.deletePermission('99999')).rejects.toThrow('Permission not found');
    });
  });

  // ── addPermissionToRole ──────────────────────────────────────

  describe('addPermissionToRole', () => {
    it('adds permission to existing role', async () => {
      const role = await fortress.iam.createRole('base', [{ resource: 'post', action: 'read' }]);

      await fortress.iam.addPermissionToRole(role.id, { resource: 'post', action: 'write' });

      const detail = await fortress.iam.getRole(role.id);
      expect(detail.permissions).toHaveLength(2);
      expect(detail.permissions.map(p => p.action).sort()).toEqual(['read', 'write']);
    });

    it('is idempotent (adding same permission twice)', async () => {
      const role = await fortress.iam.createRole('idem', [{ resource: 'post', action: 'read' }]);

      await fortress.iam.addPermissionToRole(role.id, { resource: 'post', action: 'read' });

      const detail = await fortress.iam.getRole(role.id);
      expect(detail.permissions).toHaveLength(1);
    });

    it('throws NOT_FOUND for missing role', async () => {
      await expect(
        fortress.iam.addPermissionToRole('99999', { resource: 'x', action: 'y' }),
      ).rejects.toThrow('Role not found');
    });
  });
});

describe('remediation regressions (P3.1, P3.3)', () => {
  it('deleteRole invalidates the permission cache (P3.1/M6)', async () => {
    // With caching enabled, a global checkPermission warms the cache. Without
    // the deleteRole invalidation, the granted decision would survive in cache
    // for up to the TTL even after the role (and its access) is gone.
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      rbac: { cache: { ttlSeconds: 300 } },
    });
    const user = await fortress.auth.createUser({
      email: 'cache@test.com',
      name: 'Cache',
      password: 'password-123456',
    });
    const role = await fortress.iam.createRole('reporter', [{ resource: 'reports', action: 'read' }]);
    await fortress.iam.bindRoleToUser(user.id, role.id);

    // Warm the cache with a granted decision.
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'reports', 'read')).toBe(true);

    await fortress.iam.deleteRole(role.id);

    // Must be denied immediately — not after the 300s TTL.
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'reports', 'read')).toBe(false);
  });

  it('generic bindRole invalidates cached decisions', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      rbac: { evaluationMode: 'deny-overrides', cache: { ttlSeconds: 300 } },
    });
    const user = await fortress.auth.createUser({
      email: 'generic-bind-cache@test.com',
      name: 'Generic Bind Cache',
      password: 'password-123456',
    });
    const allow = await fortress.iam.createRole('allow-report', [{ resource: 'report', action: 'read' }]);
    await fortress.iam.bindRoleToUser(user.id, allow.id);
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'report', 'read')).toBe(true);

    const deny = await fortress.iam.createRole('deny-report', [{ resource: 'report', action: 'read', effect: 'DENY' }]);
    await fortress.iam.bindRole('USER', user.id, deny.id);
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'report', 'read')).toBe(false);
  });

  it('permission identity includes effect (ALLOW and DENY are distinct rows)', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
    const role = await fortress.iam.createRole('effect-identity', [
      { resource: 'doc', action: 'archive', effect: 'ALLOW' },
      { resource: 'doc', action: 'archive', effect: 'DENY' },
    ]);

    const detail = await fortress.iam.getRole(role.id);
    expect(detail.permissions).toHaveLength(2);
    expect(detail.permissions.map(p => p.effect).sort()).toEqual(['ALLOW', 'DENY']);

    const count = await fortress.config.database.count({
      model: 'permission',
      where: [
        { field: 'resource', operator: '=', value: 'doc' },
        { field: 'action', operator: '=', value: 'archive' },
      ],
    });
    expect(count).toBe(2);
  });

  it('permission identity includes stable serialized conditions', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
    const role = await fortress.iam.createRole('conditions-identity', [
      {
        resource: 'invoice',
        action: 'read',
        conditions: [{ field: 'resource.region', operator: 'eq', value: 'eu' }],
      },
      {
        resource: 'invoice',
        action: 'read',
        conditions: [{ field: 'resource.region', operator: 'eq', value: 'us' }],
      },
    ]);

    const detail = await fortress.iam.getRole(role.id);
    expect(detail.permissions).toHaveLength(2);

    const rows = await fortress.config.database.findMany<{ conditions: string }>({
      model: 'permission',
      where: [
        { field: 'resource', operator: '=', value: 'invoice' },
        { field: 'action', operator: '=', value: 'read' },
      ],
    });
    expect(rows).toHaveLength(2);
    const serialized = rows.map(row => row.conditions).sort();
    expect(serialized[0]).toContain('eu');
    expect(serialized[1]).toContain('us');
  });

  it('pins authoritative subject identity over caller-supplied condition context', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
    const user = await fortress.auth.createUser({
      email: 'identity-context@test.com',
      name: 'Identity Context',
      password: 'password-123456',
    });
    const role = await fortress.iam.createRole('owner', [{
      resource: 'document',
      action: 'read',
      conditions: [{ field: 'resource.ownerId', operator: 'eq', value: { ref: 'user.id' } }],
    }]);
    await fortress.iam.bindRoleToUser(user.id, role.id);

    expect(await fortress.iam.checkPermission(
      { type: 'USER', id: user.id },
      'document',
      'read',
      { resource: { ownerId: 'attacker' }, user: { id: 'attacker' } },
    )).toBe(false);
    expect(await fortress.iam.checkPermission(
      { type: 'USER', id: user.id },
      'document',
      'read',
      { resource: { ownerId: user.id }, user: { id: 'attacker' } },
    )).toBe(true);
  });

  it('findOrCreatePermission resolves concurrent creates to one row (P3.3/M8)', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
    const user = await fortress.auth.createUser({
      email: 'race@test.com',
      name: 'Race',
      password: 'password-123456',
    });

    // Two concurrent binds referencing the same (resource, action, no-conditions)
    // permission. The partial unique index forbids a duplicate row; the
    // find-or-create must absorb the lost race instead of throwing a raw DB error.
    await expect(Promise.all([
      fortress.iam.bindPermissionToUser(user.id, { resource: 'doc', action: 'read' }),
      fortress.iam.bindPermissionToUser(user.id, { resource: 'doc', action: 'read' }),
    ])).resolves.toBeDefined();

    const count = await fortress.config.database.count({
      model: 'permission',
      where: [
        { field: 'resource', operator: '=', value: 'doc' },
        { field: 'action', operator: '=', value: 'read' },
        { field: 'effect', operator: '=', value: 'ALLOW' },
        { field: 'conditions', operator: 'isNull', value: null },
      ],
    });
    expect(count).toBe(1);
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'doc', 'read')).toBe(true);
  });
});

function requireAt<T>(values: readonly T[], index: number, description: string): T {
  const value = values[index];
  if (value === undefined)
    throw new Error(`Expected ${description}`);
  return value;
}
