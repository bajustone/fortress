import type { Fortress } from '../fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

const SECRET = 'iam-service-test-secret-32chars!';

describe('iam-service: isSystem flag', () => {
  let fortress: Fortress;

  beforeEach(() => {
    fortress = createFortress({
      jwt: { secret: SECRET },
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
      jwt: { secret: SECRET },
      database: createTestAdapter(),
    });
  });

  it('bindPermissionToUser grants access without a role', async () => {
    const user = await fortress.auth.createUser({
      email: 'alice@test.com',
      name: 'Alice',
      password: 'password-123',
    });

    await fortress.iam.bindPermissionToUser(user.id, { resource: 'post', action: 'read' });

    const allowed = await fortress.iam.checkPermission(user.id, 'post', 'read');
    expect(allowed).toBe(true);

    const denied = await fortress.iam.checkPermission(user.id, 'post', 'delete');
    expect(denied).toBe(false);
  });

  it('bindPermissionToGroup grants access to group members', async () => {
    const user = await fortress.auth.createUser({
      email: 'bob@test.com',
      name: 'Bob',
      password: 'password-123',
    });

    const group = await fortress.iam.createGroup('editors');
    await fortress.iam.addUserToGroup(group.id, user.id);
    await fortress.iam.bindPermissionToGroup(group.id, { resource: 'post', action: 'update' });

    const allowed = await fortress.iam.checkPermission(user.id, 'post', 'update');
    expect(allowed).toBe(true);
  });

  it('unbindPermissionFromUser revokes access', async () => {
    const user = await fortress.auth.createUser({
      email: 'carol@test.com',
      name: 'Carol',
      password: 'password-123',
    });

    await fortress.iam.bindPermissionToUser(user.id, { resource: 'post', action: 'read' });
    expect(await fortress.iam.checkPermission(user.id, 'post', 'read')).toBe(true);

    const perms = await fortress.iam.getUserPermissions(user.id);
    const perm = perms.find(p => p.resource === 'post' && p.action === 'read');
    await fortress.iam.unbindPermissionFromUser(user.id, perm!.id);

    expect(await fortress.iam.checkPermission(user.id, 'post', 'read')).toBe(false);
  });

  it('direct and role-based permissions combine', async () => {
    const user = await fortress.auth.createUser({
      email: 'dave@test.com',
      name: 'Dave',
      password: 'password-123',
    });

    const role = await fortress.iam.createRole('viewer', [{ resource: 'post', action: 'read' }]);
    await fortress.iam.bindRoleToUser(user.id, role.id);
    await fortress.iam.bindPermissionToUser(user.id, { resource: 'post', action: 'update' });

    expect(await fortress.iam.checkPermission(user.id, 'post', 'read')).toBe(true);
    expect(await fortress.iam.checkPermission(user.id, 'post', 'update')).toBe(true);
    expect(await fortress.iam.checkPermission(user.id, 'post', 'delete')).toBe(false);
  });
});
