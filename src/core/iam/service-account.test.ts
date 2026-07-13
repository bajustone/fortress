import type { Fortress } from '../fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

const SECRET = 'service-account-test-secret-32ch';

describe('iam-service: service accounts', () => {
  let fortress: Fortress;

  beforeEach(() => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
  });

  it('creates a service account with all metadata', async () => {
    const sa = await fortress.iam.createServiceAccount({
      name: 'ci-deploy',
      displayName: 'CI Deploy',
      description: 'Runs production deploys from CI',
    });

    expect(sa.id).toBeDefined();
    expect(sa.name).toBe('ci-deploy');
    expect(sa.displayName).toBe('CI Deploy');
    expect(sa.description).toBe('Runs production deploys from CI');
    expect(sa.isActive).toBe(true);
    expect(sa.createdAt).toBeInstanceOf(Date);
    expect(sa.updatedAt).toBeInstanceOf(Date);
  });

  it('createServiceAccount rejects duplicate names', async () => {
    await fortress.iam.createServiceAccount({ name: 'ci-deploy' });
    await expect(
      fortress.iam.createServiceAccount({ name: 'ci-deploy' }),
    ).rejects.toThrow(/already exists/);
  });

  it('getServiceAccount throws notFound for missing id', async () => {
    await expect(fortress.iam.getServiceAccount('9999')).rejects.toThrow(/not found/i);
  });

  it('listServiceAccounts paginates and returns total', async () => {
    for (let i = 0; i < 5; i++) {
      await fortress.iam.createServiceAccount({ name: `sa-${i}` });
    }

    const page1 = await fortress.iam.listServiceAccounts({ limit: 3, offset: 0 });
    expect(page1.serviceAccounts).toHaveLength(3);
    expect(page1.total).toBe(5);

    const page2 = await fortress.iam.listServiceAccounts({ limit: 3, offset: 3 });
    expect(page2.serviceAccounts).toHaveLength(2);
    expect(page2.total).toBe(5);
  });

  it('updateServiceAccount changes displayName/description/isActive but not name', async () => {
    const sa = await fortress.iam.createServiceAccount({ name: 'ci-deploy' });
    const updated = await fortress.iam.updateServiceAccount(sa.id, {
      displayName: 'New Display',
      description: 'New desc',
      isActive: false,
    });

    expect(updated.name).toBe('ci-deploy'); // immutable
    expect(updated.displayName).toBe('New Display');
    expect(updated.description).toBe('New desc');
    expect(updated.isActive).toBe(false);
  });

  it('deleteServiceAccount removes the account, role bindings, and direct bindings', async () => {
    const sa = await fortress.iam.createServiceAccount({ name: 'to-delete' });
    const role = await fortress.iam.createRole('rolex', [
      { resource: 'deploy', action: 'run' },
    ]);
    await fortress.iam.bindRoleToServiceAccount(sa.id, role.id);
    await fortress.iam.bindPermissionToServiceAccount(sa.id, {
      resource: 'deploy',
      action: 'promote',
    });

    await fortress.iam.deleteServiceAccount(sa.id);

    // Account is gone
    await expect(fortress.iam.getServiceAccount(sa.id)).rejects.toThrow(/not found/i);

    // Role bindings are cleaned up
    const roleBindings = await fortress.config.database.findMany({
      model: 'role_binding',
      where: [
        { field: 'subjectType', operator: '=', value: 'SERVICE_ACCOUNT' },
        { field: 'subjectId', operator: '=', value: sa.id },
      ],
    });
    expect(roleBindings).toHaveLength(0);

    // Direct permission bindings are cleaned up
    const directBindings = await fortress.config.database.findMany({
      model: 'direct_permission_binding',
      where: [
        { field: 'subjectType', operator: '=', value: 'SERVICE_ACCOUNT' },
        { field: 'subjectId', operator: '=', value: sa.id },
      ],
    });
    expect(directBindings).toHaveLength(0);
  });
});

describe('iam-service: service account permissions (regression)', () => {
  let fortress: Fortress;

  beforeEach(() => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
  });

  // Pins the core bug fix: SERVICE_ACCOUNT role bindings were silently dropped
  // by the old getUserPermissions path. With getSubjectPermissions they must
  // resolve end-to-end through checkPermission.
  it('bindRoleToServiceAccount + checkPermission resolves the role', async () => {
    const sa = await fortress.iam.createServiceAccount({ name: 'deployer' });
    const role = await fortress.iam.createRole('ops-deployer', [
      { resource: 'deploy', action: 'run' },
    ]);
    await fortress.iam.bindRoleToServiceAccount(sa.id, role.id);

    const allowed = await fortress.iam.checkPermission(
      { type: 'SERVICE_ACCOUNT', id: sa.id },
      'deploy',
      'run',
    );
    expect(allowed).toBe(true);

    const denied = await fortress.iam.checkPermission(
      { type: 'SERVICE_ACCOUNT', id: sa.id },
      'deploy',
      'destroy',
    );
    expect(denied).toBe(false);
  });

  it('bindPermissionToServiceAccount grants the permission directly', async () => {
    const sa = await fortress.iam.createServiceAccount({ name: 'audit-reader' });
    await fortress.iam.bindPermissionToServiceAccount(sa.id, {
      resource: 'audit',
      action: 'read',
    });

    const allowed = await fortress.iam.checkPermission(
      { type: 'SERVICE_ACCOUNT', id: sa.id },
      'audit',
      'read',
    );
    expect(allowed).toBe(true);
  });

  it('unbindRoleFromServiceAccount revokes the role permissions', async () => {
    const sa = await fortress.iam.createServiceAccount({ name: 'temp' });
    const role = await fortress.iam.createRole('temp-role', [
      { resource: 'temp', action: 'use' },
    ]);
    await fortress.iam.bindRoleToServiceAccount(sa.id, role.id);
    expect(await fortress.iam.checkPermission({ type: 'SERVICE_ACCOUNT', id: sa.id }, 'temp', 'use')).toBe(true);

    await fortress.iam.unbindRoleFromServiceAccount(sa.id, role.id);
    expect(await fortress.iam.checkPermission({ type: 'SERVICE_ACCOUNT', id: sa.id }, 'temp', 'use')).toBe(false);
  });

  it('inactive service account resolves to no permissions even with a bound role', async () => {
    const sa = await fortress.iam.createServiceAccount({ name: 'disabled' });
    const role = await fortress.iam.createRole('anything', [
      { resource: 'secret', action: 'read' },
    ]);
    await fortress.iam.bindRoleToServiceAccount(sa.id, role.id);

    // Flip isActive to false
    await fortress.iam.updateServiceAccount(sa.id, { isActive: false });

    const allowed = await fortress.iam.checkPermission(
      { type: 'SERVICE_ACCOUNT', id: sa.id },
      'secret',
      'read',
    );
    expect(allowed).toBe(false);

    const perms = await fortress.iam.getPermissionsForSubject({
      type: 'SERVICE_ACCOUNT',
      id: sa.id,
    });
    expect(perms).toEqual([]);
  });

  it('service accounts do not inherit permissions from groups', async () => {
    // A group has a permission; a user in the group has it via inheritance.
    const user = await fortress.auth.createUser({
      email: 'in-group@test.com',
      name: 'In Group',
      password: 'password-123456',
    });
    const group = await fortress.iam.createGroup('editors-sa-test');
    await fortress.iam.addUserToGroup(group.id, user.id);
    const role = await fortress.iam.createRole('group-editor', [
      { resource: 'article', action: 'edit' },
    ]);
    await fortress.iam.bindRoleToGroup(group.id, role.id);
    expect(await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'article', 'edit')).toBe(true);

    // A service account with the same numeric id as the group must NOT
    // pick up the group's permissions.
    const sa = await fortress.iam.createServiceAccount({ name: 'isolated-sa-group' });
    const allowed = await fortress.iam.checkPermission(
      { type: 'SERVICE_ACCOUNT', id: sa.id },
      'article',
      'edit',
    );
    expect(allowed).toBe(false);
  });
});

describe('iam-service: service accounts + tenancy', () => {
  let fortress: Fortress;

  beforeEach(() => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
  });

  it('tenant-scoped role binding only applies in its tenant', async () => {
    const sa = await fortress.iam.createServiceAccount({ name: 'tenant-bound' });
    const role = await fortress.iam.createRole('tenant-writer', [
      { resource: 'docs', action: 'write' },
    ]);
    await fortress.iam.bindRoleToServiceAccount(sa.id, role.id, 'tenant-a');

    const inA = await fortress.iam.checkPermission(
      { type: 'SERVICE_ACCOUNT', id: sa.id },
      'docs',
      'write',
      { tenantId: 'tenant-a' },
    );
    expect(inA).toBe(true);

    const inB = await fortress.iam.checkPermission(
      { type: 'SERVICE_ACCOUNT', id: sa.id },
      'docs',
      'write',
      { tenantId: 'tenant-b' },
    );
    expect(inB).toBe(false);
  });

  it('global role binding applies in any tenant', async () => {
    const sa = await fortress.iam.createServiceAccount({ name: 'global-bound' });
    const role = await fortress.iam.createRole('global-reader', [
      { resource: 'audit', action: 'read' },
    ]);
    await fortress.iam.bindRoleToServiceAccount(sa.id, role.id); // no tenantId

    expect(
      await fortress.iam.checkPermission(
        { type: 'SERVICE_ACCOUNT', id: sa.id },
        'audit',
        'read',
        { tenantId: 'tenant-a' },
      ),
    ).toBe(true);
    expect(
      await fortress.iam.checkPermission(
        { type: 'SERVICE_ACCOUNT', id: sa.id },
        'audit',
        'read',
        { tenantId: 'tenant-b' },
      ),
    ).toBe(true);
  });
});
