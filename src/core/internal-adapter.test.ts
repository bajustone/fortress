import type { DatabaseAdapter } from '../adapters/database';
import type { InternalAdapter } from './internal-adapter';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../testing';
import { createInternalAdapter } from './internal-adapter';

let db: DatabaseAdapter;
let adapter: InternalAdapter;

beforeEach(() => {
  db = createTestAdapter();
  adapter = createInternalAdapter(db);
});

describe('findUserByIdentifier', () => {
  it('finds user via login_identifier', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'alice@example.com', name: 'Alice', passwordHash: 'hashed', isActive: true },
    });

    await db.create({
      model: 'login_identifier',
      data: { userId: user.id, type: 'email', value: 'alice@example.com' },
    });

    const found = await adapter.findUserByIdentifier('alice@example.com');
    expect(found).not.toBeNull();
    expect(found!.email).toBe('alice@example.com');
    expect(found!.name).toBe('Alice');
  });

  it('falls back to email lookup when no login_identifier exists', async () => {
    await db.create({
      model: 'user',
      data: { email: 'bob@example.com', name: 'Bob', passwordHash: 'hashed', isActive: true },
    });

    const found = await adapter.findUserByIdentifier('bob@example.com');
    expect(found).not.toBeNull();
    expect(found!.email).toBe('bob@example.com');
  });

  it('returns null for unknown identifier', async () => {
    const found = await adapter.findUserByIdentifier('nobody@example.com');
    expect(found).toBeNull();
  });
});

describe('getUserGroups', () => {
  it('returns group names for a user', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'alice@example.com', name: 'Alice', passwordHash: 'hashed', isActive: true },
    });

    const g1 = await db.create<{ id: string }>({ model: 'group', data: { name: 'admins' } });
    const g2 = await db.create<{ id: string }>({ model: 'group', data: { name: 'editors' } });

    await db.create({ model: 'group_user', data: { groupId: g1.id, userId: user.id } });
    await db.create({ model: 'group_user', data: { groupId: g2.id, userId: user.id } });

    const groups = await adapter.getUserGroups(user.id);
    expect(groups).toHaveLength(2);
    expect(groups).toContain('admins');
    expect(groups).toContain('editors');
  });

  it('returns empty array for user with no groups', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'loner@example.com', name: 'Loner', passwordHash: 'hashed', isActive: true },
    });

    const groups = await adapter.getUserGroups(user.id);
    expect(groups).toEqual([]);
  });
});

describe('findRefreshTokenByHash', () => {
  it('finds a refresh token by hash', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'alice@example.com', name: 'Alice', passwordHash: 'hashed', isActive: true },
    });

    await db.create({
      model: 'refresh_token',
      data: {
        userId: user.id,
        tokenHash: 'abc123hash',
        tokenFamily: 'family-1',
        isRevoked: false,
        expiresAt: new Date(Date.now() + 86400000),
        ipAddress: '127.0.0.1',
        userAgent: 'test',
      },
    });

    const token = await adapter.findRefreshTokenByHash('abc123hash');
    expect(token).not.toBeNull();
    expect(token!.userId).toBe(user.id);
    expect(token!.tokenFamily).toBe('family-1');
    expect(token!.isRevoked).toBe(false);
  });

  it('returns null for unknown hash', async () => {
    const token = await adapter.findRefreshTokenByHash('nonexistent');
    expect(token).toBeNull();
  });
});

describe('getSubjectPermissions', () => {
  it('resolves permissions through direct role binding', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'alice@example.com', name: 'Alice', passwordHash: 'hashed', isActive: true },
    });

    await db.create({ model: 'resource', data: { name: 'document' } });

    const permission = await db.create<{ id: string }>({
      model: 'permission',
      data: { resource: 'document', action: 'read', effect: 'ALLOW', description: 'read document' },
    });

    const role = await db.create<{ id: string }>({
      model: 'role',
      data: { name: 'viewer' },
    });

    await db.create({ model: 'role_permission', data: { roleId: role.id, permissionId: permission.id } });
    await db.create({ model: 'role_binding', data: { roleId: role.id, subjectType: 'USER', subjectId: user.id } });

    const permissions = await adapter.getSubjectPermissions({ type: 'USER', id: user.id });
    expect(permissions).toHaveLength(1);
    expect(permissions[0].resource).toBe('document');
    expect(permissions[0].action).toBe('read');
  });

  it('resolves permissions through group role binding', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'bob@example.com', name: 'Bob', passwordHash: 'hashed', isActive: true },
    });

    const group = await db.create<{ id: string }>({ model: 'group', data: { name: 'editors' } });
    await db.create({ model: 'group_user', data: { groupId: group.id, userId: user.id } });

    await db.create({ model: 'resource', data: { name: 'article' } });

    const permission = await db.create<{ id: string }>({
      model: 'permission',
      data: { resource: 'article', action: 'write', effect: 'ALLOW', description: 'write article' },
    });

    const role = await db.create<{ id: string }>({
      model: 'role',
      data: { name: 'editor' },
    });

    await db.create({ model: 'role_permission', data: { roleId: role.id, permissionId: permission.id } });
    await db.create({ model: 'role_binding', data: { roleId: role.id, subjectType: 'GROUP', subjectId: group.id } });

    const permissions = await adapter.getSubjectPermissions({ type: 'USER', id: user.id });
    expect(permissions).toHaveLength(1);
    expect(permissions[0].resource).toBe('article');
    expect(permissions[0].action).toBe('write');
  });

  it('returns empty array for user with no roles', async () => {
    const user = await db.create<{ id: string }>({
      model: 'user',
      data: { email: 'nobody@example.com', name: 'Nobody', passwordHash: 'hashed', isActive: true },
    });

    const permissions = await adapter.getSubjectPermissions({ type: 'USER', id: user.id });
    expect(permissions).toEqual([]);
  });

  it('resolves permissions through a SERVICE_ACCOUNT role binding', async () => {
    const sa = await db.create<{ id: string }>({
      model: 'service_account',
      data: { name: 'ci-deploy', displayName: 'CI Deploy', description: null, isActive: true },
    });

    await db.create({ model: 'resource', data: { name: 'deploy' } });

    const permission = await db.create<{ id: string }>({
      model: 'permission',
      data: { resource: 'deploy', action: 'run', effect: 'ALLOW', description: 'run deploy' },
    });

    const role = await db.create<{ id: string }>({
      model: 'role',
      data: { name: 'deployer' },
    });

    await db.create({ model: 'role_permission', data: { roleId: role.id, permissionId: permission.id } });
    await db.create({ model: 'role_binding', data: { roleId: role.id, subjectType: 'SERVICE_ACCOUNT', subjectId: sa.id } });

    const permissions = await adapter.getSubjectPermissions({ type: 'SERVICE_ACCOUNT', id: sa.id });
    expect(permissions).toHaveLength(1);
    expect(permissions[0].resource).toBe('deploy');
    expect(permissions[0].action).toBe('run');
  });

  it('resolves direct permission bindings for a SERVICE_ACCOUNT', async () => {
    const sa = await db.create<{ id: string }>({
      model: 'service_account',
      data: { name: 'audit-reader', displayName: null, description: null, isActive: true },
    });

    await db.create({ model: 'resource', data: { name: 'audit' } });
    const permission = await db.create<{ id: string }>({
      model: 'permission',
      data: { resource: 'audit', action: 'read', effect: 'ALLOW', description: null },
    });

    await db.create({
      model: 'direct_permission_binding',
      data: { permissionId: permission.id, subjectType: 'SERVICE_ACCOUNT', subjectId: sa.id },
    });

    const permissions = await adapter.getSubjectPermissions({ type: 'SERVICE_ACCOUNT', id: sa.id });
    expect(permissions).toHaveLength(1);
    expect(permissions[0].resource).toBe('audit');
  });

  it('returns empty for an inactive SERVICE_ACCOUNT even with a bound role', async () => {
    const sa = await db.create<{ id: string }>({
      model: 'service_account',
      data: { name: 'disabled-sa', displayName: null, description: null, isActive: false },
    });

    await db.create({ model: 'resource', data: { name: 'deploy' } });
    const permission = await db.create<{ id: string }>({
      model: 'permission',
      data: { resource: 'deploy', action: 'run', effect: 'ALLOW', description: null },
    });
    const role = await db.create<{ id: string }>({ model: 'role', data: { name: 'deployer-disabled' } });
    await db.create({ model: 'role_permission', data: { roleId: role.id, permissionId: permission.id } });
    await db.create({ model: 'role_binding', data: { roleId: role.id, subjectType: 'SERVICE_ACCOUNT', subjectId: sa.id } });

    const permissions = await adapter.getSubjectPermissions({ type: 'SERVICE_ACCOUNT', id: sa.id });
    expect(permissions).toEqual([]);
  });

  it('service account subjects do not inherit permissions from groups', async () => {
    // Set up a group with a permission, and a user in that group.
    const group = await db.create<{ id: string }>({ model: 'group', data: { name: 'inheritance-group' } });
    await db.create({ model: 'resource', data: { name: 'article' } });
    const permission = await db.create<{ id: string }>({
      model: 'permission',
      data: { resource: 'article', action: 'read', effect: 'ALLOW', description: null },
    });
    const role = await db.create<{ id: string }>({ model: 'role', data: { name: 'reader-inherit' } });
    await db.create({ model: 'role_permission', data: { roleId: role.id, permissionId: permission.id } });
    await db.create({ model: 'role_binding', data: { roleId: role.id, subjectType: 'GROUP', subjectId: group.id } });

    // Create a service account with the SAME numeric id as the group — group-walk
    // must not accidentally match service accounts.
    const sa = await db.create<{ id: string }>({
      model: 'service_account',
      data: { name: 'isolated-sa', displayName: null, description: null, isActive: true },
    });

    const permissions = await adapter.getSubjectPermissions({ type: 'SERVICE_ACCOUNT', id: sa.id });
    expect(permissions).toEqual([]);
  });
});

describe('ensureResource', () => {
  it('creates a resource if it does not exist', async () => {
    await adapter.ensureResource('invoice');

    const found = await db.findOne<{ name: string }>({
      model: 'resource',
      where: [{ field: 'name', operator: '=', value: 'invoice' }],
    });
    expect(found).not.toBeNull();
    expect(found!.name).toBe('invoice');
  });

  it('is a no-op if resource already exists', async () => {
    await db.create({ model: 'resource', data: { name: 'invoice' } });
    await adapter.ensureResource('invoice');

    const count = await db.count({ model: 'resource', where: [{ field: 'name', operator: '=', value: 'invoice' }] });
    expect(count).toBe(1);
  });
});

describe('findOrCreatePermission', () => {
  it('creates a new permission', async () => {
    await db.create({ model: 'resource', data: { name: 'report' } });

    const perm = await adapter.findOrCreatePermission({ resource: 'report', action: 'generate' });
    expect(perm.resource).toBe('report');
    expect(perm.action).toBe('generate');
    expect(perm.effect).toBe('ALLOW');
  });

  it('returns existing permission on duplicate call', async () => {
    await db.create({ model: 'resource', data: { name: 'report' } });

    const first = await adapter.findOrCreatePermission({ resource: 'report', action: 'generate' });
    const second = await adapter.findOrCreatePermission({ resource: 'report', action: 'generate' });

    expect(first.id).toBe(second.id);
  });
});
