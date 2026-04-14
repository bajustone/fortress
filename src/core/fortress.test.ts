import type { DatabaseAdapter } from '../adapters/database';

import { describe, expect, it } from 'vitest';
import { createFortress } from './fortress';

// Minimal mock adapter — just enough for createFortress to wire up
const mockDb: DatabaseAdapter = {
  create: async () => ({}) as never,
  findOne: async () => null,
  findMany: async () => [],
  update: async () => ({}) as never,
  delete: async () => {},
  count: async () => 0,
  transaction: async fn => fn(mockDb),
};

describe('createFortress', () => {
  it('creates a fortress instance with auth and iam services', () => {
    const fortress = createFortress({
      jwt: { secret: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
    });

    expect(fortress.auth).toBeDefined();
    expect(fortress.auth.login).toBeTypeOf('function');
    expect(fortress.auth.refresh).toBeTypeOf('function');
    expect(fortress.auth.logout).toBeTypeOf('function');
    expect(fortress.auth.me).toBeTypeOf('function');
    expect(fortress.auth.createUser).toBeTypeOf('function');
    expect(fortress.auth.verifyToken).toBeTypeOf('function');
    expect(fortress.auth.signToken).toBeTypeOf('function');

    expect(fortress.iam).toBeDefined();
    expect(fortress.iam.checkPermission).toBeTypeOf('function');
    expect(fortress.iam.getPermissionsForSubject).toBeTypeOf('function');
    expect(fortress.iam.createRole).toBeTypeOf('function');
    expect(fortress.iam.bindRoleToUser).toBeTypeOf('function');
    expect(fortress.iam.bindRoleToGroup).toBeTypeOf('function');
    expect(fortress.iam.createGroup).toBeTypeOf('function');
    expect(fortress.iam.syncResources).toBeTypeOf('function');

    // Admin CRUD methods — auth
    expect(fortress.auth.listUsers).toBeTypeOf('function');
    expect(fortress.auth.getUserById).toBeTypeOf('function');
    expect(fortress.auth.updateUser).toBeTypeOf('function');
    expect(fortress.auth.deleteUser).toBeTypeOf('function');

    // Admin CRUD methods — IAM
    expect(fortress.iam.getRole).toBeTypeOf('function');
    expect(fortress.iam.updateRole).toBeTypeOf('function');
    expect(fortress.iam.listGroups).toBeTypeOf('function');
    expect(fortress.iam.getGroup).toBeTypeOf('function');
    expect(fortress.iam.updateGroup).toBeTypeOf('function');
    expect(fortress.iam.deleteGroup).toBeTypeOf('function');
    expect(fortress.iam.getGroupUsers).toBeTypeOf('function');
    expect(fortress.iam.listPermissions).toBeTypeOf('function');
    expect(fortress.iam.createPermission).toBeTypeOf('function');
    expect(fortress.iam.deletePermission).toBeTypeOf('function');
    expect(fortress.iam.addPermissionToRole).toBeTypeOf('function');
  });

  it('exposes config as readonly', () => {
    const config = { jwt: { secret: 'fortress-test-secret-at-least-32!' }, database: mockDb };
    const fortress = createFortress(config);
    expect(fortress.config).toBe(config);
  });

  it('returns empty plugins when none registered', () => {
    const fortress = createFortress({
      jwt: { secret: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
    });
    expect(fortress.plugins).toEqual({});
  });

  it('registers plugin methods', () => {
    const fortress = createFortress({
      jwt: { secret: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins: [
        {
          name: 'test-plugin',
          methods: () => ({
            hello: () => 'world',
          }),
        },
      ],
    });

    expect(fortress.plugins['test-plugin']).toBeDefined();
    expect((fortress.plugins['test-plugin'].hello as () => string)()).toBe('world');
  });

  it('only requires secret and database', () => {
    // Minimal config — should not throw
    const fortress = createFortress({
      jwt: { secret: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
    });
    expect(fortress).toBeDefined();
  });

  it('rejects JWT secrets shorter than 32 bytes', () => {
    expect(() => createFortress({
      jwt: { secret: 'too-short' },
      database: mockDb,
    })).toThrow('JWT secret must be at least 32 bytes');
  });

  it('rejects short secrets in rotation arrays', () => {
    expect(() => createFortress({
      jwt: { secret: ['valid-secret-that-is-32-bytes!!!', 'short'] },
      database: mockDb,
    })).toThrow('JWT secret must be at least 32 bytes');
  });
});
