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

  describe('top-level routes', () => {
    it('registers host endpoints via the top-level `routes` field', async () => {
      const { endpoint } = await import('./schema-builder');
      const getSchool = endpoint('GET', '/schools/:id')
        .summary('Get a school')
        .security('none')
        .handler('getSchool')
        .build();
      const fortress = createFortress({
        jwt: { secret: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        routes: { getSchool },
      });

      const registered = fortress.endpoints.find(e => e.handler === 'getSchool');
      expect(registered).toBeDefined();
      expect(registered?.path).toBe('/schools/:id');
      expect(fortress.manifest.some(m => m.path === '/schools/:id')).toBe(true);
      // Top-level routes are metadata-only. They don't register plugin
      // methods, so exposing them on fortress.call would create a runtime
      // NOT_FOUND footgun. Use a real plugin with routes+methods for custom
      // typed callables.
      expect((fortress.call as Record<string, unknown>).getSchool).toBeUndefined();
    });

    it('rejects a user plugin that collides with the reserved __host name', async () => {
      const { endpoint } = await import('./schema-builder');
      const ep = endpoint('GET', '/x').summary('x').security('none').handler('x').build();
      expect(() => createFortress({
        jwt: { secret: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        routes: { x: ep },
        plugins: [{ name: '__host', routes: {} }],
      })).toThrow(/reserved/);
    });

    it('works without `routes` (default behavior unchanged)', () => {
      const fortress = createFortress({
        jwt: { secret: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
      });
      // No __host plugin should appear in fortress.plugins
      expect((fortress.plugins as Record<string, unknown>).__host).toBeUndefined();
    });
  });

  describe('toOpenAPI', () => {
    it('emits a spec from fortress endpoints including top-level host routes', async () => {
      const { endpoint, obj, str } = await import('./schema-builder');
      const getSchool = endpoint('GET', '/api/v1/schools/:id')
        .summary('Get a school')
        .tags('Schools')
        .security('none')
        .params(obj({ id: str() }, 'id'))
        .response(200, 'OK', obj({ data: str() }, 'data'))
        .handler('schools.get')
        .build();
      const fortress = createFortress({
        jwt: { secret: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        routes: { getSchool },
      });

      const spec = fortress.toOpenAPI({
        title: 'REB EdIT API',
        version: '0.0.0',
        servers: [{ url: 'http://localhost:3001', description: 'Local development' }],
        tags: [{ name: 'Schools' }],
      });

      expect(spec.openapi).toBe('3.1.0');
      expect(spec.info.title).toBe('REB EdIT API');
      expect(spec.servers?.[0]?.url).toBe('http://localhost:3001');
      expect(spec.tags).toEqual([{ name: 'Schools' }]);
      expect(spec.paths['/api/v1/schools/{id}'].get.operationId).toBe('schools.get');
      expect(spec.paths['/api/v1/schools/{id}'].get.parameters?.[0]).toMatchObject({
        name: 'id',
        in: 'path',
        required: true,
      });
    });

    it('can emit a host-only spec via the endpoints option', async () => {
      const { endpoint } = await import('./schema-builder');
      const ping = endpoint('GET', '/ping')
        .summary('Ping')
        .security('none')
        .response(200, 'OK')
        .handler('ping')
        .build();
      const fortress = createFortress({
        jwt: { secret: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
      });

      const spec = fortress.toOpenAPI({ title: 'Host API', version: '1.0.0', endpoints: [ping] });
      expect(Object.keys(spec.paths)).toEqual(['/ping']);
      expect(spec.paths['/ping'].get.operationId).toBe('ping');
    });
  });
});
