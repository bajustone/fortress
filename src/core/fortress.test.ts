import type { DatabaseAdapter } from '../adapters/database';

import { describe, expect, it } from 'vitest';
import { createFortress } from './fortress';
import { definePlugin } from './plugin';

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

describe('resolvePlugin', () => {
  const plugin = definePlugin({
    name: 'known',
    methods: () => ({ ping: () => 'pong' as const }),
  });
  const fortress = createFortress({
    jwt: { key: 'fortress-test-secret-at-least-32!' },
    database: mockDb,
    plugins: [plugin] as const,
  });

  it('infers known keys and validates dynamic keys', () => {
    expect(fortress.plugins.known.ping()).toBe('pong');
    const dynamicName: string = 'known';
    const dynamic = fortress.resolvePlugin(dynamicName);
    // @ts-expect-error dynamic lookups return unknown without a validator
    dynamic.ping();
    const validated = fortress.resolvePlugin(
      dynamicName,
      (value): value is { ping: () => 'pong' } => typeof value === 'object'
        && value !== null
        && typeof Reflect.get(value, 'ping') === 'function',
    );
    expect(validated.ping()).toBe('pong');
  });

  it('rejects missing and invalid dynamic plugins', () => {
    expect(() => fortress.resolvePlugin('missing')).toThrow('Plugin \'missing\' is not registered');
    expect(() => fortress.resolvePlugin('known', (_value): _value is { nope: true } => false))
      .toThrow('Plugin \'known\' methods failed runtime validation');
  });
});

describe('createFortress', () => {
  it('creates a fortress instance with auth and iam services', () => {
    const fortress = createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
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
    const config = { jwt: { key: 'fortress-test-secret-at-least-32!' }, database: mockDb };
    const fortress = createFortress(config);
    expect(fortress.config).toBe(config);
  });

  it('returns empty plugins when none registered', () => {
    const fortress = createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
    });
    expect(fortress.plugins).toEqual({});
  });

  it('registers plugin methods', () => {
    const fortress = createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
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
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
    });
    expect(fortress).toBeDefined();
  });

  it('rejects JWT secrets shorter than 32 bytes', () => {
    expect(() => createFortress({
      jwt: { key: 'too-short' },
      database: mockDb,
    })).toThrow('JWT key must be at least 32 bytes');
  });

  it('rejects non-positive session controls', () => {
    expect(() => createFortress({
      jwt: {
        key: 'fortress-test-secret-at-least-32!',
        session: { refreshGraceSeconds: 0 },
      },
      database: mockDb,
    })).toThrow('jwt.session.refreshGraceSeconds must be a positive integer');
  });

  it('rejects short secrets in rotation arrays', () => {
    expect(() => createFortress({
      jwt: { key: ['valid-secret-that-is-32-bytes!!!', 'short'] },
      database: mockDb,
    })).toThrow('JWT key must be at least 32 bytes');
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
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        routes: { getSchool },
      });

      const registered = fortress.endpoints.find(e => e.handler === 'getSchool');
      expect(registered).toBeDefined();
      expect(registered?.path).toBe('/schools/:id');
      expect(fortress.manifest.find(m => m.path === '/schools/:id')).toMatchObject({
        plugin: null,
        mounted: false,
      });
      const direct = await fortress.handleRequest(new Request('http://localhost/schools/1'));
      expect(direct.status).toBe(404);
      // Top-level routes are metadata-only. They don't register plugin
      // methods, so exposing them on fortress.call would create a runtime
      // NOT_FOUND footgun. Use a real plugin with routes+methods for custom
      // typed callables.
      expect((fortress.call as unknown as Record<string, unknown>).getSchool).toBeUndefined();
      expect((fortress.call.plugins as Record<string, unknown>).__host).toBeUndefined();
    });

    it('keeps a top-level host override of a core route metadata-only', async () => {
      const { endpoint } = await import('./schema-builder');
      const hostMe = endpoint('GET', '/auth/me')
        .summary('Host-owned me')
        .security('none')
        .handler('hostMe')
        .build();
      const fortress = createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        routes: { hostMe },
      });

      expect(fortress.manifest.find(route => route.path === '/auth/me')).toMatchObject({
        handler: 'hostMe',
        plugin: null,
        mounted: false,
      });
      await expect(fortress.handleRequest(new Request('http://localhost/auth/me')))
        .resolves
        .toMatchObject({ status: 404 });
    });

    it('returns 404 before auth/RBAC for protected metadata-only host routes', async () => {
      const { endpoint } = await import('./schema-builder');
      const bearer = endpoint('GET', '/host-bearer')
        .summary('Bearer host route')
        .security('bearer')
        .handler('hostBearer')
        .build();
      const permission = endpoint('GET', '/host-permission')
        .summary('Permission host route')
        .permission('host', 'read')
        .handler('hostPermission')
        .build();
      const fortress = createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        routes: { bearer, permission },
      });

      await expect(fortress.handleRequest(new Request('http://localhost/host-bearer')))
        .resolves
        .toMatchObject({ status: 404 });
      await expect(fortress.handleRequest(new Request('http://localhost/host-permission')))
        .resolves
        .toMatchObject({ status: 404 });
    });

    it('rejects a user plugin that collides with the reserved __host name', async () => {
      const { endpoint } = await import('./schema-builder');
      const ep = endpoint('GET', '/x').summary('x').security('none').handler('x').build();
      expect(() => createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        routes: { x: ep },
        plugins: [{ name: '__host', routes: {} }],
      })).toThrow(/reserved/);
    });

    it('works without `routes` (default behavior unchanged)', () => {
      const fortress = createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
      });
      // No __host plugin should appear in fortress.plugins
      expect((fortress.plugins as Record<string, unknown>).__host).toBeUndefined();
    });
  });

  describe('plugin collision detection', () => {
    it('rejects duplicate method+path declarations across plugins', async () => {
      const { endpoint } = await import('./schema-builder');
      const first = endpoint('GET', '/duplicate').summary('first').security('none').handler('first').build();
      const second = endpoint('GET', '/duplicate').summary('second').security('none').handler('second').build();

      expect(() => createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        plugins: [
          { name: 'first-plugin', routes: { first } },
          { name: 'second-plugin', routes: { second } },
        ],
      })).toThrow(/Duplicate endpoint GET \/duplicate.*first-plugin.*second-plugin/);
    });

    it('rejects slash variants that canonicalize to the same route', async () => {
      const { endpoint } = await import('./schema-builder');
      const first = endpoint('GET', '/duplicate/path').summary('first').security('none').handler('first').build();
      const second = endpoint('GET', '//duplicate//path/').summary('second').security('none').handler('second').build();

      expect(() => createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        plugins: [
          { name: 'first-plugin', routes: { first } },
          { name: 'second-plugin', routes: { second } },
        ],
      })).toThrow(/Duplicate endpoint GET \/duplicate\/path/);
    });

    it('preserves intentional plugin overrides of core route and call keys', async () => {
      const { endpoint } = await import('./schema-builder');
      const me = endpoint('GET', '/auth/me')
        .summary('Override me')
        .security('none')
        .handler('me')
        .build();
      const fortress = createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        plugins: [{
          name: 'core-override',
          routes: { me },
          methods: () => ({ me: () => ({ source: 'plugin' }) }),
        }],
      });

      const response = await fortress.handleRequest(new Request('http://localhost/auth/me'));
      expect(response.status).toBe(200);
      expect(await response.json()).toEqual({ source: 'plugin' });
      expect(fortress.manifest.find(route => route.path === '/auth/me')).toMatchObject({
        plugin: 'core-override',
        mounted: true,
      });
    });

    it('namespaces shared call keys per plugin instead of colliding', async () => {
      // v1 threw on two plugins reusing a call key. In the namespaced tree
      // (ADR 0001 §5) each plugin owns its namespace, so shared keys coexist;
      // duplicate method+path routes and duplicate plugin names are still
      // rejected elsewhere.
      const { endpoint } = await import('./schema-builder');
      const first = endpoint('GET', '/first').summary('first').security('none').handler('shared').build();
      const second = endpoint('GET', '/second').summary('second').security('none').handler('shared').build();

      const fortress = createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        plugins: [
          { name: 'first-plugin', routes: { shared: first } },
          { name: 'second-plugin', routes: { shared: second } },
        ],
      });
      const tree = fortress.call.plugins as Record<string, Record<string, unknown>>;
      expect(typeof tree['first-plugin'].shared).toBe('function');
      expect(typeof tree['second-plugin'].shared).toBe('function');
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
        jwt: { key: 'fortress-test-secret-at-least-32!' },
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
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
      });

      const spec = fortress.toOpenAPI({ title: 'Host API', version: '1.0.0', endpoints: [ping] });
      expect(Object.keys(spec.paths)).toEqual(['/ping']);
      expect(spec.paths['/ping'].get.operationId).toBe('ping');
    });
  });
});
