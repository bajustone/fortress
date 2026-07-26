import type { DatabaseAdapter } from '../adapters/database';
import type { RuntimeFortressPlugin } from './plugin';
import type { StandardSchemaV1 } from './standard-schema';

import { describe, expect, it } from 'vitest';
import { oauth } from '../plugins/oauth';
import { openapi } from '../plugins/openapi';
import { createFortress } from './fortress';
import { definePlugin } from './plugin';
import { endpoint } from './schema-builder';

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
  it('matches optional built-in call routes to runtime configuration', () => {
    const configured = (plugins: readonly RuntimeFortressPlugin[]) => createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins,
    });
    const calls = (plugins: readonly RuntimeFortressPlugin[]): Record<string, Record<string, unknown>> =>
      configured(plugins).call.plugins as Record<string, Record<string, unknown>>;
    expect(calls([oauth()]).oauth).not.toHaveProperty('handleGetFlow');
    expect(calls([oauth({ enableConsentApi: true })]).oauth).toHaveProperty('handleGetFlow');
    expect(calls([oauth({ enableConsentApi: true })]).oauth).toHaveProperty('handleApproveFlow');
    expect(calls([oauth({ enableConsentApi: true })]).oauth).toHaveProperty('handleDenyFlow');

    expect(calls([openapi()]).openapi).toHaveProperty('getUI');
    expect(calls([openapi({ disableUI: false })]).openapi).toHaveProperty('getUI');
    expect(calls([openapi({ disableUI: true })]).openapi).not.toHaveProperty('getUI');
  });

  it.each([
    {
      name: 'unsafe-runtime',
      path: '/unsafe-runtime',
      handler: 'handle',
      meta: { summary: 'Unsafe', security: ['none'] as const },
      expected: 'Plugin handler \'unsafe-runtime.handle\' not found',
    },
    {
      name: 'oauth',
      path: '/oauth/.well-known/openid-configuration',
      handler: 'handleDiscovery',
      meta: { summary: 'Unsafe OAuth', security: ['none'] as const, bearerKind: 'oauth' as const },
      expected: 'OAuth handler \'handleDiscovery\' not found',
    },
  ])('fails startup for $name plugins with non-function method members', ({ name, path, handler, meta }) => {
    const unsafe = {
      name,
      methods: () => ({ [handler]: 'not callable' }),
      routes: {
        [handler]: { method: 'GET', path, handler, meta },
      },
    } as unknown as RuntimeFortressPlugin;
    expect(() => createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins: [unsafe] as const,
    })).toThrow(`Plugin "${name}" method "${handler}" must be callable`);
  });

  it('fails startup for a non-callable methods-only surface', () => {
    const unsafe = {
      name: 'methods-only-runtime',
      methods: () => ({ callable: () => 'ok', metadata: 42 }),
    } as unknown as RuntimeFortressPlugin;
    expect(() => createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins: [unsafe],
    })).toThrow('Plugin "methods-only-runtime" method "metadata" must be callable');
  });

  it('fails startup when a concrete plugin route key differs from its handler', () => {
    const mismatched = {
      name: 'mismatched-runtime-key',
      methods: () => ({ actual: () => ({ ok: true }) }),
      routes: {
        alias: { method: 'GET', path: '/mismatched-runtime-key', handler: 'actual' },
      },
    } as unknown as RuntimeFortressPlugin;

    expect(() => createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins: [mismatched],
    })).toThrow('route key "alias" must match handler "actual"');
  });

  it('passes wire input to a transforming schema and validated output to the plugin handler', async () => {
    const transformingSchema: StandardSchemaV1<
      { occurredAt: string },
      { occurredAt: Date }
    > & {
      readonly type: 'object';
      readonly properties: { readonly occurredAt: { readonly type: 'string' } };
      readonly required: readonly ['occurredAt'];
    } = {
      'type': 'object',
      'properties': { occurredAt: { type: 'string' } },
      'required': ['occurredAt'],
      '~standard': {
        version: 1,
        vendor: 'transform-test',
        validate: value => ({
          value: { occurredAt: new Date((value as { occurredAt: string }).occurredAt) },
        }),
        types: undefined,
      },
    };
    let handlerInput: { occurredAt: Date } | undefined;
    const fortress = createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins: [{
        name: 'transform-runtime',
        methods: () => ({
          transform: (input: { occurredAt: Date }) => {
            handlerInput = input;
            return { occurredAt: input.occurredAt.toISOString() };
          },
        }),
        routes: {
          transform: endpoint('POST', '/transform-runtime')
            .security('none')
            .body(transformingSchema)
            .handler('transform')
            .build(),
        },
      }] as const,
    });

    await expect(fortress.call.plugins['transform-runtime'].transform({
      occurredAt: '2026-07-25T00:00:00.000Z',
    })).resolves.toEqual({ occurredAt: '2026-07-25T00:00:00.000Z' });
    expect(handlerInput?.occurredAt).toBeInstanceOf(Date);
  });

  it('fails startup for route-only and inherited handlers', () => {
    const routeOnly = {
      name: 'route-only-runtime',
      routes: { missing: { method: 'GET', path: '/missing', handler: 'missing' } },
    } as unknown as RuntimeFortressPlugin;
    expect(() => createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins: [routeOnly],
    })).toThrow('must be an own callable method');

    const inherited = {
      name: 'inherited-runtime',
      methods: () => Object.create({ toString: () => ({ unsafe: true }) }) as object,
      routes: { toString: { method: 'GET', path: '/inherited', handler: 'toString' } },
    } as unknown as RuntimeFortressPlugin;
    expect(() => createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins: [inherited],
    })).toThrow('must be an own callable method');

    const invalidMethod = {
      name: 'invalid-method-runtime',
      methods: () => ({ trace: () => ({ ok: true }) }),
      routes: { trace: { method: 'TRACE', path: '/trace', handler: 'trace' } },
    } as unknown as RuntimeFortressPlugin;
    expect(() => createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins: [invalidMethod],
    })).toThrow('route "trace" is not a valid endpoint definition');

    const arrayBody = {
      name: 'array-body-runtime',
      methods: () => ({ accept: () => ({ ok: true }) }),
      routes: {
        accept: {
          method: 'POST',
          path: '/array-body',
          handler: 'accept',
          input: { body: { type: 'array', items: { type: 'string' } } },
        },
      },
    } as unknown as RuntimeFortressPlugin;
    expect(() => createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins: [arrayBody],
    })).toThrow('route "accept" body schema must describe a flat object');
  });

  it('safely supports poisoned own plugin and handler names', async () => {
    const methods = Object.create(null) as Record<string, () => { value: string }>;
    methods.constructor = function (this: typeof methods) {
      return { value: Reflect.get(this, '__proto__').call(this).value };
    };
    Reflect.set(methods, '__proto__', () => ({ value: 'safe' }));
    const poisoned = {
      name: '__proto__',
      methods: () => methods,
      routes: {
        constructor: {
          method: 'GET',
          path: '/poisoned',
          handler: 'constructor',
          meta: { summary: 'Poisoned', security: ['none'] },
        },
      },
    } as unknown as RuntimeFortressPlugin;
    const fortress = createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins: [poisoned] as const,
    });

    expect(fortress.resolvePlugin('__proto__')).toBe(methods);
    expect(Object.getPrototypeOf(fortress.call.plugins)).toBeNull();
    const poisonedCalls = Reflect.get(fortress.call.plugins, '__proto__') as Record<string, (input: object) => Promise<unknown>>;
    expect(Object.getPrototypeOf(poisonedCalls)).toBeNull();
    await expect(poisonedCalls.constructor({})).resolves.toEqual({ value: 'safe' });
    const response = await fortress.handleRequest(new Request('http://localhost/poisoned'));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ value: 'safe' });
  });

  it('preserves plugin method this binding during route dispatch', async () => {
    const bound = {
      name: 'bound-runtime',
      methods: () => ({
        prefix: () => 'bound',
        handle(this: { prefix: () => string }) {
          return { value: this.prefix() };
        },
      }),
      routes: {
        handle: {
          method: 'GET',
          path: '/bound-runtime',
          handler: 'handle',
          meta: { summary: 'Bound', security: ['none'] },
        },
      },
    } as unknown as RuntimeFortressPlugin;
    const fortress = createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins: [bound] as const,
    });

    const response = await fortress.handleRequest(new Request('http://localhost/bound-runtime'));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ value: 'bound' });
  });

  it('preserves OAuth method this binding during protocol dispatch', async () => {
    const boundOAuth = {
      name: 'oauth',
      methods: () => ({
        issuer: () => 'https://issuer.example',
        handleDiscovery(this: { issuer: () => string }) {
          return { issuer: this.issuer() };
        },
      }),
      routes: {
        handleDiscovery: {
          method: 'GET',
          path: '/oauth/.well-known/openid-configuration',
          handler: 'handleDiscovery',
          meta: { summary: 'Discovery', security: ['none'], bearerKind: 'oauth' },
        },
      },
    } as unknown as RuntimeFortressPlugin;
    const fortress = createFortress({
      jwt: { key: 'fortress-test-secret-at-least-32!' },
      database: mockDb,
      plugins: [boundOAuth] as const,
    });

    const response = await fortress.handleRequest(new Request('http://localhost/oauth/.well-known/openid-configuration'));
    expect(response.status).toBe(200);
    await expect(response.json()).resolves.toEqual({ issuer: 'https://issuer.example' });
  });

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

    it('rejects top-level metadata routes that collide with core routes', async () => {
      const { endpoint } = await import('./schema-builder');
      const hostMe = endpoint('GET', '/auth/me')
        .summary('Host-owned me')
        .security('none')
        .handler('hostMe')
        .build();

      expect(() => createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        routes: { hostMe },
      })).toThrow(/collides with a Fortress core route/);
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
          { name: 'first-plugin', routes: { first }, methods: () => ({ first: () => ({ ok: true }) }) },
          { name: 'second-plugin', routes: { second }, methods: () => ({ second: () => ({ ok: true }) }) },
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
          { name: 'first-plugin', routes: { first }, methods: () => ({ first: () => ({ ok: true }) }) },
          { name: 'second-plugin', routes: { second }, methods: () => ({ second: () => ({ ok: true }) }) },
        ],
      })).toThrow(/Duplicate endpoint GET \/duplicate\/path/);
    });

    it('rejects core overrides whose route key or handler does not match the core callable', async () => {
      const { endpoint } = await import('./schema-builder');
      const alternate = endpoint('GET', '/auth/me')
        .summary('Unsafe override')
        .security('none')
        .handler('alternateMe')
        .build();

      expect(() => createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        plugins: [{
          name: 'undeclared-override',
          routes: { alternateMe: alternate },
          methods: () => ({ alternateMe: () => ({ source: 'plugin' }) }),
        }],
      })).toThrow(/declare "me" in coreOverrides/);

      expect(() => createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        plugins: [{
          name: 'unsafe-override',
          coreOverrides: ['me'] as const,
          routes: { alternateMe: alternate },
          methods: () => ({ alternateMe: () => ({ source: 'plugin' }) }),
        }],
      })).toThrow(/route key and handler must both be "me"/);

      const unrelatedMe = endpoint('GET', '/custom/me')
        .summary('Not an override')
        .security('none')
        .handler('me')
        .build();
      expect(() => createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        plugins: [{
          name: 'unused-override',
          coreOverrides: ['me'] as const,
          routes: { me: unrelatedMe },
          methods: () => ({ me: () => ({ source: 'plugin' }) }),
        }],
      })).toThrow(/declares unused core override "me"/);
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
          coreOverrides: ['me'] as const,
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
      expect((fortress.call.auth as Record<string, unknown>).me).toBeUndefined();
      await expect(fortress.call.plugins['core-override'].me({})).resolves.toEqual({ source: 'plugin' });
    });

    it('excludes OAuth protocol routes from the generic runtime call tree', async () => {
      const protocol = {
        method: 'POST' as const,
        path: '/oauth/token',
        handler: 'handleTokenRequest' as const,
        meta: { summary: 'Token', bearerKind: 'oauth' as const, security: ['basic' as const] },
      };
      const consent = {
        method: 'GET' as const,
        path: '/oauth/flows/:flowId',
        handler: 'handleGetFlow' as const,
        meta: { summary: 'Consent', security: ['bearer' as const] },
      };
      const fortress = createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        plugins: [{
          name: 'oauth',
          routes: { handleTokenRequest: protocol, handleGetFlow: consent },
          methods: () => ({
            handleTokenRequest: () => ({}),
            handleGetFlow: () => ({ flowId: 'flow' }),
          }),
        }],
      });

      expect((fortress.call.plugins.oauth as Record<string, unknown>).handleTokenRequest).toBeUndefined();
      expect(Object.keys(fortress.call.plugins.oauth)).toContain('handleGetFlow');
    });

    it('treats differently named path parameters as the same route shape', async () => {
      const { endpoint } = await import('./schema-builder');
      const first = endpoint('DELETE', '/items/:id').summary('first').security('none').handler('first').build();
      const second = endpoint('DELETE', '/items/:itemId').summary('second').security('none').handler('second').build();

      expect(() => createFortress({
        jwt: { key: 'fortress-test-secret-at-least-32!' },
        database: mockDb,
        plugins: [
          { name: 'first-plugin', routes: { first }, methods: () => ({ first: () => ({ ok: true }) }) },
          { name: 'second-plugin', routes: { second }, methods: () => ({ second: () => ({ ok: true }) }) },
        ],
      })).toThrow(/Duplicate endpoint DELETE \/items\/:/);
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
          { name: 'first-plugin', routes: { shared: first }, methods: () => ({ shared: () => ({ source: 'first' }) }) },
          { name: 'second-plugin', routes: { shared: second }, methods: () => ({ shared: () => ({ source: 'second' }) }) },
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
