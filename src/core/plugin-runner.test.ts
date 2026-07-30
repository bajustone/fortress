import type { DatabaseAdapter } from '../adapters/database';
import type { FortressConfig } from './config';
import type { FortressPlugin, PluginContext, RuntimeFortressPlugin } from './plugin';

import { describe, expect, it, vi } from 'vitest';
import { definePlugin } from './plugin';
import { snapshotPluginMembership } from './plugin-membership';
import {
  chainAdapterWrappers,
  collectScopeRules,
  executePluginMiddleware,
  mergeTokenClaims,
  processPlugins,
  wrapAdapterWithScopeRules,
} from './plugin-runner';

const mockDb = {} as DatabaseAdapter;
const mockConfig = { jwt: { key: 'plugin-runner-test-secret-32ch!!' }, database: mockDb } as FortressConfig;

function testPlugin(overrides: Partial<FortressPlugin> = {}): FortressPlugin {
  return { name: 'test-plugin', ...overrides };
}

describe('processPlugins', () => {
  it('returns empty object for plugins with no methods', () => {
    const result = processPlugins([testPlugin()], mockDb, mockConfig);
    expect(result['test-plugin']).toEqual({});
  });

  it('exposes plugin methods by plugin name', () => {
    const plugin = testPlugin({
      name: 'my-plugin',
      methods: () => ({
        greet: (name: string) => `hello ${name}`,
      }),
    });
    const result = processPlugins([plugin], mockDb, mockConfig);
    const methods = requireValue(result['my-plugin'], 'my-plugin methods');
    const greet = requireValue(methods.greet, 'my-plugin greet method');
    expect(greet('world')).toBe('hello world');
  });

  it('passes PluginContext to methods factory', () => {
    const methodsFn = vi.fn(() => ({}));
    processPlugins([testPlugin({ methods: methodsFn })], mockDb, mockConfig);
    expect(methodsFn).toHaveBeenCalledWith(expect.objectContaining({
      db: mockDb,
      config: mockConfig,
      getPluginMethods: expect.any(Function),
    }));
  });

  it('rejects runtime method lookup during factory initialization', () => {
    const consumer = definePlugin({
      name: 'consumer',
      methods: (ctx) => {
        ctx.getPluginMethods?.('provider');
        return {};
      },
    });
    const provider = definePlugin({ name: 'provider', methods: () => ({ ready: () => true }) });

    expect(() => processPlugins([consumer, provider], mockDb, mockConfig)).toThrow(expect.objectContaining({
      code: 'BAD_REQUEST',
      statusCode: 400,
      message: 'Plugin "consumer" cannot resolve plugin "provider" while plugin methods are initializing; defer lookup until a returned method is called',
      details: { plugin: 'consumer', requestedPlugin: 'provider' },
    }));
  });

  it('accepts definePlugin and interface-shaped method surfaces', () => {
    interface GreeterMethods {
      greet: (name: string) => string;
    }
    const plugin = definePlugin({
      name: 'defined',
      methods: (ctx): GreeterMethods => ({
        greet: name => `${ctx.config.jwt.key}:${name}`,
      }),
    });
    const result = processPlugins([plugin], mockDb, mockConfig);
    const methods = requireValue(result.defined, 'defined plugin methods');
    const greet = requireValue(methods.greet, 'defined plugin greet method');
    expect(greet('Ada')).toBe(`${mockConfig.jwt.key}:Ada`);
  });

  it('finalizes standalone post-factory capability additions', async () => {
    let capturedContext: PluginContext | undefined;
    const originalResolver = vi.fn(async () => null);
    const originalMiddleware = vi.fn(async (_ctx: unknown, _request: unknown, next: () => Promise<void>) => next());
    const lateResolver = vi.fn(async () => ({ subject: { type: 'USER' as const, id: 'late' } }));
    const plugin: RuntimeFortressPlugin = {
      name: 'standalone',
      methods: (ctx) => {
        capturedContext = ctx;
        plugin.resolvePrincipal = originalResolver;
        plugin.middleware = [{ path: '/*', position: 'before-auth', handler: originalMiddleware }];
        return {};
      },
    };

    processPlugins([plugin], mockDb, mockConfig);
    const view = snapshotPluginMembership(capturedContext!);
    plugin.resolvePrincipal = lateResolver;
    plugin.middleware!.splice(0);

    await expect(view[0]!.resolvePrincipal!(new Request('https://example.test'), capturedContext!)).resolves.toBeNull();
    expect(originalResolver).toHaveBeenCalledOnce();
    expect(lateResolver).not.toHaveBeenCalled();
    expect(view[0]!.middleware).toHaveLength(1);
  });

  it('invalidates a standalone view when a factory fails', () => {
    let capturedContext: PluginContext | undefined;
    const plugin: RuntimeFortressPlugin = {
      name: 'failed-standalone',
      methods: (ctx) => {
        capturedContext = ctx;
        throw new Error('factory failed');
      },
    };

    expect(() => processPlugins([plugin], mockDb, mockConfig)).toThrow('factory failed');
    expect(() => snapshotPluginMembership(capturedContext!)[0]!.name).toThrow('failed construction');
  });

  it('handles multiple plugins', () => {
    const plugins = [
      testPlugin({ name: 'a', methods: () => ({ foo: () => 1 }) }),
      testPlugin({ name: 'b', methods: () => ({ bar: () => 2 }) }),
    ];
    const result = processPlugins(plugins, mockDb, mockConfig);
    expect(Object.keys(result)).toEqual(['a', 'b']);
  });
});

describe('chainAdapterWrappers', () => {
  it('returns base adapter when no plugins wrap', () => {
    const result = chainAdapterWrappers([testPlugin()], mockDb, {});
    expect(result).toBe(mockDb);
  });

  it('chains wrappers in registration order', () => {
    const calls: string[] = [];
    const plugins = [
      testPlugin({
        name: 'first',
        wrapAdapter: (adapter) => {
          calls.push('first');
          return { ...adapter, _first: true } as unknown as DatabaseAdapter;
        },
      }),
      testPlugin({
        name: 'second',
        wrapAdapter: (adapter) => {
          calls.push('second');
          return { ...adapter, _second: true } as unknown as DatabaseAdapter;
        },
      }),
    ];

    const result = chainAdapterWrappers(plugins, mockDb, {}) as unknown as Record<string, unknown>;
    expect(calls).toEqual(['first', 'second']);
    expect(result._first).toBe(true);
    expect(result._second).toBe(true);
  });

  it('passes request context to wrapAdapter', () => {
    const wrapFn = vi.fn(adapter => adapter);
    const plugin = testPlugin({ wrapAdapter: wrapFn });
    const ctx = { tenantId: '5' };

    chainAdapterWrappers([plugin], mockDb, ctx);
    expect(wrapFn).toHaveBeenCalledWith(mockDb, ctx);
  });
});

describe('mergeTokenClaims', () => {
  it('returns empty object when no plugins enrich claims', async () => {
    const result = await mergeTokenClaims([testPlugin()], '1', { db: mockDb, config: mockConfig });
    expect(result).toEqual({});
  });

  it('merges claims from multiple plugins', async () => {
    const plugins = [
      testPlugin({
        name: 'tenancy',
        enrichTokenClaims: async () => ({ tenantId: '5' }),
      }),
      testPlugin({
        name: 'custom',
        enrichTokenClaims: async () => ({ role: 'admin' }),
      }),
    ];

    const result = await mergeTokenClaims(plugins, '1', { db: mockDb, config: mockConfig });
    expect(result).toEqual({ tenantId: '5', role: 'admin' });
  });

  it('later plugin wins on key conflict', async () => {
    const plugins = [
      testPlugin({
        name: 'a',
        enrichTokenClaims: async () => ({ key: 'first' }),
      }),
      testPlugin({
        name: 'b',
        enrichTokenClaims: async () => ({ key: 'second' }),
      }),
    ];

    const result = await mergeTokenClaims(plugins, '1', { db: mockDb, config: mockConfig });
    expect(result.key).toBe('second');
  });
});

describe('executePluginMiddleware', () => {
  it('canonicalizes double and trailing slashes before path matching', async () => {
    const handler = vi.fn(async (_ctx, _request, next) => next());
    const plugin = testPlugin({
      middleware: [{ position: 'before-auth', path: '/auth/login', handler }],
    });
    const request = {
      request: new Request('http://localhost/auth//login/'),
    };

    await executePluginMiddleware(
      [plugin],
      'before-auth',
      '/auth//login/',
      { db: mockDb, config: mockConfig },
      request,
    );
    expect(handler).toHaveBeenCalledOnce();
  });

  it('enforces middleware methods case-insensitively from the request method', async () => {
    const handler = vi.fn(async (_ctx, _request, next) => next());
    const plugin = testPlugin({
      middleware: [{ position: 'before-auth', path: '/submit', methods: ['post'], handler }],
    });
    const context = { db: mockDb, config: mockConfig };

    await executePluginMiddleware(
      [plugin],
      'before-auth',
      '/submit',
      context,
      { request: new Request('http://localhost/submit') },
    );
    expect(handler).not.toHaveBeenCalled();

    await executePluginMiddleware(
      [plugin],
      'before-auth',
      '/submit',
      context,
      { request: new Request('http://localhost/submit', { method: 'POST' }) },
    );
    expect(handler).toHaveBeenCalledOnce();
  });
});

describe('collectScopeRules', () => {
  it('returns null when no plugins have scope rules', async () => {
    const result = await collectScopeRules([testPlugin()], '1', 'sale', { db: mockDb, config: mockConfig });
    expect(result).toBeNull();
  });

  it('returns null when plugin returns null for the model', async () => {
    const plugin = testPlugin({
      scopeRules: async () => null,
    });
    const result = await collectScopeRules([plugin], '1', 'sale', { db: mockDb, config: mockConfig });
    expect(result).toBeNull();
  });

  it('collects filters and defaults from a single plugin', async () => {
    const plugin = testPlugin({
      scopeRules: async () => ({
        filters: [{ field: 'siteId', operator: '=', value: 3 }],
        defaults: { siteId: 3 },
      }),
    });

    const result = await collectScopeRules([plugin], '1', 'sale', { db: mockDb, config: mockConfig });
    expect(result).toEqual({
      filters: [{ field: 'siteId', operator: '=', value: 3 }],
      defaults: { siteId: 3 },
    });
  });

  it('stacks filters and merges defaults from multiple plugins', async () => {
    const plugins = [
      testPlugin({
        name: 'org',
        scopeRules: async () => ({
          filters: [{ field: 'orgId', operator: '=', value: 7 }],
          defaults: { orgId: 7 },
        }),
      }),
      testPlugin({
        name: 'site',
        scopeRules: async () => ({
          filters: [{ field: 'siteId', operator: '=', value: 3 }],
          defaults: { siteId: 3 },
        }),
      }),
    ];

    const result = await collectScopeRules(plugins, '1', 'sale', { db: mockDb, config: mockConfig });
    expect(result?.filters).toHaveLength(2);
    expect(result?.defaults).toEqual({ orgId: 7, siteId: 3 });
  });
});

describe('wrapAdapterWithScopeRules', () => {
  it('forces scoped defaults on create and rejects scoped-field updates', async () => {
    const adapter = {
      ...mockDb,
      create: vi.fn(async params => params.data),
      update: vi.fn(async params => params.data),
      transaction: async (fn: (tx: DatabaseAdapter) => Promise<unknown>) => fn(adapter as unknown as DatabaseAdapter),
    } as unknown as DatabaseAdapter & { create: ReturnType<typeof vi.fn>; update: ReturnType<typeof vi.fn> };

    const scoped = wrapAdapterWithScopeRules(adapter, {
      filters: [{ field: 'orgId', operator: '=', value: 'org-1' }],
      defaults: { orgId: 'org-1' },
    });

    await scoped.create({ model: 'post', data: { title: 'hello', orgId: 'attacker-org' } });
    expect(adapter.create).toHaveBeenCalledWith({ model: 'post', data: { title: 'hello', orgId: 'org-1' } });

    await expect(scoped.update({
      model: 'post',
      where: [{ field: 'id', operator: '=', value: '1' }],
      data: { orgId: 'attacker-org' },
    })).rejects.toThrow('Cannot update scoped field \'orgId\'');
  });
});

function requireValue<T>(value: T | undefined, description: string): T {
  if (value === undefined)
    throw new Error(`Expected ${description}`);
  return value;
}
