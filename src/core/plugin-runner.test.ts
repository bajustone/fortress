import type { DatabaseAdapter } from '../adapters/database';
import type { FortressConfig } from './config';
import type { FortressPlugin, PluginContext, PluginMethod, RuntimeFortressPlugin } from './plugin';

import { runInNewContext } from 'node:vm';
import { describe, expect, it, vi } from 'vitest';
import { definePlugin } from './plugin';
import { snapshotPluginMembership } from './plugin-membership';
import { createPluginMethodController } from './plugin-method-capabilities';
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

  it('publishes one frozen facade while leaving caller and closure state live', () => {
    let closureState = 'initial';
    const source = { ping: () => 'original', readState: () => closureState };
    let lazyLookup: (() => Readonly<Record<string, unknown>> | undefined) | undefined;
    const plugin = definePlugin({
      name: 'surface',
      methods: (ctx) => {
        lazyLookup = () => ctx.getPluginMethods?.('surface');
        return source;
      },
    });
    const result = processPlugins([plugin], mockDb, mockConfig);
    const facade = result.surface!;

    expect(lazyLookup!()).toBe(facade);
    expect(Object.isFrozen(result)).toBe(true);
    expect(Object.isFrozen(facade)).toBe(true);
    expect(facade).not.toBe(source);
    expect(Reflect.get(facade, 'toString')).toBeUndefined();
    expect(Object.isFrozen(source)).toBe(false);
    expect(Object.isExtensible(source)).toBe(true);

    source.ping = () => 'replaced';
    closureState = 'updated';
    Object.assign(source, { added: () => 'added' });
    expect(facade.ping!()).toBe('original');
    expect(facade.readState!()).toBe('updated');
    expect(Reflect.get(facade, 'added')).toBeUndefined();
    expect(Reflect.set(facade, 'ping', () => 'facade replacement')).toBe(false);
    expect(Reflect.set(result, 'surface', Object.create(null))).toBe(false);
    expect(facade.ping!()).toBe('original');
  });

  it('materializes an owned method controller with an external capability view', () => {
    const plugin = definePlugin({ name: 'external-view', methods: () => ({ ping: () => 'pong' }) });
    const result = processPlugins(
      [plugin],
      mockDb,
      mockConfig,
      undefined,
      undefined,
      undefined,
      [plugin],
    );

    expect(Object.keys(result)).toEqual(['external-view']);
    expect(result['external-view']!.ping!()).toBe('pong');
    expect(Object.isFrozen(result)).toBe(true);
  });

  it('defers a caller-supplied controller until explicit materialization and activation', () => {
    const plugin = definePlugin({ name: 'deferred', methods: () => ({ ping: () => 'pong' }) });
    const controller = createPluginMethodController();
    const result = processPlugins(
      [plugin],
      mockDb,
      mockConfig,
      undefined,
      undefined,
      undefined,
      [plugin],
      controller,
    );

    expect(result).toBe(controller.methods);
    expect(Object.keys(result)).toEqual([]);
    expect(() => controller.resolveForContext('deferred')).toThrow('until construction succeeds');
    controller.materialize([plugin]);
    expect(Object.keys(result)).toEqual(['deferred']);
    expect(() => result.deferred!.ping!()).toThrow('until construction succeeds');
    controller.activate();
    expect(result.deferred!.ping!()).toBe('pong');
  });

  it('captures surfaces after all factories and ignores later source mutation', () => {
    const source = { ping: () => 'initial' };
    const first = definePlugin({ name: 'first', methods: () => source });
    const second = definePlugin({
      name: 'second',
      methods: () => {
        source.ping = () => 'during construction';
        return {};
      },
    });

    const result = processPlugins([first, second], mockDb, mockConfig);
    expect(result.first!.ping!()).toBe('during construction');
    source.ping = () => 'after construction';
    expect(result.first!.ping!()).toBe('during construction');
  });

  it('captures inherited, symbol, non-enumerable, and getter-backed methods once', () => {
    const symbolMethod = Symbol('symbolMethod');
    let ownGetterReads = 0;
    let inheritedGetterReads = 0;
    let shadowedGetterReads = 0;

    class Surface {
      #count = 0;

      increment(): number {
        return ++this.#count;
      }

      receiver(source: Surface): boolean {
        return this === source;
      }
    }
    Object.defineProperty(Surface.prototype, 'inheritedGetter', {
      configurable: true,
      get(this: Surface) {
        inheritedGetterReads++;
        return () => this.increment();
      },
    });

    const source = new Surface();
    Object.defineProperty(source, 'hidden', {
      value: () => 'hidden',
      configurable: true,
      writable: true,
      enumerable: false,
    });
    Object.defineProperty(source, symbolMethod, {
      value: () => 'symbol',
      configurable: true,
      writable: true,
      enumerable: false,
    });
    Object.defineProperty(source, 'ownGetter', {
      configurable: true,
      enumerable: true,
      get() {
        ownGetterReads++;
        Object.defineProperty(source, 'addedByGetter', { value: () => 'late', configurable: true });
        return () => 'getter';
      },
    });

    class BaseSurface {}
    Object.defineProperty(BaseSurface.prototype, 'shadowed', {
      get() {
        shadowedGetterReads++;
        throw new Error('shadowed getter must not run');
      },
    });
    class DerivedSurface extends BaseSurface {
      shadowed(): string {
        return 'nearest';
      }
    }

    const plugin = { name: 'class-surface', methods: () => source } as unknown as RuntimeFortressPlugin;
    const shadowedPlugin = { name: 'shadowed', methods: () => new DerivedSurface() } as unknown as RuntimeFortressPlugin;
    const result = processPlugins([plugin, shadowedPlugin], mockDb, mockConfig);
    const facade = result['class-surface']! as Record<PropertyKey, (...args: unknown[]) => unknown>;

    expect(ownGetterReads).toBe(1);
    expect(inheritedGetterReads).toBe(1);
    expect(shadowedGetterReads).toBe(0);
    expect(result.shadowed!.shadowed!()).toBe('nearest');
    expect(facade.increment!()).toBe(1);
    expect(facade.increment!()).toBe(2);
    expect(facade.receiver!(source)).toBe(true);
    expect(facade.hidden!()).toBe('hidden');
    expect(facade[symbolMethod]!()).toBe('symbol');
    expect(facade.ownGetter!()).toBe('getter');
    expect(facade.inheritedGetter!()).toBe(3);
    const extractedIncrement = facade.increment!;
    expect(Reflect.apply(extractedIncrement, { increment: () => 99 }, [])).toBe(4);
    expect(Reflect.get(facade, 'addedByGetter')).toBeUndefined();
    expect(Object.hasOwn(facade, 'increment')).toBe(false);
    expect(Object.hasOwn(facade, 'hidden')).toBe(true);
  });

  it('rejects non-callable effective inherited properties', () => {
    const dataPrototype = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(dataPrototype, 'inheritedData', { value: 42 });
    const dataSurface = Object.create(dataPrototype) as Record<string, PluginMethod>;
    expect(() => processPlugins([
      testPlugin({ name: 'inherited-data', methods: () => dataSurface }),
    ], mockDb, mockConfig)).toThrow('Plugin "inherited-data" method "inheritedData" must be callable');

    const getterPrototype = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(getterPrototype, 'inheritedGetter', { get: () => 42 });
    const getterSurface = Object.create(getterPrototype) as Record<string, PluginMethod>;
    expect(() => processPlugins([
      testPlugin({ name: 'inherited-getter', methods: () => getterSurface }),
    ], mockDb, mockConfig)).toThrow('Plugin "inherited-getter" method "inheritedGetter" must be callable');
  });

  it('fixes direct inherited identities while documenting live sibling lookups', () => {
    class Surface {
      sibling(): string {
        return 'captured';
      }

      outer(): string {
        return this.sibling();
      }
    }
    const source = new Surface();
    const originalSibling = Surface.prototype.sibling;
    const plugin = { name: 'siblings', methods: () => source } as unknown as RuntimeFortressPlugin;
    const result = processPlugins([plugin], mockDb, mockConfig);
    const facade = result.siblings! as unknown as Surface;

    Surface.prototype.sibling = () => 'prototype replaced';
    expect(facade.sibling()).toBe('captured');
    expect(facade.outer()).toBe('prototype replaced');
    Surface.prototype.sibling = originalSibling;
  });

  it('retains custom terminal capabilities but excludes a real cross-realm Object.prototype', () => {
    const customTerminal = Object.create(null) as Record<PropertyKey, unknown>;
    const CustomTerminal = function CustomTerminal(): void {};
    CustomTerminal.prototype = customTerminal;
    Reflect.defineProperty(customTerminal, 'constructor', { value: CustomTerminal });
    Reflect.defineProperty(customTerminal, 'inherited', { value: () => 'retained' });
    const customSource = Object.create(customTerminal) as Record<string, () => string>;
    customSource.ping = () => 'pong';

    const foreignSource = runInNewContext('({ ping() { return "foreign pong"; } })') as Record<string, () => string>;
    const result = processPlugins([
      testPlugin({ name: 'custom-terminal', methods: () => customSource }),
      testPlugin({ name: 'foreign-realm', methods: () => foreignSource }),
    ], mockDb, mockConfig);

    expect(result['custom-terminal']!.ping!()).toBe('pong');
    expect(result['custom-terminal']!.inherited!()).toBe('retained');
    expect(result['foreign-realm']!.ping!()).toBe('foreign pong');
    expect(Reflect.get(result['foreign-realm']!, 'toString')).toBeUndefined();
  });

  it('supports own constructor and __proto__ capabilities safely', () => {
    const source = Object.create(null) as Record<string, () => string>;
    Reflect.defineProperty(source, 'constructor', { value: () => 'constructor', enumerable: true, configurable: true, writable: true });
    Reflect.defineProperty(source, '__proto__', { value: () => 'proto', enumerable: true, configurable: true, writable: true });
    const result = processPlugins([
      testPlugin({ name: '__proto__', methods: () => source }),
    ], mockDb, mockConfig);
    const facade = Reflect.get(result, '__proto__') as Record<string, () => string>;

    expect(Object.getPrototypeOf(result)).toBeNull();
    expect(facade.constructor()).toBe('constructor');
    expect(Reflect.get(facade, '__proto__')()).toBe('proto');
  });

  it('fails closed for intrinsic prototypes, non-callable effective values, and accessor exceptions', () => {
    expect(() => processPlugins([
      testPlugin({ name: 'object-prototype', methods: () => Object.prototype as unknown as Record<string, PluginMethod> }),
    ], mockDb, mockConfig)).toThrow('methods factory must not return Object.prototype');

    const foreignObjectPrototype = runInNewContext('Object.prototype') as Record<string, PluginMethod>;
    expect(() => processPlugins([
      testPlugin({ name: 'foreign-object-prototype', methods: () => foreignObjectPrototype }),
    ], mockDb, mockConfig)).toThrow('methods factory must not return Object.prototype');

    const nonCallable = { method: 42 };
    expect(() => processPlugins([
      testPlugin({ name: 'non-callable', methods: () => nonCallable as unknown as Record<string, PluginMethod> }),
    ], mockDb, mockConfig)).toThrow('Plugin "non-callable" method "method" must be callable');

    const throwing = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(throwing, 'explode', {
      enumerable: true,
      get() {
        throw new Error('getter exploded');
      },
    });
    expect(() => processPlugins([
      testPlugin({ name: 'throwing', methods: () => throwing as Record<string, PluginMethod> }),
    ], mockDb, mockConfig)).toThrow('getter exploded');

    const cycle: { value?: object } = {};
    const cyclic = new Proxy(Object.create(null) as object, { getPrototypeOf: () => cycle.value! });
    cycle.value = cyclic;
    expect(() => processPlugins([
      testPlugin({ name: 'cyclic', methods: () => cyclic as Record<string, PluginMethod> }),
    ], mockDb, mockConfig)).toThrow('methods object has a cyclic prototype chain');
  });

  it('invalidates leaked method lookup when construction fails', () => {
    let context: PluginContext | undefined;
    const surface = { invalid: 42 };
    const plugin = testPlugin({
      name: 'invalid-surface',
      methods: (ctx) => {
        context = ctx;
        return surface as unknown as Record<string, PluginMethod>;
      },
    });

    expect(() => processPlugins([plugin], mockDb, mockConfig)).toThrow('must be callable');
    expect(() => context!.getPluginMethods?.('invalid-surface')).toThrow('failed construction');
  });

  it('invalidates a captured wrapper when later construction fails', () => {
    const controller = createPluginMethodController();
    controller.record({ ping: () => 'captured' });
    controller.materialize([testPlugin({ name: 'valid' })]);
    const leaked = controller.methods.valid!.ping!;

    controller.fail();
    expect(() => leaked()).toThrow('failed construction');
    expect(() => controller.resolveForContext('valid')).toThrow('failed construction');
  });

  it('publishes no partial map when materialization fails', () => {
    const controller = createPluginMethodController();
    controller.record({ ping: () => 'captured' });
    const invalid = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(invalid, 'broken', { value: 42, enumerable: true });
    controller.record(invalid);

    expect(() => controller.materialize([
      testPlugin({ name: 'valid' }),
      testPlugin({ name: 'invalid' }),
    ])).toThrow('method "broken" must be callable');
    expect(Object.keys(controller.methods)).toEqual([]);
    expect(() => controller.resolveForContext('valid')).toThrow('failed construction');
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
