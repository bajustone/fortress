/* eslint-disable ts/no-unsafe-function-type -- test uses Function type for plugin methods */
import type { DatabaseAdapter } from '../adapters/database';
import type { FortressConfig } from './config';
import type { FortressPlugin } from './plugin';

import { describe, expect, it, vi } from 'vitest';
import {
  chainAdapterWrappers,
  collectScopeRules,
  mergeTokenClaims,
  processPlugins,
} from './plugin-runner';

const mockDb = {} as DatabaseAdapter;
const mockConfig = { jwt: { secret: 'test' }, database: mockDb } as FortressConfig;

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
    expect((result['my-plugin'].greet as Function)('world')).toBe('hello world');
  });

  it('passes PluginContext to methods factory', () => {
    const methodsFn = vi.fn(() => ({}));
    processPlugins([testPlugin({ methods: methodsFn })], mockDb, mockConfig);
    expect(methodsFn).toHaveBeenCalledWith({ db: mockDb, config: mockConfig });
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
    const ctx = { tenantId: 5 };

    chainAdapterWrappers([plugin], mockDb, ctx);
    expect(wrapFn).toHaveBeenCalledWith(mockDb, ctx);
  });
});

describe('mergeTokenClaims', () => {
  it('returns empty object when no plugins enrich claims', async () => {
    const result = await mergeTokenClaims([testPlugin()], 1, { db: mockDb, config: mockConfig });
    expect(result).toEqual({});
  });

  it('merges claims from multiple plugins', async () => {
    const plugins = [
      testPlugin({
        name: 'tenancy',
        enrichTokenClaims: async () => ({ tenantId: 5 }),
      }),
      testPlugin({
        name: 'custom',
        enrichTokenClaims: async () => ({ role: 'admin' }),
      }),
    ];

    const result = await mergeTokenClaims(plugins, 1, { db: mockDb, config: mockConfig });
    expect(result).toEqual({ tenantId: 5, role: 'admin' });
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

    const result = await mergeTokenClaims(plugins, 1, { db: mockDb, config: mockConfig });
    expect(result.key).toBe('second');
  });
});

describe('collectScopeRules', () => {
  it('returns null when no plugins have scope rules', async () => {
    const result = await collectScopeRules([testPlugin()], 1, 'sale', { db: mockDb, config: mockConfig });
    expect(result).toBeNull();
  });

  it('returns null when plugin returns null for the model', async () => {
    const plugin = testPlugin({
      scopeRules: async () => null,
    });
    const result = await collectScopeRules([plugin], 1, 'sale', { db: mockDb, config: mockConfig });
    expect(result).toBeNull();
  });

  it('collects filters and defaults from a single plugin', async () => {
    const plugin = testPlugin({
      scopeRules: async () => ({
        filters: [{ field: 'siteId', operator: '=', value: 3 }],
        defaults: { siteId: 3 },
      }),
    });

    const result = await collectScopeRules([plugin], 1, 'sale', { db: mockDb, config: mockConfig });
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

    const result = await collectScopeRules(plugins, 1, 'sale', { db: mockDb, config: mockConfig });
    expect(result?.filters).toHaveLength(2);
    expect(result?.defaults).toEqual({ orgId: 7, siteId: 3 });
  });
});
