import type { PluginContext } from '../../core/plugin';
import { describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { dataIsolation } from './index';

describe('data-isolation plugin', () => {
  it('generates scope rules for matching models', async () => {
    const db = createTestAdapter();
    const plugin = dataIsolation({
      scopes: [{
        name: 'site',
        field: 'siteId',
        models: ['sale', 'inventory'],
        resolveValue: async () => 3,
      }],
    });

    const ctx: PluginContext = { db, config: { jwt: { key: 'x'.repeat(32) }, database: db } };
    const rules = await plugin.scopeRules!('1', 'sale', ctx);

    expect(rules).not.toBeNull();
    expect(rules!.filters).toEqual([{ field: 'siteId', operator: '=', value: 3 }]);
    expect(rules!.defaults).toEqual({ siteId: 3 });
  });

  it('returns null for non-matching models', async () => {
    const db = createTestAdapter();
    const plugin = dataIsolation({
      scopes: [{
        name: 'site',
        field: 'siteId',
        models: ['sale'],
        resolveValue: async () => 3,
      }],
    });

    const ctx: PluginContext = { db, config: { jwt: { key: 'x'.repeat(32) }, database: db } };
    const rules = await plugin.scopeRules!('1', 'user', ctx);

    expect(rules).toBeNull();
  });

  it('stacks multiple scopes for same model', async () => {
    const db = createTestAdapter();
    const plugin = dataIsolation({
      scopes: [
        { name: 'org', field: 'orgId', models: ['sale'], resolveValue: async () => 7 },
        { name: 'site', field: 'siteId', models: ['sale'], resolveValue: async () => 3 },
      ],
    });

    const ctx: PluginContext = { db, config: { jwt: { key: 'x'.repeat(32) }, database: db } };
    const rules = await plugin.scopeRules!('1', 'sale', ctx);

    expect(rules!.filters).toHaveLength(2);
    expect(rules!.defaults).toEqual({ orgId: 7, siteId: 3 });
  });

  it('supports wildcard * model matching', async () => {
    const db = createTestAdapter();
    const plugin = dataIsolation({
      scopes: [{
        name: 'tenant',
        field: 'tenantId',
        models: ['*'],
        resolveValue: async () => 1,
      }],
    });

    const ctx: PluginContext = { db, config: { jwt: { key: 'x'.repeat(32) }, database: db } };
    const rules = await plugin.scopeRules!('1', 'anything', ctx);

    expect(rules).not.toBeNull();
    expect(rules!.filters[0].value).toBe(1);
  });

  it.each([null, undefined])('denies by default when an applicable scope resolves to %s', async (value) => {
    const db = createTestAdapter();
    const plugin = dataIsolation({
      scopes: [{
        name: 'site',
        field: 'siteId',
        models: ['sale'],
        resolveValue: async () => value,
      }],
    });

    const ctx: PluginContext = { db, config: { jwt: { key: 'x'.repeat(32) }, database: db } };

    await expect(plugin.scopeRules!('1', 'sale', ctx)).rejects.toMatchObject({
      code: 'FORBIDDEN',
      message: 'Data isolation scope \'site\' could not be resolved',
    });
  });

  it('supports explicit unsafe legacy skip mode for unresolved scopes', async () => {
    const db = createTestAdapter();
    const plugin = dataIsolation({
      unresolvedScope: 'skip',
      scopes: [{
        name: 'site',
        field: 'siteId',
        models: ['sale'],
        resolveValue: async () => null,
      }],
    });

    const ctx: PluginContext = { db, config: { jwt: { key: 'x'.repeat(32) }, database: db } };

    await expect(plugin.scopeRules!('1', 'sale', ctx)).resolves.toBeNull();
  });

  describe('bypass methods', () => {
    it('withoutScope bypasses a specific scope', async () => {
      const db = createTestAdapter();
      const plugin = dataIsolation({
        scopes: [
          { name: 'org', field: 'orgId', models: ['sale'], resolveValue: async () => 7 },
          { name: 'site', field: 'siteId', models: ['sale'], resolveValue: async () => 3 },
        ],
      });

      const ctx: PluginContext = { db, config: { jwt: { key: 'x'.repeat(32) }, database: db } };
      const methods = plugin.methods!(ctx) as { withoutScope: <T>(name: string, fn: () => Promise<T>) => Promise<T> };

      const rules = await methods.withoutScope('site', async () => {
        return plugin.scopeRules!('1', 'sale', ctx);
      });

      expect(rules!.filters).toHaveLength(1);
      expect(rules!.filters[0].field).toBe('orgId');
    });

    it('withoutScope explicitly bypasses an unresolved named scope', async () => {
      const db = createTestAdapter();
      const plugin = dataIsolation({
        scopes: [{ name: 'site', field: 'siteId', models: ['sale'], resolveValue: async () => null }],
      });
      const ctx: PluginContext = { db, config: { jwt: { key: 'x'.repeat(32) }, database: db } };
      const methods = plugin.methods!(ctx) as { withoutScope: <T>(name: string, fn: () => Promise<T>) => Promise<T> };

      await expect(
        methods.withoutScope('site', () => plugin.scopeRules!('1', 'sale', ctx)),
      ).resolves.toBeNull();
    });

    it('unscoped bypasses all scopes', async () => {
      const db = createTestAdapter();
      const plugin = dataIsolation({
        scopes: [
          { name: 'org', field: 'orgId', models: ['sale'], resolveValue: async () => 7 },
          { name: 'site', field: 'siteId', models: ['sale'], resolveValue: async () => 3 },
        ],
      });

      const ctx: PluginContext = { db, config: { jwt: { key: 'x'.repeat(32) }, database: db } };
      const methods = plugin.methods!(ctx) as { unscoped: <T>(fn: () => Promise<T>) => Promise<T> };

      const rules = await methods.unscoped(async () => {
        return plugin.scopeRules!('1', 'sale', ctx);
      });

      expect(rules).toBeNull();
    });

    // H4 regression: pre-fix, `unscoped()` set a module-level flag so a
    // concurrent request would see no isolation while the first request
    // was still awaiting inside the bypass window.
    it('unscoped does not leak across concurrent async flows (H4)', async () => {
      const db = createTestAdapter();
      const plugin = dataIsolation({
        scopes: [
          { name: 'org', field: 'orgId', models: ['sale'], resolveValue: async () => 7 },
        ],
      });
      const ctx: PluginContext = { db, config: { jwt: { key: 'x'.repeat(32) }, database: db } };
      const methods = plugin.methods!(ctx) as { unscoped: <T>(fn: () => Promise<T>) => Promise<T> };

      // Flow A holds an unscoped window open across an await.
      // Flow B asks for scope rules in the middle.
      const flowB = (async (): Promise<unknown> => {
        // Microtask-delay so flow A is already "inside" unscoped().
        await Promise.resolve();
        return plugin.scopeRules!('1', 'sale', ctx);
      })();
      const flowA = methods.unscoped(async () => {
        await new Promise(r => setTimeout(r, 5));
        return 'a-done';
      });

      const [flowAResult, flowBResult] = await Promise.all([flowA, flowB]);
      expect(flowAResult).toBe('a-done');
      // Flow B is in its own async context — still scoped.
      expect((flowBResult as { filters: { field: string }[] }).filters[0].field).toBe('orgId');
    });
  });
});
