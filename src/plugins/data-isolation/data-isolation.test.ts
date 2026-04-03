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

    const ctx: PluginContext = { db, config: { jwt: { secret: 'x'.repeat(32) }, database: db } };
    const rules = await plugin.scopeRules!(1, 'sale', ctx);

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

    const ctx: PluginContext = { db, config: { jwt: { secret: 'x'.repeat(32) }, database: db } };
    const rules = await plugin.scopeRules!(1, 'user', ctx);

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

    const ctx: PluginContext = { db, config: { jwt: { secret: 'x'.repeat(32) }, database: db } };
    const rules = await plugin.scopeRules!(1, 'sale', ctx);

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

    const ctx: PluginContext = { db, config: { jwt: { secret: 'x'.repeat(32) }, database: db } };
    const rules = await plugin.scopeRules!(1, 'anything', ctx);

    expect(rules).not.toBeNull();
    expect(rules!.filters[0].value).toBe(1);
  });

  it('skips scope when resolveValue returns null', async () => {
    const db = createTestAdapter();
    const plugin = dataIsolation({
      scopes: [{
        name: 'site',
        field: 'siteId',
        models: ['sale'],
        resolveValue: async () => null,
      }],
    });

    const ctx: PluginContext = { db, config: { jwt: { secret: 'x'.repeat(32) }, database: db } };
    const rules = await plugin.scopeRules!(1, 'sale', ctx);

    expect(rules).toBeNull();
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

      const ctx: PluginContext = { db, config: { jwt: { secret: 'x'.repeat(32) }, database: db } };
      const methods = plugin.methods!(ctx) as { withoutScope: <T>(name: string, fn: () => Promise<T>) => Promise<T> };

      const rules = await methods.withoutScope('site', async () => {
        return plugin.scopeRules!(1, 'sale', ctx);
      });

      expect(rules!.filters).toHaveLength(1);
      expect(rules!.filters[0].field).toBe('orgId');
    });

    it('unscoped bypasses all scopes', async () => {
      const db = createTestAdapter();
      const plugin = dataIsolation({
        scopes: [
          { name: 'org', field: 'orgId', models: ['sale'], resolveValue: async () => 7 },
          { name: 'site', field: 'siteId', models: ['sale'], resolveValue: async () => 3 },
        ],
      });

      const ctx: PluginContext = { db, config: { jwt: { secret: 'x'.repeat(32) }, database: db } };
      const methods = plugin.methods!(ctx) as { unscoped: <T>(fn: () => Promise<T>) => Promise<T> };

      const rules = await methods.unscoped(async () => {
        return plugin.scopeRules!(1, 'sale', ctx);
      });

      expect(rules).toBeNull();
    });
  });
});
