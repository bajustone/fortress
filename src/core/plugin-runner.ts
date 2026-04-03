/* eslint-disable ts/no-unsafe-function-type -- plugin methods are dynamically typed */
import type { DatabaseAdapter } from '../adapters/database';
import type { ScopeRule, WhereClause } from '../adapters/database/types';
import type { FortressConfig } from './config';
import type { FortressPlugin, PluginContext } from './plugin';

/**
 * Process registered plugins and return their exposed methods.
 */

export function processPlugins(
  plugins: FortressPlugin[],
  db: DatabaseAdapter,
  config: FortressConfig,
): Record<string, Record<string, Function>> {
  const ctx: PluginContext = { db, config };
  const result: Record<string, Record<string, Function>> = {};

  for (const plugin of plugins) {
    result[plugin.name] = plugin.methods?.(ctx) ?? {};
  }

  return result;
}

/**
 * Chain wrapAdapter from all plugins in registration order.
 * Each wrapper receives the result of the previous.
 */
export function chainAdapterWrappers(
  plugins: FortressPlugin[],
  baseAdapter: DatabaseAdapter,
  requestContext: Record<string, unknown>,
): DatabaseAdapter {
  let adapter = baseAdapter;

  for (const plugin of plugins) {
    if (plugin.wrapAdapter) {
      adapter = plugin.wrapAdapter(adapter, requestContext);
    }
  }

  return adapter;
}

/**
 * Collect and merge enrichTokenClaims from all plugins.
 * Later plugins override earlier ones on key conflicts.
 */
export async function mergeTokenClaims(
  plugins: FortressPlugin[],
  userId: number,
  ctx: PluginContext,
): Promise<Record<string, unknown>> {
  const merged: Record<string, unknown> = {};

  for (const plugin of plugins) {
    if (plugin.enrichTokenClaims) {
      const claims = await plugin.enrichTokenClaims(userId, ctx);
      Object.assign(merged, claims);
    }
  }

  return merged;
}

/**
 * Collect and stack scopeRules from all plugins for a given model.
 * All filters are AND'd together. All defaults are merged.
 */
export async function collectScopeRules(
  plugins: FortressPlugin[],
  userId: number,
  model: string,
  ctx: PluginContext,
): Promise<ScopeRule | null> {
  const allFilters: WhereClause[] = [];
  const allDefaults: Record<string, unknown> = {};

  for (const plugin of plugins) {
    if (plugin.scopeRules) {
      const rule = await plugin.scopeRules(userId, model, ctx);
      if (rule) {
        allFilters.push(...rule.filters);
        Object.assign(allDefaults, rule.defaults);
      }
    }
  }

  if (allFilters.length === 0 && Object.keys(allDefaults).length === 0) {
    return null;
  }

  return { filters: allFilters, defaults: allDefaults };
}

/**
 * Get all model definitions declared by plugins.
 */
export function collectPluginModels(plugins: FortressPlugin[]): { pluginName: string; models: FortressPlugin['models'] }[] {
  return plugins
    .filter(p => p.models && p.models.length > 0)
    .map(p => ({ pluginName: p.name, models: p.models }));
}
