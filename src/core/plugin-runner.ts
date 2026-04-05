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
  auth?: Record<string, Function>,
): Record<string, Record<string, Function>> {
  const ctx: PluginContext = { db, config, auth };
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
      if (process.env.NODE_ENV !== 'production') {
        for (const key of Object.keys(claims)) {
          if (key in merged) {
            console.warn(
              `[fortress] Plugin '${plugin.name}' overwrites token claim '${key}' set by a previous plugin`,
            );
          }
        }
      }
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
    if (!plugin.scopeRules) {
      continue;
    }
    const rule = await plugin.scopeRules(userId, model, ctx);
    if (!rule) {
      continue;
    }
    allFilters.push(...rule.filters);
    Object.assign(allDefaults, rule.defaults);
  }

  if (allFilters.length === 0 && Object.keys(allDefaults).length === 0) {
    return null;
  }

  return { filters: allFilters, defaults: allDefaults };
}

/**
 * Wrap a DatabaseAdapter to auto-apply scope rules on every operation.
 * Reads (findOne, findMany, count) get extra WHERE clauses.
 * Writes (create) get default values merged into data.
 * Mutations (update, delete) get extra WHERE clauses to prevent cross-scope changes.
 */
export function wrapAdapterWithScopeRules(
  adapter: DatabaseAdapter,
  scopeRule: ScopeRule,
): DatabaseAdapter {
  const { filters, defaults } = scopeRule;

  return {
    ...adapter,

    create: <T>(params: {
      model: string;
      data: Record<string, unknown>;
    }): Promise<T> =>
      adapter.create<T>({
        ...params,
        data: { ...defaults, ...params.data },
      }),

    findOne: <T>(params: {
      model: string;
      where: WhereClause[];
    }): Promise<T | null> =>
      adapter.findOne<T>({
        ...params,
        where: [...params.where, ...filters],
      }),

    findMany: <T>(params: {
      model: string;
      where?: WhereClause[];
      limit?: number;
      offset?: number;
      sortBy?: { field: string; direction: 'asc' | 'desc' };
    }): Promise<T[]> =>
      adapter.findMany<T>({
        ...params,
        where: [...(params.where ?? []), ...filters],
      }),

    update: <T>(params: {
      model: string;
      where: WhereClause[];
      data: Record<string, unknown>;
    }): Promise<T | null> =>
      adapter.update<T>({
        ...params,
        where: [...params.where, ...filters],
      }),

    delete: (params: { model: string; where: WhereClause[] }): Promise<void> =>
      adapter.delete({
        ...params,
        where: [...params.where, ...filters],
      }),

    count: (params: {
      model: string;
      where?: WhereClause[];
    }): Promise<number> =>
      adapter.count({
        ...params,
        where: [...(params.where ?? []), ...filters],
      }),

    transaction: <T>(fn: (tx: DatabaseAdapter) => Promise<T>): Promise<T> =>
      adapter.transaction(tx => fn(wrapAdapterWithScopeRules(tx, scopeRule))),
  };
}

/**
 * Get all model definitions declared by plugins.
 */
export function collectPluginModels(
  plugins: FortressPlugin[],
): { pluginName: string; models: FortressPlugin['models'] }[] {
  return plugins
    .filter(p => p.models && p.models.length > 0)
    .map(p => ({ pluginName: p.name, models: p.models }));
}
