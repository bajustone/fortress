import type { DatabaseAdapter } from '../adapters/database';
import type { ScopeRule, WhereClause } from '../adapters/database/types';
import type { AuthService } from './auth/auth-service';
import type { FortressConfig } from './config';
import type { PluginRequestContext } from './http/plugin-middleware';
import type { IamService } from './iam/iam-service';
import type { FortressLogger } from './observability/logger';
import type { FortressPlugin, MiddlewareDefinition, PluginContext, PluginMethod, RuntimeFortressPlugin } from './plugin';
import { Errors } from './errors';
import { canonicalizePath } from './http/match';
import { createPluginCapabilityController, materializePluginCapabilities } from './plugin-capabilities';
import { publishPluginMembership } from './plugin-membership';

/**
 * Process registered plugins and return their exposed methods.
 */

export function processPlugins(
  plugins: readonly RuntimeFortressPlugin[],
  db: DatabaseAdapter,
  config: FortressConfig,
  auth?: AuthService,
  iam?: IamService,
  logger?: FortressLogger,
  publishedPlugins?: readonly RuntimeFortressPlugin[],
): Record<string, Record<string, PluginMethod>> {
  const standaloneController = publishedPlugins === undefined
    ? createPluginCapabilityController(plugins)
    : undefined;
  const capabilityView = publishedPlugins ?? standaloneController!.plugins;
  const result: Record<string, Record<string, PluginMethod>> = Object.create(null) as Record<string, Record<string, PluginMethod>>;
  let initializingPlugin: string | undefined;
  const ctx: PluginContext = {
    db,
    config,
    auth,
    iam,
    logger,
    getPluginMethods: (name) => {
      if (initializingPlugin) {
        throw Errors.badRequest(
          `Plugin "${initializingPlugin}" cannot resolve plugin "${name}" while plugin methods are initializing; defer lookup until a returned method is called`,
          { details: { plugin: initializingPlugin, requestedPlugin: name } },
        );
      }
      return result[name];
    },
  };
  // The context is construction-owned, unlike `config`. Binding membership to
  // it before the first factory prevents a re-entrant createFortress(config)
  // call from changing what later factories in this construction observe.
  publishPluginMembership(ctx, capabilityView);

  try {
    for (const plugin of plugins) {
      initializingPlugin = plugin.name;
      const methods = plugin.methods ? plugin.methods(ctx) : Object.create(null) as object;
      if (methods === null || typeof methods !== 'object')
        throw Errors.badRequest(`Plugin "${plugin.name}" methods factory must return an object`);
      for (const key of Reflect.ownKeys(methods)) {
        if (typeof Reflect.get(methods, key) !== 'function') {
          throw Errors.badRequest(
            `Plugin "${plugin.name}" method "${String(key)}" must be callable`,
          );
        }
      }
      // Keep each surface's own properties and `this` identity intact. Dispatch
      // performs own-property checks, so inherited names can never become route
      // handlers accidentally.
      result[plugin.name] = methods as Record<string, PluginMethod>;
    }
    initializingPlugin = undefined;
    if (standaloneController)
      standaloneController.finalize(materializePluginCapabilities(plugins));
    return result;
  }
  catch (error) {
    standaloneController?.fail();
    throw error;
  }
}

/**
 * Chain wrapAdapter from all plugins in registration order.
 * Each wrapper receives the result of the previous.
 */
export function chainAdapterWrappers(
  plugins: readonly RuntimeFortressPlugin[],
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
  plugins: readonly RuntimeFortressPlugin[],
  userId: string,
  ctx: PluginContext,
): Promise<Record<string, unknown>> {
  const merged: Record<string, unknown> = {};

  for (const plugin of plugins) {
    if (plugin.enrichTokenClaims) {
      const claims = await plugin.enrichTokenClaims(userId, ctx);
      if (process.env.NODE_ENV !== 'production') {
        for (const key of Object.keys(claims)) {
          if (key in merged) {
            ctx.logger?.warn(
              { plugin: plugin.name, claim: key },
              `plugin overwrites token claim '${key}'`,
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
  plugins: readonly RuntimeFortressPlugin[],
  userId: string,
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
        data: { ...params.data, ...defaults },
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
    }): Promise<T | null> => Promise.resolve().then(() => {
      for (const key of Object.keys(defaults)) {
        if (Object.hasOwn(params.data, key))
          throw Errors.forbidden(`Cannot update scoped field '${key}'`);
      }
      return adapter.update<T>({
        ...params,
        where: [...params.where, ...filters],
      });
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
  plugins: readonly RuntimeFortressPlugin[],
): { pluginName: string; models: FortressPlugin['models'] }[] {
  return plugins
    .filter(p => p.models && p.models.length > 0)
    .map(p => ({ pluginName: p.name, models: p.models }));
}

/**
 * Convert a middleware path pattern to a regex.
 * Supports `:param` (single segment) and `*` (wildcard).
 */
function middlewarePathToRegex(pattern: string): RegExp {
  const regexStr = canonicalizePath(pattern)
    .replace(/[.*+?^${}()|[\]\\]/g, '\\$&')
    .replace(/:[^/]+/g, '[^/]+')
    .replace(/\\\*/g, '.*')
    .replace(/\//g, '\\/');
  return new RegExp(`^${regexStr}$`);
}

/**
 * Collect all middleware definitions from plugins matching a given position.
 * Returns them in plugin registration order.
 */
export function collectPluginMiddleware(
  plugins: readonly RuntimeFortressPlugin[],
  position: MiddlewareDefinition['position'],
): { plugin: RuntimeFortressPlugin; middleware: MiddlewareDefinition }[] {
  const result: { plugin: RuntimeFortressPlugin; middleware: MiddlewareDefinition }[] = [];
  for (const plugin of plugins) {
    if (!plugin.middleware)
      continue;
    for (const mw of plugin.middleware) {
      if (mw.position === position) {
        result.push({ plugin, middleware: mw });
      }
    }
  }
  return result;
}

/**
 * Execute plugin middleware for a given position and request path.
 *
 * Iterates through all plugins in registration order, filters by position,
 * matches the middleware path pattern against the request path, and chains
 * handlers so each `next()` invokes the next matching middleware.
 */
export async function executePluginMiddleware(
  plugins: readonly RuntimeFortressPlugin[],
  position: MiddlewareDefinition['position'],
  requestPath: string,
  ctx: PluginContext,
  request: PluginRequestContext,
): Promise<void> {
  const canonicalRequestPath = canonicalizePath(requestPath);
  const requestMethod = request.request.method.toUpperCase();
  const matching = collectPluginMiddleware(plugins, position)
    .filter(({ middleware: mw }) =>
      middlewarePathToRegex(mw.path).test(canonicalRequestPath)
      && (mw.methods === undefined || mw.methods.some(method => method.toUpperCase() === requestMethod)),
    );

  if (matching.length === 0)
    return;

  // Build a chain where each handler's `next` calls the next middleware
  let index = 0;

  async function runNext(): Promise<void> {
    if (index >= matching.length)
      return;
    const current = matching[index++];
    if (current === undefined)
      throw new Error('Plugin middleware chain invariant violated: missing current handler');
    await current.middleware.handler(ctx, request, runNext);
  }

  await runNext();
}
