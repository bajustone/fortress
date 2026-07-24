/**
 * Row-level data isolation plugin for fortress.
 *
 * Lets you scope read/write access to a database row by per-user assignments,
 * for example "user can only see rows where `org_id` equals their assigned
 * org". Works with any database adapter via the core `scopeRules` capability.
 *
 * @module
 */

import type { ScopeRule } from '../../adapters/database/types';
import type { FortressPlugin, PluginContext } from '../../core/plugin';
import { AsyncLocalStorage } from 'node:async_hooks';
import { Errors } from '../../core/errors';
import { definePlugin } from '../../core/plugin';

export interface DataIsolationScope {
  /** Scope name for identification and bypass control */
  name: string;
  /** Column name that holds the scoping value in the target tables */
  field: string;
  /** Which models (tables) this scope applies to. Use ['*'] for all models. */
  models: string[];
  /** Resolve the current user's value for this scope */
  resolveValue: (userId: string, ctx: PluginContext) => Promise<unknown>;
}

export interface DataIsolationConfig {
  scopes: DataIsolationScope[];
  /**
   * Behavior when an applicable scope resolves to `null` or `undefined`.
   * Defaults to `'deny'`. `'skip'` is an unsafe legacy compatibility mode
   * that removes that scope's row isolation for the operation.
   */
  unresolvedScope?: 'deny' | 'skip';
}

/**
 * Per-request bypass state. Stored in `AsyncLocalStorage` so concurrent
 * requests don't trample each other's `unscoped()` / `withoutScope()`
 * windows. The pre-fix implementation used module-level globals — one
 * request's `unscoped()` await would silently disable isolation for every
 * other in-flight request handling the same async tick (H4).
 *
 * Runtime support: `AsyncLocalStorage` is Node core and is implemented by
 * Bun, Deno, Cloudflare Workers (with the `nodejs_compat` flag and a
 * compatibility date of 2024-09-23 or later), and Vercel Edge. This plugin
 * uses only the universally-supported subset — `run()` and `getStore()`,
 * never `enterWith()`/`disable()` — and wraps native async callbacks, so the
 * workerd "thenable context-loss" caveat does not apply. The only hot-path
 * call is the cheap `getStore()` read in `scopeRules`. This is also the
 * direction of the TC39 AsyncContext proposal (Stage 2), so the approach is
 * standards-track rather than a Node-specific hack.
 *
 * The dependency is scoped to this module — importing the main
 * `@bajustone/fortress` entry only pulls in plugin *types*, not
 * `node:async_hooks`, so it loads only when this plugin is actually used.
 * On a runtime that genuinely lacks `node:async_hooks`, importing the
 * plugin throws at import time.
 */
interface BypassState {
  all: boolean;
  scopes: Set<string>;
}

const bypassStore = new AsyncLocalStorage<BypassState>();

function currentBypassState(): BypassState | undefined {
  return bypassStore.getStore();
}

export interface DataIsolationMethods {
  withoutScope: <T>(scopeName: string, fn: () => Promise<T>) => Promise<T>;
  unscoped: <T>(fn: () => Promise<T>) => Promise<T>;
}
/**
 * Data isolation plugin factory. Returns a {@link FortressPlugin} that scopes
 * read and write access to a database row by per-user scope assignments,
 * enforcing isolation through the core `scopeRules` capability.
 */
// eslint-disable-next-line ts/explicit-function-return-type -- definePlugin preserves the exact public contract
export function dataIsolation(config: DataIsolationConfig) {
  return definePlugin({
    name: 'data-isolation',

    models: [{
      name: 'user_scope_assignment',
      fields: {
        id: { type: 'number', required: true },
        userId: { type: 'number', required: true, references: { model: 'user', field: 'id' } },
        scopeName: { type: 'string', required: true },
        scopeValue: { type: 'string', required: true },
        createdAt: { type: 'date', required: true },
      },
    }],

    async scopeRules(userId: string, model: string, ctx: PluginContext): Promise<ScopeRule | null> {
      const state = currentBypassState();
      if (state?.all)
        return null;

      const filters: ScopeRule['filters'] = [];
      const defaults: ScopeRule['defaults'] = {};

      for (const scope of config.scopes) {
        if (state?.scopes.has(scope.name))
          continue;

        // Check if this scope applies to the queried model
        const applies = scope.models.includes('*') || scope.models.includes(model);
        if (!applies)
          continue;

        const value = await scope.resolveValue(userId, ctx);
        if (value === undefined || value === null) {
          if (config.unresolvedScope === 'skip')
            continue;
          throw Errors.forbidden(`Data isolation scope '${scope.name}' could not be resolved`);
        }

        filters.push({ field: scope.field, operator: '=', value });
        defaults[scope.field] = value;
      }

      return filters.length > 0 ? { filters, defaults } : null;
    },

    methods: () => ({
      /**
       * Execute a callback with a specific scope bypassed.
       * Queries within the callback will not have the named scope filter applied.
       *
       * The bypass is async-context-local: it applies only to async work
       * spawned inside `fn` and never leaks across concurrent requests.
       */
      async withoutScope<T>(scopeName: string, fn: () => Promise<T>): Promise<T> {
        const existing = currentBypassState();
        const nextScopes = new Set(existing?.scopes ?? []);
        nextScopes.add(scopeName);
        const next: BypassState = { all: existing?.all ?? false, scopes: nextScopes };
        return bypassStore.run(next, fn);
      },

      /**
       * Execute a callback with all scopes bypassed.
       * Use with caution \u2014 no row-level isolation is applied.
       *
       * The bypass is async-context-local. Calls outside the callback (and
       * concurrent requests running on different async contexts) are
       * unaffected.
       */
      async unscoped<T>(fn: () => Promise<T>): Promise<T> {
        const existing = currentBypassState();
        const next: BypassState = { all: true, scopes: new Set(existing?.scopes ?? []) };
        return bypassStore.run(next, fn);
      },
    }),
  } satisfies FortressPlugin<'data-isolation', DataIsolationMethods>);
}
