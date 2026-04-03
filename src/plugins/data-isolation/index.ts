import type { ScopeRule } from '../../adapters/database/types';
import type { FortressPlugin, PluginContext } from '../../core/plugin';

export interface DataIsolationScope {
  /** Scope name for identification and bypass control */
  name: string;
  /** Column name that holds the scoping value in the target tables */
  field: string;
  /** Which models (tables) this scope applies to. Use ['*'] for all models. */
  models: string[];
  /** Resolve the current user's value for this scope */
  resolveValue: (userId: number, ctx: PluginContext) => Promise<unknown>;
}

export interface DataIsolationConfig {
  scopes: DataIsolationScope[];
}

// Track bypassed scopes via a module-level set (per-request bypass context)
const bypassedScopes = new Set<string>();
let bypassAll = false;

export function dataIsolation(config: DataIsolationConfig): FortressPlugin {
  return {
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

    async scopeRules(userId: number, model: string, ctx: PluginContext): Promise<ScopeRule | null> {
      if (bypassAll)
        return null;

      const filters: ScopeRule['filters'] = [];
      const defaults: ScopeRule['defaults'] = {};

      for (const scope of config.scopes) {
        if (bypassedScopes.has(scope.name))
          continue;

        // Check if this scope applies to the queried model
        const applies = scope.models.includes('*') || scope.models.includes(model);
        if (!applies)
          continue;

        const value = await scope.resolveValue(userId, ctx);
        if (value === undefined || value === null)
          continue;

        filters.push({ field: scope.field, operator: '=', value });
        defaults[scope.field] = value;
      }

      return filters.length > 0 ? { filters, defaults } : null;
    },

    methods: () => ({
      /**
       * Execute a callback with a specific scope bypassed.
       * Queries within the callback will not have the named scope filter applied.
       */
      async withoutScope<T>(scopeName: string, fn: () => Promise<T>): Promise<T> {
        bypassedScopes.add(scopeName);
        try {
          return await fn();
        }
        finally {
          bypassedScopes.delete(scopeName);
        }
      },

      /**
       * Execute a callback with all scopes bypassed.
       * Use with caution — no row-level isolation is applied.
       */
      async unscoped<T>(fn: () => Promise<T>): Promise<T> {
        bypassAll = true;
        try {
          return await fn();
        }
        finally {
          bypassAll = false;
        }
      },
    }),
  };
}
