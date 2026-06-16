/**
 * Binds fortress's auth lifecycle hooks to the webhook `emit` path, one hook
 * per declared built-in `source`. Built-in events fire-and-forget — login and
 * registration are never blocked on webhook persistence/delivery; user code
 * uses the awaitable `emit()` method for at-least-once semantics.
 *
 * @module
 */

import type { DatabaseAdapter } from '../../adapters/database';
import type { PluginHooks } from '../../core/plugin';
import type { EventRegistry } from './registry';

/** Persist + enqueue an event for delivery. */
export type EmitFn = (db: DatabaseAdapter, eventName: string, payload: Record<string, unknown>) => Promise<void>;

/**
 * Wire the built-in auth hooks to `emit`. Only sources present in the registry
 * are bound — excluding a built-in via `builtinEvents({ exclude })` leaves its
 * hook unbound (a no-op for that event).
 */
export function bindBuiltinHooks(registry: EventRegistry, emit: EmitFn): PluginHooks {
  const sources = registry.sources();
  const hooks: PluginHooks = {};

  const loginName = sources.get('afterLogin');
  if (loginName) {
    hooks.afterLogin = async (ctx, result) => {
      void emit(ctx.db, loginName, {
        event: loginName,
        userId: result.user.id,
        email: result.user.email,
        timestamp: new Date().toISOString(),
        ip: ctx.meta?.ipAddress ?? null,
      }).catch(() => {});
      return result;
    };
  }

  const failureName = sources.get('onLoginFailure');
  if (failureName) {
    hooks.onLoginFailure = async (ctx) => {
      void emit(ctx.db, failureName, {
        event: failureName,
        identifier: ctx.identifier,
        error: ctx.error.message,
        timestamp: new Date().toISOString(),
      }).catch(() => {});
    };
  }

  const logoutName = sources.get('beforeLogout');
  if (logoutName) {
    hooks.beforeLogout = async (ctx) => {
      void emit(ctx.db, logoutName, {
        event: logoutName,
        timestamp: new Date().toISOString(),
        ip: ctx.meta?.ipAddress ?? null,
      }).catch(() => {});
    };
  }

  const registerName = sources.get('afterRegister');
  if (registerName) {
    hooks.afterRegister = async (ctx, user) => {
      void emit(ctx.db, registerName, {
        event: registerName,
        userId: user.id,
        email: user.email,
        timestamp: new Date().toISOString(),
        ip: ctx.meta?.ipAddress ?? null,
      }).catch(() => {});
    };
  }

  const refreshName = sources.get('afterTokenRefresh');
  if (refreshName) {
    hooks.afterTokenRefresh = async (ctx, result) => {
      void emit(ctx.db, refreshName, {
        event: refreshName,
        timestamp: new Date().toISOString(),
        ip: ctx.meta?.ipAddress ?? null,
      }).catch(() => {});
      return result;
    };
  }

  return hooks;
}
