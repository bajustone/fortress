import type { FortressLogger } from './logger';

export type Unsubscribe = () => void;

export interface ListenerList<E> {
  emit: (event: E) => void;
  add: (listener: (event: E) => void | Promise<void>) => Unsubscribe;
  size: () => number;
}

/**
 * Create a typed listener list with error routing and a sync/async contract.
 *
 * - `sync` kind: listeners return `void`. Used for hot-path observers
 *   (permission checks) where the type signature discourages awaiting
 *   expensive work inline.
 * - `async` kind: listeners may return `void | Promise<void>`. Promises
 *   returned by listeners are attached a `.catch` that routes failures to
 *   the logger at `error` level — observer bugs never break the caller.
 *
 *   **Error-routing gotcha (async kind):** the safety net only engages
 *   when the listener *returns* the promise. A listener that fires work
 *   via `void asyncWork()` inside a sync body returns `undefined`, so the
 *   listener list cannot observe a later rejection — it escapes to the
 *   runtime's unhandled-rejection handler. If you want the safety net,
 *   `return asyncWork()` or make the whole body `async`. `void asyncWork()`
 *   is an explicit opt-out.
 *
 * The `logger` parameter is a thunk so the list can resolve the current
 * logger lazily — allowing callers to construct the list before the final
 * logger is available in the closure.
 */
export function createListenerList<E>(opts: {
  kind: 'sync' | 'async';
  eventLabel: string;
  logger: () => FortressLogger;
}): ListenerList<E> {
  const listeners: Array<(event: E) => void | Promise<void>> = [];

  return {
    emit(event: E): void {
      for (const listener of listeners) {
        try {
          const result = listener(event);
          if (opts.kind === 'async' && result instanceof Promise) {
            result.catch((err: unknown) => {
              opts.logger().error(
                { err, event: opts.eventLabel },
                'fortress observer threw',
              );
            });
          }
        }
        catch (err) {
          opts.logger().error(
            { err, event: opts.eventLabel },
            'fortress observer threw',
          );
        }
      }
    },
    add(listener): Unsubscribe {
      listeners.push(listener);
      return () => {
        const i = listeners.indexOf(listener);
        if (i >= 0) {
          listeners.splice(i, 1);
        }
      };
    },
    size: () => listeners.length,
  };
}
