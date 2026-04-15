import type { DatabaseAdapter } from '../../adapters/database';
import type { Histogram, TelemetryProvider } from './types';

/**
 * Wrap a {@link DatabaseAdapter} so every operation records its duration
 * into the standard OpenTelemetry semantic-convention histogram
 * `db.client.operation.duration`, with attributes matching the stable
 * database spec:
 * - `db.system.name`  — adapter dialect (`sqlite` / `pg` / `mysql` / `unknown`)
 * - `db.operation.name` — verb (`create` / `findOne` / `findMany` / `update` / `delete` / `count` / `rawQuery`)
 * - `db.collection.name` — model name (only for CRUD ops, not `rawQuery`)
 *
 * When the adapter's `transaction` method is called, the child adapter
 * passed to the callback is recursively wrapped so queries inside a
 * transaction are also instrumented.
 *
 * When the telemetry provider is the no-op default, `createHistogram`
 * returns a no-op histogram, so the wrapper imposes essentially zero
 * overhead beyond the monotonic `performance.now()` pair.
 */
export function instrumentAdapter(
  adapter: DatabaseAdapter,
  telemetry: TelemetryProvider,
): DatabaseAdapter {
  const histogram: Histogram = telemetry.meter.createHistogram(
    'db.client.operation.duration',
    {
      unit: 's',
      description: 'Duration of database client operations',
      boundaries: [0.001, 0.005, 0.01, 0.05, 0.1, 0.5, 1, 5, 10],
    },
  );
  const dbSystem = adapter.dialect ?? 'unknown';

  function record(
    operation: string,
    model: string | undefined,
    start: number,
  ): void {
    const durationSeconds = (performance.now() - start) / 1000;
    const attrs: Record<string, string> = {
      'db.system.name': dbSystem,
      'db.operation.name': operation,
    };
    if (model !== undefined) {
      attrs['db.collection.name'] = model;
    }
    histogram.record(durationSeconds, attrs);
  }

  const wrapped: DatabaseAdapter = {
    dialect: adapter.dialect,
    async create<T>(params: { model: string; data: Record<string, unknown> }): Promise<T> {
      const start = performance.now();
      try {
        return await adapter.create<T>(params);
      }
      finally {
        record('create', params.model, start);
      }
    },
    async findOne<T>(params: Parameters<DatabaseAdapter['findOne']>[0]): Promise<T | null> {
      const start = performance.now();
      try {
        return await adapter.findOne<T>(params);
      }
      finally {
        record('findOne', params.model, start);
      }
    },
    async findMany<T>(params: Parameters<DatabaseAdapter['findMany']>[0]): Promise<T[]> {
      const start = performance.now();
      try {
        return await adapter.findMany<T>(params);
      }
      finally {
        record('findMany', params.model, start);
      }
    },
    async update<T>(params: Parameters<DatabaseAdapter['update']>[0]): Promise<T | null> {
      const start = performance.now();
      try {
        return await adapter.update<T>(params);
      }
      finally {
        record('update', params.model, start);
      }
    },
    async delete(params: Parameters<DatabaseAdapter['delete']>[0]): Promise<void> {
      const start = performance.now();
      try {
        await adapter.delete(params);
      }
      finally {
        record('delete', params.model, start);
      }
    },
    async count(params: Parameters<DatabaseAdapter['count']>[0]): Promise<number> {
      const start = performance.now();
      try {
        return await adapter.count(params);
      }
      finally {
        record('count', params.model, start);
      }
    },
    async transaction<T>(fn: (tx: DatabaseAdapter) => Promise<T>): Promise<T> {
      const start = performance.now();
      try {
        return await adapter.transaction(tx => fn(instrumentAdapter(tx, telemetry)));
      }
      finally {
        record('transaction', undefined, start);
      }
    },
  };

  if (adapter.rawQuery) {
    wrapped.rawQuery = async <T>(sql: string, params?: unknown[]): Promise<T[]> => {
      const start = performance.now();
      try {
        return await adapter.rawQuery!<T>(sql, params);
      }
      finally {
        record('rawQuery', undefined, start);
      }
    };
  }

  return wrapped;
}
