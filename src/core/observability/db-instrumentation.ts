import type { DatabaseAdapter } from '../../adapters/database';
import type { Histogram, Span, TelemetryProvider } from './types';

/**
 * Wrap a {@link DatabaseAdapter} so every operation records its duration
 * into the standard OpenTelemetry semantic-convention histogram
 * `db.client.operation.duration`, **and** emits a matching span for the
 * operation. Attributes follow the stable database spec:
 * - `db.system.name`  — adapter dialect (`sqlite` / `pg` / `unknown`)
 * - `db.operation.name` — verb (`create` / `findOne` / `findMany` / `update` / `delete` / `count` / `rawQuery` / `transaction`)
 * - `db.collection.name` — model name (only when known)
 *
 * Span names follow the OTel DB convention `{operation} {collection}` when
 * the model is known (e.g. `findOne user`), or just `{operation}` for
 * `rawQuery` / `transaction` where there's no single collection.
 *
 * When the adapter's `transaction` method is called, the child adapter
 * passed to the callback is recursively wrapped so queries inside a
 * transaction are also instrumented.
 *
 * When the telemetry provider is the no-op default, both
 * `createHistogram` and `startSpan` return shared no-op singletons, so
 * the wrapper imposes essentially zero overhead beyond the monotonic
 * `performance.now()` pair.
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
  const tracer = telemetry.tracer;
  const dbSystem = adapter.dialect ?? 'unknown';

  function spanAttrs(
    operation: string,
    model: string | undefined,
  ): Record<string, string> {
    const attrs: Record<string, string> = {
      'db.system.name': dbSystem,
      'db.operation.name': operation,
    };
    if (model !== undefined) {
      attrs['db.collection.name'] = model;
    }
    return attrs;
  }

  function startDbSpan(operation: string, model: string | undefined): Span {
    const name = model !== undefined ? `${operation} ${model}` : operation;
    return tracer.startSpan(name, spanAttrs(operation, model));
  }

  function record(
    operation: string,
    model: string | undefined,
    start: number,
  ): void {
    const durationSeconds = (performance.now() - start) / 1000;
    histogram.record(durationSeconds, spanAttrs(operation, model));
  }

  function finishErr(span: Span, err: unknown): void {
    span.recordException(err);
    span.setStatus({
      code: 'error',
      message: err instanceof Error ? err.message : String(err),
    });
  }

  const wrapped: DatabaseAdapter = {
    dialect: adapter.dialect,
    async create<T>(params: { model: string; data: Record<string, unknown> }): Promise<T> {
      const start = performance.now();
      const span = startDbSpan('create', params.model);
      try {
        return await adapter.create<T>(params);
      }
      catch (err) {
        finishErr(span, err);
        throw err;
      }
      finally {
        record('create', params.model, start);
        span.end();
      }
    },
    async findOne<T>(params: Parameters<DatabaseAdapter['findOne']>[0]): Promise<T | null> {
      const start = performance.now();
      const span = startDbSpan('findOne', params.model);
      try {
        return await adapter.findOne<T>(params);
      }
      catch (err) {
        finishErr(span, err);
        throw err;
      }
      finally {
        record('findOne', params.model, start);
        span.end();
      }
    },
    async findMany<T>(params: Parameters<DatabaseAdapter['findMany']>[0]): Promise<T[]> {
      const start = performance.now();
      const span = startDbSpan('findMany', params.model);
      try {
        return await adapter.findMany<T>(params);
      }
      catch (err) {
        finishErr(span, err);
        throw err;
      }
      finally {
        record('findMany', params.model, start);
        span.end();
      }
    },
    async update<T>(params: Parameters<DatabaseAdapter['update']>[0]): Promise<T | null> {
      const start = performance.now();
      const span = startDbSpan('update', params.model);
      try {
        return await adapter.update<T>(params);
      }
      catch (err) {
        finishErr(span, err);
        throw err;
      }
      finally {
        record('update', params.model, start);
        span.end();
      }
    },
    async delete(params: Parameters<DatabaseAdapter['delete']>[0]): Promise<void> {
      const start = performance.now();
      const span = startDbSpan('delete', params.model);
      try {
        await adapter.delete(params);
      }
      catch (err) {
        finishErr(span, err);
        throw err;
      }
      finally {
        record('delete', params.model, start);
        span.end();
      }
    },
    async count(params: Parameters<DatabaseAdapter['count']>[0]): Promise<number> {
      const start = performance.now();
      const span = startDbSpan('count', params.model);
      try {
        return await adapter.count(params);
      }
      catch (err) {
        finishErr(span, err);
        throw err;
      }
      finally {
        record('count', params.model, start);
        span.end();
      }
    },
    async transaction<T>(fn: (tx: DatabaseAdapter) => Promise<T>): Promise<T> {
      const start = performance.now();
      const span = startDbSpan('transaction', undefined);
      try {
        return await adapter.transaction(tx => fn(instrumentAdapter(tx, telemetry)));
      }
      catch (err) {
        finishErr(span, err);
        throw err;
      }
      finally {
        record('transaction', undefined, start);
        span.end();
      }
    },
  };

  if (adapter.rawQuery) {
    wrapped.rawQuery = async <T>(sql: string, params?: unknown[]): Promise<T[]> => {
      const start = performance.now();
      const span = startDbSpan('rawQuery', undefined);
      try {
        return await adapter.rawQuery!<T>(sql, params);
      }
      catch (err) {
        finishErr(span, err);
        throw err;
      }
      finally {
        record('rawQuery', undefined, start);
        span.end();
      }
    };
  }

  return wrapped;
}
