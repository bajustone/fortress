/**
 * OpenTelemetry adapter for Fortress.
 *
 * This is the **only file in the repository that imports `@opentelemetry/api`**.
 * Core Fortress code depends on the internal {@link TelemetryProvider}
 * interface in `src/core/observability/types.ts`; this sub-path exists so
 * runtimes that never opt in (Cloudflare Workers, Deno without OTel, etc.)
 * never resolve `@opentelemetry/api` at all.
 *
 * The import is dynamic (`await import(...)`) as a belt-and-suspenders
 * guarantee: even if a bundler or package resolver attempts to evaluate
 * this module, `@opentelemetry/api` is not referenced until
 * {@link createOtelTelemetry} is actually called.
 *
 * Usage:
 * ```ts
 * import { createFortress } from '@bajustone/fortress';
 * import { createOtelTelemetry } from '@bajustone/fortress/otel';
 * import pino from 'pino';
 *
 * const observability = await createOtelTelemetry({ name: 'my-app-auth' });
 * const fortress = createFortress({
 *   // ...config
 *   logger: pino(),
 *   observability,
 * });
 * ```
 *
 * The returned provider satisfies Fortress's internal
 * {@link TelemetryProvider} interface and can be wired into any
 * `FortressConfig.observability` slot. Because Fortress's metric catalog
 * uses the stable OTel semantic convention for database operations
 * (`db.client.operation.duration`), Grafana/Prometheus dashboards that
 * know about that name will automatically pick up Fortress's DB queries.
 */

import type { TelemetryProvider } from '../core/observability/types';

export interface OtelTelemetryOptions {
  /** Instrumentation scope name. Defaults to `'fortress'`. */
  name?: string;
  /** Instrumentation scope version. Defaults to `'0.0.x'`. */
  version?: string;
}

/**
 * Create a Fortress {@link TelemetryProvider} backed by OpenTelemetry's
 * global tracer and meter providers.
 *
 * If `@opentelemetry/api` is not installed, this function throws with a
 * clear error message pointing at the missing peer dependency. The
 * dynamic import ensures the failure mode is a controlled throw at call
 * time — not a module-load crash.
 *
 * When no OTel SDK is registered globally, the returned provider's spans
 * and metric instruments will resolve to OTel's own no-op implementations
 * and impose no measurable overhead.
 */
export async function createOtelTelemetry(
  options: OtelTelemetryOptions = {},
): Promise<TelemetryProvider> {
  let api: typeof import('@opentelemetry/api');
  try {
    api = await import('@opentelemetry/api');
  }
  catch (cause) {
    throw new Error(
      '@opentelemetry/api is not installed. Add it to your dependencies to use createOtelTelemetry().',
      { cause },
    );
  }

  const name = options.name ?? 'fortress';
  const version = options.version ?? '0.0.x';
  const otelTracer = api.trace.getTracer(name, version);
  const otelMeter = api.metrics.getMeter(name, version);
  const { SpanStatusCode } = api;

  return {
    tracer: {
      startSpan(spanName, attrs): import('../core/observability/types').Span {
        const span = otelTracer.startSpan(spanName, { attributes: attrs });
        return {
          setAttribute: (k, v): void => {
            span.setAttribute(k, v);
          },
          recordException: (err): void => {
            span.recordException(err as Error);
          },
          setStatus: (s): void => {
            span.setStatus({
              code: s.code === 'ok' ? SpanStatusCode.OK : SpanStatusCode.ERROR,
              message: s.message,
            });
          },
          end: (): void => {
            span.end();
          },
        };
      },
    },
    meter: {
      createCounter(metricName, opts): import('../core/observability/types').Counter {
        const c = otelMeter.createCounter(metricName, opts);
        return {
          add: (v, a): void => {
            c.add(v, a);
          },
        };
      },
      createHistogram(metricName, opts): import('../core/observability/types').Histogram {
        const h = otelMeter.createHistogram(metricName, {
          description: opts?.description,
          unit: opts?.unit,
          advice: opts?.boundaries
            ? { explicitBucketBoundaries: opts.boundaries }
            : undefined,
        });
        return {
          record: (v, a): void => {
            h.record(v, a);
          },
        };
      },
    },
  };
}
