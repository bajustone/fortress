/**
 * Fortress-internal telemetry interfaces.
 *
 * Core code depends on these shapes, never on `@opentelemetry/api`. The OTel
 * adapter in `src/otel/index.ts` is the only file in the repo that imports
 * `@opentelemetry/api`; it returns a {@link TelemetryProvider} that satisfies
 * these interfaces. This keeps `@opentelemetry/api` off the core critical
 * path — runtimes like Cloudflare Workers and Deno never resolve it unless
 * the user explicitly imports `@bajustone/fortress/otel`.
 */

export type AttributeValue = string | number | boolean;
export type Attributes = Record<string, AttributeValue>;

export interface Span {
  setAttribute: (key: string, value: AttributeValue) => void;
  recordException: (error: unknown) => void;
  setStatus: (status: { code: 'ok' | 'error'; message?: string }) => void;
  end: () => void;
}

export interface Tracer {
  startSpan: (name: string, attributes?: Attributes) => Span;
}

export interface Counter {
  add: (value: number, attributes?: Attributes) => void;
}

export interface Histogram {
  record: (value: number, attributes?: Attributes) => void;
}

export interface Meter {
  createCounter: (
    name: string,
    options?: { description?: string; unit?: string },
  ) => Counter;
  createHistogram: (
    name: string,
    options?: { description?: string; unit?: string; boundaries?: number[] },
  ) => Histogram;
}

export interface TelemetryProvider {
  tracer: Tracer;
  meter: Meter;
}

const NO_OP_SPAN: Span = {
  setAttribute: () => {},
  recordException: () => {},
  setStatus: () => {},
  end: () => {},
};

const NO_OP_COUNTER: Counter = { add: () => {} };
const NO_OP_HISTOGRAM: Histogram = { record: () => {} };

/**
 * Default telemetry provider used when {@link FortressConfig.observability}
 * is not set. Zero allocation per call — the instrument factories return
 * shared no-op singletons and {@link Tracer.startSpan} returns a shared span.
 */
export const NO_OP_TELEMETRY: TelemetryProvider = {
  tracer: { startSpan: () => NO_OP_SPAN },
  meter: {
    createCounter: () => NO_OP_COUNTER,
    createHistogram: () => NO_OP_HISTOGRAM,
  },
};
