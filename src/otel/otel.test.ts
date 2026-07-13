import type { MetricData, ResourceMetrics } from '@opentelemetry/sdk-metrics';
import type { Fortress } from '../core/fortress';
import { metrics } from '@opentelemetry/api';
import {
  AggregationTemporality,
  InMemoryMetricExporter,
  MeterProvider,
  PeriodicExportingMetricReader,
} from '@opentelemetry/sdk-metrics';
import { afterEach, beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from '../core/fortress';
import { createTestAdapter } from '../testing';
import { createOtelTelemetry } from './index';

const SECRET = 'otel-integration-test-secret-32!!';

let fortress: Fortress;
let exporter: InMemoryMetricExporter;
let reader: PeriodicExportingMetricReader;
let provider: MeterProvider;

async function collectMetrics(): Promise<MetricData[]> {
  await reader.forceFlush();
  const snapshots: ResourceMetrics[] = exporter.getMetrics();
  const all: MetricData[] = [];
  for (const snapshot of snapshots) {
    for (const scope of snapshot.scopeMetrics) {
      all.push(...scope.metrics);
    }
  }
  return all;
}

function findMetric(list: MetricData[], name: string): MetricData | undefined {
  return list.find(m => m.descriptor.name === name);
}

describe('createOtelTelemetry', () => {
  beforeEach(async () => {
    exporter = new InMemoryMetricExporter(AggregationTemporality.CUMULATIVE);
    reader = new PeriodicExportingMetricReader({
      exporter,
      exportIntervalMillis: 60_000,
    });
    provider = new MeterProvider({ readers: [reader] });
    metrics.setGlobalMeterProvider(provider);

    const telemetry = await createOtelTelemetry({ name: 'fortress-test' });
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      rbac: { cache: { ttlSeconds: 30, maxEntries: 100 } },
      observability: telemetry,
    });

    await fortress.auth.createUser({
      email: 'otel@example.com',
      name: 'OTel User',
      password: 'password-123456',
    });
  });

  afterEach(async () => {
    await provider.shutdown();
    metrics.disable();
  });

  it('emits fortress.auth.events.total on successful login', async () => {
    await fortress.auth.login('otel@example.com', 'password-123456');
    const all = await collectMetrics();

    const authEvents = findMetric(all, 'fortress.auth.events.total');
    expect(authEvents).toBeDefined();
    // There should be at least one data point with LOGIN_SUCCESS + password.
    const points = authEvents!.dataPoints;
    const success = points.find((p) => {
      const attrs = p.attributes as Record<string, string>;
      return attrs.event === 'LOGIN_SUCCESS' && attrs.outcome === 'success';
    });
    expect(success).toBeDefined();
  });

  it('emits fortress.auth.events.total with outcome=failure on bad credentials', async () => {
    await expect(
      fortress.auth.login('otel@example.com', 'wrong'),
    ).rejects.toThrow();
    const all = await collectMetrics();

    const authEvents = findMetric(all, 'fortress.auth.events.total');
    expect(authEvents).toBeDefined();
    const failure = authEvents!.dataPoints.find((p) => {
      const attrs = p.attributes as Record<string, string>;
      return attrs.event === 'LOGIN_FAILURE' && attrs.outcome === 'failure';
    });
    expect(failure).toBeDefined();
  });

  it('emits fortress.iam.permission_check.duration histogram + cache hit/miss counters', async () => {
    // Set up permissions.
    const user = await fortress.auth.createUser({
      email: 'perm-otel@example.com',
      name: 'Perm User',
      password: 'password-123456',
    });
    const role = await fortress.iam.createRole('reader', [
      { resource: 'post', action: 'read' },
    ]);
    await fortress.iam.bindRoleToUser(user.id, role.id);

    // Two checks: miss + hit.
    await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'read');
    await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'read');

    const all = await collectMetrics();

    const duration = findMetric(all, 'fortress.iam.permission_check.duration');
    expect(duration).toBeDefined();
    expect(duration!.dataPoints.length).toBeGreaterThan(0);

    const hits = findMetric(all, 'fortress.iam.permission_check.cache.hits');
    const misses = findMetric(all, 'fortress.iam.permission_check.cache.misses');
    expect(hits).toBeDefined();
    expect(misses).toBeDefined();

    // Sum the counters — there must be at least one hit and one miss.
    function sumCounter(m: MetricData | undefined): number {
      if (!m)
        return 0;
      return m.dataPoints.reduce((acc, p) => acc + Number(p.value), 0);
    }
    expect(sumCounter(misses)).toBeGreaterThanOrEqual(1);
    expect(sumCounter(hits)).toBeGreaterThanOrEqual(1);
  });

  it('emits the standard db.client.operation.duration histogram for Fortress DB calls', async () => {
    // Any DB operation will do — the register in beforeEach is enough.
    await fortress.auth.login('otel@example.com', 'password-123456');
    const all = await collectMetrics();

    const dbDuration = findMetric(all, 'db.client.operation.duration');
    expect(dbDuration).toBeDefined();
    expect(dbDuration!.dataPoints.length).toBeGreaterThan(0);

    // At least one data point should carry the standard semantic-convention
    // attributes: db.system.name and db.operation.name.
    const hasDbAttrs = dbDuration!.dataPoints.some((p) => {
      const attrs = p.attributes as Record<string, string>;
      return 'db.system.name' in attrs && 'db.operation.name' in attrs;
    });
    expect(hasDbAttrs).toBe(true);
  });

  it('emits fortress.auth.token_verify.duration on verifyToken calls', async () => {
    const login = await fortress.auth.login('otel@example.com', 'password-123456');
    expect(login.accessToken).toBeTruthy();
    // Successful verify
    await fortress.auth.verifyToken(login.accessToken as string);
    // Failed verify
    await expect(fortress.auth.verifyToken('not.a.jwt')).rejects.toThrow();

    const all = await collectMetrics();
    const verify = findMetric(all, 'fortress.auth.token_verify.duration');
    expect(verify).toBeDefined();

    const ok = verify!.dataPoints.find((p) => {
      const attrs = p.attributes as Record<string, string>;
      return attrs.result === 'ok';
    });
    const invalid = verify!.dataPoints.find((p) => {
      const attrs = p.attributes as Record<string, string>;
      return attrs.result === 'invalid';
    });
    expect(ok).toBeDefined();
    expect(invalid).toBeDefined();
  });

  it('createOtelTelemetry returns a zero-overhead provider when no SDK is registered', async () => {
    // Shut down the SDK so there's no global provider.
    await provider.shutdown();
    metrics.disable();

    const fresh = await createOtelTelemetry({ name: 'fortress-no-sdk' });
    // Methods should exist and be callable without throwing.
    const counter = fresh.meter.createCounter('foo');
    expect(() => counter.add(1, { attr: 'x' })).not.toThrow();
    const histogram = fresh.meter.createHistogram('bar');
    expect(() => histogram.record(0.5)).not.toThrow();
    const span = fresh.tracer.startSpan('baz');
    expect(() => {
      span.setAttribute('k', 'v');
      span.end();
    }).not.toThrow();
  });
});
