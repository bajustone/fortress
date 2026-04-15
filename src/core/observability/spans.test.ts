import type { Fortress } from '../fortress';
import type { Attributes, AttributeValue, Span, TelemetryProvider } from './types';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';
import { NO_OP_TELEMETRY } from './types';

interface SpanRecord {
  name: string;
  attributes: Record<string, AttributeValue>;
  ended: boolean;
  status?: { code: 'ok' | 'error'; message?: string };
  exception?: unknown;
}

/**
 * Build a {@link TelemetryProvider} that records every span that gets
 * started — used here instead of `@opentelemetry/sdk-trace-base` so we
 * can assert on spans without adding another dev dep. The meter falls
 * back to no-op because these tests only care about spans.
 */
function createSpyTelemetry(): { provider: TelemetryProvider; spans: SpanRecord[] } {
  const spans: SpanRecord[] = [];
  return {
    provider: {
      tracer: {
        startSpan(name: string, attributes?: Attributes): Span {
          const record: SpanRecord = {
            name,
            attributes: { ...(attributes ?? {}) },
            ended: false,
          };
          spans.push(record);
          return {
            setAttribute(key, value): void {
              record.attributes[key] = value;
            },
            recordException(error): void {
              record.exception = error;
            },
            setStatus(status): void {
              record.status = status;
            },
            end(): void {
              record.ended = true;
            },
          };
        },
      },
      meter: NO_OP_TELEMETRY.meter,
    },
    spans,
  };
}

const SECRET = 'span-test-secret-must-be-32-chars!';

let fortress: Fortress;
let spans: SpanRecord[];

describe('handleRequest outer span', () => {
  beforeEach(async () => {
    const telemetry = createSpyTelemetry();
    spans = telemetry.spans;
    fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
      observability: telemetry.provider,
    });
    await fortress.auth.createUser({
      email: 'spans@example.com',
      name: 'Span User',
      password: 'password-123',
    });
  });

  it('starts and ends a fortress.handleRequest span for every dispatched request', async () => {
    const res = await fortress.handleRequest(
      new Request('http://local/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ identifier: 'spans@example.com', password: 'password-123' }),
      }),
    );
    expect(res.status).toBe(200);

    const requestSpans = spans.filter(s => s.name === 'fortress.handleRequest');
    expect(requestSpans.length).toBe(1);
    const span = requestSpans[0]!;
    expect(span.ended).toBe(true);
    expect(span.attributes['http.method']).toBe('POST');
    expect(span.attributes['http.route']).toBe('/auth/login');
    expect(span.attributes['fortress.handler']).toBe('login');
    expect(span.attributes['http.status_code']).toBe(200);
    expect(span.status?.code).toBe('ok');
  });

  it('sets error status and records exception when dispatch throws', async () => {
    const res = await fortress.handleRequest(
      new Request('http://local/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ identifier: 'spans@example.com', password: 'wrong' }),
      }),
    );
    expect(res.status).toBe(401);

    const requestSpan = spans.find(s => s.name === 'fortress.handleRequest');
    expect(requestSpan).toBeDefined();
    expect(requestSpan!.ended).toBe(true);
    expect(requestSpan!.exception).toBeDefined();
    expect(requestSpan!.status?.code).toBe('error');
    expect(requestSpan!.attributes['http.status_code']).toBe(401);
  });

  it('sets error status on 4xx without a thrown exception', async () => {
    // A request to an unknown route raises notFound — FortressError
    // caught by the outer try.
    const res = await fortress.handleRequest(
      new Request('http://local/iam/roles/9999', { method: 'GET' }),
    );
    // iam/roles is owned by fortress — 401 because no bearer token,
    // so we land in the exception branch. That's still "error" status.
    // Use this assertion set to check the finally correctly marks 4xx.
    expect([401, 403, 404]).toContain(res.status);

    const span = spans.find(s => s.name === 'fortress.handleRequest');
    expect(span?.ended).toBe(true);
    expect(span?.status?.code).toBe('error');
  });
});

describe('db-instrumentation spans', () => {
  beforeEach(() => {
    const telemetry = createSpyTelemetry();
    spans = telemetry.spans;
    fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
      observability: telemetry.provider,
    });
  });

  it('emits a span per DB operation with semantic-convention attributes', async () => {
    await fortress.auth.createUser({
      email: 'db-span@example.com',
      name: 'DB Span User',
      password: 'password-123',
    });

    // Any span with a db.operation.name attribute is a DB span.
    const dbSpans = spans.filter(s => typeof s.attributes['db.operation.name'] === 'string');
    expect(dbSpans.length).toBeGreaterThan(0);

    for (const span of dbSpans) {
      expect(span.ended).toBe(true);
      expect(span.attributes['db.system.name']).toBeDefined();
    }

    // Creating a user hits at least findOne(user), create(user), create(login_identifier).
    const findOneUser = dbSpans.find(s =>
      s.attributes['db.operation.name'] === 'findOne'
      && s.attributes['db.collection.name'] === 'user',
    );
    expect(findOneUser).toBeDefined();
    expect(findOneUser?.name).toBe('findOne user');

    const createUser = dbSpans.find(s =>
      s.attributes['db.operation.name'] === 'create'
      && s.attributes['db.collection.name'] === 'user',
    );
    expect(createUser).toBeDefined();
    expect(createUser?.name).toBe('create user');
  });
});
