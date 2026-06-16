import type { FetchFn } from '@bajustone/fetcher';
import type { Fortress } from '../../core/fortress';
import type { RedactedWebhookEndpoint, WebhookDelivery, WebhookDeliveryConfig, WebhookEndpoint, WebhookEventDeclaration } from './index';
import { afterEach, describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { obj, str } from '../../core/schema-builder';
import { createTestAdapter } from '../../testing';
import { assertSafeWebhookUrl, builtinEvents, webhook } from './index';

const SECRET = 'webhook-test-secret-32chars!!xxx';

interface WebhookMethods {
  emit: (name: string, payload: Record<string, unknown>, opts?: { idempotencyKey?: string }) => Promise<void>;
  registerEndpoint: (url: string, events: string[], opts?: { secret?: string }) => Promise<WebhookEndpoint>;
  updateEndpoint: (id: string, patch: { url?: string; events?: string[]; isActive?: boolean }) => Promise<RedactedWebhookEndpoint | null>;
  rotateSecret: (id: string) => Promise<{ id: string; secret: string }>;
  listEndpoints: () => Promise<RedactedWebhookEndpoint[]>;
  removeEndpoint: (id: string) => Promise<void>;
  listEventTypes: () => { name: string; description?: string }[];
  stop: () => Promise<void>;
}

interface RecordedCall { url: string; body: string; headers: Record<string, string> }

function recordingTransport(respond: () => Response | Promise<Response> = () => new Response(null, { status: 200 })): { fetch: FetchFn; calls: RecordedCall[] } {
  const calls: RecordedCall[] = [];
  const fetch: FetchFn = async (req) => {
    const body = await req.text();
    const headers: Record<string, string> = {};
    req.headers.forEach((value, key) => {
      headers[key] = value;
    });
    calls.push({ url: req.url, body, headers });
    return respond();
  };
  return { fetch, calls };
}

const open: WebhookMethods[] = [];

interface SetupOpts {
  respond?: () => Response | Promise<Response>;
  events?: WebhookEventDeclaration[];
  maxRetries?: number;
  maxPayloadBytes?: number;
  delivery?: Partial<Omit<WebhookDeliveryConfig, 'fetch'>>;
}

function setup(opts: SetupOpts = {}): { fortress: Fortress; wh: WebhookMethods; calls: RecordedCall[] } {
  const transport = recordingTransport(opts.respond);
  const fortress = createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
    plugins: [webhook({
      events: opts.events,
      maxRetries: opts.maxRetries,
      maxPayloadBytes: opts.maxPayloadBytes,
      delivery: { fetch: transport.fetch, ...opts.delivery },
    })],
  });
  const wh = fortress.plugins.webhook as unknown as WebhookMethods;
  open.push(wh);
  return { fortress, wh, calls: transport.calls };
}

async function waitFor(predicate: () => boolean, tries = 100): Promise<void> {
  for (let i = 0; i < tries && !predicate(); i++)
    await new Promise(resolve => setTimeout(resolve, 10));
}

async function seedLogin(fortress: Fortress, email: string): Promise<void> {
  await fortress.auth.createUser({ email, name: 'Test', password: 'password-123' });
  await fortress.auth.login(email, 'password-123');
}

afterEach(async () => {
  for (const wh of open)
    await wh.stop().catch(() => {});
  open.length = 0;
});

describe('webhook plugin — built-in events', () => {
  it('delivers the built-in auth.login.success event', async () => {
    const { fortress, wh, calls } = setup();
    await wh.registerEndpoint('https://example.com/hook', ['auth.login.success']);
    await seedLogin(fortress, 'alice@example.com');
    await waitFor(() => calls.length >= 1);

    expect(calls.length).toBe(1);
    const body = JSON.parse(calls[0].body);
    expect(body.event).toBe('auth.login.success');
    expect(body.email).toBe('alice@example.com');
  });

  it('signs with stable Standard Webhooks headers (webhook-id is msg_<deliveryId>)', async () => {
    const { fortress, wh, calls } = setup();
    await wh.registerEndpoint('https://example.com/hook', ['auth.login.success']);
    await seedLogin(fortress, 'bob@example.com');
    await waitFor(() => calls.length >= 1);

    const headers = calls[0].headers;
    expect(headers['webhook-id']).toMatch(/^msg_/);
    expect(Number(headers['webhook-timestamp'])).toBeGreaterThan(0);
    expect(headers['webhook-signature']).toMatch(/^v1,/);
  });

  it('only delivers to endpoints subscribed to the event', async () => {
    const { fortress, wh, calls } = setup();
    await wh.registerEndpoint('https://example.com/login-hook', ['auth.login.success']);
    await wh.registerEndpoint('https://example.com/register-hook', ['auth.user.registered']);
    await seedLogin(fortress, 'carol@example.com');
    await waitFor(() => calls.length >= 2);

    const login = calls.filter(c => c.url === 'https://example.com/login-hook');
    const register = calls.filter(c => c.url === 'https://example.com/register-hook');
    expect(login).toHaveLength(1);
    expect(JSON.parse(login[0].body).event).toBe('auth.login.success');
    expect(register).toHaveLength(1);
    expect(JSON.parse(register[0].body).event).toBe('auth.user.registered');
  });

  it('excluding a built-in event makes its hook a no-op', async () => {
    const { fortress, wh, calls } = setup({ events: builtinEvents({ exclude: ['auth.login.success'] }) });
    await wh.registerEndpoint('https://example.com/hook', ['auth.login.success']);
    await seedLogin(fortress, 'dave@example.com');
    await new Promise(resolve => setTimeout(resolve, 50));
    expect(calls.length).toBe(0);
  });
});

describe('webhook plugin — endpoint management', () => {
  it('generates a CSPRNG secret when omitted and returns it once', async () => {
    const { wh } = setup();
    const endpoint = await wh.registerEndpoint('https://example.com/hook', ['auth.logout']);
    expect(endpoint.secret).toMatch(/^whsec_/);
    expect(endpoint.isActive).toBe(true);
    expect(JSON.parse(endpoint.events)).toEqual(['auth.logout']);
  });

  it('redacts the secret from listEndpoints', async () => {
    const { wh } = setup();
    await wh.registerEndpoint('https://a.com/hook', ['auth.logout'], { secret: 'my-secret' });
    const list = await wh.listEndpoints();
    expect(list).toHaveLength(1);
    expect((list[0] as { secret?: string }).secret).toBeUndefined();
    expect(list[0].url).toBe('https://a.com/hook');
  });

  it('updateEndpoint patches (redacted) and rotateSecret returns a fresh secret', async () => {
    const { wh } = setup();
    const endpoint = await wh.registerEndpoint('https://a.com/hook', ['auth.logout'], { secret: 's1' });

    const updated = await wh.updateEndpoint(endpoint.id, { url: 'https://b.com/hook', isActive: false });
    expect(updated?.url).toBe('https://b.com/hook');
    expect(updated?.isActive).toBe(false);
    expect((updated as { secret?: string } | null)?.secret).toBeUndefined();

    const rotated = await wh.rotateSecret(endpoint.id);
    expect(rotated.secret).toMatch(/^whsec_/);
    expect(rotated.secret).not.toBe('s1');
  });

  it('removeEndpoint deletes the endpoint', async () => {
    const { wh } = setup();
    const endpoint = await wh.registerEndpoint('https://example.com/hook', ['auth.logout']);
    await wh.removeEndpoint(endpoint.id);
    expect(await wh.listEndpoints()).toHaveLength(0);
  });

  it('listEventTypes returns the registered events', async () => {
    const { wh } = setup({ events: [...builtinEvents(), { name: 'order.paid', description: 'An order was paid' }] });
    const names = wh.listEventTypes().map(e => e.name);
    expect(names).toContain('auth.login.success');
    expect(names).toContain('order.paid');
  });
});

describe('webhook plugin — custom events + emit()', () => {
  const OrderPaid = obj({ orderId: str() }, 'orderId');

  it('emit() throws WebhookEmitError for unknown events and invalid payloads', async () => {
    const { wh } = setup({ events: [...builtinEvents(), { name: 'order.paid', schema: OrderPaid }] });
    await wh.registerEndpoint('https://example.com/hook', ['order.paid']);

    await expect(wh.emit('nope.event', {})).rejects.toMatchObject({ code: 'unknown_event' });
    await expect(wh.emit('order.paid', { wrong: 1 })).rejects.toMatchObject({ code: 'invalid_payload' });
  });

  it('emit() delivers a valid custom event', async () => {
    const { wh, calls } = setup({ events: [...builtinEvents(), { name: 'order.paid', schema: OrderPaid }] });
    await wh.registerEndpoint('https://example.com/hook', ['order.paid']);
    await wh.emit('order.paid', { orderId: 'o1' });
    await waitFor(() => calls.length >= 1);
    expect(JSON.parse(calls[0].body).orderId).toBe('o1');
  });

  it('emit() rejects an oversized payload', async () => {
    const { wh } = setup({ maxPayloadBytes: 100, events: [...builtinEvents(), { name: 'big.event' }] });
    await expect(wh.emit('big.event', { blob: 'x'.repeat(500) })).rejects.toMatchObject({ code: 'payload_too_large' });
  });

  it('emit() is idempotent per (endpoint, idempotencyKey)', async () => {
    const { wh, calls } = setup({ events: [...builtinEvents(), { name: 'order.paid' }] });
    await wh.registerEndpoint('https://example.com/hook', ['order.paid']);
    await wh.emit('order.paid', { orderId: 'o1' }, { idempotencyKey: 'k1' });
    await wh.emit('order.paid', { orderId: 'o1' }, { idempotencyKey: 'k1' });
    await waitFor(() => calls.length >= 1);
    await new Promise(resolve => setTimeout(resolve, 40));
    expect(calls.length).toBe(1);
  });

  it('emit() dedup is concurrency-safe via the unique-index backstop', async () => {
    const { wh, calls } = setup({ events: [...builtinEvents(), { name: 'order.paid' }] });
    await wh.registerEndpoint('https://example.com/hook', ['order.paid']);
    // Two concurrent emits with the same key race the findOne pre-check; the DB
    // unique index must keep it to a single delivery row.
    await Promise.all([
      wh.emit('order.paid', { orderId: 'o1' }, { idempotencyKey: 'race-key' }),
      wh.emit('order.paid', { orderId: 'o1' }, { idempotencyKey: 'race-key' }),
    ]);
    await waitFor(() => calls.length >= 1);
    await new Promise(resolve => setTimeout(resolve, 40));
    expect(calls.length).toBe(1);
  });
});

describe('webhook plugin — failure handling', () => {
  const events: WebhookEventDeclaration[] = [...builtinEvents(), { name: 'order.paid' }];

  it('deactivates an endpoint on a permanent status (410) and fires onEndpointDeactivated', async () => {
    let reason: string | null = null;
    const { wh } = setup({
      respond: () => new Response(null, { status: 410 }),
      events,
      delivery: { onEndpointDeactivated: (_e, r) => { reason = r; } },
    });
    await wh.registerEndpoint('https://example.com/hook', ['order.paid']);
    await wh.emit('order.paid', { orderId: 'o1' });
    await waitFor(() => reason !== null);

    expect(reason).toBe('permanent_410');
    const list = await wh.listEndpoints();
    expect(list[0].isActive).toBe(false);
    expect(list[0].deactivatedReason).toBe('permanent_410');
  });

  it('fails fast on a non-retriable 4xx (422) and fires onDeliveryFailed', async () => {
    let failed: WebhookDelivery | null = null;
    const { wh } = setup({
      respond: () => new Response('bad request', { status: 422 }),
      events,
      delivery: { onDeliveryFailed: (d) => { failed = d; } },
    });
    await wh.registerEndpoint('https://example.com/hook', ['order.paid']);
    await wh.emit('order.paid', { orderId: 'o1' });
    await waitFor(() => failed !== null);

    expect(failed!.status).toBe('failed');
    expect(failed!.responseStatus).toBe(422);
    expect(failed!.errorKind).toBe('http');
  });

  it('opens the circuit breaker after maxConsecutiveFailures and marks the row failed (no zombie pending)', async () => {
    let reason: string | null = null;
    let failed: WebhookDelivery | null = null;
    const { wh } = setup({
      respond: () => new Response(null, { status: 500 }),
      events,
      maxRetries: 100,
      delivery: {
        maxConsecutiveFailures: 1,
        onEndpointDeactivated: (_e, r) => { reason = r; },
        onDeliveryFailed: (d) => { failed = d; },
      },
    });
    await wh.registerEndpoint('https://example.com/hook', ['order.paid']);
    await wh.emit('order.paid', { orderId: 'o1' });
    await waitFor(() => reason !== null && failed !== null);
    expect(reason).toBe('too_many_failures');
    // M1: a tripped breaker marks the delivery failed (DLQ seam sees it) instead
    // of leaving a permanent zombie `pending` row.
    expect(failed!.status).toBe('failed');
  });

  it('counts consecutive failures correctly under concurrent same-endpoint deliveries', async () => {
    const { fortress, wh } = setup({
      respond: () => new Response(null, { status: 500 }),
      events,
      maxRetries: 100,
      delivery: { maxConsecutiveFailures: 100 }, // just count, don't deactivate
    });
    // One endpoint subscribed to two built-in events that both fire on signup+login.
    await wh.registerEndpoint('https://example.com/hook', ['auth.user.registered', 'auth.login.success']);
    await seedLogin(fortress, 'race@example.com');
    // Poll until both failing deliveries have updated the counter (serialized → 2).
    let cf = 0;
    for (let i = 0; i < 100 && cf < 2; i++) {
      await new Promise(resolve => setTimeout(resolve, 10));
      cf = (await wh.listEndpoints())[0]?.consecutiveFailures ?? 0;
    }
    expect(cf).toBe(2);
  });
});

describe('webhook plugin — SSRF guard', () => {
  it('assertSafeWebhookUrl rejects non-https and private targets', async () => {
    await expect(assertSafeWebhookUrl('http://example.com/hook')).rejects.toThrow();
    await expect(assertSafeWebhookUrl('https://[::ffff:169.254.169.254]/hook')).rejects.toThrow();
  });
});
