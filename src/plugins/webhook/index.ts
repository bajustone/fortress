/**
 * Webhook delivery plugin for fortress (v1).
 *
 * - **Custom events** — declare and `emit()` your own events through the same
 *   path the built-in auth events use.
 * - **Bring-Your-Own-Queue** — delivery is always queued; plug in any backend
 *   via {@link import('./queue/types').WebhookQueue}. Defaults to the dev-only
 *   {@link inMemoryQueue}; use {@link databaseQueue} (crash-safe) or a broker in prod.
 * - **Standard Webhooks** signing (HMAC-SHA256), with a stable per-delivery
 *   `webhook-id` for receiver-side idempotency.
 * - **SSRF-safe delivery** over `@bajustone/fetcher` with connect-time IP pinning.
 * - Failure classification, jittered backoff, circuit-breaker auto-deactivation,
 *   and DLQ observability hooks.
 *
 * @module
 */

import type { DatabaseAdapter, WhereClause } from '../../adapters/database';
import type { FortressPlugin } from '../../core/plugin';
import type { DeliveryResult } from './delivery';
import type { WebhookQueueJob } from './queue/types';
import type {
  EmitOptions,
  RedactedWebhookEndpoint,
  RegisterEndpointOptions,
  UpdateEndpointPatch,
  WebhookConfig,
  WebhookDeactivatedReason,
  WebhookDelivery,
  WebhookEndpoint,
} from './types';
import { Buffer } from 'node:buffer';
import { definePlugin } from '../../core/plugin';
import { builtinEvents } from './builtin-events';
import { createDeliveryClient, deliver } from './delivery';
import { bindBuiltinHooks } from './hooks';
import { inMemoryQueue } from './queue/in-memory';
import { createEventRegistry } from './registry';
import { signatureHeaders } from './signing';
import { WebhookEmitError } from './types';

export { builtinEvents } from './builtin-events';
export { databaseQueue } from './queue/database';
export { inMemoryQueue } from './queue/in-memory';
export type { WebhookQueue, WebhookQueueContext, WebhookQueueJob } from './queue/types';
export { assertSafeWebhookUrl } from './ssrf';
export type {
  EmitOptions,
  RedactedWebhookEndpoint,
  RegisterEndpointOptions,
  UpdateEndpointPatch,
  WebhookConfig,
  WebhookDeactivatedReason,
  WebhookDelivery,
  WebhookDeliveryConfig,
  WebhookEmitErrorCode,
  WebhookEndpoint,
  WebhookErrorKind,
  WebhookEventDeclaration,
} from './types';
export { WebhookEmitError } from './types';

export interface WebhookMethods {
  emit: (eventName: string, payload: Record<string, unknown>, opts?: EmitOptions) => Promise<void>;
  registerEndpoint: (url: string, events: string[], opts?: RegisterEndpointOptions) => Promise<WebhookEndpoint>;
  updateEndpoint: (id: string, patch: UpdateEndpointPatch) => Promise<RedactedWebhookEndpoint | null>;
  rotateSecret: (id: string) => Promise<{ id: string; secret: string }>;
  listEndpoints: () => Promise<RedactedWebhookEndpoint[]>;
  removeEndpoint: (id: string) => Promise<void>;
  listEventTypes: () => { name: string; description?: string }[];
  stop: () => Promise<void>;
}

/** Plugin-scheduled retry backoff ladder (ms); jittered ±25% per attempt. */
const RETRY_INTERVALS_MS = [5_000, 5 * 60_000, 30 * 60_000, 2 * 60 * 60_000, 5 * 60 * 60_000];

/** 4xx statuses that are transient and worth retrying (matches the fetcher transport's retry set). */
const TRANSIENT_4XX = new Set([408, 425, 429]);

function withJitter(ms: number): number {
  // Full ±25% jitter so an endpoint recovering doesn't get a synchronized spike.
  return Math.max(0, Math.round(ms * (1 + (Math.random() - 0.5) * 0.5)));
}

/** Generate a Standard-Webhooks-style signing secret (`whsec_<hex>`), CSPRNG-backed. */
function generateSecret(): string {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes, b => b.toString(16).padStart(2, '0')).join('');
  return `whsec_${hex}`;
}

function idWhere(id: string): WhereClause[] {
  return [{ field: 'id', operator: '=', value: id }];
}

function redact(endpoint: WebhookEndpoint): RedactedWebhookEndpoint {
  const { secret: _secret, ...rest } = endpoint;
  return rest;
}

/**
 * Webhook plugin factory. See the module docs for the full feature set.
 */
export function webhook(config: WebhookConfig = {}): FortressPlugin<'webhook', WebhookMethods, undefined> {
  const registry = createEventRegistry(config.events ?? builtinEvents());
  const queue = config.queue ?? inMemoryQueue();
  const retryMode = config.delivery?.retry ?? 'pluginScheduled';
  const maxRetries = config.maxRetries ?? 5;
  const maxPayloadBytes = config.maxPayloadBytes ?? 256 * 1024;
  const timeoutMs = config.delivery?.timeoutMs ?? 10_000;
  const permanentStatuses = new Set(config.delivery?.permanentStatuses ?? [404, 410, 421]);
  const maxConsecutiveFailures = config.delivery?.maxConsecutiveFailures ?? 15;
  const onDeliveryFailed = config.delivery?.onDeliveryFailed;
  const onEndpointDeactivated = config.delivery?.onEndpointDeactivated;

  if (retryMode === 'queue' && !queue.handlesRetries) {
    throw new Error('delivery.retry: "queue" requires a queue with handlesRetries: true');
  }

  const client = createDeliveryClient({ timeoutMs, retryMode, fetch: config.delivery?.fetch });
  const deliverFn = (url: string, body: string, headers: Record<string, string>): Promise<DeliveryResult> =>
    deliver(client, url, body, headers);

  // ── Failure classification ────────────────────────────────────────
  function classify(result: DeliveryResult): 'deactivate' | 'permanent_fail' | 'retry' {
    if (!result.ok && result.kind === 'http' && result.status !== null) {
      if (permanentStatuses.has(result.status))
        return 'deactivate';
      if (TRANSIENT_4XX.has(result.status))
        return 'retry'; // 408 / 425 / 429 are transient
      if (result.status >= 400 && result.status < 500)
        return 'permanent_fail'; // other 4xx — retrying just burns attempts
      return 'retry'; // 5xx
    }
    return 'retry'; // network / timeout
  }

  async function deactivateEndpoint(db: DatabaseAdapter, endpoint: WebhookEndpoint, reason: WebhookDeactivatedReason): Promise<void> {
    if (!endpoint.isActive)
      return;
    await db.update({ model: 'webhook_endpoint', where: idWhere(endpoint.id), data: { isActive: false, deactivatedReason: reason } });
    if (onEndpointDeactivated)
      await onEndpointDeactivated({ ...endpoint, isActive: false, deactivatedReason: reason }, reason);
  }

  // ── Delivery (one queue job = one attempt) ────────────────────────
  async function processJob(db: DatabaseAdapter, job: WebhookQueueJob): Promise<void> {
    const delivery = await db.findOne<WebhookDelivery>({ model: 'webhook_delivery', where: idWhere(job.deliveryId) });
    if (!delivery || delivery.status !== 'pending')
      return;
    const endpoint = await db.findOne<WebhookEndpoint>({ model: 'webhook_endpoint', where: idWhere(delivery.endpointId) });
    if (!endpoint || !endpoint.isActive)
      return;

    // Stable per-delivery id (receiver idempotency key); only the timestamp changes per attempt.
    const webhookId = `msg_${delivery.id}`;
    const timestamp = Math.floor(Date.now() / 1000);
    const headers = await signatureHeaders(endpoint.secret, webhookId, timestamp, delivery.payload);

    const result = await deliverFn(endpoint.url, delivery.payload, headers);
    const now = new Date();
    const attempts = delivery.attempts + 1;

    if (result.ok) {
      await db.update({
        model: 'webhook_delivery',
        where: idWhere(delivery.id),
        data: { status: 'success', attempts, lastAttemptAt: now, nextRetryAt: null, responseStatus: result.status, errorKind: null },
      });
      if (endpoint.consecutiveFailures > 0)
        await db.update({ model: 'webhook_endpoint', where: idWhere(endpoint.id), data: { consecutiveFailures: 0 } });
      return;
    }

    // Failure path.
    const consecutiveFailures = endpoint.consecutiveFailures + 1;
    await db.update({ model: 'webhook_endpoint', where: idWhere(endpoint.id), data: { consecutiveFailures } });

    const responseStatus = result.status;
    const responseBody = result.responseBody;
    const errorKind = result.kind;
    const action = classify(result);
    const exhausted = attempts >= maxRetries;
    const breakerTripped = consecutiveFailures >= maxConsecutiveFailures;
    // `inProcess` mode already retried inside fetcher, so a failure here is terminal.
    const willRetry = action === 'retry' && !exhausted && retryMode !== 'inProcess';

    const markFailed = async (): Promise<void> => {
      await db.update({
        model: 'webhook_delivery',
        where: idWhere(delivery.id),
        data: { status: 'failed', attempts, lastAttemptAt: now, nextRetryAt: null, responseStatus, responseBody, errorKind },
      });
      if (onDeliveryFailed) {
        const row = await db.findOne<WebhookDelivery>({ model: 'webhook_delivery', where: idWhere(delivery.id) });
        if (row)
          await onDeliveryFailed(row);
      }
    };

    // Permanent status → fail + deactivate.
    if (action === 'deactivate') {
      await markFailed();
      await deactivateEndpoint(db, endpoint, `permanent_${responseStatus}` as WebhookDeactivatedReason);
      return;
    }

    // Terminal: no further attempt will run — non-retriable, retries exhausted,
    // `inProcess` (fetcher already retried), or the circuit breaker has tripped.
    // Mark failed FIRST so a tripped-breaker delivery never lingers as a zombie
    // `pending` row that nothing re-attempts and `onDeliveryFailed` never sees.
    if (!willRetry || breakerTripped) {
      await markFailed();
      if (breakerTripped)
        await deactivateEndpoint(db, endpoint, 'too_many_failures');
      return;
    }

    // Retry is warranted and the breaker has NOT tripped.
    if (retryMode === 'queue') {
      // The external queue owns retries: keep the row pending and re-throw.
      await db.update({
        model: 'webhook_delivery',
        where: idWhere(delivery.id),
        data: { status: 'pending', attempts, lastAttemptAt: now, responseStatus, responseBody, errorKind },
      });
      throw new Error(`Webhook delivery failed (${errorKind}${responseStatus !== null ? ` ${responseStatus}` : ''}); queue will retry`);
    }

    // pluginScheduled: schedule the next attempt with jitter and re-enqueue.
    const retryMs = withJitter(RETRY_INTERVALS_MS[Math.min(attempts - 1, RETRY_INTERVALS_MS.length - 1)]!);
    const nextRetryAt = new Date(Date.now() + retryMs);
    await db.update({
      model: 'webhook_delivery',
      where: idWhere(delivery.id),
      data: { status: 'pending', attempts, lastAttemptAt: now, nextRetryAt, responseStatus, responseBody, errorKind },
    });
    await queue.enqueue({
      deliveryId: delivery.id,
      endpointId: endpoint.id,
      eventType: delivery.eventType,
      attempt: attempts + 1,
      scheduledFor: nextRetryAt,
    });
  }

  // ── Emit (persist outbox row + enqueue) ───────────────────────────
  async function emitEvent(db: DatabaseAdapter, eventName: string, payload: Record<string, unknown>, opts?: EmitOptions): Promise<void> {
    const declaration = registry.get(eventName);
    if (!declaration)
      throw new WebhookEmitError('unknown_event', `Unknown webhook event: ${eventName}`);

    if (declaration.schema) {
      const result = await declaration.schema['~standard'].validate(payload);
      if (result.issues)
        throw new WebhookEmitError('invalid_payload', `Invalid payload for webhook event '${eventName}'`);
    }

    const payloadJson = JSON.stringify(payload);
    if (Buffer.byteLength(payloadJson, 'utf8') > maxPayloadBytes)
      throw new WebhookEmitError('payload_too_large', `Webhook payload for '${eventName}' exceeds ${maxPayloadBytes} bytes`);

    const endpoints = await db.findMany<WebhookEndpoint>({ model: 'webhook_endpoint', where: [{ field: 'isActive', operator: '=', value: true }] });
    const now = new Date();

    for (const endpoint of endpoints) {
      let names: string[];
      try {
        names = JSON.parse(endpoint.events) as string[];
      }
      catch {
        continue;
      }
      if (!names.includes(eventName))
        continue;

      if (opts?.idempotencyKey) {
        const existing = await db.findOne<WebhookDelivery>({
          model: 'webhook_delivery',
          where: [
            { field: 'endpointId', operator: '=', value: endpoint.id },
            { field: 'idempotencyKey', operator: '=', value: opts.idempotencyKey },
          ],
        });
        if (existing)
          continue; // already emitted to this endpoint
      }

      // Outbox: persist the row first, then signal the queue. The findOne above
      // is the fast path; the unique index on (endpoint_id, idempotency_key) is
      // the race backstop — a concurrent emit with the same key loses the insert,
      // and we treat that as "already emitted" rather than enqueuing a duplicate.
      let delivery: WebhookDelivery;
      try {
        delivery = await db.create<WebhookDelivery>({
          model: 'webhook_delivery',
          data: {
            endpointId: endpoint.id,
            eventType: eventName,
            payload: payloadJson,
            status: 'pending',
            attempts: 0,
            idempotencyKey: opts?.idempotencyKey ?? null,
            nextRetryAt: now, // due immediately (the database queue selects on this)
          },
        });
      }
      catch (err) {
        if (opts?.idempotencyKey) {
          const winner = await db.findOne<WebhookDelivery>({
            model: 'webhook_delivery',
            where: [
              { field: 'endpointId', operator: '=', value: endpoint.id },
              { field: 'idempotencyKey', operator: '=', value: opts.idempotencyKey },
            ],
          });
          if (winner)
            continue; // a concurrent emit with the same key won the insert
        }
        throw err;
      }
      await queue.enqueue({ deliveryId: delivery.id, endpointId: endpoint.id, eventType: eventName, attempt: 1, scheduledFor: now });
    }
  }

  // ── Queue lifecycle ───────────────────────────────────────────────
  let queueStarted = false;
  let queueTeardown: (() => Promise<void>) | null = null;
  function ensureQueueStarted(db: DatabaseAdapter): void {
    if (queueStarted || !queue.start)
      return;
    queueStarted = true;
    // start() sets its handler synchronously before its first await, so jobs
    // enqueued right after this call are not dropped.
    void queue.start(job => processJob(db, job), { db })
      .then((teardown) => {
        queueTeardown = teardown;
      })
      .catch(() => {
        queueStarted = false;
      });
  }

  return definePlugin({
    name: 'webhook',

    models: [
      {
        name: 'webhook_endpoint',
        fields: {
          id: { type: 'string', required: true },
          url: { type: 'string', required: true },
          events: { type: 'string', required: true },
          secret: { type: 'string', required: true },
          isActive: { type: 'boolean', required: true },
          deactivatedReason: { type: 'string' },
          consecutiveFailures: { type: 'number', required: true },
          createdAt: { type: 'date', required: true },
        },
      },
      {
        name: 'webhook_delivery',
        fields: {
          id: { type: 'string', required: true },
          endpointId: { type: 'string', required: true, references: { model: 'webhook_endpoint', field: 'id' } },
          eventType: { type: 'string', required: true },
          payload: { type: 'string', required: true },
          status: { type: 'string', required: true },
          attempts: { type: 'number', required: true },
          idempotencyKey: { type: 'string' },
          lastAttemptAt: { type: 'date' },
          nextRetryAt: { type: 'date' },
          responseStatus: { type: 'number' },
          responseBody: { type: 'string' },
          errorKind: { type: 'string' },
          createdAt: { type: 'date', required: true },
        },
      },
    ],

    hooks: bindBuiltinHooks(registry, emitEvent),

    methods: (ctx) => {
      ensureQueueStarted(ctx.db);

      return {
        /** Emit an event — validates against the declared schema and the payload cap, then queues delivery to every subscribed endpoint. */
        emit(eventName: string, payload: Record<string, unknown>, opts?: EmitOptions): Promise<void> {
          return emitEvent(ctx.db, eventName, payload, opts);
        },

        /** Register a delivery endpoint. A CSPRNG `secret` is generated when omitted and returned once on the result. */
        async registerEndpoint(url: string, events: string[], opts?: RegisterEndpointOptions): Promise<WebhookEndpoint> {
          const secret = opts?.secret ?? generateSecret();
          return ctx.db.create<WebhookEndpoint>({
            model: 'webhook_endpoint',
            data: { url, events: JSON.stringify(events), secret, isActive: true, consecutiveFailures: 0 },
          });
        },

        /** Patch an endpoint's url / events / active flag. Re-activating clears the deactivation reason and resets the failure counter. Secret is redacted. */
        async updateEndpoint(id: string, patch: UpdateEndpointPatch): Promise<RedactedWebhookEndpoint | null> {
          const data: Record<string, unknown> = {};
          if (patch.url !== undefined)
            data.url = patch.url;
          if (patch.events !== undefined)
            data.events = JSON.stringify(patch.events);
          if (patch.isActive !== undefined) {
            data.isActive = patch.isActive;
            if (patch.isActive) {
              data.deactivatedReason = null;
              data.consecutiveFailures = 0;
            }
          }
          const updated = await ctx.db.update<WebhookEndpoint>({ model: 'webhook_endpoint', where: idWhere(id), data });
          return updated ? redact(updated) : null;
        },

        /** Rotate an endpoint's signing secret. Returns the new secret once. */
        async rotateSecret(id: string): Promise<{ id: string; secret: string }> {
          const secret = generateSecret();
          const updated = await ctx.db.update<WebhookEndpoint>({ model: 'webhook_endpoint', where: idWhere(id), data: { secret } });
          if (!updated)
            throw new Error(`Webhook endpoint not found: ${id}`);
          return { id, secret };
        },

        /** List all endpoints with `secret` redacted. */
        async listEndpoints(): Promise<RedactedWebhookEndpoint[]> {
          const rows = await ctx.db.findMany<WebhookEndpoint>({ model: 'webhook_endpoint' });
          return rows.map(redact);
        },

        /** Delete an endpoint and its delivery rows. */
        async removeEndpoint(id: string): Promise<void> {
          await ctx.db.delete({ model: 'webhook_delivery', where: [{ field: 'endpointId', operator: '=', value: id }] });
          await ctx.db.delete({ model: 'webhook_endpoint', where: idWhere(id) });
        },

        /** The registered event types (name + description). */
        listEventTypes(): { name: string; description?: string }[] {
          return registry.list().map(e => ({ name: e.name, description: e.description }));
        },

        /** Stop the queue worker (timers/poller) — call on shutdown. */
        async stop(): Promise<void> {
          if (queueTeardown) {
            await queueTeardown();
            queueTeardown = null;
          }
          queueStarted = false;
        },
      };
    },
  } satisfies FortressPlugin<'webhook', WebhookMethods>);
}
