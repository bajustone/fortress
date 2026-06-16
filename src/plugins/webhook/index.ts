/**
 * Webhook delivery plugin for fortress.
 *
 * Implements the [Standard Webhooks](https://www.standardwebhooks.com) spec
 * with HMAC-SHA256 signing, configurable retry with exponential backoff, and
 * persisted delivery state. Subscribes to fortress lifecycle events and
 * pushes them to consumer-registered endpoints.
 *
 * @module
 */

import type { DatabaseAdapter } from '../../adapters/database';
import type { FortressPlugin } from '../../core/plugin';
import { request as httpsRequest } from 'node:https';
import { signPayload } from './signing';
import { resolveSafeWebhookTarget } from './ssrf';

export { assertSafeWebhookUrl } from './ssrf';

export interface WebhookConfig {
  /** Events to deliver. Default: all. */
  events?: WebhookEventType[];
  /** Maximum delivery retries. Default: 5. */
  maxRetries?: number;
  /** Custom delivery function (for testing or custom transports). */
  deliver?: (url: string, payload: string, headers: Record<string, string>) => Promise<boolean>;
  /** Delivery timeout in milliseconds. Default: 5000. */
  timeoutMs?: number;
}

export type WebhookEventType
  = | 'LOGIN_SUCCESS'
    | 'LOGIN_FAILURE'
    | 'LOGOUT'
    | 'REGISTER'
    | 'TOKEN_REFRESH';

export interface WebhookEndpoint {
  id: string;
  url: string;
  events: string; // JSON array
  secret: string;
  isActive: boolean;
  createdAt: Date;
}

export interface WebhookDelivery {
  id: string;
  endpointId: string;
  eventType: string;
  payload: string; // JSON
  status: 'pending' | 'success' | 'failed';
  attempts: number;
  lastAttemptAt: Date | null;
  nextRetryAt: Date | null;
  responseStatus: number | null;
  createdAt: Date;
}

const RETRY_INTERVALS_MS = [
  5 * 1000, // 5s
  5 * 60 * 1000, // 5min
  30 * 60 * 1000, // 30min
  2 * 60 * 60 * 1000, // 2h
  5 * 60 * 60 * 1000, // 5h
];

async function defaultDeliver(url: string, payload: string, headers: Record<string, string>, timeoutMs: number): Promise<boolean> {
  const target = await resolveSafeWebhookTarget(url);
  return new Promise((resolve) => {
    const req = httpsRequest({
      protocol: target.url.protocol,
      hostname: target.url.hostname,
      port: target.url.port || 443,
      path: `${target.url.pathname}${target.url.search}`,
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      timeout: timeoutMs,
      lookup: (_hostname, _options, cb) => cb(null, target.address, target.family),
    }, (res) => {
      res.resume();
      resolve(Boolean(res.statusCode && res.statusCode >= 200 && res.statusCode < 300));
    });
    req.on('timeout', () => req.destroy());
    req.on('error', () => resolve(false));
    req.end(payload);
  });
}

/**
 * Webhook plugin factory. Returns a {@link FortressPlugin} that delivers
 * fortress lifecycle events to subscriber endpoints using the Standard
 * Webhooks spec (HMAC-SHA256 signing, retries with exponential backoff).
 */
export function webhook(config: WebhookConfig = {}): FortressPlugin {
  const allowedEvents = config.events ?? null;
  const maxRetries = config.maxRetries ?? 5;
  const timeoutMs = config.timeoutMs ?? 5000;
  const deliver = config.deliver
    ? (url: string, payload: string, headers: Record<string, string>): Promise<boolean> => config.deliver!(url, payload, headers)
    : (url: string, payload: string, headers: Record<string, string>): Promise<boolean> => defaultDeliver(url, payload, headers, timeoutMs);

  function shouldDeliver(eventType: WebhookEventType): boolean {
    if (!allowedEvents)
      return true;
    return allowedEvents.includes(eventType);
  }

  async function deliverWebhook(
    db: DatabaseAdapter,
    endpoint: WebhookEndpoint,
    delivery: WebhookDelivery,
  ): Promise<void> {
    const webhookId = `wh_${Date.now()}_${Math.random().toString(36).slice(2, 10)}`;
    const timestamp = Math.floor(Date.now() / 1000);
    const signature = await signPayload(endpoint.secret, webhookId, timestamp, delivery.payload);

    const headers: Record<string, string> = {
      'webhook-id': webhookId,
      'webhook-timestamp': String(timestamp),
      'webhook-signature': `v1,${signature}`,
    };

    // SSRF protection lives inside `defaultDeliver` (it resolves the host
    // and pins the request to that exact IP, closing the DNS-rebind window).
    // Custom `config.deliver` transports are responsible for their own
    // outbound safety — running an extra `dns.lookup` here would just block
    // offline/CI consumers and inject a TOCTOU gap before their transport.
    let success = false;
    try {
      success = await deliver(endpoint.url, delivery.payload, headers);
    }
    catch {
      success = false;
    }
    const now = new Date();

    if (success) {
      await db.update({
        model: 'webhook_delivery',
        where: [{ field: 'id', operator: '=', value: delivery.id }],
        data: {
          status: 'success',
          attempts: delivery.attempts + 1,
          lastAttemptAt: now,
          nextRetryAt: null,
          responseStatus: 200,
        },
      });
    }
    else {
      const newAttempts = delivery.attempts + 1;
      if (newAttempts >= maxRetries) {
        await db.update({
          model: 'webhook_delivery',
          where: [{ field: 'id', operator: '=', value: delivery.id }],
          data: {
            status: 'failed',
            attempts: newAttempts,
            lastAttemptAt: now,
            nextRetryAt: null,
          },
        });
      }
      else {
        const retryMs = RETRY_INTERVALS_MS[Math.min(newAttempts - 1, RETRY_INTERVALS_MS.length - 1)];
        const nextRetryAt = new Date(Date.now() + retryMs);
        await db.update({
          model: 'webhook_delivery',
          where: [{ field: 'id', operator: '=', value: delivery.id }],
          data: {
            status: 'pending',
            attempts: newAttempts,
            lastAttemptAt: now,
            nextRetryAt,
          },
        });
      }
    }
  }

  async function dispatchEvent(
    db: DatabaseAdapter,
    eventType: WebhookEventType,
    payload: Record<string, unknown>,
  ): Promise<void> {
    const allEndpoints = await db.findMany<WebhookEndpoint>({
      model: 'webhook_endpoint',
      where: [{ field: 'isActive', operator: '=', value: true }],
    });

    const payloadJson = JSON.stringify(payload);

    for (const endpoint of allEndpoints) {
      let endpointEvents: string[];
      try {
        endpointEvents = JSON.parse(endpoint.events) as string[];
      }
      catch {
        continue;
      }
      if (!endpointEvents.includes(eventType)) {
        continue;
      }

      const delivery = await db.create<WebhookDelivery>({
        model: 'webhook_delivery',
        data: {
          endpointId: endpoint.id,
          eventType,
          payload: payloadJson,
          status: 'pending',
          attempts: 0,
        },
      });

      await deliverWebhook(db, endpoint, delivery);
    }
  }

  function scheduleDispatchEvent(db: DatabaseAdapter, eventType: WebhookEventType, payload: Record<string, unknown>): void {
    queueMicrotask(() => {
      void dispatchEvent(db, eventType, payload).catch(() => {});
    });
  }

  return {
    name: 'webhook',

    models: [
      {
        name: 'webhook_endpoint',
        fields: {
          id: { type: 'number', required: true },
          url: { type: 'string', required: true },
          events: { type: 'string', required: true },
          secret: { type: 'string', required: true },
          isActive: { type: 'boolean', required: true },
          createdAt: { type: 'date', required: true },
        },
      },
      {
        name: 'webhook_delivery',
        fields: {
          id: { type: 'number', required: true },
          endpointId: { type: 'number', required: true, references: { model: 'webhook_endpoint', field: 'id' } },
          eventType: { type: 'string', required: true },
          payload: { type: 'string', required: true },
          status: { type: 'string', required: true },
          attempts: { type: 'number', required: true },
          lastAttemptAt: { type: 'string' },
          nextRetryAt: { type: 'string' },
          responseStatus: { type: 'number' },
          createdAt: { type: 'date', required: true },
        },
      },
    ],

    hooks: {
      async afterLogin(ctx, result) {
        if (!shouldDeliver('LOGIN_SUCCESS'))
          return result;

        scheduleDispatchEvent(ctx.db, 'LOGIN_SUCCESS', {
          event: 'LOGIN_SUCCESS',
          userId: result.user.id,
          email: result.user.email,
          timestamp: new Date().toISOString(),
          ip: ctx.meta?.ipAddress ?? null,
        });

        return result;
      },

      async onLoginFailure(ctx) {
        if (!shouldDeliver('LOGIN_FAILURE'))
          return;

        scheduleDispatchEvent(ctx.db, 'LOGIN_FAILURE', {
          event: 'LOGIN_FAILURE',
          identifier: ctx.identifier,
          error: ctx.error.message,
          timestamp: new Date().toISOString(),
        });
      },

      async beforeLogout(ctx) {
        if (!shouldDeliver('LOGOUT'))
          return;

        scheduleDispatchEvent(ctx.db, 'LOGOUT', {
          event: 'LOGOUT',
          timestamp: new Date().toISOString(),
          ip: ctx.meta?.ipAddress ?? null,
        });
      },

      async afterRegister(ctx, user) {
        if (!shouldDeliver('REGISTER'))
          return;

        scheduleDispatchEvent(ctx.db, 'REGISTER', {
          event: 'REGISTER',
          userId: user.id,
          email: user.email,
          timestamp: new Date().toISOString(),
          ip: ctx.meta?.ipAddress ?? null,
        });
      },

      async afterTokenRefresh(ctx, result) {
        if (!shouldDeliver('TOKEN_REFRESH'))
          return result;

        scheduleDispatchEvent(ctx.db, 'TOKEN_REFRESH', {
          event: 'TOKEN_REFRESH',
          timestamp: new Date().toISOString(),
          ip: ctx.meta?.ipAddress ?? null,
        });

        return result;
      },
    },

    methods: ctx => ({
      async registerEndpoint(url: string, events: WebhookEventType[], secret: string): Promise<WebhookEndpoint> {
        return ctx.db.create<WebhookEndpoint>({
          model: 'webhook_endpoint',
          data: {
            url,
            events: JSON.stringify(events),
            secret,
            isActive: true,
          },
        });
      },

      async listEndpoints(): Promise<WebhookEndpoint[]> {
        return ctx.db.findMany<WebhookEndpoint>({
          model: 'webhook_endpoint',
          where: [{ field: 'isActive', operator: '=', value: true }],
        });
      },

      async removeEndpoint(id: string): Promise<void> {
        await ctx.db.delete({
          model: 'webhook_delivery',
          where: [{ field: 'endpointId', operator: '=', value: id }],
        });
        await ctx.db.delete({
          model: 'webhook_endpoint',
          where: [{ field: 'id', operator: '=', value: id }],
        });
      },

      async processRetries(): Promise<void> {
        const now = new Date();
        const pendingDeliveries = await ctx.db.findMany<WebhookDelivery>({
          model: 'webhook_delivery',
          where: [
            { field: 'status', operator: '=', value: 'pending' },
            { field: 'nextRetryAt', operator: 'lte', value: now },
          ],
        });

        for (const delivery of pendingDeliveries) {
          const endpoint = await ctx.db.findOne<WebhookEndpoint>({
            model: 'webhook_endpoint',
            where: [{ field: 'id', operator: '=', value: delivery.endpointId }],
          });

          if (!endpoint || !endpoint.isActive) {
            continue;
          }

          await deliverWebhook(ctx.db, endpoint, delivery);
        }
      },
    }),
  };
}
