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

export interface WebhookConfig {
  /** Events to deliver. Default: all. */
  events?: WebhookEventType[];
  /** Maximum delivery retries. Default: 5. */
  maxRetries?: number;
  /** Custom delivery function (for testing or custom transports). */
  deliver?: (url: string, payload: string, headers: Record<string, string>) => Promise<boolean>;
}

export type WebhookEventType
  = | 'LOGIN_SUCCESS'
    | 'LOGIN_FAILURE'
    | 'LOGOUT'
    | 'REGISTER'
    | 'TOKEN_REFRESH';

export interface WebhookEndpoint {
  id: number;
  url: string;
  events: string; // JSON array
  secret: string;
  isActive: boolean;
  createdAt: Date;
}

export interface WebhookDelivery {
  id: number;
  endpointId: number;
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

async function signPayload(secret: string, webhookId: string, timestamp: number, body: string): Promise<string> {
  const content = `${webhookId}.${timestamp}.${body}`;
  const key = await crypto.subtle.importKey(
    'raw',
    new TextEncoder().encode(secret),
    { name: 'HMAC', hash: 'SHA-256' },
    false,
    ['sign'],
  );
  const sig = await crypto.subtle.sign('HMAC', key, new TextEncoder().encode(content));
  const b64 = btoa(String.fromCharCode(...new Uint8Array(sig)));
  return b64;
}

async function defaultDeliver(url: string, payload: string, headers: Record<string, string>): Promise<boolean> {
  try {
    const response = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json', ...headers },
      body: payload,
    });
    return response.ok;
  }
  catch {
    return false;
  }
}

/**
 * Webhook plugin factory. Returns a {@link FortressPlugin} that delivers
 * fortress lifecycle events to subscriber endpoints using the Standard
 * Webhooks spec (HMAC-SHA256 signing, retries with exponential backoff).
 */
export function webhook(config: WebhookConfig = {}): FortressPlugin {
  const allowedEvents = config.events ?? null;
  const maxRetries = config.maxRetries ?? 5;
  const deliver = config.deliver ?? defaultDeliver;

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

    const success = await deliver(endpoint.url, delivery.payload, headers);
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
      const endpointEvents: string[] = JSON.parse(endpoint.events);
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

        await dispatchEvent(ctx.db, 'LOGIN_SUCCESS', {
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

        await dispatchEvent(ctx.db, 'LOGIN_FAILURE', {
          event: 'LOGIN_FAILURE',
          identifier: ctx.identifier,
          error: ctx.error.message,
          timestamp: new Date().toISOString(),
        });
      },

      async beforeLogout(ctx) {
        if (!shouldDeliver('LOGOUT'))
          return;

        await dispatchEvent(ctx.db, 'LOGOUT', {
          event: 'LOGOUT',
          timestamp: new Date().toISOString(),
          ip: ctx.meta?.ipAddress ?? null,
        });
      },

      async afterRegister(ctx, user) {
        if (!shouldDeliver('REGISTER'))
          return;

        await dispatchEvent(ctx.db, 'REGISTER', {
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

        await dispatchEvent(ctx.db, 'TOKEN_REFRESH', {
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

      async removeEndpoint(id: number): Promise<void> {
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
