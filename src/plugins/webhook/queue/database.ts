/**
 * Crash-safe bundled queue: polls `webhook_delivery` for due `pending` rows and
 * drives delivery. The `webhook_delivery` table is the transactional outbox, so
 * `enqueue` is a no-op — the row already exists and the poller picks it up.
 * This is the only bundled queue that survives a process restart.
 *
 * @module
 */

import type { WebhookDelivery } from '../types';
import type { WebhookQueue } from './types';

export function databaseQueue(opts: { pollMs?: number } = {}): WebhookQueue {
  const pollMs = opts.pollMs ?? 10_000;

  return {
    async enqueue() {
      // No-op: the webhook_delivery row IS the queue entry; the poller delivers it.
    },

    async start(handler, ctx) {
      let stopped = false;
      let timer: ReturnType<typeof setTimeout> | null = null;

      const poll = async (): Promise<void> => {
        if (stopped)
          return;
        try {
          const due = await ctx.db.findMany<WebhookDelivery>({
            model: 'webhook_delivery',
            where: [
              { field: 'status', operator: '=', value: 'pending' },
              { field: 'nextRetryAt', operator: 'lte', value: new Date() },
            ],
            sortBy: { field: 'nextRetryAt', direction: 'asc' },
          });
          for (const delivery of due) {
            if (stopped)
              break;
            // Sequential, so a slow delivery doesn't get double-picked next tick.
            await handler({
              deliveryId: delivery.id,
              endpointId: delivery.endpointId,
              eventType: delivery.eventType,
              attempt: delivery.attempts + 1,
              scheduledFor: delivery.nextRetryAt ?? undefined,
            }).catch(() => {});
          }
        }
        catch {
          // Swallow poll errors (e.g. transient DB hiccup); retry next tick.
        }
        if (!stopped)
          timer = setTimeout(() => void poll(), pollMs);
      };

      // First poll runs immediately and doubles as the startup recovery sweep.
      timer = setTimeout(() => void poll(), 0);

      return async () => {
        stopped = true;
        if (timer)
          clearTimeout(timer);
      };
    },
  } satisfies WebhookQueue;
}
