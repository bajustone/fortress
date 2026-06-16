/**
 * `setTimeout`-driven, single-process queue. The **default** when no queue is
 * configured.
 *
 * **Dev-only.** Scheduled retries live in in-process timers, so a restart
 * **loses every pending retry** — the `webhook_delivery` row stays `pending`
 * but nothing re-attempts it until the next process runs its startup recovery
 * sweep (see {@link inMemoryQueue}'s `start`). Use {@link import('./database').databaseQueue}
 * (or a real broker) in production.
 *
 * @module
 */

import type { WebhookDelivery } from '../types';
import type { WebhookQueue, WebhookQueueJob } from './types';

export function inMemoryQueue(): WebhookQueue {
  let handler: ((job: WebhookQueueJob) => Promise<void>) | null = null;
  const timers = new Set<ReturnType<typeof setTimeout>>();

  const enqueue = async (job: WebhookQueueJob): Promise<void> => {
    const delay = job.scheduledFor ? Math.max(0, job.scheduledFor.getTime() - Date.now()) : 0;
    const run = (): void => {
      if (handler)
        void handler(job).catch(() => {});
    };
    if (delay === 0) {
      queueMicrotask(run);
    }
    else {
      const timer = setTimeout(() => {
        timers.delete(timer);
        run();
      }, delay);
      timers.add(timer);
    }
  };

  return {
    enqueue,
    async start(h, ctx) {
      handler = h;
      // Startup recovery sweep: re-enqueue rows a prior process left pending.
      const pending = await ctx.db.findMany<WebhookDelivery>({
        model: 'webhook_delivery',
        where: [{ field: 'status', operator: '=', value: 'pending' }],
      });
      for (const delivery of pending) {
        void enqueue({
          deliveryId: delivery.id,
          endpointId: delivery.endpointId,
          eventType: delivery.eventType,
          attempt: delivery.attempts + 1,
          scheduledFor: delivery.nextRetryAt ?? undefined,
        });
      }
      return async () => {
        for (const timer of timers)
          clearTimeout(timer);
        timers.clear();
        handler = null;
      };
    },
  };
}
