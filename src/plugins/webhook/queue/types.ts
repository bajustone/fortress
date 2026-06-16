/**
 * Bring-Your-Own-Queue interface. Delivery is always queued; consumers can
 * back it with any system (in-memory, DB, BullMQ, SQS, Cloudflare Queues,
 * Inngest, …) by implementing this small surface.
 *
 * @module
 */

import type { DatabaseAdapter } from '../../../adapters/database';

/** One unit of delivery work — a single attempt of a single delivery row. */
export interface WebhookQueueJob {
  deliveryId: string;
  endpointId: string;
  eventType: string;
  /** 1-based attempt number. */
  attempt: number;
  /** When this attempt should run (retries); absent means "now". */
  scheduledFor?: Date;
}

/** Context handed to {@link WebhookQueue.start} so fortress-aware queues can reach the DB. */
export interface WebhookQueueContext {
  /** The fortress database adapter — used by the database queue to poll, and for the startup recovery sweep. */
  db: DatabaseAdapter;
}

export interface WebhookQueue {
  /**
   * If true, the plugin re-throws on failed delivery and the queue is expected
   * to retry per its own policy (BullMQ/SQS/Inngest). If false/absent, the
   * plugin schedules retries itself.
   */
  handlesRetries?: boolean;

  /** Enqueue a delivery job. (A no-op for the database queue — the table IS the queue.) */
  enqueue: (job: WebhookQueueJob) => Promise<void>;

  /**
   * Optional worker registration. Pull queues (in-memory, database) implement
   * this; push/serverless queues (Cloudflare Queues with a separate consumer,
   * Inngest, …) leave it undefined. Returns a teardown the consumer calls on
   * shutdown. Implementations SHOULD run a startup recovery sweep here —
   * re-enqueue rows left `pending` by a prior process — so at-least-once holds
   * across restarts.
   */
  start?: (
    handler: (job: WebhookQueueJob) => Promise<void>,
    ctx: WebhookQueueContext,
  ) => Promise<() => Promise<void>>;
}
