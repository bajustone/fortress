import type { DatabaseAdapter } from '../../../adapters/database';
import type { WebhookQueueContext, WebhookQueueJob } from './types';
import { describe, expect, it } from 'vitest';
import { inMemoryQueue } from './in-memory';

function ctxWithPending(pending: unknown[] = []): WebhookQueueContext {
  return { db: { findMany: async () => pending } as unknown as DatabaseAdapter };
}
const tick = (): Promise<void> => new Promise(resolve => setTimeout(resolve, 5));

describe('inMemoryQueue', () => {
  it('delivers an enqueued job to the handler', async () => {
    const jobs: WebhookQueueJob[] = [];
    const queue = inMemoryQueue();
    const stop = await queue.start!(async job => void jobs.push(job), ctxWithPending());

    await queue.enqueue({ deliveryId: 'd1', endpointId: 'e1', eventType: 'order.paid', attempt: 1 });
    await tick();

    expect(jobs.map(j => j.deliveryId)).toEqual(['d1']);
    await stop();
  });

  it('runs a startup recovery sweep over pending rows', async () => {
    const jobs: WebhookQueueJob[] = [];
    const queue = inMemoryQueue();
    const stop = await queue.start!(
      async job => void jobs.push(job),
      ctxWithPending([{ id: 'd9', endpointId: 'e9', eventType: 'auth.login.success', attempts: 2, nextRetryAt: null }]),
    );
    await tick();

    expect(jobs[0]).toMatchObject({ deliveryId: 'd9', attempt: 3 });
    await stop();
  });

  it('stops delivering after teardown', async () => {
    const jobs: WebhookQueueJob[] = [];
    const queue = inMemoryQueue();
    const stop = await queue.start!(async job => void jobs.push(job), ctxWithPending());
    await stop();

    await queue.enqueue({ deliveryId: 'd2', endpointId: 'e2', eventType: 'order.paid', attempt: 1 });
    await tick();

    expect(jobs).toHaveLength(0);
  });
});
