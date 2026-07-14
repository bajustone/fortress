import { afterEach, describe, expect, it, vi } from 'vitest';
import { createOutboundClient } from './outbound';

describe('outbound full-exchange timeout', () => {
  afterEach(() => vi.restoreAllMocks());

  it('keeps the deadline active while the response body is consumed', async () => {
    vi.spyOn(globalThis, 'fetch').mockImplementation(async (input) => {
      const request = input as Request;
      const body = new ReadableStream<Uint8Array>({
        start(controller) {
          request.signal.addEventListener('abort', () => {
            controller.error(request.signal.reason);
          }, { once: true });
        },
      });
      return new Response(body, { status: 200 });
    });

    const client = createOutboundClient(20);
    const response = await client.get('https://slow.example.test/data');

    await expect(response.text()).rejects.toThrow(/timed out/i);
  });

  it('clears the deadline after a complete body is read', async () => {
    vi.spyOn(globalThis, 'fetch').mockResolvedValue(new Response('{"ok":true}', { status: 200 }));
    const client = createOutboundClient(100);

    const response = await client.get('https://example.test/data');

    await expect(response.json()).resolves.toEqual({ ok: true });
  });
});
