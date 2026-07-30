import { describe, expect, it } from 'vitest';
import { createDeliveryClient, deliver, ssrfSafeFetch } from './delivery';
import { isPrivateIp } from './ssrf';

describe('webhook delivery request', () => {
  it('forwards the JSON body and caller-supplied signing headers', async () => {
    let captured: Request | undefined;
    const client = createDeliveryClient({
      retryMode: 'pluginScheduled',
      fetch: async (request) => {
        captured = request;
        return new Response(null, { status: 204 });
      },
    });

    await expect(deliver(
      client,
      'https://hooks.example.com/fortress',
      '{"event":"user.created"}',
      { 'webhook-id': 'evt-1', 'webhook-signature': 'signature' },
    )).resolves.toEqual({ ok: true, status: 204 });

    expect(captured).toBeDefined();
    expect(captured?.headers.get('content-type')).toBe('application/json');
    expect(captured?.headers.get('webhook-id')).toBe('evt-1');
    expect(captured?.headers.get('webhook-signature')).toBe('signature');
    await expect(captured?.text()).resolves.toBe('{"event":"user.created"}');
  });
});

// The SSRF guard MUST live inside the delivery transport: validation and the
// pinned connection use the same resolved IP, so there is no rebinding window.
// These assert the guard runs through the real `FetchFn` (the path fetcher
// uses), rejecting before any connection is made.
describe('ssrfSafeFetch — SSRF guard in the delivery transport', () => {
  const fetchFn = ssrfSafeFetch();

  it('rejects non-https targets', async () => {
    await expect(
      fetchFn(new Request('http://example.com/hook', { method: 'POST' })),
    ).rejects.toThrow(/https/i);
  });

  it('rejects the cloud metadata IP', async () => {
    await expect(
      fetchFn(new Request('https://169.254.169.254/hook', { method: 'POST' })),
    ).rejects.toThrow(/private/i);
  });

  it('rejects loopback', async () => {
    await expect(
      fetchFn(new Request('https://127.0.0.1/hook', { method: 'POST' })),
    ).rejects.toThrow(/private/i);
  });

  it('rejects IPv4-mapped IPv6 metadata targets', async () => {
    await expect(
      fetchFn(new Request('https://[::ffff:169.254.169.254]/hook', { method: 'POST' })),
    ).rejects.toThrow();
  });

  it('rejects NAT64 well-known-prefix (64:ff9b::/96) targets that embed private IPv4', async () => {
    // 64:ff9b::a9fe:a9fe == NAT64 form of 169.254.169.254 (cloud metadata)
    await expect(
      fetchFn(new Request('https://[64:ff9b::a9fe:a9fe]/hook', { method: 'POST' })),
    ).rejects.toThrow(/private/i);
    // 64:ff9b::7f00:1 == NAT64 form of 127.0.0.1 (loopback)
    await expect(
      fetchFn(new Request('https://[64:ff9b::7f00:1]/hook', { method: 'POST' })),
    ).rejects.toThrow(/private/i);
  });

  it('rejects localhost by name', async () => {
    await expect(
      fetchFn(new Request('https://localhost/hook', { method: 'POST' })),
    ).rejects.toThrow(/not allowed/i);
  });

  it('treats malformed IP parser input as unsafe without blocking valid public literals', () => {
    // A partial numeric parse used to classify the malformed mapped/NAT64 forms
    // below as public. Resolver input must be a proven IP literal, never a
    // best-effort interpretation, because this predicate guards DNS targets.
    expect(isPrivateIp('8.8.8.8')).toBe(false);
    expect(isPrivateIp('::ffff:8.8.8.8')).toBe(false);
    expect(isPrivateIp('64:ff9b::808:808')).toBe(false);

    expect(isPrivateIp('8.8.8.8not-an-ip')).toBe(true);
    expect(isPrivateIp('::ffff:0808:0808oops')).toBe(true);
    expect(isPrivateIp('64:ff9b::0808:zzzz')).toBe(true);
  });
});
