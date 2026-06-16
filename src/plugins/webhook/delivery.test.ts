import { describe, expect, it } from 'vitest';
import { ssrfSafeFetch } from './delivery';

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
});
