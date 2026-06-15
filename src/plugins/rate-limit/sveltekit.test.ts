import type { SvelteKitRateLimitEvent } from './sveltekit';
import { describe, expect, it } from 'vitest';
import { FortressError } from '../../core/errors';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { rateLimit } from './index';
import { svelteKitRateLimit } from './sveltekit';

const SECRET = 'sveltekit-rate-limit-wrapper-test-32!!';

function setup(maxPerIp: number) {
  return createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
    plugins: [rateLimit({ rules: { api: { maxPerIp, windowSeconds: 60 } } })],
  });
}

function mockEvent(headers: Record<string, string>, userId?: string): SvelteKitRateLimitEvent {
  return {
    request: new Request('http://localhost/api/thing', { headers }),
    locals: userId != null ? { fortressUserId: userId } : undefined,
  };
}

describe('svelteKitRateLimit (framework wrapper)', () => {
  it('resolves under the limit and throws FortressError when exceeded', async () => {
    const fortress = setup(2);

    await svelteKitRateLimit(fortress, 'api', mockEvent({ 'x-forwarded-for': '10.0.0.1' }));
    await svelteKitRateLimit(fortress, 'api', mockEvent({ 'x-forwarded-for': '10.0.0.1' }));

    await expect(
      svelteKitRateLimit(fortress, 'api', mockEvent({ 'x-forwarded-for': '10.0.0.1' })),
    ).rejects.toMatchObject({ code: 'RATE_LIMITED' });
  });

  it('keys by userId from event.locals when keyByUser is on (default)', async () => {
    const fortress = setup(1);

    await svelteKitRateLimit(fortress, 'api', mockEvent({ 'x-forwarded-for': '10.0.0.2' }, '42'));

    // Same IP+user → second hit blocked.
    await expect(
      svelteKitRateLimit(fortress, 'api', mockEvent({ 'x-forwarded-for': '10.0.0.2' }, '42')),
    ).rejects.toBeInstanceOf(FortressError);
  });

  it('throws synchronously when the plugin is not registered', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
    await expect(
      svelteKitRateLimit(fortress, 'api', mockEvent({ 'x-forwarded-for': '10.0.0.3' })),
    ).rejects.toThrow(/rate-limit plugin is not registered/);
  });
});
