/**
 * Drives the expressRateLimit middleware directly (no real Express runtime)
 * to confirm it calls the plugin's check() and surfaces errors via next(err).
 */

import type { MinimalExpressRequest } from './express';
import { describe, expect, it } from 'vitest';
import { FortressError } from '../../core/errors';
import { createFortress } from '../../core/fortress';
import { createTestAdapter } from '../../testing';
import { expressRateLimit } from './express';
import { rateLimit } from './index';

const SECRET = 'express-rate-limit-wrapper-test-secret32!';

function setup(maxPerIp: number) {
  const fortress = createFortress({
    jwt: { secret: SECRET },
    database: createTestAdapter(),
    plugins: [rateLimit({ rules: { api: { maxPerIp, windowSeconds: 60 } } })],
  });
  return fortress;
}

function mockReq(overrides: Partial<MinimalExpressRequest> = {}): MinimalExpressRequest {
  return { headers: {}, ...overrides };
}

async function invoke(
  mw: (req: MinimalExpressRequest, res: unknown, next: (err?: unknown) => void) => void,
  req: MinimalExpressRequest,
): Promise<{ err?: unknown; called: boolean }> {
  return new Promise((resolve) => {
    let called = false;
    mw(req, {}, (err?: unknown) => {
      called = true;
      resolve({ err, called });
    });
  });
}

describe('expressRateLimit (framework wrapper)', () => {
  it('calls next() under the limit and next(FortressError) when exceeded', async () => {
    const fortress = setup(2);
    const mw = expressRateLimit(fortress, 'api');

    const r1 = await invoke(mw, mockReq({ ip: '10.0.0.1' }));
    const r2 = await invoke(mw, mockReq({ ip: '10.0.0.1' }));
    expect(r1.err).toBeUndefined();
    expect(r2.err).toBeUndefined();

    const r3 = await invoke(mw, mockReq({ ip: '10.0.0.1' }));
    expect(r3.err).toBeInstanceOf(FortressError);
    expect((r3.err as FortressError).code).toBe('RATE_LIMITED');
    expect((r3.err as FortressError).retryAfter).toBeGreaterThan(0);
  });

  it('falls back to x-forwarded-for when req.ip is missing', async () => {
    const fortress = setup(1);
    const mw = expressRateLimit(fortress, 'api');

    // First request with XFF only — should pass.
    const r1 = await invoke(mw, mockReq({ headers: { 'x-forwarded-for': '10.0.0.9' } }));
    expect(r1.err).toBeUndefined();

    // Same XFF, second hit — should be limited.
    const r2 = await invoke(mw, mockReq({ headers: { 'x-forwarded-for': '10.0.0.9' } }));
    expect(r2.err).toBeInstanceOf(FortressError);
  });

  it('keys by user when fortressUserId is present and keyByUser is on (default)', async () => {
    const fortress = setup(1);
    const mw = expressRateLimit(fortress, 'api');

    // User 1 gets one hit, then blocked on same IP+user combo.
    const r1 = await invoke(mw, mockReq({ ip: '10.0.0.5', fortressUserId: 1 }));
    const r2 = await invoke(mw, mockReq({ ip: '10.0.0.5', fortressUserId: 1 }));
    expect(r1.err).toBeUndefined();
    expect(r2.err).toBeInstanceOf(FortressError);
  });

  it('throws synchronously during setup when the plugin is not registered', () => {
    const fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
    });
    expect(() => expressRateLimit(fortress, 'api')).toThrow(/rate-limit plugin is not registered/);
  });
});
