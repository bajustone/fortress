import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { createFortress } from '../../core/fortress';
import { definePlugin } from '../../core/plugin';
import { createHonoMiddleware } from '../../hono';
import { createTestAdapter } from '../../testing';
import { honoRateLimit } from './hono';
import { rateLimit } from './index';

const SECRET = 'hono-rate-limit-wrapper-test-secret-32!';

describe('honoRateLimit (framework wrapper)', () => {
  function setup(ruleMaxPerIp: number) {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [
        rateLimit({
          rules: { api: { maxPerIp: ruleMaxPerIp, windowSeconds: 60 } },
        }),
      ],
    });
    const { errorHandler } = createHonoMiddleware(fortress);
    const app = new Hono();
    app.onError(errorHandler);
    app.use('/api/*', honoRateLimit(fortress, 'api'));
    app.get('/api/things', c => c.json({ ok: true }));
    return { fortress, app };
  }

  it('allows requests under the limit and blocks the next with 429 + Retry-After', async () => {
    const { app } = setup(2);
    const headers = { 'x-forwarded-for': '10.0.0.1' };

    const r1 = await app.request('/api/things', { headers });
    const r2 = await app.request('/api/things', { headers });
    expect(r1.status).toBe(200);
    expect(r2.status).toBe(200);

    const r3 = await app.request('/api/things', { headers });
    expect(r3.status).toBe(429);
    expect(r3.headers.get('Retry-After')).toBeTruthy();
  });

  it('keys by IP — different forwarded-for values have separate buckets', async () => {
    const { app } = setup(1);

    const a = await app.request('/api/things', { headers: { 'x-forwarded-for': '10.0.0.2' } });
    const b = await app.request('/api/things', { headers: { 'x-forwarded-for': '10.0.0.3' } });
    expect(a.status).toBe(200);
    expect(b.status).toBe(200); // different IP, still in budget
  });

  it('accepts the check-only surface consumed by the framework helper', async () => {
    const check = async (): Promise<void> => {};
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [definePlugin({
        name: 'rate-limit',
        methods: () => ({ check }),
      })],
    });
    const app = new Hono();
    app.use('/api/*', honoRateLimit(fortress, 'api'));
    app.get('/api/things', c => c.json({ ok: true }));
    expect((await app.request('/api/things')).status).toBe(200);
  });

  it('rejects a surface without the consumed check method', () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [definePlugin({ name: 'rate-limit' })],
    });
    expect(() => honoRateLimit(fortress, 'api')).toThrow(/rate-limit plugin is not registered/);
  });

  it('throws synchronously during setup when the plugin is not registered', () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
    expect(() => honoRateLimit(fortress, 'api')).toThrow(/rate-limit plugin is not registered/);
  });
});
