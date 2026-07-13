import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { createCsrfMiddleware } from './csrf';

describe('csrf middleware', () => {
  it('allows GET requests without CSRF header', async () => {
    const app = new Hono();
    app.use('/*', createCsrfMiddleware());
    app.get('/api/data', c => c.json({ ok: true }));

    const res = await app.request('/api/data', { method: 'GET' });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({ ok: true });
  });

  it('allows POST requests with valid CSRF header', async () => {
    const app = new Hono();
    app.use('/*', createCsrfMiddleware());
    app.post('/api/data', c => c.json({ ok: true }));

    const res = await app.request('/api/data', {
      method: 'POST',
      headers: { 'X-Fortress-CSRF': '1' },
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({ ok: true });
  });

  it('blocks POST requests without CSRF header (403)', async () => {
    const app = new Hono();
    app.use('/*', createCsrfMiddleware());
    app.post('/api/data', c => c.json({ ok: true }));

    const res = await app.request('/api/data', {
      method: 'POST',
    });

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe('CSRF_MISSING');
  });

  it('allows requests to skip paths', async () => {
    const app = new Hono();
    app.use('/*', createCsrfMiddleware({ skipPaths: ['/webhook'] }));
    app.post('/webhook', c => c.json({ ok: true }));

    const res = await app.request('/webhook', {
      method: 'POST',
    });

    expect(res.status).toBe(200);
    const body = await res.json();
    expect(body).toEqual({ ok: true });
  });

  it('matches skip paths at segment boundaries', async () => {
    const app = new Hono();
    app.use('/*', createCsrfMiddleware({ skipPaths: ['/webhook'] }));
    app.post('/webhook/delivery', c => c.json({ ok: true }));
    app.post('/webhook-evil', c => c.json({ ok: true }));

    expect((await app.request('/webhook/delivery', { method: 'POST' })).status).toBe(200);
    expect((await app.request('/webhook-evil', { method: 'POST' })).status).toBe(403);
  });

  it('blocks cross-site requests (Sec-Fetch-Site: cross-site)', async () => {
    const app = new Hono();
    app.use('/*', createCsrfMiddleware());
    app.post('/api/data', c => c.json({ ok: true }));

    const res = await app.request('/api/data', {
      method: 'POST',
      headers: {
        'X-Fortress-CSRF': '1',
        'Sec-Fetch-Site': 'cross-site',
      },
    });

    expect(res.status).toBe(403);
    const body = await res.json();
    expect(body.error).toBe('CSRF_REJECTED');
  });

  it('custom header name works', async () => {
    const app = new Hono();
    app.use('/*', createCsrfMiddleware({ headerName: 'X-Custom-CSRF' }));
    app.post('/api/data', c => c.json({ ok: true }));

    // Should fail with default header name
    const res1 = await app.request('/api/data', {
      method: 'POST',
      headers: { 'X-Fortress-CSRF': '1' },
    });
    expect(res1.status).toBe(403);

    // Should succeed with custom header name
    const res2 = await app.request('/api/data', {
      method: 'POST',
      headers: { 'X-Custom-CSRF': '1' },
    });
    expect(res2.status).toBe(200);
  });

  it('custom safe methods work', async () => {
    const app = new Hono();
    app.use('/*', createCsrfMiddleware({ safeMethods: ['GET', 'HEAD', 'OPTIONS', 'POST'] }));
    app.post('/api/data', c => c.json({ ok: true }));
    app.put('/api/data', c => c.json({ ok: true }));

    // POST is now safe, should pass without CSRF header
    const res1 = await app.request('/api/data', {
      method: 'POST',
    });
    expect(res1.status).toBe(200);

    // PUT is not safe, should fail without CSRF header
    const res2 = await app.request('/api/data', {
      method: 'PUT',
    });
    expect(res2.status).toBe(403);
  });
});
