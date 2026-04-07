import { Hono } from 'hono';
import { describe, expect, it } from 'vitest';
import { endpoint, int, obj, str } from '../core/schema-builder';
import { createValidationMiddleware } from './validation-middleware';

const endpoints = [
  endpoint('POST', '/users')
    .body(obj({ name: str(), email: str() }, 'name', 'email'))
    .handler('createUser')
    .build(),

  endpoint('GET', '/users/:id')
    .params(obj({ id: int('User ID') }, 'id'))
    .handler('getUser')
    .build(),

  endpoint('GET', '/search')
    .query(obj({ q: str('Search query') }, 'q'))
    .handler('search')
    .build(),
];

function createApp(): Hono {
  const app = new Hono();
  app.use('/*', createValidationMiddleware(endpoints));
  app.post('/users', c => c.json({ ok: true }));
  app.get('/users/:id', c => c.json({ id: c.req.param('id') }));
  app.get('/search', c => c.json({ q: 'ok' }));
  app.get('/unmatched', c => c.json({ ok: true }));
  return app;
}

describe('createValidationMiddleware', () => {
  it('passes valid POST body', async () => {
    const app = createApp();
    const res = await app.request('/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Alice', email: 'alice@test.com' }),
    });
    expect(res.status).toBe(200);
  });

  it('rejects invalid POST body (missing required)', async () => {
    const app = createApp();
    const res = await app.request('/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 'Alice' }),
    });
    expect(res.status).toBe(422);
    const body = await res.json();
    expect(body.code).toBe('VALIDATION_ERROR');
    expect(body.details).toBeDefined();
  });

  it('rejects invalid POST body (wrong type)', async () => {
    const app = createApp();
    const res = await app.request('/users', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ name: 123, email: 'alice@test.com' }),
    });
    expect(res.status).toBe(422);
  });

  it('passes through unmatched routes', async () => {
    const app = createApp();
    const res = await app.request('/unmatched');
    expect(res.status).toBe(200);
  });

  it('validates params on parameterized paths', async () => {
    const app = createApp();
    // Params come as strings from URL — int validator will catch non-integer strings
    const res = await app.request('/users/abc');
    // The param 'abc' is a string, int() expects a number → validation fails
    expect(res.status).toBe(422);
  });

  it('validates query parameters', async () => {
    const app = createApp();
    // Missing required query param 'q'
    const res = await app.request('/search');
    expect(res.status).toBe(422);
  });

  it('passes valid query parameters', async () => {
    const app = createApp();
    const res = await app.request('/search?q=hello');
    expect(res.status).toBe(200);
  });
});
