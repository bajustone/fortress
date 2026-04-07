/**
 * Integration tests: FortressSchema → EndpointDefinition → validation middleware → Hono handler.
 *
 * Tests the full flow from schema definition to HTTP request/response.
 */

import type { Infer } from '../core/json-schema';
import { Hono } from 'hono';
import { beforeEach, describe, expect, it } from 'vitest';
import { arr, endpoint, enums, int, obj, str } from '../core/schema-builder';
import { createValidationMiddleware } from './validation-middleware';

// ── Define typed endpoints ──────────────────────────────────────────

const createUserBody = obj(
  {
    name: str('User name'),
    email: str('Email address'),
    role: enums('admin', 'user'),
  },
  'name',
  'email',
  'role',
);
type CreateUserBody = Infer<typeof createUserBody>;

const listUsersQuery = obj({
  page: int('Page number'),
  limit: int('Items per page'),
  search: str('Search term'),
});

const appEndpoints = [
  endpoint('POST', '/api/users')
    .summary('Create user')
    .tags('Users')
    .security('bearer')
    .body(createUserBody)
    .response(201, 'User created')
    .handler('createUser')
    .build(),

  endpoint('GET', '/api/users')
    .summary('List users')
    .tags('Users')
    .security('bearer')
    .query(listUsersQuery)
    .response(200, 'User list')
    .handler('listUsers')
    .build(),

  endpoint('GET', '/api/users/:id')
    .summary('Get user')
    .tags('Users')
    .security('bearer')
    .params(obj({ id: int('User ID') }, 'id'))
    .response(200, 'User detail')
    .handler('getUser')
    .build(),

  endpoint('POST', '/api/items')
    .summary('Create item')
    .body(obj({ title: str(), tags: arr(str()) }, 'title', 'tags'))
    .handler('createItem')
    .build(),
];

let app: Hono;

beforeEach(() => {
  app = new Hono();

  // Validation middleware — validates all matched endpoints
  app.use('/*', createValidationMiddleware(appEndpoints));

  // Handlers
  app.post('/api/users', async (c) => {
    const body = await c.req.json() as CreateUserBody;
    return c.json({ id: 1, ...body }, 201);
  });

  app.get('/api/users', (c) => {
    return c.json({ users: [], total: 0 });
  });

  app.get('/api/users/:id', (c) => {
    return c.json({ id: c.req.param('id'), name: 'Alice' });
  });

  app.post('/api/items', async (c) => {
    const body = await c.req.json();
    return c.json({ ok: true, ...body }, 201);
  });

  // Unvalidated route — not in appEndpoints
  app.get('/api/health', c => c.json({ status: 'ok' }));
});

describe('validation integration', () => {
  describe('pOST /api/users — body validation', () => {
    it('accepts valid body', async () => {
      const res = await app.request('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Alice', email: 'alice@test.com', role: 'admin' }),
      });
      expect(res.status).toBe(201);
      const body = await res.json();
      expect(body.name).toBe('Alice');
      expect(body.role).toBe('admin');
    });

    it('rejects missing required fields', async () => {
      const res = await app.request('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Alice' }),
      });
      expect(res.status).toBe(422);
      const body = await res.json();
      expect(body.code).toBe('VALIDATION_ERROR');
      expect(body.details.length).toBeGreaterThan(0);
    });

    it('rejects invalid enum value', async () => {
      const res = await app.request('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 'Alice', email: 'a@b.com', role: 'superadmin' }),
      });
      expect(res.status).toBe(422);
    });

    it('rejects wrong property type', async () => {
      const res = await app.request('/api/users', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: 123, email: 'a@b.com', role: 'user' }),
      });
      expect(res.status).toBe(422);
    });
  });

  describe('pOST /api/items — nested array validation', () => {
    it('accepts valid body with array', async () => {
      const res = await app.request('/api/items', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'My Item', tags: ['a', 'b'] }),
      });
      expect(res.status).toBe(201);
    });

    it('rejects invalid array items', async () => {
      const res = await app.request('/api/items', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'My Item', tags: [1, 2] }),
      });
      expect(res.status).toBe(422);
    });

    it('rejects missing required array field', async () => {
      const res = await app.request('/api/items', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ title: 'My Item' }),
      });
      expect(res.status).toBe(422);
    });
  });

  describe('gET /api/users/:id — params validation', () => {
    it('rejects non-integer path param', async () => {
      const res = await app.request('/api/users/abc');
      expect(res.status).toBe(422);
    });
  });

  describe('gET /api/health — unmatched route passthrough', () => {
    it('passes through routes not in endpoint list', async () => {
      const res = await app.request('/api/health');
      expect(res.status).toBe(200);
      const body = await res.json();
      expect(body.status).toBe('ok');
    });
  });

  describe('type inference', () => {
    it('createUserBody infers correct type', () => {
      // Compile-time check — if this compiles, inference works
      void (0 as unknown as CreateUserBody satisfies {
        name: string;
        email: string;
        role: 'admin' | 'user';
      });
      expect(true).toBe(true);
    });
  });
});
