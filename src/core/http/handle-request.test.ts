import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

const SECRET = 'fortress-test-secret-at-least-32-bytes-long!';

function makeFortress() {
  return createFortress({
    jwt: { secret: SECRET },
    database: createTestAdapter(),
  });
}

interface AuthBody {
  status: string;
  user: { id: number; email: string };
  accessToken: string;
  refreshToken: string;
}

describe('fortress.handleRequest', () => {
  let fortress: ReturnType<typeof makeFortress>;

  beforeEach(() => {
    fortress = makeFortress();
  });

  describe('public endpoints', () => {
    it('creates a user via POST /auth/register (201)', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/auth/register', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ email: 'a@b.co', name: 'Alice', password: 'password123' }),
      }));
      expect(res.status).toBe(201);
      const body = await res.json() as { id: number; email: string };
      expect(body.email).toBe('a@b.co');
    });

    it('returns tokens AND sets cookies on successful POST /auth/login', async () => {
      // create user via service to skip the http-layer registration above
      await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password123' });

      const res = await fortress.handleRequest(new Request('http://localhost/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ identifier: 'a@b.co', password: 'password123' }),
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as AuthBody;
      expect(typeof body.accessToken).toBe('string');
      expect(typeof body.refreshToken).toBe('string');

      const setCookies = res.headers.getSetCookie();
      expect(setCookies.length).toBe(2);
      expect(setCookies.some(c => c.startsWith(`${fortress.cookies.accessName}=`))).toBe(true);
      expect(setCookies.some(c => c.startsWith(`${fortress.cookies.refreshName}=`))).toBe(true);
    });

    it('returns 401 from POST /auth/login with bad creds', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ identifier: 'nope@b.co', password: 'wrong' }),
      }));
      expect(res.status).toBe(401);
      const body = await res.json() as { code: string };
      expect(body.code).toBe('UNAUTHORIZED');
      // No cookies on a failed login
      expect(res.headers.getSetCookie().length).toBe(0);
    });

    it('returns 404 for unknown endpoints', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/nope/whatever'));
      expect(res.status).toBe(404);
    });
  });

  describe('bearer-protected endpoints', () => {
    let accessToken: string;

    beforeEach(async () => {
      await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password123' });
      const result = await fortress.auth.login('a@b.co', 'password123');
      if (result.status !== 'success')
        throw new Error('expected success');
      accessToken = result.accessToken;
    });

    it('returns 401 from GET /auth/me without a token', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/auth/me'));
      expect(res.status).toBe(401);
    });

    it('returns the user from GET /auth/me with Bearer token', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/auth/me', {
        headers: { authorization: `Bearer ${accessToken}` },
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as { email: string };
      expect(body.email).toBe('a@b.co');
    });

    it('reads the token from the configured cookie on GET /auth/me', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/auth/me', {
        headers: { cookie: `${fortress.cookies.accessName}=${accessToken}` },
      }));
      expect(res.status).toBe(200);
    });
  });

  describe('refresh flow', () => {
    it('issues new tokens AND sets new cookies on POST /auth/refresh', async () => {
      await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password123' });
      const login = await fortress.auth.login('a@b.co', 'password123');
      if (login.status !== 'success')
        throw new Error('expected success');

      const res = await fortress.handleRequest(new Request('http://localhost/auth/refresh', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({ refreshToken: login.refreshToken }),
      }));
      expect(res.status).toBe(200);
      const body = await res.json() as { accessToken: string; refreshToken: string };
      expect(typeof body.accessToken).toBe('string');
      expect(typeof body.refreshToken).toBe('string');
      expect(body.refreshToken).not.toBe(login.refreshToken); // rotated

      const setCookies = res.headers.getSetCookie();
      expect(setCookies.length).toBe(2);
    });
  });

  describe('iam endpoints (bearer + permission)', () => {
    let accessToken: string;

    beforeEach(async () => {
      // (Skipping syncResources here — without resources synced, checkPermission
      // returns false, which is exactly what we want to assert default-deny.)
      await fortress.auth.createUser({ email: 'admin@x.co', name: 'Admin', password: 'password123' });
      const result = await fortress.auth.login('admin@x.co', 'password123');
      if (result.status !== 'success')
        throw new Error('expected success');
      accessToken = result.accessToken;
    });

    it('returns 403 from POST /iam/roles without permission', async () => {
      const res = await fortress.handleRequest(new Request('http://localhost/iam/roles', {
        method: 'POST',
        headers: {
          'authorization': `Bearer ${accessToken}`,
          'content-type': 'application/json',
        },
        body: JSON.stringify({ name: 'editor', permissions: [] }),
      }));
      expect(res.status).toBe(403);
    });
  });

  describe('validation', () => {
    it('returns 422 when required fields are missing', async () => {
      // /auth/login requires identifier + password
      const res = await fortress.handleRequest(new Request('http://localhost/auth/login', {
        method: 'POST',
        headers: { 'content-type': 'application/json' },
        body: JSON.stringify({}),
      }));
      expect(res.status).toBe(422);
      const body = await res.json() as { code: string };
      expect(body.code).toBe('VALIDATION_ERROR');
    });
  });
});
