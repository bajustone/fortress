/**
 * Pipeline CSRF check (H5) regression tests.
 *
 * Cover the matrix:
 * - Safe methods always pass.
 * - Bearer / API-key flows skip even when unsafe.
 * - Cookie-authenticated POST with no CSRF header → 403.
 * - Cookie-authenticated POST with valid CSRF header → passes.
 * - `Sec-Fetch-Site: cross-site` → 403 regardless of header.
 * - Opt-out via `csrf: { enabled: false }` disables the check.
 */

import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

interface LoginResult { accessToken: string; refreshToken: string }

async function setup(csrf?: { enabled?: boolean }): Promise<{ fortress: Awaited<ReturnType<typeof createFortress>>; login: LoginResult }> {
  const fortress = createFortress({
    database: createTestAdapter(),
    jwt: { key: 'x'.repeat(32) },
    cookies: { secure: false },
    csrf,
  });
  await fortress.auth.createUser({ email: 'csrf@test.com', name: 'C', password: 'pass-test-1234' });
  const login = await fortress.auth.login('csrf@test.com', 'pass-test-1234');
  return { fortress, login: { accessToken: login.accessToken!, refreshToken: login.refreshToken! } };
}

describe('pipeline CSRF check (H5)', () => {
  let fortress: Awaited<ReturnType<typeof createFortress>>;
  let login: LoginResult;

  beforeEach(async () => {
    ({ fortress, login } = await setup());
  });

  it('safe methods pass without CSRF header', async () => {
    const res = await fortress.handleRequest(new Request('http://localhost/auth/me', {
      headers: { cookie: `${fortress.cookies.accessName}=${login.accessToken}` },
    }));
    expect(res.status).toBe(200);
  });

  it('bearer POST passes without CSRF header', async () => {
    const res = await fortress.handleRequest(new Request('http://localhost/auth/logout', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'authorization': `Bearer ${login.accessToken}`,
      },
      body: JSON.stringify({ refreshToken: login.refreshToken }),
    }));
    // Logout uses security:['none'] but cookie absence + bearer header
    // means no cookie auth ambient credential — CSRF skipped.
    expect(res.status).toBe(200);
  });

  it('cookie POST without CSRF header is rejected (403)', async () => {
    const res = await fortress.handleRequest(new Request('http://localhost/auth/logout', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cookie': `${fortress.cookies.accessName}=${login.accessToken}`,
      },
      body: JSON.stringify({ refreshToken: login.refreshToken }),
    }));
    expect(res.status).toBe(403);
  });

  it('cookie POST with custom CSRF header passes', async () => {
    const res = await fortress.handleRequest(new Request('http://localhost/auth/logout', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cookie': `${fortress.cookies.accessName}=${login.accessToken}`,
        'x-fortress-csrf': '1',
      },
      body: JSON.stringify({ refreshToken: login.refreshToken }),
    }));
    expect(res.status).toBe(200);
  });

  it('sec-fetch-site: cross-site is rejected even with the header', async () => {
    const res = await fortress.handleRequest(new Request('http://localhost/auth/logout', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cookie': `${fortress.cookies.accessName}=${login.accessToken}`,
        'x-fortress-csrf': '1',
        'sec-fetch-site': 'cross-site',
      },
      body: JSON.stringify({ refreshToken: login.refreshToken }),
    }));
    expect(res.status).toBe(403);
  });

  it('refresh-cookie-only request (expired access) is still CSRF-checked', async () => {
    // A session whose access cookie has expired still carries the refresh
    // cookie. Such a request has ambient credentials and must not slip the
    // check by virtue of the access cookie being absent.
    const res = await fortress.handleRequest(new Request('http://localhost/auth/logout', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cookie': `${fortress.cookies.refreshName}=${login.refreshToken}`,
      },
      body: JSON.stringify({ refreshToken: login.refreshToken }),
    }));
    expect(res.status).toBe(403);
  });

  it('opting out via csrf.enabled=false disables the check', async () => {
    const optedOut = await setup({ enabled: false });
    const res = await optedOut.fortress.handleRequest(new Request('http://localhost/auth/logout', {
      method: 'POST',
      headers: {
        'content-type': 'application/json',
        'cookie': `${optedOut.fortress.cookies.accessName}=${optedOut.login.accessToken}`,
      },
      body: JSON.stringify({ refreshToken: optedOut.login.refreshToken }),
    }));
    expect(res.status).toBe(200);
  });
});
