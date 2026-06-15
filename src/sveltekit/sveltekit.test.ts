/**
 * Integration tests for the SvelteKit adapter. We mock just enough of
 * SvelteKit's `RequestEvent` shape to exercise the real fortress instance
 * end-to-end (with the in-memory test DB).
 */

import type { Fortress } from '../core/fortress';
import type { Subject } from '../core/types';
import type { FortressLocals, SvelteKitCookieOptions, SvelteKitCookies, SvelteKitRequestEvent } from './types';
import { beforeEach, describe, expect, it } from 'vitest';
import { signAccessToken } from '../core/auth/jwt';
import { createFortress } from '../core/fortress';
import { apiKey } from '../plugins/api-key';
import { createTestAdapter } from '../testing';
import { fortressActions } from './actions';
import { toSvelteKitHandler } from './catch-all';
import { replayCookies, setAuthCookies } from './cookies';
import { createSvelteKitHandle } from './handle';
import { getSubject, getUserId } from './helpers';

const SECRET = 'sveltekit-test-secret-32-chars-long!';

function makeFortress() {
  return createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
  });
}

/** Build a SvelteKit-shaped Cookies object backed by a Map. */
function fakeCookies(initial: Record<string, string> = {}): SvelteKitCookies & { _store: Map<string, string> } {
  const store = new Map(Object.entries(initial));
  return {
    _store: store,
    get: name => store.get(name),
    set: (name, value, _opts?: SvelteKitCookieOptions) => {
      store.set(name, value);
    },
    delete: (name) => {
      store.delete(name);
    },
    getAll: () => Array.from(store.entries()).map(([name, value]) => ({ name, value })),
  };
}

interface FakeEventOpts {
  method?: string;
  url?: string;
  headers?: Record<string, string>;
  cookies?: Record<string, string>;
  body?: string | FormData;
}

/** Build a fake SvelteKit `RequestEvent` for tests. */
function fakeEvent(opts: FakeEventOpts = {}): SvelteKitRequestEvent & { cookies: ReturnType<typeof fakeCookies> } {
  const url = new URL(opts.url ?? 'http://localhost/');
  const headers = new Headers(opts.headers);
  // Merge cookies into the request header so fortress.extractAccessToken sees them too.
  if (opts.cookies && Object.keys(opts.cookies).length > 0) {
    headers.set('cookie', Object.entries(opts.cookies).map(([k, v]) => `${k}=${encodeURIComponent(v)}`).join('; '));
  }
  const init: RequestInit = { method: opts.method ?? 'GET', headers };
  if (opts.body !== undefined && (opts.method === 'POST' || opts.method === 'PUT' || opts.method === 'PATCH')) {
    init.body = opts.body;
  }
  const request = new Request(url.toString(), init);
  const cookies = fakeCookies(opts.cookies);
  const event = {
    request,
    url,
    cookies,
    locals: {} as Record<string, unknown>,
    params: {},
  } satisfies SvelteKitRequestEvent;
  return event as SvelteKitRequestEvent & { cookies: ReturnType<typeof fakeCookies> };
}

// ── createSvelteKitHandle: Fortress-managed paths ───────────────────

describe('createSvelteKitHandle: fortress paths', () => {
  let fortress: ReturnType<typeof makeFortress>;

  beforeEach(() => {
    fortress = makeFortress();
  });

  it('intercepts /auth/login and returns Response without calling resolve', async () => {
    await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password123' });
    const handle = createSvelteKitHandle(fortress);
    const event = fakeEvent({
      method: 'POST',
      url: 'http://localhost/auth/login',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identifier: 'a@b.co', password: 'password123' }),
    });
    let resolveCalled = false;
    const response = await handle({
      event,
      resolve: async () => {
        resolveCalled = true;
        return new Response('should not run');
      },
    });
    expect(resolveCalled).toBe(false);
    expect(response.status).toBe(200);

    // Cookies were set on the response AND replayed into event.cookies
    expect(response.headers.getSetCookie().length).toBe(2);
    expect(event.cookies._store.get(fortress.cookies.accessName)).toBeTruthy();
    expect(event.cookies._store.get(fortress.cookies.refreshName)).toBeTruthy();
  });

  it('strips basePath before delegating to core', async () => {
    await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password123' });
    const handle = createSvelteKitHandle(fortress, { basePath: '/api' });
    const event = fakeEvent({
      method: 'POST',
      url: 'http://localhost/api/auth/login',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identifier: 'a@b.co', password: 'password123' }),
    });
    const response = await handle({ event, resolve: async () => new Response() });
    expect(response.status).toBe(200);
  });

  it('falls through to resolve for paths outside basePath', async () => {
    const handle = createSvelteKitHandle(fortress, { basePath: '/api' });
    const event = fakeEvent({ url: 'http://localhost/about' });
    const result = await handle({
      event,
      resolve: async () => new Response('user page'),
    });
    expect(await result.text()).toBe('user page');
  });
});

// ── createSvelteKitHandle: user-route auth + auto-refresh ───────────

describe('createSvelteKitHandle: user routes', () => {
  let fortress: ReturnType<typeof makeFortress>;
  let accessToken: string;

  beforeEach(async () => {
    fortress = makeFortress();
    await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password123' });
    const result = await fortress.auth.login('a@b.co', 'password123');
    if (result.status !== 'success')
      throw new Error('expected success');
    accessToken = result.accessToken;
  });

  it('populates event.locals.fortress when a valid cookie is present', async () => {
    const handle = createSvelteKitHandle(fortress);
    const event = fakeEvent({
      url: 'http://localhost/dashboard',
      cookies: { [fortress.cookies.accessName]: accessToken },
    });
    let observed: unknown;
    await handle({
      event,
      resolve: async () => {
        observed = (event.locals as { fortress?: { userId?: number } }).fortress?.userId;
        return new Response('ok');
      },
    });
    expect(observed).toBeGreaterThan(0);
    expect(getUserId(event as never)).toBe(observed);
  });

  it('falls back to Authorization: Bearer when no cookie', async () => {
    const handle = createSvelteKitHandle(fortress);
    const event = fakeEvent({
      url: 'http://localhost/dashboard',
      headers: { authorization: `Bearer ${accessToken}` },
    });
    await handle({ event, resolve: async () => new Response() });
    expect((event.locals as { fortress?: { userId?: number } }).fortress?.userId).toBeGreaterThan(0);
  });

  it('leaves locals empty when no token at all', async () => {
    const handle = createSvelteKitHandle(fortress);
    const event = fakeEvent({ url: 'http://localhost/dashboard' });
    await handle({ event, resolve: async () => new Response() });
    const locals = (event.locals as { fortress?: { userId?: number } }).fortress;
    expect(locals).toBeDefined();
    expect(locals?.userId).toBeUndefined();
  });

  it('auto-refreshes an expired access token using the refresh cookie', async () => {
    // Issue a normal login to get a valid refresh token, then pair it with a
    // deliberately expired access token. This avoids the previous 1-second
    // expiry + sleep race: on slow CI, the freshly refreshed 1-second access
    // token could expire before the adapter verified it and populated locals.
    const freshLogin = await fortress.auth.login('a@b.co', 'password123');
    if (freshLogin.status !== 'success')
      throw new Error('expected success');
    const validRefresh = freshLogin.refreshToken;
    const expiredAccess = await signAccessToken({
      sub: freshLogin.user.id,
      subjectType: 'USER',
      name: freshLogin.user.name,
      groups: [],
      iss: 'fortress',
    }, SECRET, -1);

    const handle = createSvelteKitHandle(fortress);
    const event = fakeEvent({
      url: 'http://localhost/dashboard',
      cookies: {
        [fortress.cookies.accessName]: expiredAccess,
        [fortress.cookies.refreshName]: validRefresh,
      },
    });
    await handle({ event, resolve: async () => new Response() });
    // After auto-refresh, the cookie store should have a NEW access token
    // (different from the expired one) and locals.fortress.userId set.
    const newAccess = event.cookies._store.get(fortress.cookies.accessName);
    expect(newAccess).toBeTruthy();
    expect(newAccess).not.toBe(expiredAccess);
    expect((event.locals as { fortress?: { userId?: number } }).fortress?.userId).toBeGreaterThan(0);
  });

  it('does NOT silently refresh on unsafe methods (CSRF — P1.5/H5)', async () => {
    // A silent refresh rotates the refresh token, so it must not be triggered
    // by an unsafe (cross-site-reachable) request. SSR loads are GETs; an
    // expired-access POST should fall through with no subject and no rotation.
    const freshLogin = await fortress.auth.login('a@b.co', 'password123');
    if (freshLogin.status !== 'success')
      throw new Error('expected success');
    const validRefresh = freshLogin.refreshToken;
    const expiredAccess = await signAccessToken({
      sub: freshLogin.user.id,
      subjectType: 'USER',
      name: freshLogin.user.name,
      groups: [],
      iss: 'fortress',
    }, SECRET, -1);

    const handle = createSvelteKitHandle(fortress);
    const event = fakeEvent({
      method: 'POST',
      url: 'http://localhost/dashboard',
      cookies: {
        [fortress.cookies.accessName]: expiredAccess,
        [fortress.cookies.refreshName]: validRefresh,
      },
    });
    await handle({ event, resolve: async () => new Response() });
    // No rotation: access cookie unchanged, no authenticated subject.
    expect(event.cookies._store.get(fortress.cookies.accessName)).toBe(expiredAccess);
    expect((event.locals as { fortress?: { userId?: number } }).fortress?.userId).toBeUndefined();
  });
});

// ── toSvelteKitHandler ──────────────────────────────────────────────

describe('toSvelteKitHandler', () => {
  it('exports {GET, POST, PUT, DELETE, PATCH} that all delegate to handleRequest', async () => {
    const fortress = makeFortress();
    await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password123' });
    const handlers = toSvelteKitHandler(fortress);
    expect(typeof handlers.GET).toBe('function');
    expect(typeof handlers.POST).toBe('function');
    expect(typeof handlers.PUT).toBe('function');
    expect(typeof handlers.DELETE).toBe('function');
    expect(typeof handlers.PATCH).toBe('function');

    const event = fakeEvent({
      method: 'POST',
      url: 'http://localhost/auth/login',
      headers: { 'content-type': 'application/json' },
      body: JSON.stringify({ identifier: 'a@b.co', password: 'password123' }),
    });
    const response = await handlers.POST(event);
    expect(response.status).toBe(200);
  });
});

// ── fortressActions ─────────────────────────────────────────────────

describe('fortressActions.login', () => {
  it('sets cookies on success and returns { success: true }', async () => {
    const fortress = makeFortress();
    await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password123' });
    const action = fortressActions.login(fortress);
    const form = new FormData();
    form.set('identifier', 'a@b.co');
    form.set('password', 'password123');
    const event = fakeEvent({ method: 'POST', body: form });
    const result = await action(event);
    expect(result).toEqual({ success: true });
    expect(event.cookies._store.get(fortress.cookies.accessName)).toBeTruthy();
    expect(event.cookies._store.get(fortress.cookies.refreshName)).toBeTruthy();
  });

  it('returns fail() shape on bad credentials', async () => {
    const fortress = makeFortress();
    const action = fortressActions.login(fortress);
    const form = new FormData();
    form.set('identifier', 'nope@b.co');
    form.set('password', 'wrong');
    const event = fakeEvent({ method: 'POST', body: form });
    const result = await action(event) as { status: number; data: { code: string } };
    expect(result.status).toBe(401);
    expect(result.data.code).toBe('UNAUTHORIZED');
    expect(event.cookies._store.size).toBe(0);
  });

  it('throws a 303 Response when redirectTo is configured', async () => {
    const fortress = makeFortress();
    await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password123' });
    const action = fortressActions.login(fortress, { redirectTo: '/dashboard' });
    const form = new FormData();
    form.set('identifier', 'a@b.co');
    form.set('password', 'password123');
    const event = fakeEvent({ method: 'POST', body: form });

    let thrown: Response | undefined;
    try {
      await action(event);
    }
    catch (e) {
      if (e instanceof Response)
        thrown = e;
    }
    expect(thrown).toBeDefined();
    expect(thrown?.status).toBe(303);
    expect(thrown?.headers.get('location')).toBe('/dashboard');
  });
});

describe('fortressActions.logout', () => {
  it('clears auth cookies', async () => {
    const fortress = makeFortress();
    await fortress.auth.createUser({ email: 'a@b.co', name: 'Alice', password: 'password123' });
    const login = await fortress.auth.login('a@b.co', 'password123');
    if (login.status !== 'success')
      throw new Error('expected success');

    const action = fortressActions.logout(fortress);
    const event = fakeEvent({
      method: 'POST',
      cookies: {
        [fortress.cookies.accessName]: login.accessToken,
        [fortress.cookies.refreshName]: login.refreshToken,
      },
    });
    await action(event);
    expect(event.cookies._store.has(fortress.cookies.accessName)).toBe(false);
    expect(event.cookies._store.has(fortress.cookies.refreshName)).toBe(false);
  });
});

// ── cookies utilities ───────────────────────────────────────────────

describe('replayCookies', () => {
  it('mirrors Set-Cookie headers from a Response into event.cookies', async () => {
    const event = fakeEvent();
    const response = new Response('{}', {
      status: 200,
      headers: {
        'Content-Type': 'application/json',
      },
    });
    response.headers.append('set-cookie', 'foo=bar; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=60');
    response.headers.append('set-cookie', 'baz=qux; Path=/');

    replayCookies(response, event);
    expect(event.cookies._store.get('foo')).toBe('bar');
    expect(event.cookies._store.get('baz')).toBe('qux');
  });
});

describe('setAuthCookies', () => {
  it('sets both access and refresh cookies with Fortress config names', () => {
    const fortress = makeFortress();
    const event = fakeEvent();
    setAuthCookies(event, fortress, { accessToken: 'a', refreshToken: 'r' });
    expect(event.cookies._store.get(fortress.cookies.accessName)).toBe('a');
    expect(event.cookies._store.get(fortress.cookies.refreshName)).toBe('r');
  });

  it('omits the refresh cookie when refreshToken is null', () => {
    const fortress = makeFortress();
    const event = fakeEvent();
    setAuthCookies(event, fortress, { accessToken: 'a', refreshToken: null });
    expect(event.cookies._store.get(fortress.cookies.accessName)).toBe('a');
    expect(event.cookies._store.has(fortress.cookies.refreshName)).toBe(false);
  });
});

// ── createSvelteKitHandle: api-key on user routes ───────────────────

/**
 * These tests cover the gap this branch closed: plugin `resolvePrincipal`
 * hooks (api-key) must fire on user-owned routes, not just Fortress-managed
 * ones. Every request goes through `tryPluginPrincipal` before the JWT
 * fallback, so both USER and SERVICE_ACCOUNT api-keys authenticate SvelteKit
 * user routes uniformly and `event.locals.fortress.subject` is the
 * authoritative principal.
 */
describe('createSvelteKitHandle: api-key on user routes', () => {
  async function setupWithApiKey() {
    const fortress: Fortress<any> = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [apiKey({ prefix: 'test' })],
    });

    const user = await fortress.auth.createUser({
      email: 'human@example.com',
      name: 'Human',
      password: 'password-123',
    });
    const deployRole = await fortress.iam.createRole('deployer', [
      { resource: 'deploy', action: 'run' },
    ]);
    await fortress.iam.bindRoleToUser(user.id, deployRole.id);

    const sa = await fortress.iam.createServiceAccount({ name: 'ci-deploy-bot' });
    await fortress.iam.bindRoleToServiceAccount(sa.id, deployRole.id);
    const saNoPerm = await fortress.iam.createServiceAccount({ name: 'observer-bot' });

    const { key: userKey } = await fortress.plugins['api-key'].createKey({
      subject: { type: 'USER', id: user.id },
      name: 'user-key',
    });
    const { key: saKey } = await fortress.plugins['api-key'].createKey({
      subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
      name: 'sa-key',
    });
    const { key: saKeyNoPerm } = await fortress.plugins['api-key'].createKey({
      subject: { type: 'SERVICE_ACCOUNT', id: saNoPerm.id },
      name: 'observer-key',
    });

    return { fortress, user, sa, userKey, saKey, saKeyNoPerm };
  }

  it('populates locals.fortress.subject for a USER api-key', async () => {
    const { fortress, user, userKey } = await setupWithApiKey();
    const handle = createSvelteKitHandle(fortress);
    const event = fakeEvent({
      url: 'http://localhost/dashboard',
      headers: { authorization: `ApiKey ${userKey}` },
    });
    await handle({ event, resolve: async () => new Response() });
    const locals = event.locals as unknown as FortressLocals;
    expect(locals.fortress?.subject).toEqual({ type: 'USER', id: user.id });
    expect(locals.fortress?.userId).toBe(user.id);
    expect(getSubject(event as never)).toEqual({ type: 'USER', id: user.id });
    expect(getUserId(event as never)).toBe(user.id);
  });

  it('populates locals.fortress.subject for a SERVICE_ACCOUNT api-key; userId stays undefined', async () => {
    const { fortress, sa, saKey } = await setupWithApiKey();
    const handle = createSvelteKitHandle(fortress);
    const event = fakeEvent({
      url: 'http://localhost/dashboard',
      headers: { 'x-api-key': saKey },
    });
    await handle({ event, resolve: async () => new Response() });
    const locals = event.locals as unknown as FortressLocals;
    expect(locals.fortress?.subject).toEqual({ type: 'SERVICE_ACCOUNT', id: sa.id });
    // userId is USER-only
    expect(locals.fortress?.userId).toBeUndefined();
    expect(getSubject(event as never).type).toBe('SERVICE_ACCOUNT');
  });

  it('getUserId throws for a SERVICE_ACCOUNT principal', async () => {
    const { fortress, saKey } = await setupWithApiKey();
    const handle = createSvelteKitHandle(fortress);
    const event = fakeEvent({
      url: 'http://localhost/dashboard',
      headers: { 'x-api-key': saKey },
    });
    await handle({ event, resolve: async () => new Response() });
    expect(() => getUserId(event as never)).toThrow(/User not authenticated/);
  });

  it('still falls back to JWT bearer when no api-key header is present', async () => {
    const { fortress, user } = await setupWithApiKey();
    const login = await fortress.auth.login('human@example.com', 'password-123');
    if (login.status !== 'success')
      throw new Error('login should succeed');
    const handle = createSvelteKitHandle(fortress);
    const event = fakeEvent({
      url: 'http://localhost/dashboard',
      headers: { authorization: `Bearer ${login.accessToken}` },
    });
    await handle({ event, resolve: async () => new Response() });
    const locals = event.locals as unknown as FortressLocals;
    expect(locals.fortress?.subject).toEqual({ type: 'USER', id: user.id });
    expect(locals.fortress?.claims).toBeDefined();
  });

  it('plugin resolvers win over a present JWT (api-key takes priority)', async () => {
    const { fortress, sa, saKey } = await setupWithApiKey();
    const login = await fortress.auth.login('human@example.com', 'password-123');
    if (login.status !== 'success')
      throw new Error('login should succeed');
    const handle = createSvelteKitHandle(fortress);
    const event = fakeEvent({
      url: 'http://localhost/dashboard',
      headers: {
        'authorization': `Bearer ${login.accessToken}`,
        'x-api-key': saKey,
      },
    });
    await handle({ event, resolve: async () => new Response() });
    const locals = event.locals as unknown as FortressLocals;
    expect(locals.fortress?.subject).toEqual({ type: 'SERVICE_ACCOUNT', id: sa.id });
  });

  it('leaves locals empty for an unknown api-key (no fallthrough to JWT)', async () => {
    const { fortress } = await setupWithApiKey();
    const handle = createSvelteKitHandle(fortress);
    const event = fakeEvent({
      url: 'http://localhost/dashboard',
      headers: { 'x-api-key': 'test_sk_not-a-real-key' },
    });
    await handle({ event, resolve: async () => new Response() });
    const locals = event.locals as unknown as FortressLocals;
    expect(locals.fortress?.subject).toBeUndefined();
  });

  it('route-map RBAC allows a SERVICE_ACCOUNT with the required permission', async () => {
    const { fortress, saKey } = await setupWithApiKey();
    const handle = createSvelteKitHandle(fortress, {
      routeMap: { 'POST /deploy/run': { resource: 'deploy', action: 'run' } },
    });
    const event = fakeEvent({
      method: 'POST',
      url: 'http://localhost/deploy/run',
      headers: { authorization: `ApiKey ${saKey}` },
    });
    let resolved = false;
    let observed: Subject | undefined;
    const response = await handle({
      event,
      resolve: async () => {
        resolved = true;
        observed = (event.locals as unknown as FortressLocals).fortress?.subject;
        return new Response('ok');
      },
    });
    expect(response.status).toBe(200);
    expect(resolved).toBe(true);
    expect(observed?.type).toBe('SERVICE_ACCOUNT');
  });

  it('route-map RBAC denies a SERVICE_ACCOUNT without the permission', async () => {
    const { fortress, saKeyNoPerm } = await setupWithApiKey();
    const handle = createSvelteKitHandle(fortress, {
      routeMap: { 'POST /deploy/run': { resource: 'deploy', action: 'run' } },
    });
    const event = fakeEvent({
      method: 'POST',
      url: 'http://localhost/deploy/run',
      headers: { 'x-api-key': saKeyNoPerm },
    });
    let resolved = false;
    const response = await handle({
      event,
      resolve: async () => {
        resolved = true;
        return new Response('should not reach');
      },
    });
    expect(resolved).toBe(false);
    expect(response.status).toBe(403);
  });

  it('route-map RBAC returns 401 when there is no credential at all', async () => {
    const { fortress } = await setupWithApiKey();
    const handle = createSvelteKitHandle(fortress, {
      routeMap: { 'POST /deploy/run': { resource: 'deploy', action: 'run' } },
    });
    const event = fakeEvent({
      method: 'POST',
      url: 'http://localhost/deploy/run',
    });
    const response = await handle({ event, resolve: async () => new Response('x') });
    expect(response.status).toBe(401);
  });
});
