/**
 * Unit tests for the shared request-principal resolver
 * (`src/core/http/principal.ts`). Exercises the plugin-chain + JWT
 * fallback pipeline that both `handleRequest` and the adapter user-route
 * middleware delegate to.
 */

import type { FortressPlugin } from '../plugin';
import type { Subject } from '../types';
import { beforeEach, describe, expect, it } from 'vitest';
import { apiKey } from '../../plugins/api-key';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';
import { resolveRequestPrincipal, tryPluginPrincipal } from './principal';

const SECRET = 'principal-resolver-test-secret-32char!';

async function makeFortressWithApiKey() {
  const fortress = createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
    plugins: [apiKey({ prefix: 'test' })],
  });
  const user = await fortress.auth.createUser({
    email: 'u@example.com',
    name: 'User',
    password: 'password-123456',
  });
  const sa = await fortress.iam.createServiceAccount({ name: 'ci-bot' });
  const userKey = await fortress.plugins['api-key'].createKey({
    subject: { type: 'USER', id: user.id },
    name: 'user-key',
  });
  const saKey = await fortress.plugins['api-key'].createKey({
    subject: { type: 'SERVICE_ACCOUNT', id: sa.id },
    name: 'sa-key',
  });
  return { fortress, user, sa, userKey: userKey.key, saKey: saKey.key };
}

describe('tryPluginPrincipal', () => {
  it('returns null when no plugin is registered', async () => {
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
    const result = await tryPluginPrincipal(
      fortress,
      new Request('http://localhost/api/anything'),
    );
    expect(result).toBeNull();
  });

  it('returns null when a plugin is registered but no credential is present', async () => {
    const { fortress } = await makeFortressWithApiKey();
    const result = await tryPluginPrincipal(
      fortress,
      new Request('http://localhost/api/anything'),
    );
    expect(result).toBeNull();
  });

  it('resolves a USER subject from Authorization: ApiKey', async () => {
    const { fortress, user, userKey } = await makeFortressWithApiKey();
    const result = await tryPluginPrincipal(
      fortress,
      new Request('http://localhost/api/anything', {
        headers: { authorization: `ApiKey ${userKey}` },
      }),
    );
    expect(result).not.toBeNull();
    expect(result?.subject).toEqual({ type: 'USER', id: user.id });
  });

  it('resolves a SERVICE_ACCOUNT subject from X-API-Key', async () => {
    const { fortress, sa, saKey } = await makeFortressWithApiKey();
    const result = await tryPluginPrincipal(
      fortress,
      new Request('http://localhost/api/anything', {
        headers: { 'x-api-key': saKey },
      }),
    );
    expect(result).not.toBeNull();
    expect(result?.subject).toEqual({ type: 'SERVICE_ACCOUNT', id: sa.id });
  });

  it('returns null for an unknown api-key', async () => {
    const { fortress } = await makeFortressWithApiKey();
    const result = await tryPluginPrincipal(
      fortress,
      new Request('http://localhost/api/anything', {
        headers: { authorization: 'ApiKey test_sk_not-a-real-key' },
      }),
    );
    expect(result).toBeNull();
  });

  it('walks plugins in registration order — first non-null wins', async () => {
    // Two synthetic resolving plugins: only the second would return non-null
    // if the first deferred. Assert the first-registered plugin wins when
    // both would match.
    const calls: string[] = [];
    const firstHit: FortressPlugin = {
      name: 'first',
      resolvePrincipal: async () => {
        calls.push('first');
        return { subject: { type: 'USER', id: '100' } };
      },
    };
    const secondHit: FortressPlugin = {
      name: 'second',
      resolvePrincipal: async () => {
        calls.push('second');
        return { subject: { type: 'USER', id: '200' } };
      },
    };
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [firstHit, secondHit],
    });
    const result = await tryPluginPrincipal(
      fortress,
      new Request('http://localhost/api/anything'),
    );
    expect(result?.subject).toEqual({ type: 'USER', id: '100' });
    expect(calls).toEqual(['first']); // second never ran
  });

  it('defers to the next plugin when a resolver returns null', async () => {
    const calls: string[] = [];
    const firstDefers: FortressPlugin = {
      name: 'first',
      resolvePrincipal: async () => {
        calls.push('first');
        return null;
      },
    };
    const secondHit: FortressPlugin = {
      name: 'second',
      resolvePrincipal: async () => {
        calls.push('second');
        return { subject: { type: 'SERVICE_ACCOUNT', id: '42' } };
      },
    };
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [firstDefers, secondHit],
    });
    const result = await tryPluginPrincipal(
      fortress,
      new Request('http://localhost/api/anything'),
    );
    expect(result?.subject).toEqual({ type: 'SERVICE_ACCOUNT', id: '42' });
    expect(calls).toEqual(['first', 'second']);
  });

  it('bounds standalone capability fixtures to membership from their first call', async () => {
    const baseline = createFortress({ jwt: { key: SECRET }, database: createTestAdapter() });
    const calls: string[] = [];
    const plugins: FortressPlugin[] = [{
      name: 'initial',
      resolvePrincipal: async () => {
        calls.push('initial');
        return null;
      },
    }];
    const fixture = {
      auth: baseline.auth,
      iam: baseline.iam,
      config: { ...baseline.config, plugins },
      extractAccessToken: baseline.extractAccessToken,
    };
    const request = new Request('http://localhost/fixture');

    expect(await tryPluginPrincipal(fixture, request)).toBeNull();
    plugins.splice(0, plugins.length, {
      name: 'late',
      resolvePrincipal: async () => ({ subject: { type: 'USER', id: 'attacker' } }),
    });
    expect(await tryPluginPrincipal(fixture, request)).toBeNull();
    expect(calls).toEqual(['initial', 'initial']);
  });

  it('skips plugins that do not implement resolvePrincipal', async () => {
    const unrelated: FortressPlugin = { name: 'unrelated' };
    const hit: FortressPlugin = {
      name: 'hit',
      resolvePrincipal: async () => ({ subject: { type: 'USER', id: '7' } }),
    };
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [unrelated, hit],
    });
    const result = await tryPluginPrincipal(
      fortress,
      new Request('http://localhost/'),
    );
    expect(result?.subject).toEqual({ type: 'USER', id: '7' });
  });
});

describe('resolveRequestPrincipal', () => {
  let fortress: Awaited<ReturnType<typeof makeFortressWithApiKey>>['fortress'];
  let user: Awaited<ReturnType<typeof makeFortressWithApiKey>>['user'];
  let sa: Awaited<ReturnType<typeof makeFortressWithApiKey>>['sa'];
  let userKey: string;
  let saKey: string;
  let validAccessToken: string;

  beforeEach(async () => {
    const setup = await makeFortressWithApiKey();
    fortress = setup.fortress;
    user = setup.user;
    sa = setup.sa;
    userKey = setup.userKey;
    saKey = setup.saKey;

    const login = await fortress.auth.login('u@example.com', 'password-123456');
    if (login.status !== 'success')
      throw new Error('login should succeed');
    validAccessToken = login.accessToken;
  });

  it('returns null when no credential is present', async () => {
    const result = await resolveRequestPrincipal(
      fortress,
      new Request('http://localhost/api'),
    );
    expect(result).toBeNull();
  });

  it('resolves via the plugin chain BEFORE trying the JWT', async () => {
    // Present BOTH a valid JWT and an api-key. The plugin-resolved principal
    // should win (this matches handle-request semantics and is the whole
    // reason we wired the chain into user-route middleware).
    const result = await resolveRequestPrincipal(
      fortress,
      new Request('http://localhost/api', {
        headers: {
          'authorization': `Bearer ${validAccessToken}`,
          'x-api-key': saKey,
        },
      }),
    );
    expect(result?.subject).toEqual({ type: 'SERVICE_ACCOUNT', id: sa.id });
  });

  it('falls back to JWT bearer when no plugin matches', async () => {
    const result = await resolveRequestPrincipal(
      fortress,
      new Request('http://localhost/api', {
        headers: { authorization: `Bearer ${validAccessToken}` },
      }),
    );
    expect(result?.subject).toEqual({ type: 'USER', id: user.id });
    expect(result?.claims).toBeDefined();
    expect(result?.claims?.sub).toBe(user.id);
  });

  it('resolves a USER api-key via the plugin chain', async () => {
    const result = await resolveRequestPrincipal(
      fortress,
      new Request('http://localhost/api', {
        headers: { authorization: `ApiKey ${userKey}` },
      }),
    );
    expect(result?.subject).toEqual({ type: 'USER', id: user.id });
    // api-key path doesn't carry JWT claims
    expect(result?.claims).toBeUndefined();
  });

  it('returns null (does NOT throw) for an invalid JWT', async () => {
    const result = await resolveRequestPrincipal(
      fortress,
      new Request('http://localhost/api', {
        headers: { authorization: 'Bearer definitely-not-a-jwt' },
      }),
    );
    expect(result).toBeNull();
  });

  it('returns null (does NOT throw) for a malformed JWT with tampered signature', async () => {
    // Take a real JWT and flip the FIRST signature char. Mangling the last
    // base64url char is non-deterministic — the trailing char only carries a
    // few significant bits, so a different char can decode to the same
    // signature bytes (and occasionally the original char already is the
    // replacement). A mid-segment char carries full bits, so flipping it
    // always invalidates the signature.
    const parts = validAccessToken.split('.');
    const sig = requireAt(parts, 2, 'JWT signature segment');
    parts[2] = (sig[0] === 'A' ? 'B' : 'A') + sig.slice(1);
    const bad = parts.join('.');
    const result = await resolveRequestPrincipal(
      fortress,
      new Request('http://localhost/api', {
        headers: { authorization: `Bearer ${bad}` },
      }),
    );
    expect(result).toBeNull();
  });

  it('reads the access token from the configured cookie as JWT fallback', async () => {
    const result = await resolveRequestPrincipal(
      fortress,
      new Request('http://localhost/api', {
        headers: {
          cookie: `${fortress.cookies.accessName}=${validAccessToken}`,
        },
      }),
    );
    expect(result?.subject).toEqual({ type: 'USER', id: user.id });
  });

  it('resolves a SERVICE_ACCOUNT principal even though it has no USER analogue', async () => {
    const result = await resolveRequestPrincipal(
      fortress,
      new Request('http://localhost/api', {
        headers: { 'x-api-key': saKey },
      }),
    );
    expect(result?.subject.type).toBe('SERVICE_ACCOUNT');
    expect(result?.subject.id).toBe(sa.id);
  });
});

describe('fortress.resolvePrincipal (instance method)', () => {
  it('exposes the same resolver as the module-level helper', async () => {
    const { fortress, userKey } = await makeFortressWithApiKey();
    const result = await fortress.resolvePrincipal(
      new Request('http://localhost/', {
        headers: { authorization: `ApiKey ${userKey}` },
      }),
    );
    expect(result?.subject.type).toBe('USER');
  });

  it('returns null when no credential is present', async () => {
    const { fortress } = await makeFortressWithApiKey();
    const result = await fortress.resolvePrincipal(
      new Request('http://localhost/'),
    );
    expect(result).toBeNull();
  });
});

// Guard against the regression where plugins list is passed via `unknown` and
// silently loses its type. The resolver accepts any Subject shape back from a
// plugin and threads it through unchanged.
describe('resolveRequestPrincipal — subject shape pass-through', () => {
  it('preserves arbitrary SubjectType values from plugins', async () => {
    const custom: FortressPlugin = {
      name: 'group-resolver',
      resolvePrincipal: async (): Promise<{ subject: Subject }> => ({
        subject: { type: 'GROUP', id: '99' },
      }),
    };
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [custom],
    });
    const result = await resolveRequestPrincipal(
      fortress,
      new Request('http://localhost/'),
    );
    expect(result?.subject).toEqual({ type: 'GROUP', id: '99' });
  });
});
function requireAt<T>(values: readonly T[], index: number, description: string): T {
  const value = values[index];
  if (value === undefined)
    throw new Error(`Expected ${description}`);
  return value;
}
