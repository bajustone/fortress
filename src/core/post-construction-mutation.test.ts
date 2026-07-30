/**
 * `createFortress()` validates a route set and then publishes it. Until the
 * validated set was snapshotted, "publishes" meant handing back the very
 * objects the caller still held: dispatch, the plugin call tree, protected
 * route handlers, and principal resolution all re-read live config, so
 * flipping `bearerKind` or rewriting `path` after construction changed how
 * requests were authenticated while the manifest kept describing the route as
 * validated.
 *
 * These tests pin the boundary against the real request pipeline rather than
 * against `endpoints`/`manifest` shape alone — shape assertions would also
 * have passed on the old, bypassable dispatch.
 *
 * Validation schemas hanging off `input`/`responses` are deliberately still
 * shared by reference, because schema identity binds `$ref` component context.
 * That is a documented non-goal, and the identity test below keeps it
 * deliberate rather than accidental.
 */

import type { FortressConfig } from './config';
import type { EndpointDefinition, SecurityRequirement } from './endpoint';
import type { RouteManifestEntry } from './manifest/route-manifest';
import type { PluginContext, PostAuthGateProvider, RuntimeFortressPlugin } from './plugin';
import { describe, expect, it, vi } from 'vitest';
import { admin } from '../plugins/admin';
import { openapi } from '../plugins/openapi';
import { checkPublicRoutes } from '../testing/checks';
import { createTestAdapter } from '../testing/index';
import { authEndpoints } from './auth/auth-endpoints';
import { createFortress } from './fortress';
import { protect } from './http/protect';
import { detectRouteManifestDrift, hasRouteManifestDrift } from './manifest/drift';
import { buildRouteManifest } from './manifest/route-manifest';
import { definePlugin } from './plugin';
import { snapshotPluginMembership } from './plugin-membership';
import {
  chainAdapterWrappers,
  collectScopeRules,
  executePluginMiddleware,
  mergeTokenClaims,
} from './plugin-runner';
import { endpointProvenance, snapshotEndpointDefinition } from './route-assembly';
import { endpoint, obj, str } from './schema-builder';

const SECRET = 'post-construction-test-secret-32-chars!';

function protectedRoute(path: string, handler: string): EndpointDefinition {
  return endpoint('GET', path)
    .summary(`${handler} route`)
    .permission('thing', 'read')
    .response(200, 'ok', obj({ ok: str() }, 'ok'))
    .handler(handler)
    .build() as EndpointDefinition;
}

function publicRoute(path: string, handler: string): EndpointDefinition {
  return endpoint('GET', path)
    .summary(`${handler} route`)
    .security('none')
    .response(200, 'ok', obj({ ok: str() }, 'ok'))
    .handler(handler)
    .build() as EndpointDefinition;
}

interface MutablePlugin {
  name: string;
  routes: Record<string, EndpointDefinition>;
  methods: () => Record<string, () => Promise<{ ok: string }>>;
}

function pluginFor(route: EndpointDefinition, name = 'thing') {
  const spy = vi.fn(async () => ({ ok: 'yes' }));
  const plugin: MutablePlugin = {
    name,
    routes: { [route.handler]: route },
    methods: () => ({ [route.handler]: spy }),
  };
  return { plugin, spy };
}

function build(plugins: unknown[]) {
  return createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
    plugins: plugins as never,
  });
}

function get(path: string): Request {
  return new Request(`http://localhost${path}`);
}

describe('published route set is a snapshot', () => {
  it('ignores mutation of the declared route object', () => {
    const route = protectedRoute('/thing/ping', 'ping');
    const { plugin } = pluginFor(route);
    const fortress = build([plugin]);
    const published = fortress.endpoints.find(e => e.handler === 'ping')!;

    route.path = '/thing/hijacked';
    route.method = 'DELETE';
    route.handler = 'somethingElse';
    route.meta!.bearerKind = 'oauth';
    route.meta!.dispatchKind = 'oauth';
    route.meta!.security = ['none'];
    route.meta!.permission = { resource: 'other', action: 'admin' };
    route.responses = { 204: { description: 'gone' } };

    expect(published.path).toBe('/thing/ping');
    expect(published.method).toBe('GET');
    expect(published.handler).toBe('ping');
    expect(published.meta?.bearerKind).toBeUndefined();
    expect(published.meta?.dispatchKind).toBeUndefined();
    expect(published.meta?.permission).toEqual({ resource: 'thing', action: 'read' });
    expect(Object.keys(published.responses ?? {})).toEqual(['200']);
  });

  it('preserves response map keys exactly, including raw and non-numeric ones', () => {
    // `defineProperty` installs a genuine own `__proto__` key; plain
    // assignment would go through the prototype setter and be lost.
    const responses: Record<string, { description: string }> = {
      200: { description: 'ok' },
      default: { description: 'fallback' },
    };
    Object.defineProperty(responses, '__proto__', {
      value: { description: 'raw' },
      enumerable: true,
      writable: true,
      configurable: true,
    });

    const raw = {
      method: 'GET',
      path: '/thing/raw',
      handler: 'raw',
      meta: { summary: 'raw route', security: ['none'] },
      responses,
    } as unknown as EndpointDefinition;
    const { plugin } = pluginFor(raw, 'raws');
    const fortress = build([plugin]);
    const published = fortress.endpoints.find(e => e.handler === 'raw')!;
    const publishedKeys = Object.keys(published.responses ?? {});

    expect(publishedKeys.sort()).toEqual(['200', '__proto__', 'default']);
    expect(publishedKeys).not.toContain('NaN');
    expect(Object.getPrototypeOf(published.responses)).toBeNull();
  });

  it('preserves body-only input shape and schema identity', () => {
    const body = obj({ name: str() }, 'name');
    const input = { body };
    const route = {
      method: 'POST',
      path: '/thing/body-only',
      handler: 'bodyOnly',
      meta: { summary: 'body only', security: ['none'] },
      input,
      responses: { 200: { description: 'ok' } },
    } as unknown as EndpointDefinition;
    const { plugin } = pluginFor(route, 'body-only');
    const fortress = build([plugin]);
    const published = fortress.endpoints.find(endpoint => endpoint.handler === 'bodyOnly')!;

    expect(Object.keys(published.input ?? {})).toEqual(Object.keys(input));
    expect(published.input?.body).toBe(body);
  });

  it('does not promote inherited security into the published route', async () => {
    const meta = Object.assign(Object.create({ security: ['none'] }), { summary: 'not public' });
    const route = {
      method: 'GET',
      path: '/thing/inherited-security',
      handler: 'inheritedSecurity',
      meta,
      responses: { 200: { description: 'ok' } },
    } as unknown as EndpointDefinition;
    const { plugin, spy } = pluginFor(route, 'inherited-security');
    const fortress = build([plugin]);
    const published = fortress.endpoints.find(endpoint => endpoint.handler === 'inheritedSecurity')!;

    expect(Object.hasOwn(published.meta ?? {}, 'security')).toBe(false);
    expect(fortress.manifest.find(entry => entry.path === route.path)?.classification).toBe('default-deny');
    const response = await fortress.handleRequest(get(route.path));
    expect(response.status).toBe(403);
    expect(spy).not.toHaveBeenCalled();
  });

  it('captures accepted endpoint fields once without later reads', () => {
    const reads = {
      meta: 0,
      summary: 0,
      security: 0,
      input: 0,
      body: 0,
      responses: 0,
      response: 0,
      description: 0,
      schema: 0,
    };
    const body = obj({ name: str() }, 'name');
    const responseSchema = obj({ ok: str() }, 'ok');
    const meta = {
      get summary() {
        reads.summary++;
        return 'captured';
      },
      get security() {
        reads.security++;
        return ['none'] as const;
      },
    };
    const input = {
      get body() {
        reads.body++;
        return body;
      },
    };
    const response = {
      get description() {
        reads.description++;
        return 'ok';
      },
      get schema() {
        reads.schema++;
        return responseSchema;
      },
    };
    const responses = Object.create(null) as Record<string, unknown>;
    Object.defineProperty(responses, '200', {
      enumerable: true,
      get: () => {
        reads.response++;
        return response;
      },
    });
    const route = {
      method: 'POST',
      path: '/thing/getter-shape',
      handler: 'getterShape',
      get meta() {
        reads.meta++;
        return meta;
      },
      get input() {
        reads.input++;
        return input;
      },
      get responses() {
        reads.responses++;
        return responses;
      },
    } as unknown as EndpointDefinition;

    const published = snapshotEndpointDefinition(route);
    expect(reads).toEqual({
      meta: 1,
      summary: 1,
      security: 1,
      input: 1,
      body: 1,
      responses: 1,
      response: 1,
      description: 1,
      schema: 1,
    });
    expect(Object.keys(published.input ?? {})).toEqual(['body']);
    expect(published.input?.body).toBe(body);
    expect(published.responses?.[200]?.schema).toBe(responseSchema);

    // Repeated consumers of the snapshot never reach back into the declaration.
    void published.meta?.summary;
    void published.input?.body;
    void published.responses?.[200]?.description;
    expect(Object.values(reads).every(count => count === 1)).toBe(true);
  });

  it('rejects inherited routing identity during final route materialization', () => {
    const inherited = Object.create({
      method: 'GET',
      path: '/thing/inherited-route',
      handler: 'inheritedRoute',
    }) as EndpointDefinition;
    inherited.meta = { summary: 'inherited route', security: ['none'] };
    inherited.responses = { 200: { description: 'ok' } };
    const plugin = {
      name: 'inherited-route',
      routes: { inheritedRoute: inherited },
      methods: () => ({ inheritedRoute: async () => ({ ok: true }) }),
    } as RuntimeFortressPlugin;

    expect(() => build([plugin])).toThrow('Endpoint method must be an own enumerable property');
  });

  it('freezes the provenance record it hands out', () => {
    const route = publicRoute('/thing/open', 'ping');
    const { plugin } = pluginFor(route);
    const fortress = build([plugin]);
    const published = fortress.endpoints.find(e => e.handler === 'ping')!;
    const provenance = endpointProvenance(published)!;

    expect(provenance).toEqual({ owner: 'thing', manifestLabel: 'thing' });
    expect(() => {
      (provenance as { owner: string }).owner = 'evil';
    }).toThrow(TypeError);
  });

  it('freezes the published array and each route envelope', () => {
    const route = protectedRoute('/thing/ping', 'ping');
    const { plugin } = pluginFor(route);
    const fortress = build([plugin]);
    const published = fortress.endpoints.find(e => e.handler === 'ping')!;

    expect(() => (fortress.endpoints as unknown as EndpointDefinition[]).push(protectedRoute('/x', 'x'))).toThrow(TypeError);
    expect(() => {
      (published as { path: string }).path = '/nope';
    }).toThrow(TypeError);
    expect(() => {
      (published.meta as { bearerKind?: string }).bearerKind = 'oauth';
    }).toThrow(TypeError);
    expect(() => {
      (published.meta!.permission as { action: string }).action = 'admin';
    }).toThrow(TypeError);
    expect(() => {
      (published.responses![200] as { description: string }).description = 'changed';
    }).toThrow(TypeError);
  });

  it('freezes the cached instance manifest and its entries', () => {
    const route = protectedRoute('/thing/ping', 'ping');
    const { plugin } = pluginFor(route);
    const fortress = build([plugin]);
    const entry = fortress.manifest.find(e => e.path === '/thing/ping')!;

    expect(() => (fortress.manifest as unknown as RouteManifestEntry[]).pop()).toThrow(TypeError);
    expect(() => {
      (entry as { path: string }).path = '/nope';
    }).toThrow(TypeError);
    expect(() => {
      (entry.security as SecurityRequirement[]).push('none');
    }).toThrow(TypeError);
    expect(() => {
      (entry.permission as { action: string }).action = 'admin';
    }).toThrow(TypeError);
    // A directly built manifest and its nested adjustment surfaces stay mutable.
    const direct = buildRouteManifest(fortress);
    const directEntry = direct.find(e => e.path === '/thing/ping')!;
    expect(Object.isFrozen(direct)).toBe(false);
    directEntry.security.push('none');
    directEntry.permission!.action = 'adjusted';
  });

  it('materializes getter-backed routes once before final validation and dispatch', async () => {
    const reads = { method: 0, path: 0, handler: 0, meta: 0 };
    const declared = {
      get method() {
        reads.method++;
        return reads.method === 1 ? 'GET' : 'POST';
      },
      get path() {
        reads.path++;
        return reads.path === 1 ? '/getter/declared' : '/getter/final';
      },
      get handler() {
        reads.handler++;
        return 'ping';
      },
      get meta() {
        reads.meta++;
        return { summary: `summary-${reads.meta}`, security: ['none'] };
      },
      responses: { 200: { description: 'ok' } },
    } as unknown as EndpointDefinition;
    const handler = vi.fn(async () => ({ ok: true }));
    const plugin = {
      name: 'getter-route',
      routes: { ping: declared },
      methods: () => ({ ping: handler }),
    } as RuntimeFortressPlugin;
    const fortress = build([plugin]);
    const constructionReads = { ...reads };
    expect(constructionReads).toEqual({ method: 2, path: 2, handler: 3, meta: 1 });
    const published = fortress.endpoints.find(endpoint => endpoint.handler === 'ping')!;

    expect(published).toMatchObject({ method: 'POST', path: '/getter/final', handler: 'ping' });
    expect(published.meta).toMatchObject({ summary: 'summary-1', security: ['none'] });
    expect(endpointProvenance(published)?.owner).toBe('getter-route');
    const response = await fortress.handleRequest(new Request('http://localhost/getter/final', { method: 'POST' }));
    expect(response.status).toBe(200);
    expect(handler).toHaveBeenCalledOnce();
    expect(reads).toEqual(constructionReads);
    expect(reads.meta).toBe(1);
  });

  it('keeps validation schemas referentially shared — a documented non-goal', () => {
    const route = endpoint('POST', '/thing/create')
      .summary('create')
      .permission('thing', 'write')
      .body(obj({ name: str() }, 'name'))
      .response(200, 'ok', obj({ ok: str() }, 'ok'))
      .handler('create')
      .build() as EndpointDefinition;
    const { plugin } = pluginFor(route);
    const fortress = build([plugin]);
    const published = fortress.endpoints.find(e => e.handler === 'create')!;

    expect(published.input?.body).toBe(route.input?.body);
    expect(published.input?.bodySchema).toBe(route.input?.bodySchema);
    expect(published.responses![200]!.schema).toBe(route.responses![200]!.schema);
  });
});

describe('request pipeline uses the validated snapshot', () => {
  it('serves the validated route after the plugin route record is replaced', async () => {
    const route = publicRoute('/thing/open', 'ping');
    const { plugin, spy } = pluginFor(route);
    const fortress = build([plugin]);

    plugin.routes = { ping: publicRoute('/thing/replaced', 'ping') };

    const original = await fortress.handleRequest(get('/thing/open'));
    expect(original.status).toBe(200);
    expect(await original.json()).toEqual({ ok: 'yes' });
    expect(spy).toHaveBeenCalledTimes(1);

    const replacement = await fortress.handleRequest(get('/thing/replaced'));
    expect(replacement.status).toBe(404);
  });

  it('still serves the validated route after the record is deleted', async () => {
    const route = publicRoute('/thing/open', 'ping');
    const { plugin, spy } = pluginFor(route);
    const fortress = build([plugin]);

    plugin.routes = {};

    const response = await fortress.handleRequest(get('/thing/open'));
    expect(response.status).toBe(200);
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('does not let a post-construction bearerKind flip bypass auth', async () => {
    const route = protectedRoute('/thing/ping', 'ping');
    const { plugin, spy } = pluginFor(route);
    const fortress = build([plugin]);

    route.meta!.bearerKind = 'oauth';

    const response = await fortress.handleRequest(get('/thing/ping'));
    expect(response.status).toBe(401);
    expect(spy).not.toHaveBeenCalled();
  });

  it('does not let a post-construction security flip make a route public', async () => {
    const route = protectedRoute('/thing/ping', 'ping');
    const { plugin, spy } = pluginFor(route);
    const fortress = build([plugin]);

    route.meta!.security = ['none'];
    route.meta!.permission = undefined;

    const response = await fortress.handleRequest(get('/thing/ping'));
    expect(response.status).toBe(401);
    expect(spy).not.toHaveBeenCalled();
  });

  it('binds the snapshot endpoint into protect()', async () => {
    const route = protectedRoute('/thing/ping', 'ping');
    const { plugin } = pluginFor(route);
    const fortress = build([plugin]);
    const handler = vi.fn(async () => ({ ok: 'yes' }));
    const protectedHandler = protect(fortress, route, handler);

    route.meta!.bearerKind = 'oauth';

    const response = await protectedHandler(get('/thing/ping'));
    expect(response.status).toBe(401);
    expect(handler).not.toHaveBeenCalled();
  });

  it('dispatches by validated owner name, not a mutated plugin descriptor', async () => {
    const route = publicRoute('/thing/open', 'ping');
    const { plugin, spy } = pluginFor(route);
    const fortress = build([plugin]);

    plugin.name = 'renamed';

    const response = await fortress.handleRequest(get('/thing/open'));
    expect(response.status).toBe(200);
    expect(spy).toHaveBeenCalledTimes(1);
  });
});

describe('plugin membership comes from the validated snapshot', () => {
  it('does not let a late plugin join the principal-resolution chain', async () => {
    const route = publicRoute('/thing/open', 'ping');
    const { plugin } = pluginFor(route);
    const plugins: unknown[] = [plugin];
    const fortress = build(plugins);

    plugins.push({
      name: 'evil',
      resolvePrincipal: async () => ({ subject: { type: 'USER', id: 'attacker' } }),
    });

    const resolved = await fortress.resolvePrincipal(get('/thing/open'));
    expect(resolved).toBeNull();
  });

  it('does not let a late plugin join the middleware chain', async () => {
    const route = publicRoute('/thing/open', 'ping');
    const { plugin } = pluginFor(route);
    const plugins: unknown[] = [plugin];
    const fortress = build(plugins);

    const lateMiddleware = vi.fn(async (_ctx: unknown, _req: unknown, next: () => Promise<void>) => {
      await next();
    });
    plugins.push({
      name: 'evil',
      middleware: [{ path: '/thing/*', position: 'before-auth', handler: lateMiddleware }],
    });

    const response = await fortress.handleRequest(get('/thing/open'));
    expect(response.status).toBe(200);
    expect(lateMiddleware).not.toHaveBeenCalled();

    await fortress.runPluginMiddleware('before-auth', { request: get('/thing/open') });
    expect(lateMiddleware).not.toHaveBeenCalled();
  });
});

describe('registered plugin capabilities come from the post-factory snapshot', () => {
  it('ignores resolver addition, replacement, and removal while closure state remains dynamic', async () => {
    const empty = { name: 'empty' } as RuntimeFortressPlugin;
    const emptyFortress = build([empty]);
    const late = vi.fn(async () => ({ subject: { type: 'USER' as const, id: 'late-attacker' } }));
    empty.resolvePrincipal = late;
    expect(await emptyFortress.resolvePrincipal(get('/anything'))).toBeNull();
    expect(late).not.toHaveBeenCalled();

    let enabled = false;
    const original = vi.fn(async () => enabled
      ? { subject: { type: 'USER' as const, id: 'captured' } }
      : null);
    const plugin = { name: 'resolver', resolvePrincipal: original } as RuntimeFortressPlugin;
    const fortress = build([plugin]);
    const replacement = vi.fn(async () => ({ subject: { type: 'USER' as const, id: 'replacement' } }));
    plugin.resolvePrincipal = replacement;
    expect(await fortress.resolvePrincipal(get('/anything'))).toBeNull();
    enabled = true;
    expect(await fortress.resolvePrincipal(get('/anything'))).toEqual({
      subject: { type: 'USER', id: 'captured' },
      claims: undefined,
      scopes: undefined,
    });
    plugin.resolvePrincipal = undefined;
    expect((await fortress.resolvePrincipal(get('/anything')))?.subject.id).toBe('captured');
    expect(replacement).not.toHaveBeenCalled();
  });

  it('preserves captured callable receivers while fixing descriptor slots', async () => {
    const calls: string[] = [];
    const middlewareDefinition = {
      path: '/*',
      position: 'before-auth' as const,
      label: 'original-middleware',
      async handler(this: { label: string }, _ctx: unknown, _request: unknown, next: () => Promise<void>) {
        calls.push(this.label);
        await next();
      },
    };
    const plugin = {
      name: 'receiver',
      label: 'original-plugin',
      async resolvePrincipal(this: { label: string }) {
        calls.push(`resolver:${this.label}`);
        return null;
      },
      wrapAdapter(this: { label: string }, adapter: ReturnType<typeof createTestAdapter>) {
        calls.push(`wrapper:${this.label}`);
        return adapter;
      },
      async scopeRules(this: { label: string }) {
        calls.push(`scope:${this.label}`);
        return null;
      },
      async enrichTokenClaims(this: { label: string }) {
        calls.push(`claims:${this.label}`);
        return {};
      },
      middleware: [middlewareDefinition],
    } as unknown as RuntimeFortressPlugin & { label: string };
    const fortress = build([plugin]);
    const view = snapshotPluginMembership(fortress);
    plugin.resolvePrincipal = async () => ({ subject: { type: 'USER', id: 'late' } });
    plugin.wrapAdapter = adapter => adapter;
    plugin.scopeRules = async () => null;
    plugin.enrichTokenClaims = async () => ({ late: true });
    middlewareDefinition.handler = async (_ctx, _request, next) => next();

    await fortress.resolvePrincipal(get('/receiver'));
    chainAdapterWrappers(view, createTestAdapter(), {});
    await collectScopeRules(view, 'user', 'document', { db: createTestAdapter(), config: fortress.config });
    await mergeTokenClaims(view, 'user', { db: createTestAdapter(), config: fortress.config });
    await executePluginMiddleware(
      view,
      'before-auth',
      '/receiver',
      { db: createTestAdapter(), config: fortress.config },
      { request: get('/receiver') },
    );

    expect(calls).toEqual([
      'resolver:original-plugin',
      'wrapper:original-plugin',
      'scope:original-plugin',
      'claims:original-plugin',
      'original-middleware',
    ]);
  });

  it('does not invoke caller descriptor accessors at request time', async () => {
    const resolver = vi.fn(async () => null);
    let reads = 0;
    const plugin = { name: 'accessor' } as RuntimeFortressPlugin;
    Object.defineProperty(plugin, 'resolvePrincipal', {
      configurable: true,
      get: () => {
        reads++;
        return resolver;
      },
    });
    const fortress = build([plugin]);
    const constructionReads = reads;
    expect(constructionReads).toBe(1);

    await fortress.resolvePrincipal(get('/one'));
    await fortress.resolvePrincipal(get('/two'));
    expect(reads).toBe(constructionReads);
    expect(resolver).toHaveBeenCalledTimes(2);
  });

  it('copies middleware definitions and ordering without freezing caller containers', async () => {
    const calls: string[] = [];
    const handler = (name: string) => vi.fn(async (_ctx: unknown, _request: unknown, next: () => Promise<void>) => {
      calls.push(name);
      await next();
    });
    const first: { path: string; position: 'before-auth' | 'after-auth' | 'after-rbac'; handler: ReturnType<typeof handler>; methods: string[] } = {
      path: '/*',
      position: 'before-auth',
      handler: handler('first'),
      methods: ['GET'],
    };
    const second = { path: '/*', position: 'before-auth' as const, handler: handler('second') };
    const middleware = [first, second];
    const plugin = { name: 'middleware', middleware } as unknown as RuntimeFortressPlugin;
    const fortress = build([plugin]);
    const late = handler('late');

    first.path = '/late';
    first.position = 'after-rbac';
    first.handler = late;
    first.methods.splice(0, 1, 'POST');
    middleware.reverse();
    middleware.splice(0, 1);
    middleware.push({ path: '/*', position: 'before-auth', handler: late });

    await fortress.runPluginMiddleware('before-auth', { request: get('/original') });
    expect(calls).toEqual(['first', 'second']);
    expect(late).not.toHaveBeenCalled();
    expect(Object.isFrozen(plugin)).toBe(false);
    expect(Object.isFrozen(middleware)).toBe(false);
    expect(Object.isFrozen(first)).toBe(false);
    expect(Object.isFrozen(first.methods)).toBe(false);
  });

  it('captures each middleware method slot once before freezing and classification', () => {
    let methodReads = 0;
    const declaredMethods: string[] = [];
    Object.defineProperty(declaredMethods, 0, {
      configurable: true,
      enumerable: true,
      get: () => {
        methodReads++;
        if (methodReads === 1)
          return 'post';
        if (methodReads === 2)
          return { toUpperCase: () => 'GET' } as unknown as string;
        return 'GET';
      },
    });
    const limiter = {
      name: 'rate-limit',
      middleware: [{
        path: '/captured-method',
        position: 'before-auth' as const,
        methods: declaredMethods,
        handler: async (_ctx: unknown, _request: unknown, next: () => Promise<void>) => next(),
      }],
    } as RuntimeFortressPlugin;
    const route = {
      method: 'POST',
      path: '/captured-method',
      handler: 'capturedMethod',
      meta: { summary: 'captured method', security: ['none'] },
      responses: { 200: { description: 'ok' } },
    } as unknown as EndpointDefinition;
    const surface = {
      name: 'captured-method',
      routes: { capturedMethod: route },
      methods: () => ({ capturedMethod: async () => ({ ok: true }) }),
    } as RuntimeFortressPlugin;
    const fortress = build([limiter, surface]);
    const publishedMiddleware = snapshotPluginMembership(fortress)
      .find(plugin => plugin.name === 'rate-limit')!
      .middleware![0]!;

    expect(methodReads).toBe(1);
    expect(publishedMiddleware.methods).toEqual(['post']);
    expect(Object.isFrozen(publishedMiddleware.methods)).toBe(true);
    Object.defineProperty(declaredMethods, 0, { configurable: true, enumerable: true, value: 'GET' });
    expect(publishedMiddleware.methods).toEqual(['post']);
    expect(fortress.manifest.find(entry => entry.path === '/captured-method')?.rateLimited).toBe(true);
    expect(methodReads).toBe(1);
  });

  it('accepts all standard HTTP methods in middleware filters case-insensitively', () => {
    const methods = ['GET', 'head', 'POST', 'put', 'DELETE', 'connect', 'OPTIONS', 'trace', 'PATCH'];
    const plugin = {
      name: 'standard-methods',
      middleware: [{
        path: '/*',
        position: 'before-auth' as const,
        methods,
        handler: async (_ctx: unknown, _request: unknown, next: () => Promise<void>) => next(),
      }],
    } as RuntimeFortressPlugin;

    const fortress = build([plugin]);
    expect(snapshotPluginMembership(fortress)[0]?.middleware?.[0]?.methods).toEqual(methods);
  });

  it('keeps protect() on the captured resolver', async () => {
    const route = protectedRoute('/captured/protect', 'capturedProtect');
    route.meta!.permission = undefined;
    route.meta!.security = ['bearer'];
    const original = vi.fn(async () => ({ subject: { type: 'USER' as const, id: 'member' } }));
    const plugin = { name: 'protect-resolver', resolvePrincipal: original } as RuntimeFortressPlugin;
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      routes: { capturedProtect: route },
      plugins: [plugin],
    });
    plugin.resolvePrincipal = async () => null;

    const handler = vi.fn(async () => ({ ok: true }));
    const response = await protect(fortress, route, handler)(get('/captured/protect'));
    expect(response.status).toBe(200);
    expect(handler).toHaveBeenCalledOnce();
    expect(original).toHaveBeenCalledOnce();
  });

  it('captures factory-time capability additions and rejects malformed final values', async () => {
    const middleware = vi.fn(async (_ctx: unknown, _request: unknown, next: () => Promise<void>) => next());
    const plugin = { name: 'factory-added' } as RuntimeFortressPlugin;
    plugin.methods = () => {
      plugin.resolvePrincipal = async () => ({ subject: { type: 'USER', id: 'factory' } });
      plugin.middleware = [{ path: '/*', position: 'before-auth', handler: middleware }];
      return {};
    };
    const fortress = build([plugin]);
    expect((await fortress.resolvePrincipal(get('/anything')))?.subject.id).toBe('factory');
    await fortress.runPluginMiddleware('before-auth', { request: get('/anything') });
    expect(middleware).toHaveBeenCalledOnce();

    const malformed = { name: 'malformed' } as RuntimeFortressPlugin;
    malformed.methods = () => {
      malformed.middleware = [{ path: '/*', position: 'before-auth', handler: 'not-callable' }] as never;
      return {};
    };
    expect(() => build([malformed])).toThrow('middleware[0].handler must be callable');
  });

  it.each([
    {
      label: 'callable capability',
      mutate: (plugin: RuntimeFortressPlugin) => { plugin.wrapAdapter = 'invalid' as never; },
      error: 'wrapAdapter must be callable',
    },
    {
      label: 'hook',
      mutate: (plugin: RuntimeFortressPlugin) => { plugin.hooks = { beforeLogin: 'invalid' as never }; },
      error: 'hooks.beforeLogin must be callable',
    },
    {
      label: 'post-auth gate',
      mutate: (plugin: RuntimeFortressPlugin) => {
        plugin.hooks = { postAuthGate: { reason: 'two-factor', evaluate: async () => undefined } as never };
      },
      error: 'hooks.postAuthGate.verify must be callable',
    },
    {
      label: 'middleware methods',
      mutate: (plugin: RuntimeFortressPlugin) => {
        plugin.middleware = [{
          path: '/*',
          position: 'before-auth',
          handler: async (_ctx: unknown, _request: unknown, next: () => Promise<void>) => next(),
          methods: ['INVALID'],
        } as never];
      },
      error: 'middleware[0].methods[0] must be a valid HTTP method',
    },
  ])('rejects a malformed final $label added by a factory', ({ mutate, error }) => {
    const plugin = { name: 'malformed-final' } as RuntimeFortressPlugin;
    plugin.methods = () => {
      mutate(plugin);
      return {};
    };
    expect(() => build([plugin])).toThrow(error);
  });

  it.each([
    {
      label: 'middleware',
      mutate: (plugin: RuntimeFortressPlugin) => { plugin.middleware = Array.from({ length: 1 }) as never; },
      error: 'middleware[0] must not contain holes or undefined',
    },
    {
      label: 'dependency methods',
      mutate: (plugin: RuntimeFortressPlugin) => {
        plugin.dependencies = [{ plugin: 'provider', methods: Array.from({ length: 1 }) as never }];
      },
      error: 'dependencies[0].methods[0] must not contain holes or undefined',
    },
    {
      label: 'core overrides',
      mutate: (plugin: RuntimeFortressPlugin) => { plugin.coreOverrides = Array.from({ length: 1 }) as never; },
      error: 'coreOverrides[0] must not contain holes or undefined',
    },
    {
      label: 'models',
      mutate: (plugin: RuntimeFortressPlugin) => { plugin.models = Array.from({ length: 1 }) as never; },
      error: 'models[0] must not contain holes or undefined',
    },
    {
      label: 'constraint fields',
      mutate: (plugin: RuntimeFortressPlugin) => {
        plugin.models = [{
          name: 'document',
          fields: { tenantId: { type: 'string' } },
          constraints: [{ type: 'index', fields: Array.from({ length: 1 }) as never }],
        }];
      },
      error: 'models[0].constraints[0].fields[0] must not contain holes or undefined',
    },
  ])('rejects sparse final $label arrays', ({ mutate, error }) => {
    const plugin = { name: 'sparse-final' } as RuntimeFortressPlugin;
    plugin.methods = () => {
      mutate(plugin);
      return {};
    };
    expect(() => build([{ name: 'provider' }, plugin])).toThrow(error);
  });

  it('invalidates a leaked construction view when final validation fails', () => {
    let leaked: PluginContext | undefined;
    const plugin = { name: 'failed-view' } as RuntimeFortressPlugin;
    plugin.methods = (ctx) => {
      leaked = ctx;
      plugin.middleware = [{ path: '/*', position: 'before-auth', handler: 'invalid' }] as never;
      return {};
    };

    expect(() => build([plugin])).toThrow('middleware[0].handler must be callable');
    expect(leaked).toBeDefined();
    expect(() => snapshotPluginMembership(leaked!)[0]!.name).toThrow('failed construction');
  });

  it('snapshots auth hooks and claim enrichers in configured order', async () => {
    const calls: string[] = [];
    const plugin = (name: string): RuntimeFortressPlugin => ({
      name,
      hooks: {
        beforeRegister: async () => { calls.push(`before:${name}`); },
        afterRegister: async () => { calls.push(`after:${name}`); },
      },
      enrichTokenClaims: async () => {
        calls.push(`claims:${name}`);
        return { [name]: true };
      },
    });
    const first = plugin('first');
    const second = plugin('second');
    const fortress = build([first, second]);
    const late = vi.fn(async () => {});
    first.hooks!.beforeRegister = late;
    first.hooks = {};
    first.enrichTokenClaims = async () => ({ attacker: true });
    second.hooks = undefined;
    second.enrichTokenClaims = undefined;

    await fortress.auth.createUser({
      email: 'capability-snapshot@example.com',
      name: 'Capability Snapshot',
      password: 'password-123456',
    });
    expect(calls).toEqual(['before:first', 'before:second', 'after:first', 'after:second']);
    expect(late).not.toHaveBeenCalled();

    calls.length = 0;
    await fortress.auth.login('capability-snapshot@example.com', 'password-123456');
    expect(calls).toEqual(['claims:first', 'claims:second']);
  });

  it('captures post-auth gate evaluation, verification, policies, and receiver', async () => {
    const calls: string[] = [];
    const provider: PostAuthGateProvider & { label: string } = {
      label: 'original-provider',
      reason: 'two-factor',
      maxAttempts: 3,
      cooldownSeconds: 0,
      async evaluate(this: { label: string }) {
        calls.push(`evaluate:${this.label}`);
        return { pluginData: { source: this.label } };
      },
      async verify(this: { label: string }) {
        calls.push(`verify:${this.label}`);
        return { verified: true };
      },
    };
    const originalEvaluate = provider.evaluate;
    const originalVerify = provider.verify;
    const lateEvaluate = vi.fn(async () => ({ pluginData: { attacker: true } }));
    const lateVerify = vi.fn(async () => ({ attacker: true }));
    const plugin = { name: 'gate', hooks: { postAuthGate: provider } } as RuntimeFortressPlugin;
    const fortress = build([plugin]);
    provider.reason = 'email-verification';
    provider.maxAttempts = 99;
    provider.cooldownSeconds = 99;
    provider.evaluate = lateEvaluate;
    provider.verify = lateVerify;
    plugin.hooks = undefined;

    const user = await fortress.auth.createUser({
      email: 'gate-snapshot@example.com',
      name: 'Gate Snapshot',
      password: 'password-123456',
    });
    const pending = await fortress.auth.login('gate-snapshot@example.com', 'password-123456');
    expect(pending).toMatchObject({
      status: 'pending',
      pending: { reason: 'two-factor' },
      pluginData: { source: 'original-provider' },
    });
    if (pending.status !== 'pending' || !pending.pending)
      throw new Error('Expected pending authentication');
    const stored = await fortress.config.database.findOne<{ maxAttempts: number; cooldownSeconds: number }>({
      model: 'auth_continuation',
      where: [{ field: 'userId', operator: '=', value: user.id }],
    });
    expect(stored).toMatchObject({ maxAttempts: 3, cooldownSeconds: 0 });

    const completed = await fortress.auth.completePendingAuth(
      pending.pending.continuationToken,
      'proof',
    );
    expect(completed.status).toBe('success');
    expect(calls).toEqual(['evaluate:original-provider', 'verify:original-provider']);
    expect(originalEvaluate).not.toBe(lateEvaluate);
    expect(originalVerify).not.toBe(lateVerify);
    expect(lateEvaluate).not.toHaveBeenCalled();
    expect(lateVerify).not.toHaveBeenCalled();
  });
});

describe('all membership consumers retain configured membership and order', () => {
  const mutations: Array<{
    name: string;
    apply: (plugins: RuntimeFortressPlugin[], late: RuntimeFortressPlugin) => void;
  }> = [
    { name: 'append', apply: (plugins, late) => plugins.push(late) },
    { name: 'remove', apply: plugins => plugins.splice(0, 1) },
    { name: 'replace', apply: (plugins, late) => { plugins[0] = late; } },
    { name: 'reorder', apply: plugins => plugins.reverse() },
  ];

  it.each(mutations)('ignores a late $name in core and protect pipelines', async ({ apply }) => {
    const calls: string[] = [];
    const membershipPlugin = (name: string): RuntimeFortressPlugin => definePlugin({
      name,
      resolvePrincipal: async () => {
        calls.push(`principal:${name}`);
        return null;
      },
      middleware: [{
        path: '/*',
        position: 'before-auth',
        handler: async (_ctx, _request, next) => {
          calls.push(`middleware:${name}`);
          await next();
        },
      }],
    });
    const first = membershipPlugin('first');
    const second = membershipPlugin('second');
    const late = definePlugin({
      name: 'late',
      resolvePrincipal: async () => ({ subject: { type: 'USER', id: 'attacker' } }),
      middleware: [{
        path: '/*',
        position: 'before-auth',
        handler: async (_ctx, _request, next) => {
          calls.push('middleware:late');
          await next();
        },
      }],
    });
    const plugins: RuntimeFortressPlugin[] = [first, second];
    const route = protectedRoute('/host/secret', 'hostSecret');
    // Bearer-only makes the original exploit observable as a 200: a late
    // resolver can fully satisfy auth without needing an IAM binding.
    route.meta!.permission = undefined;
    route.meta!.security = ['bearer'];
    const config = {
      jwt: { key: SECRET },
      database: createTestAdapter(),
      routes: { hostSecret: route },
      plugins,
    };
    const fortress = createFortress(config);

    expect(Object.isFrozen(plugins)).toBe(false);
    expect(Object.isFrozen(config)).toBe(false);
    expect(fortress.config).toBe(config);
    expect(fortress.config.plugins).toBe(plugins);
    apply(plugins, late);

    expect(await fortress.resolvePrincipal(get('/host/secret'))).toBeNull();
    expect(calls.splice(0)).toEqual(['principal:first', 'principal:second']);

    await fortress.runPluginMiddleware('before-auth', { request: get('/host/secret') });
    expect(calls.splice(0)).toEqual(['middleware:first', 'middleware:second']);

    const handler = vi.fn(async () => ({ ok: true }));
    const response = await protect(fortress, route, handler)(get('/host/secret'));
    expect(response.status).toBe(401);
    expect(handler).not.toHaveBeenCalled();
    expect(calls).toEqual([
      'middleware:first',
      'middleware:second',
      'principal:first',
      'principal:second',
    ]);
  });

  it('uses snapshotted membership for manifest rate-limit classification', () => {
    const limiter = definePlugin({
      name: 'rate-limit',
      middleware: [{
        path: '/auth/login',
        position: 'before-auth',
        methods: ['post'],
        handler: async (_ctx, _request, next) => next(),
      }],
    });
    const configured: RuntimeFortressPlugin[] = [limiter];
    const withLimiter = build(configured);
    configured.length = 0;
    (limiter.middleware![0] as { path: string }).path = '/late';
    (limiter.middleware![0] as { methods?: string[] }).methods = ['GET'];
    limiter.middleware?.splice(0);
    expect(buildRouteManifest(withLimiter).find(entry => entry.path === '/auth/login')?.rateLimited).toBe(true);

    const initiallyEmpty: RuntimeFortressPlugin[] = [];
    const withoutLimiter = build(initiallyEmpty);
    initiallyEmpty.push(limiter);
    expect(buildRouteManifest(withoutLimiter).find(entry => entry.path === '/auth/login')?.rateLimited).toBe(false);
  });

  it('isolates outer built-in factories from re-entrant construction with the same config', async () => {
    const outerRoute = protectedRoute('/outer/report', 'outerReport');
    const outerSurface = {
      name: 'outer-surface',
      routes: { outerReport: outerRoute },
      methods: () => ({ outerReport: async () => ({ ok: 'outer' }) }),
    } as RuntimeFortressPlugin;
    const nestedRoute = protectedRoute('/nested/report', 'nestedReport');
    nestedRoute.meta!.permission = { resource: 'nested', action: 'takeover' };
    const nestedSurface = {
      name: 'nested-surface',
      routes: { nestedReport: nestedRoute },
      methods: () => ({ nestedReport: async () => ({ ok: 'nested' }) }),
    } as RuntimeFortressPlugin;
    let sharedConfig: FortressConfig;
    const reentrant = definePlugin({
      name: 'reentrant',
      methods: () => {
        sharedConfig.plugins = [nestedSurface];
        createFortress(sharedConfig);
        return {};
      },
    });
    sharedConfig = {
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [
        reentrant,
        outerSurface,
        admin({ bootstrap: { enabled: true, secret: 'reentrant-bootstrap' } }),
        openapi({ includeCoreIam: false }),
      ],
    };

    const outer = createFortress(sharedConfig);
    const methods = (outer.plugins as Record<string, unknown>).openapi as {
      getSpec: () => Promise<{ paths: Record<string, unknown> }>;
    };
    const spec = await methods.getSpec();

    expect(spec.paths).toHaveProperty('/outer/report');
    expect(spec.paths).not.toHaveProperty('/nested/report');

    const user = await outer.auth.createUser({
      email: 'reentrant-admin@example.com',
      name: 'Reentrant Admin',
      password: 'password-123456',
    });
    const adminMethods = (outer.plugins as Record<string, unknown>).admin as {
      bootstrap: (input: { userId: string; secret: string }) => Promise<unknown>;
    };
    await adminMethods.bootstrap({ userId: user.id, secret: 'reentrant-bootstrap' });
    const permissions = await outer.iam.getPermissionsForSubject({ type: 'USER', id: user.id });
    expect(permissions).toEqual(expect.arrayContaining([
      expect.objectContaining({ resource: 'thing', action: 'read' }),
    ]));
    expect(permissions).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ resource: 'nested', action: 'takeover' }),
    ]));
    expect(sharedConfig.plugins).toEqual([nestedSurface]);
  });

  it('does not let failed construction seed later config tooling membership', () => {
    const failedConfig: FortressConfig = {
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: [{
        name: 'failed-factory',
        methods: () => ({ invalid: 'not callable' as never }),
      }],
    };
    expect(() => createFortress(failedConfig)).toThrow('must be callable');

    const limiter = definePlugin({
      name: 'rate-limit',
      middleware: [{
        path: '/auth/login',
        position: 'before-auth',
        handler: async (_ctx, _request, next) => next(),
      }],
    });
    failedConfig.plugins = [limiter];
    const manifest = buildRouteManifest({
      config: failedConfig,
      endpoints: Object.values(authEndpoints) as EndpointDefinition[],
    });

    expect(manifest.find(entry => entry.path === '/auth/login')?.rateLimited).toBe(true);
  });

  it('keeps OpenAPI plugin endpoint discovery on startup membership', async () => {
    const initialRoute = publicRoute('/initial/report', 'report');
    const initial = {
      name: 'initial',
      routes: { report: initialRoute },
      methods: () => ({ report: async () => ({ ok: 'initial' }) }),
    } as RuntimeFortressPlugin;
    const replacementRoute = publicRoute('/late/report', 'report');
    const replacement = {
      name: 'replacement',
      routes: { report: replacementRoute },
      methods: () => ({ report: async () => ({ ok: 'late' }) }),
    } as RuntimeFortressPlugin;
    const plugins: RuntimeFortressPlugin[] = [initial, openapi()];
    const fortress = build(plugins);
    plugins.splice(0, plugins.length, replacement);
    initial.routes = replacement.routes;

    const methods = (fortress.plugins as Record<string, unknown>).openapi as { getSpec: () => Promise<{ paths: Record<string, unknown> }> };
    const spec = await methods.getSpec();
    expect(spec.paths).toHaveProperty('/initial/report');
    expect(spec.paths).not.toHaveProperty('/late/report');
  });

  it('keeps OpenAPI host discovery on the authoritative route snapshot', async () => {
    const initialRoute = publicRoute('/initial/host-report', 'hostReport');
    const routes = { hostReport: initialRoute };
    const fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      routes,
      plugins: [openapi({ includeCoreAuth: false, includeCoreIam: false })],
    });
    routes.hostReport = publicRoute('/late/host-report', 'hostReport');
    initialRoute.path = '/mutated/host-report';

    const methods = (fortress.plugins as Record<string, unknown>).openapi as {
      getSpec: () => Promise<{ paths: Record<string, unknown> }>;
    };
    const spec = await methods.getSpec();
    expect(spec.paths).toHaveProperty('/initial/host-report');
    expect(spec.paths).not.toHaveProperty('/late/host-report');
    expect(spec.paths).not.toHaveProperty('/mutated/host-report');
  });

  it('keeps admin bootstrap permission discovery on startup membership', async () => {
    const initial = {
      name: 'initial-admin-surface',
      routes: { report: protectedRoute('/initial/admin-report', 'report') },
      methods: () => ({ report: async () => ({ ok: 'initial' }) }),
    } as RuntimeFortressPlugin;
    const replacementRoute = protectedRoute('/late/admin-report', 'lateReport');
    replacementRoute.meta!.permission = { resource: 'late', action: 'takeover' };
    const replacement = {
      name: 'replacement-admin-surface',
      routes: { lateReport: replacementRoute },
      methods: () => ({ lateReport: async () => ({ ok: 'late' }) }),
    } as RuntimeFortressPlugin;
    const plugins: RuntimeFortressPlugin[] = [initial, admin({ bootstrap: { enabled: true, secret: 'bootstrap-secret' } })];
    const fortress = build(plugins);
    const user = await fortress.auth.createUser({
      email: 'membership-admin@example.com',
      name: 'Membership Admin',
      password: 'password-123456',
    });
    plugins.splice(0, plugins.length, replacement);

    const adminMethods = (fortress.plugins as Record<string, unknown>).admin as {
      bootstrap: (input: { userId: string; secret: string }) => Promise<unknown>;
    };
    await adminMethods.bootstrap({ userId: user.id, secret: 'bootstrap-secret' });
    const permissions = await fortress.iam.getPermissionsForSubject({ type: 'USER', id: user.id });
    expect(permissions).toEqual(expect.arrayContaining([
      expect.objectContaining({ resource: 'thing', action: 'read' }),
    ]));
    expect(permissions).not.toEqual(expect.arrayContaining([
      expect.objectContaining({ resource: 'late', action: 'takeover' }),
    ]));
  });
});

describe('core route singletons stay per-instance', () => {
  it('does not share or freeze core endpoints between instances', () => {
    const a = build([]);
    const b = build([]);
    const loginA = a.endpoints.find(e => e.path === '/auth/login')!;
    const loginB = b.endpoints.find(e => e.path === '/auth/login')!;

    expect(loginA).not.toBe(loginB);
    expect(loginA).not.toBe(authEndpoints.login as unknown as EndpointDefinition);
    expect(Object.isFrozen(authEndpoints.login)).toBe(false);
  });
});

describe('every consumer agrees after hostile mutation', () => {
  function hostile() {
    const route = protectedRoute('/thing/ping', 'ping');
    const { plugin, spy } = pluginFor(route);
    const fortress = build([plugin]);

    route.path = '/thing/hijacked';
    route.meta!.bearerKind = 'oauth';
    route.meta!.security = ['none'];
    route.meta!.permission = undefined;
    plugin.routes = { ping: publicRoute('/thing/replaced', 'ping') };

    return { fortress, spy };
  }

  it('agrees between the cached manifest and a direct rebuild', () => {
    const { fortress } = hostile();
    const cached = fortress.manifest.find(e => e.path === '/thing/ping');
    const rebuilt = buildRouteManifest(fortress).find(e => e.path === '/thing/ping');

    expect(cached).toBeDefined();
    expect(rebuilt).toBeDefined();
    expect(rebuilt!.plugin).toBe(cached!.plugin);
    expect(rebuilt!.plugin).toBe('thing');
    expect(rebuilt!.mounted).toBe(cached!.mounted);
    expect(rebuilt!.mounted).toBe(true);
    expect(rebuilt!.classification).toBe(cached!.classification);
    expect(rebuilt!.classification).toBe('rbac');
  });

  it('invokes the validated route through the plugin call tree', async () => {
    const route = publicRoute('/thing/open', 'ping');
    const { plugin, spy } = pluginFor(route);
    const fortress = build([plugin]);

    route.path = '/thing/hijacked';
    route.handler = 'somethingElse';
    plugin.routes = { ping: publicRoute('/thing/replaced', 'ping') };
    plugin.name = 'renamed';

    // `build()` erases the plugin tuple type, so the typed tree is empty here;
    // the assertion is about runtime resolution, not inference.
    const callTree = fortress.call.plugins as unknown as Record<
      string,
      Record<string, (input: Record<string, unknown>) => Promise<{ ok: string }>>
    >;

    expect(Object.keys(callTree)).toContain('thing');
    expect(Object.keys(callTree)).not.toContain('renamed');

    const result = await callTree.thing!.ping!({});
    expect(result).toEqual({ ok: 'yes' });
    expect(spy).toHaveBeenCalledTimes(1);
  });

  it('keeps the validated path in the OpenAPI document', () => {
    const { fortress } = hostile();
    const paths = Object.keys(fortress.toOpenAPI().paths ?? {});

    expect(paths).toContain('/thing/ping');
    expect(paths).not.toContain('/thing/hijacked');
    expect(paths).not.toContain('/thing/replaced');
  });

  it('keeps the validated permission for permission sync', () => {
    const { fortress } = hostile();
    const published = fortress.endpoints.find(e => e.handler === 'ping')!;

    // `syncPermissions` scans `meta.permission` over an endpoint list that
    // defaults to `fortress.endpoints`, so asserting the published set is
    // exactly the input that sync would read — no database needed.
    expect(published.meta?.permission).toEqual({ resource: 'thing', action: 'read' });
  });

  it('reports no drift for the authoritative snapshot but still detects a broken manifest', () => {
    const { fortress } = hostile();

    expect(hasRouteManifestDrift(detectRouteManifestDrift(fortress))).toBe(false);

    const broken = detectRouteManifestDrift(fortress, { manifest: [] });
    expect(hasRouteManifestDrift(broken)).toBe(true);
    expect(broken.mountedMissingFromManifest.length).toBeGreaterThan(0);
  });

  it('does not report a route made public after construction', () => {
    const { fortress } = hostile();
    const result = checkPublicRoutes(fortress);

    expect(result.unexpected.map(entry => entry.path)).not.toContain('/thing/ping');
  });
});
