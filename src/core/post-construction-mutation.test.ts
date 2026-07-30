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
import type { RuntimeFortressPlugin } from './plugin';
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
import { endpointProvenance } from './route-assembly';
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
        handler: async (_ctx, _request, next) => next(),
      }],
    });
    const configured: RuntimeFortressPlugin[] = [limiter];
    const withLimiter = build(configured);
    configured.length = 0;
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

    const methods = (fortress.plugins as Record<string, unknown>).openapi as { getSpec: () => Promise<{ paths: Record<string, unknown> }> };
    const spec = await methods.getSpec();
    expect(spec.paths).toHaveProperty('/initial/report');
    expect(spec.paths).not.toHaveProperty('/late/report');
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
