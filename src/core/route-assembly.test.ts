/**
 * Route assembly runs in two phases because a plugin's `methods()` factory is
 * handed the live route objects and can mutate them. Phase 1 validates what a
 * plugin declares; phase 2 derives the route set that actually gets published,
 * and must run after the factories.
 *
 * These tests exist because collapsing the two — validating everything up
 * front — let a factory flip `bearerKind` to `'oauth'` after the allow-list
 * check had already passed, publishing a route that skips the auth pipeline.
 */

import type { EndpointDefinition } from './endpoint';
import { describe, expect, it } from 'vitest';
import { createTestAdapter } from '../testing/index';
import { createFortress } from './fortress';
import {
  assembleEndpoints,
  CORE_ENDPOINT_OWNER,
  isApprovedOAuthSelfManagedRoute,
  isSelfManagedOAuthRoute,
  normalizePlugins,
} from './route-assembly';
import { endpoint, obj, str } from './schema-builder';

const SECRET = 'route-assembly-test-secret-32-chars!';

function makeEndpoint(path: string, handler: string): EndpointDefinition {
  return endpoint('GET', path)
    .summary(`${handler} route`)
    .permission('thing', 'read')
    .response(200, 'ok', obj({ ok: str() }, 'ok'))
    .handler(handler)
    .build() as EndpointDefinition;
}

function build(plugins: unknown[]) {
  return createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
    plugins: plugins as never,
  });
}

describe('plugin factories cannot escape route validation', () => {
  it('rejects a factory that marks its own route as self-managed OAuth', () => {
    // bearerKind:'oauth' means the handler owns protocol security, bypassing
    // principal resolution, the bearer requirement, RBAC, and input
    // validation. The allow-list exists to keep that off app routes.
    const route = makeEndpoint('/sneaky/ping', 'ping');
    const sneaky = {
      name: 'sneaky',
      routes: { ping: route },
      methods: () => {
        route.meta!.bearerKind = 'oauth';
        return { ping: async () => ({ ok: 'yes' }) };
      },
    };

    expect(() => build([sneaky])).toThrow('is not an approved self-managed OAuth protocol route');
  });

  it('rejects a factory that mutates its route through the config it is handed', () => {
    // Every factory receives ctx.config, whose `plugins` array holds the same
    // route objects — a second handle on the same graph.
    const route = makeEndpoint('/via-ctx/ping', 'ping');
    const plugin = {
      name: 'via-ctx',
      routes: { ping: route },
      methods: (ctx: { config: { plugins?: readonly { name: string; routes?: Record<string, EndpointDefinition> }[] } }) => {
        const own = ctx.config.plugins?.find(candidate => candidate.name === 'via-ctx');
        const ping = own?.routes?.ping;
        if (ping?.meta === undefined)
          throw new Error('Expected via-ctx route metadata');
        ping.meta.bearerKind = 'oauth';
        return { ping: async () => ({ ok: 'yes' }) };
      },
    };

    expect(() => build([plugin])).toThrow('is not an approved self-managed OAuth protocol route');
  });

  it('rejects a route a factory adds that violates the security invariants', () => {
    const routes: Record<string, EndpointDefinition> = { ping: makeEndpoint('/adder/ping', 'ping') };
    const adder = {
      name: 'adder',
      routes,
      methods: () => {
        const smuggled = endpoint('GET', '/adder/smuggled')
          .summary('Added after declaration')
          .security('none')
          .response(200, 'ok', obj({ ok: str() }, 'ok'))
          .handler('smuggled')
          .build() as EndpointDefinition;
        smuggled.meta!.permission = { resource: 'x', action: 'y' };
        routes.smuggled = smuggled;
        return { ping: async () => ({ ok: 'yes' }), smuggled: async () => ({ ok: 'yes' }) };
      },
    };

    expect(() => build([adder])).toThrow('mutually');
  });

  it('rejects a factory that rewrites its path onto a core route', () => {
    const route = makeEndpoint('/shadow/ping', 'ping');
    const shadower = {
      name: 'shadower',
      routes: { ping: route },
      methods: () => {
        route.path = '/auth/me';
        return { ping: async () => ({ ok: 'yes' }) };
      },
    };

    expect(() => build([shadower])).toThrow('coreOverrides');
  });

  it('drops a route a factory removes rather than publishing a ghost entry', () => {
    const routes: Record<string, EndpointDefinition> = {
      keep: makeEndpoint('/ghost/keep', 'keep'),
      gone: makeEndpoint('/ghost/gone', 'gone'),
    };
    const remover = {
      name: 'remover',
      routes,
      methods: () => {
        delete routes.gone;
        return { keep: async () => ({ ok: 'yes' }) };
      },
    };

    const fortress = build([remover]);
    const paths = fortress.manifest.map(entry => entry.path);
    expect(paths).toContain('/ghost/keep');
    expect(paths).not.toContain('/ghost/gone');
    expect(fortress.endpoints.some(ep => ep.path === '/ghost/gone')).toBe(false);
  });

  it('does not assemble conflicting endpoints until factories have run', () => {
    const firstRoutes: Record<string, EndpointDefinition> = {
      first: makeEndpoint('/initial-conflict', 'first'),
    };
    let factoryRan = 0;
    const first = {
      name: 'first',
      routes: firstRoutes,
      methods: () => {
        factoryRan += 1;
        delete firstRoutes.first;
        return { first: async () => ({ ok: 'yes' }) };
      },
    };
    const second = {
      name: 'second',
      routes: { second: makeEndpoint('/initial-conflict', 'second') },
      methods: () => {
        factoryRan += 1;
        return { second: async () => ({ ok: 'yes' }) };
      },
    };

    const fortress = build([first, second]);
    expect(factoryRan).toBe(2);
    expect(fortress.endpoints.filter(ep => ep.path === '/initial-conflict')).toHaveLength(1);
    expect(fortress.manifest.find(entry => entry.path === '/initial-conflict')?.plugin).toBe('second');
  });

  it('still constructs a well-behaved plugin', () => {
    const wellBehaved = {
      name: 'fine',
      routes: { ping: makeEndpoint('/fine/ping', 'ping') },
      methods: () => ({ ping: async () => ({ ok: 'yes' }) }),
    };

    const fortress = build([wellBehaved]);
    expect(fortress.manifest.some(entry => entry.path === '/fine/ping')).toBe(true);
  });
});

describe('phase separation', () => {
  it('validates the declaration without deriving the route set', () => {
    const plugins = normalizePlugins({
      plugins: [{
        name: 'declared',
        routes: { ping: makeEndpoint('/declared/ping', 'ping') },
        methods: () => ({ ping: async () => ({ ok: 'yes' }) }),
      }] as never,
    });
    expect(plugins.map(plugin => plugin.name)).toEqual(['declared']);
  });

  it('rejects a malformed declaration in phase 1, before any factory could run', () => {
    expect(() => normalizePlugins({
      plugins: [{
        name: 'mismatched',
        routes: { wrongKey: makeEndpoint('/mismatched', 'handlerName') },
        methods: () => ({ handlerName: async () => ({ ok: 'yes' }) }),
      }] as never,
    })).toThrow('must match handler');
  });

  it('derives and validates the route set in phase 2', () => {
    const plugins = normalizePlugins({
      plugins: [{
        name: 'two',
        routes: { ping: makeEndpoint('/two/ping', 'ping') },
        methods: () => ({ ping: async () => ({ ok: 'yes' }) }),
      }] as never,
    });
    const { endpoints, endpointOwners } = assembleEndpoints(plugins);
    expect(endpoints.some(ep => ep.path === '/two/ping')).toBe(true);
    expect(endpointOwners.get('GET /two/ping')).toBe('two');
  });
});

describe('endpoint owner sentinels', () => {
  it('reserves \'__host\' as a plugin name even when no top-level routes exist', () => {
    // The synthetic __host plugin backs top-level `routes`. Even with none
    // declared, a user plugin may not take the name: a later `routes` addition
    // would collide, and until then its routes would look host-owned.
    expect(() => normalizePlugins({
      plugins: [{
        name: '__host',
        routes: { ping: makeEndpoint('/host-clash/ping', 'ping') },
        methods: () => ({ ping: async () => ({ ok: 'yes' }) }),
      }] as never,
    })).toThrow(/reserved for top-level/);
  });

  it('owns built-in routes with a sentinel a plugin named \'core\' cannot forge', () => {
    // A plugin literally named 'core' owns its routes under the string 'core',
    // which must stay distinct from the built-in owner marker so the core call
    // tree never mistakes the plugin's routes for Fortress's own.
    const plugins = normalizePlugins({
      plugins: [{
        name: 'core',
        routes: { ping: makeEndpoint('/core-plugin/ping', 'ping') },
        methods: () => ({ ping: async () => ({ ok: 'yes' }) }),
      }] as never,
    });
    const { endpointOwners } = assembleEndpoints(plugins);
    expect(endpointOwners.get('GET /core-plugin/ping')).toBe('core');
    const builtinOwner = endpointOwners.get('GET /auth/me');
    expect(builtinOwner).toBe(CORE_ENDPOINT_OWNER);
    expect(builtinOwner).not.toBe('core');
  });

  it('does not let a plugin named \'core\' shield a route from duplicate detection', () => {
    // With a string 'core' sentinel the first plugin's route would look
    // built-in, so a second plugin could 'override' it — by declaring the
    // handler in coreOverrides — and slip past the duplicate-plugin check.
    const plugins = normalizePlugins({
      plugins: [
        {
          name: 'core',
          routes: { ping: makeEndpoint('/shared/ping', 'ping') },
          methods: () => ({ ping: async () => ({ ok: 'yes' }) }),
        },
        {
          name: 'impostor',
          coreOverrides: ['ping'],
          routes: { ping: makeEndpoint('/shared/ping', 'ping') },
          methods: () => ({ ping: async () => ({ ok: 'yes' }) }),
        },
      ] as never,
    });
    expect(() => assembleEndpoints(plugins)).toThrow(/Duplicate endpoint GET \/shared\/ping/);
  });
});

/**
 * Fortress ships no HTTP Basic verifier. A route declaring `security: ['basic']`
 * with no IAM permission did not require those credentials and could be served
 * unauthenticated while the manifest labelled it `authenticated`, so no check
 * reported it. Construction now
 * rejects that combination, and the only exemption — the OAuth client-auth
 * endpoints, which verify credentials inside their own handlers — is pinned to
 * the owning plugin, the exact method/path, and the expected handler.
 */
describe('basic-auth route invariants', () => {
  function basicRoute(path: string, handler: string, method: 'GET' | 'POST' = 'GET'): EndpointDefinition {
    return endpoint(method, path)
      .summary(`${handler} route`)
      .security('basic')
      .response(200, 'ok', obj({ ok: str() }, 'ok'))
      .handler(handler)
      .build() as EndpointDefinition;
  }

  function selfManagedRoute(path: string, handler: string, method: 'GET' | 'POST' = 'POST'): EndpointDefinition {
    const route = basicRoute(path, handler, method);
    route.meta!.bearerKind = 'oauth';
    return route;
  }

  function pluginWith(route: EndpointDefinition, name: string) {
    return {
      name,
      routes: { [route.handler]: route },
      methods: () => ({ [route.handler]: async () => ({ ok: 'yes' }) }),
    };
  }

  it('rejects a generic Basic route with no permission', () => {
    expect(() => build([pluginWith(basicRoute('/reports/list', 'list'), 'reports')]))
      .toThrow(/declares security:\['basic'\] without a permission/);
  });

  it('accepts a Basic route that declares a permission', () => {
    const route = endpoint('GET', '/reports/list')
      .summary('list route')
      .security('basic')
      .permission('reports', 'read')
      .response(200, 'ok', obj({ ok: str() }, 'ok'))
      .handler('list')
      .build() as EndpointDefinition;

    const fortress = build([pluginWith(route, 'reports')]);
    const published = fortress.endpoints.find(e => e.handler === 'list')!;
    expect(published.meta?.permission).toEqual({ resource: 'reports', action: 'read' });
  });

  it('accepts the OAuth client-auth exemption when owner, route, and handler all match', () => {
    const route = selfManagedRoute('/oauth/token', 'handleTokenRequest');
    const fortress = build([pluginWith(route, 'oauth')]);
    const published = fortress.endpoints.find(e => e.handler === 'handleTokenRequest')!;

    expect(isApprovedOAuthSelfManagedRoute(published)).toBe(true);
    expect(isSelfManagedOAuthRoute(published)).toBe(true);
  });

  // The owner and handler halves of the contract are proven independently:
  // each of these differs from the accepted case in exactly one dimension.
  it('rejects an approved route and handler claimed by a different owner', () => {
    const route = selfManagedRoute('/oauth/token', 'handleTokenRequest');

    expect(() => build([pluginWith(route, 'evil')]))
      .toThrow(/is not an approved self-managed OAuth protocol route/);
    expect(() => build([pluginWith(route, 'evil')])).toThrow(/owner='evil'/);
  });

  it('rejects the oauth owner on an approved route with the wrong handler', () => {
    const route = selfManagedRoute('/oauth/token', 'stealTokens');

    expect(() => build([pluginWith(route, 'oauth')]))
      .toThrow(/is not an approved self-managed OAuth protocol route/);
    expect(() => build([pluginWith(route, 'oauth')])).toThrow(/handler 'handleTokenRequest', got 'stealTokens'/);
  });

  it('reports the forged exemption rather than the Basic error when both apply', () => {
    // A forged self-managed route also declares Basic without a permission. The
    // forgery is the more specific diagnosis and must win.
    const route = selfManagedRoute('/oauth/token', 'handleTokenRequest');

    expect(() => build([pluginWith(route, 'evil')]))
      .not
      .toThrow(/without a permission/);
  });

  it('treats a metadata-only route as self-managed when it has no provenance', () => {
    // Hand-built capability runtimes never go through assembly, so there is no
    // snapshot to check them against and their declared metadata is honoured.
    const unassembled = selfManagedRoute('/oauth/token', 'handleTokenRequest');

    expect(isApprovedOAuthSelfManagedRoute(unassembled)).toBe(false);
    expect(isSelfManagedOAuthRoute(unassembled)).toBe(true);
  });

  it('does not treat a non-oauth route as self-managed', () => {
    expect(isSelfManagedOAuthRoute(basicRoute('/reports/list', 'list'))).toBe(false);
  });

  // Owning protocol security and Basic-verifying are different properties.
  // All seven routes manage protocol security, but only the three client-auth
  // endpoints verify a Basic credential (RFC 6749 §2.3.1, RFC 7662, RFC 7009).
  // Basic on the other four would falsely claim protection they do not
  // provide; discovery and JWKS remain intentionally public.
  const clientAuthRoutes: [method: 'GET' | 'POST', path: string, handler: string][] = [
    ['POST', '/oauth/token', 'handleTokenRequest'],
    ['POST', '/oauth/introspect', 'handleIntrospectRequest'],
    ['POST', '/oauth/revoke', 'handleRevokeRequest'],
  ];

  const nonClientAuthRoutes: [method: 'GET' | 'POST', path: string, handler: string][] = [
    ['GET', '/oauth/authorize', 'handleAuthorizeRequest'],
    ['GET', '/oauth/userinfo', 'handleUserInfoRequest'],
    ['GET', '/oauth/.well-known/openid-configuration', 'handleDiscovery'],
    ['GET', '/oauth/.well-known/jwks.json', 'handleJwksRequest'],
  ];

  for (const [method, path, handler] of clientAuthRoutes) {
    it(`accepts permissionless Basic on ${method} ${path}`, () => {
      const fortress = build([pluginWith(selfManagedRoute(path, handler, method), 'oauth')]);
      expect(fortress.endpoints.some(e => e.path === path && e.handler === handler)).toBe(true);
    });
  }

  for (const [method, path, handler] of nonClientAuthRoutes) {
    it(`rejects permissionless Basic on ${method} ${path}`, () => {
      expect(() => build([pluginWith(selfManagedRoute(path, handler, method), 'oauth')]))
        .toThrow(/declares security:\['basic'\] without a permission/);
    });
  }

  // A self-managed handler skips principal resolution and Fortress RBAC, so a
  // declared permission is never evaluated — and it satisfied the Basic rule
  // above, falsely assuring callers that discovery was IAM-protected while it
  // remained intentionally public.
  for (const [method, path, handler] of [...clientAuthRoutes, ...nonClientAuthRoutes]) {
    it(`rejects an IAM permission on self-managed ${method} ${path}`, () => {
      const route = selfManagedRoute(path, handler, method);
      route.meta!.permission = { resource: 'oauth', action: 'read' };

      expect(() => build([pluginWith(route, 'oauth')]))
        .toThrow(/is a self-managed OAuth protocol route and cannot declare a permission/);
    });
  }

  // Owner and handler are already proven independently above; these isolate
  // the remaining two dimensions of the tuple.
  it('rejects the expected token handler declared on the wrong method', () => {
    expect(() => build([pluginWith(selfManagedRoute('/oauth/token', 'handleTokenRequest', 'GET'), 'oauth')]))
      .toThrow(/is not an approved self-managed OAuth protocol route/);
  });

  it('rejects the expected token handler declared on the wrong path', () => {
    expect(() => build([pluginWith(selfManagedRoute('/oauth/tokens', 'handleTokenRequest'), 'oauth')]))
      .toThrow(/is not an approved self-managed OAuth protocol route/);
  });
});
