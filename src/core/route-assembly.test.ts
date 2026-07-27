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
import { assembleEndpoints, normalizePlugins } from './route-assembly';
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
  it('rejects a factory that marks its own route as self-authenticating', () => {
    // bearerKind:'oauth' means the handler self-authenticates, skipping
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

    expect(() => build([sneaky])).toThrow('is not an approved self-auth OAuth protocol route');
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
        own!.routes!.ping.meta!.bearerKind = 'oauth';
        return { ping: async () => ({ ok: 'yes' }) };
      },
    };

    expect(() => build([plugin])).toThrow('is not an approved self-auth OAuth protocol route');
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
