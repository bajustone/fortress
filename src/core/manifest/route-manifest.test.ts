import type { EndpointDefinition } from '../endpoint';
import { describe, expect, it } from 'vitest';
import { authEndpoints } from '../auth/auth-endpoints';
import { endpoint, obj, str } from '../schema-builder';
import { detectRouteManifestDrift, hasRouteManifestDrift } from './drift';
import { buildRouteManifest } from './route-manifest';

function fakeFortress(endpoints: EndpointDefinition[], plugins: any[] = [], csrf: any = undefined) {
  return {
    endpoints,
    config: { plugins, csrf },
    get manifest() {
      return buildRouteManifest(this as any);
    },
  };
}

describe('route manifest', () => {
  it('classifies public, authenticated, rbac, and oauth protocol routes', () => {
    const routes = {
      publicPing: endpoint('GET', '/plugin/ping')
        .summary('Ping')
        .security('none')
        .response(200, 'OK', obj({ ok: str() }, 'ok'))
        .handler('publicPing')
        .build(),
      me: endpoint('GET', '/plugin/me')
        .summary('Me')
        .security('bearer')
        .response(200, 'OK', obj({ ok: str() }, 'ok'))
        .handler('me')
        .build(),
      admin: endpoint('POST', '/plugin/admin')
        .summary('Admin')
        .security('bearer')
        .permission('plugin', 'admin')
        .response(200, 'OK', obj({ ok: str() }, 'ok'))
        .handler('admin')
        .build(),
      token: {
        ...endpoint('POST', '/oauth/token')
          .summary('Token')
          .security('none')
          .response(200, 'OK', obj({ ok: str() }, 'ok'))
          .handler('token')
          .build(),
        meta: { summary: 'Token', security: ['none'], bearerKind: 'oauth' as const },
      },
    };
    const plugin = {
      name: 'plugin',
      routes,
    };
    const rateLimitPlugin = {
      name: 'rate-limit',
      middleware: [{ path: '/plugin/admin', position: 'before-auth', handler: async (_ctx: unknown, _req: unknown, next: () => Promise<void>) => next() }],
    };
    const fortress = fakeFortress(Object.values(routes) as EndpointDefinition[], [plugin, rateLimitPlugin]);

    const manifest = buildRouteManifest(fortress as any);
    expect(manifest.map(entry => [entry.method, entry.path, entry.plugin, entry.classification])).toEqual([
      ['GET', '/plugin/me', 'plugin', 'authenticated'],
      ['GET', '/plugin/ping', 'plugin', 'public'],
      ['POST', '/oauth/token', 'plugin', 'oauth-protocol'],
      ['POST', '/plugin/admin', 'plugin', 'rbac'],
    ]);
    expect(manifest.find(entry => entry.path === '/plugin/admin')).toMatchObject({
      permission: { resource: 'plugin', action: 'admin' },
      csrfApplicable: true,
      rateLimited: true,
      mounted: true,
    });
  });

  it('snapshots the core auth manifest subset', () => {
    const endpoints = Object.values(authEndpoints) as EndpointDefinition[];
    const manifest = buildRouteManifest(fakeFortress(endpoints) as any);

    expect(manifest).toMatchSnapshot();
    expect(manifest.every(entry => entry.classification !== 'default-deny')).toBe(true);
  });

  it('does not report valid metadata-only host routes as manifest drift', () => {
    const host = endpoint('GET', '/host')
      .summary('Host route')
      .security('none')
      .response(200, 'OK', obj({ ok: str() }, 'ok'))
      .handler('host')
      .build() as EndpointDefinition;
    const fortress = fakeFortress([host]);
    const drift = detectRouteManifestDrift(fortress as any);

    expect(buildRouteManifest(fortress as any)[0]).toMatchObject({ mounted: false, plugin: null });
    expect(hasRouteManifestDrift(drift)).toBe(false);
  });

  it('detects drift in mounted routes, OpenAPI routes, and RBAC permissions', () => {
    const endpointDef = endpoint('POST', '/things/:id')
      .summary('Update thing')
      .security('bearer')
      .permission('thing', 'update')
      .response(200, 'OK', obj({ ok: str() }, 'ok'))
      .handler('updateThing')
      .build() as EndpointDefinition;
    const otherEndpointDef = endpoint('POST', '/other/:id')
      .summary('Update other thing')
      .security('bearer')
      .permission('other', 'update')
      .response(200, 'OK', obj({ ok: str() }, 'ok'))
      .handler('updateOtherThing')
      .build() as EndpointDefinition;
    const fortress = fakeFortress(
      [endpointDef, otherEndpointDef],
      [{ name: 'test-routes', routes: { updateThing: endpointDef, updateOtherThing: otherEndpointDef } }],
    );
    const manifest = buildRouteManifest(fortress as any);

    const brokenManifest = [
      { ...manifest.find(entry => entry.path === '/things/:id')!, path: '/things/:otherId' },
      {
        ...manifest.find(entry => entry.path === '/other/:id')!,
        permission: undefined,
        classification: 'authenticated' as const,
      },
    ];
    const drift = detectRouteManifestDrift(fortress as any, { manifest: brokenManifest, openapi: {
      openapi: '3.1.0',
      info: { title: 'x', version: '1' },
      paths: { '/things/{id}': { post: { responses: { 200: { description: 'OK' } } } as any } },
      components: { schemas: {}, securitySchemes: {} },
    } });

    expect(hasRouteManifestDrift(drift)).toBe(true);
    expect(drift.mountedMissingFromManifest).toEqual(['POST /things/:id']);
    expect(drift.manifestMissingFromMounted).toEqual(['POST /things/:otherId']);
    expect(drift.rbacPermissionMismatches).toContainEqual({
      route: 'POST /other/:id',
      expected: 'other:update',
      actual: undefined,
    });
  });
});
