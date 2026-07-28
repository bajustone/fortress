import { describe, expect, it } from 'vitest';
import { admin } from '../../plugins/admin';
import { createFortress } from '../fortress';
import { endpoint, obj, str } from '../schema-builder';
import { describeRouteSurface } from './route-surface';

const SECRET = 'route-surface-test-secret-32-chars!!';

let methodsCalls = 0;

const reportsPlugin = {
  name: 'reports',
  routes: {
    createReport: endpoint('POST', '/reports')
      .summary('Create a report')
      .permission('report', 'create')
      .body(obj({ title: str() }, 'title'))
      .response(200, 'ok', obj({ ok: str() }, 'ok'))
      .handler('createReport')
      .build(),
  },
  // Stands in for a plugin that starts a worker or queries the database here,
  // as the bundled webhook plugin's queue does.
  methods: () => {
    methodsCalls += 1;
    return { createReport: async () => ({ ok: 'yes' }) };
  },
};

const hostRoute = endpoint('GET', '/host/stats')
  .summary('Host-owned stats route')
  .permission('stats', 'read')
  .response(200, 'ok', obj({ ok: str() }, 'ok'))
  .handler('hostStats')
  .build();

function makeConfig() {
  return {
    jwt: { key: SECRET },
    database: undefined as never,
    plugins: [reportsPlugin],
    routes: { hostStats: hostRoute },
  };
}

describe('describeRouteSurface', () => {
  // Declaring a dependency on an unregistered plugin is a composition error,
  // not a route-surface one. `fortress init` scaffolds configs that cannot
  // boot, so codegen in CI must still describe their declared routes.
  it('describes declared routes when a plugin dependency is unregistered', () => {
    const config = {
      jwt: { key: SECRET },
      database: undefined as never,
      plugins: [admin({ apiKeyRoutes: true })],
    };

    const surface = describeRouteSurface(config);
    expect(surface.manifest.some(entry => entry.path.includes('api-keys'))).toBe(true);

    // Construction is where composition is enforced.
    expect(() => createFortress({ ...config, database: {} as never }))
      .toThrow('Plugin "admin" requires plugin "api-key" to be registered');
  });

  it('includes core, plugin, and host-owned routes', () => {
    const surface = describeRouteSurface(makeConfig());

    expect(surface.endpoints.length).toBeGreaterThan(40);
    const routes = surface.manifest.map(entry => `${entry.method} ${entry.path}`);
    expect(routes).toContain('POST /auth/login');
    expect(routes).toContain('POST /reports');
    expect(routes).toContain('GET /host/stats');
  });

  it('records route origins the same way a constructed instance does', () => {
    const surface = describeRouteSurface(makeConfig());
    const byRoute = new Map(surface.manifest.map(entry => [`${entry.method} ${entry.path}`, entry]));

    expect(byRoute.get('POST /reports')).toMatchObject({ plugin: 'reports', classification: 'rbac', mounted: true });
    // Top-level routes are host-owned: recorded, but left for the host router.
    expect(byRoute.get('GET /host/stats')).toMatchObject({ plugin: null, classification: 'rbac', mounted: false });
  });

  it('never invokes plugin methods, unlike createFortress', () => {
    methodsCalls = 0;
    describeRouteSurface(makeConfig());
    expect(methodsCalls).toBe(0);

    // Constructing the app does run them — that is the cost this avoids.
    createFortress({ ...makeConfig(), database: {} as never });
    expect(methodsCalls).toBe(1);
  });

  it('agrees with a constructed instance on the route surface', () => {
    const surface = describeRouteSurface(makeConfig());
    const fortress = createFortress({ ...makeConfig(), database: {} as never });

    const summarise = (entries: typeof surface.manifest): string[] =>
      entries.map(entry => `${entry.method} ${entry.path} ${entry.plugin} ${entry.classification} ${entry.mounted}`).sort();

    expect(summarise(surface.manifest)).toEqual(summarise(fortress.manifest));
  });

  // A silently-dropped route is a hidden route: an app-aware check would
  // report a clean manifest for a config the app cannot actually boot. Every
  // conflict createFortress() rejects must be rejected here too.
  describe('route conflicts', () => {
    function pluginWithRoute(name: string, path: string, handler = 'dup') {
      return {
        name,
        routes: {
          [handler]: endpoint('GET', path)
            .summary(`${name} route`)
            .permission('dup', 'read')
            .response(200, 'ok', obj({ ok: str() }, 'ok'))
            .handler(handler)
            .build(),
        },
        methods: () => ({ [handler]: async () => ({ ok: 'yes' }) }),
      };
    }

    const cases: Array<{ name: string; config: () => Parameters<typeof describeRouteSurface>[0]; message: string }> = [
      {
        name: 'two plugins claiming the same method and path',
        config: () => ({
          jwt: { key: SECRET },
          database: undefined as never,
          plugins: [pluginWithRoute('first', '/dup'), pluginWithRoute('second', '/dup')],
        }),
        message: 'Duplicate endpoint GET /dup declared by plugins "first" and "second"',
      },
      {
        name: 'a plugin colliding with a host-owned route',
        config: () => ({
          jwt: { key: SECRET },
          database: undefined as never,
          plugins: [pluginWithRoute('stats', '/host/stats', 'hostStats')],
          routes: { hostStats: hostRoute },
        }),
        message: 'Duplicate endpoint GET /host/stats declared by plugins "__host" and "stats"',
      },
      {
        name: 'a host route colliding with a core route',
        config: () => ({
          jwt: { key: SECRET },
          database: undefined as never,
          routes: {
            login: endpoint('POST', '/auth/login')
              .summary('Host override of a core route')
              .security('none')
              .response(200, 'ok', obj({ ok: str() }, 'ok'))
              .handler('login')
              .build(),
          },
        }),
        message: 'collides with a Fortress core route',
      },
      {
        name: 'an undeclared core override',
        config: () => ({
          jwt: { key: SECRET },
          database: undefined as never,
          plugins: [{
            name: 'override',
            routes: {
              login: endpoint('POST', '/auth/login')
                .summary('Undeclared core override')
                .security('none')
                .response(200, 'ok', obj({ ok: str() }, 'ok'))
                .handler('login')
                .build(),
            },
            methods: () => ({ login: async () => ({ ok: 'yes' }) }),
          }],
        }),
        message: 'declare "login" in coreOverrides',
      },
      {
        name: 'an unused declared core override',
        config: () => ({
          jwt: { key: SECRET },
          database: undefined as never,
          plugins: [{ ...pluginWithRoute('unused', '/unused'), coreOverrides: ['login'] }],
        }),
        message: 'declares unused core override "login"',
      },
      {
        name: 'a reserved __host plugin name',
        config: () => ({
          jwt: { key: SECRET },
          database: undefined as never,
          plugins: [pluginWithRoute('__host', '/reserved')],
          routes: { hostStats: hostRoute },
        }),
        message: `Plugin name '__host' is reserved`,
      },
      {
        name: 'security none combined with a permission',
        config: () => ({
          jwt: { key: SECRET },
          database: undefined as never,
          plugins: [{
            name: 'contradiction',
            routes: {
              both: endpoint('GET', '/both')
                .summary('Contradictory security')
                .security('none')
                .permission('both', 'read')
                .response(200, 'ok', obj({ ok: str() }, 'ok'))
                .handler('both')
                .build(),
            },
            methods: () => ({ both: async () => ({ ok: 'yes' }) }),
          }],
        }),
        message: 'mutually',
      },
    ];

    for (const testCase of cases) {
      it(`rejects ${testCase.name}`, () => {
        expect(() => describeRouteSurface(testCase.config())).toThrow(testCase.message);
        // createFortress() must agree — that is the point of sharing assembly.
        expect(() => createFortress({ ...testCase.config(), database: {} as never })).toThrow(testCase.message);
      });
    }
  });
});
