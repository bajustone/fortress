import { describe, expect, it } from 'vitest';
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

  it('lets a plugin route override a host route, matching construction order', () => {
    const collidingPlugin = {
      name: 'stats',
      routes: {
        hostStats: endpoint('GET', '/host/stats')
          .summary('Plugin-owned override')
          .permission('stats', 'read')
          .response(200, 'ok', obj({ ok: str() }, 'ok'))
          .handler('hostStats')
          .build(),
      },
      methods: () => ({ hostStats: async () => ({ ok: 'yes' }) }),
    };

    const surface = describeRouteSurface({
      jwt: { key: SECRET },
      database: undefined as never,
      plugins: [collidingPlugin],
      routes: { hostStats: hostRoute },
    });

    const entry = surface.manifest.find(candidate => candidate.path === '/host/stats');
    expect(entry).toMatchObject({ plugin: 'stats', mounted: true });
  });
});
