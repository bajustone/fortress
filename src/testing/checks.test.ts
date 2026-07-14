/**
 * Tests for the CI check utilities (P1-10). Exercises each helper end-to-end
 * against a real Fortress instance backed by the test adapter.
 */

import { describe, expect, it } from 'vitest';
import { createFortress } from '../core/fortress';
import { endpoint, obj, str } from '../core/schema-builder';
import {
  checkMigrationDrift,
  checkPublicRoutes,
  checkRouteManifestDrift,
  runFortressChecks,
  smokeTestAuth,
} from './checks';
import { createTestAdapter } from './index';

const SECRET = 'checks-test-secret-at-least-32-chars!';

function makeFortress(extraRoutes?: Parameters<typeof publicLeakPlugin>[0]) {
  const plugins = extraRoutes ? [publicLeakPlugin(extraRoutes)] : [];
  return createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
    plugins,
  });
}

function publicLeakPlugin(opts: { unexpectedPublic?: boolean }) {
  // Tiny throw-away plugin so we can introduce a non-allow-listed public
  // route on demand. Exposes a single GET handler classified as `public`.
  return {
    name: 'leak-test',
    routes: {
      ping: endpoint('GET', '/leak/ping')
        .summary('Leaky test route')
        .security(opts.unexpectedPublic ? 'none' : 'bearer')
        .response(200, 'ok', obj({ ok: str() }, 'ok'))
        .handler('ping')
        .build(),
    },
    methods: () => ({ ping: async () => ({ ok: 'yes' }) }),
  };
}

describe('checkRouteManifestDrift', () => {
  it('returns ok when the manifest matches the mounted routes', () => {
    const fortress = makeFortress();
    const result = checkRouteManifestDrift(fortress);
    expect(result.ok).toBe(true);
    expect(result.messages).toEqual([]);
  });
});

describe('checkPublicRoutes', () => {
  it('passes when every public route is on the default allow-list', () => {
    const fortress = makeFortress();
    const result = checkPublicRoutes(fortress);
    expect(result.ok).toBe(true);
    expect(result.unexpected).toEqual([]);
  });

  it('flags an unexpected public route from a plugin', () => {
    const fortress = makeFortress({ unexpectedPublic: true });
    const result = checkPublicRoutes(fortress);
    expect(result.ok).toBe(false);
    expect(result.unexpected.map(r => `${r.method} ${r.path}`)).toEqual(['GET /leak/ping']);
    expect(result.messages[0]).toContain('GET /leak/ping');
  });

  it('honors an explicit allow-list override', () => {
    const fortress = makeFortress({ unexpectedPublic: true });
    const result = checkPublicRoutes(fortress, { allow: ['GET /leak/ping'] });
    expect(result.ok).toBe(true);
  });
});

describe('checkMigrationDrift', () => {
  it('reports a clean SQLite test adapter as upgraded', async () => {
    const fortress = makeFortress();
    const result = await checkMigrationDrift(fortress.config.database, 'sqlite');
    // The test adapter installs the current schema and stamps the matching
    // migration version, so it is ready for checks without a redundant migrate.
    expect(result.drift.missingTables).toEqual([]);
    expect(result.drift.missingColumns).toEqual([]);
    expect(result.drift.pendingVersions).toEqual([]);
    expect(result.ok).toBe(true);
    expect(result.messages).toEqual([]);
  });
});

describe('smokeTestAuth', () => {
  it('runs register → login → refresh → logout against a fresh fortress', async () => {
    const fortress = makeFortress();
    const result = await smokeTestAuth(fortress, {
      email: `smoke+${Math.random().toString(36).slice(2)}@fortress.test`,
    });
    expect(result.ok).toBe(true);
    expect(result.messages).toEqual([]);
  });
});

describe('runFortressChecks aggregator', () => {
  it('passes with its default configuration', async () => {
    const fortress = makeFortress();
    const result = await runFortressChecks({ fortress });
    expect(result.manifest.ok).toBe(true);
    expect(result.publicRoutes.ok).toBe(true);
    expect(result.migrations?.ok).toBe(true);
    expect(result.authSmokeTest?.ok).toBe(true);
    expect(result.ok).toBe(true);
  });

  it('rolls a single failure up to the aggregate result', async () => {
    const fortress = makeFortress({ unexpectedPublic: true });
    const result = await runFortressChecks({
      fortress,
      skipMigrations: true,
      skipAuthSmokeTest: true,
    });
    expect(result.ok).toBe(false);
    expect(result.messages.some(m => m.includes('GET /leak/ping'))).toBe(true);
  });
});
