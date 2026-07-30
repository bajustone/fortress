import type { FortressConfig } from './config';
import type { RuntimeFortressPlugin } from './plugin';
import { describe, expect, it, vi } from 'vitest';
import { createTestAdapter } from '../testing';
import { publishPluginMembership, snapshotPluginMembership } from './plugin-membership';

const SECRET = 'plugin-membership-test-secret-32-chars!';

describe('internal plugin membership boundary', () => {
  it('copies mutable publication input without freezing or retaining the caller array', () => {
    const configured: RuntimeFortressPlugin[] = [{ name: 'configured' }];
    const carrier = {};

    publishPluginMembership(carrier, configured);
    const snapshot = snapshotPluginMembership(carrier);

    expect(snapshot).not.toBe(configured);
    expect(Object.isFrozen(snapshot)).toBe(true);
    expect(Object.isFrozen(configured)).toBe(false);
    configured.push({ name: 'late' });
    expect(snapshot.map(plugin => plugin.name)).toEqual(['configured']);
  });

  it('does not leave registry proof when defining the carrier property fails', () => {
    const carrier = Object.preventExtensions({
      config: {
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [{ name: 'fixture' }],
      } satisfies FortressConfig,
    });
    const attempted: RuntimeFortressPlugin[] = [{ name: 'attempted-publication' }];

    expect(() => publishPluginMembership(carrier, attempted)).toThrow();
    expect(Object.isFrozen(attempted)).toBe(false);
    expect(snapshotPluginMembership(carrier).map(plugin => plugin.name)).toEqual(['fixture']);
  });

  it('requires an own direct snapshot to agree with the publication registry', () => {
    const carrier = {};
    const configured = Object.freeze([{ name: 'configured' }]);
    publishPluginMembership(carrier, configured);
    const published = snapshotPluginMembership(carrier);
    expect(published).not.toBe(configured);
    expect(published.map(plugin => plugin.name)).toEqual(['configured']);

    const registry = Reflect.get(
      globalThis,
      Symbol.for('@bajustone/fortress/internal/plugin-membership-registry/v2'),
    ) as WeakMap<object, {
      membership: readonly RuntimeFortressPlugin[];
      published: boolean;
    }>;
    registry.set(carrier, {
      membership: Object.freeze([{ name: 'forged-registry-value' }]),
      published: true,
    });

    expect(() => snapshotPluginMembership(carrier)).toThrow('snapshot is invalid');
  });

  it('rejects a forged own symbol backed only by a fixture fallback record', () => {
    const membershipKey = Symbol.for('@bajustone/fortress/internal/plugin-membership/v1');
    const fixture = {
      config: {
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [{ name: 'fixture' }],
      } satisfies FortressConfig,
    };
    const fallback = snapshotPluginMembership(fixture);
    Object.defineProperty(fixture, membershipKey, { value: fallback });

    expect(() => snapshotPluginMembership(fixture)).toThrow('snapshot is invalid');
  });

  it('rejects a forged own symbol without registry proof', () => {
    const carrier = {};
    Object.defineProperty(
      carrier,
      Symbol.for('@bajustone/fortress/internal/plugin-membership/v1'),
      { value: Object.freeze([{ name: 'forged' }]) },
    );

    expect(() => snapshotPluginMembership(carrier)).toThrow('snapshot is invalid');
  });

  it('does not invoke inherited or own symbol accessors', () => {
    const membershipKey = Symbol.for('@bajustone/fortress/internal/plugin-membership/v1');
    const inheritedGetter = vi.fn(() => {
      throw new Error('inherited getter must not run');
    });
    const prototype = {};
    Object.defineProperty(prototype, membershipKey, { get: inheritedGetter });
    const fixture = Object.assign(Object.create(prototype) as object, {
      config: {
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [{ name: 'fixture' }],
      } satisfies FortressConfig,
    });

    expect(snapshotPluginMembership(fixture).map(plugin => plugin.name)).toEqual(['fixture']);
    expect(inheritedGetter).not.toHaveBeenCalled();

    const ownGetter = vi.fn(() => Object.freeze([{ name: 'forged' }]));
    const forged = {};
    Object.defineProperty(forged, membershipKey, { get: ownGetter });
    expect(() => snapshotPluginMembership(forged)).toThrow('snapshot is invalid');
    expect(ownGetter).not.toHaveBeenCalled();
  });

  it.each(['mutable', 'frozen'] as const)('does not trust a caller-forged capability marker on a $s array', async (kind) => {
    const original = vi.fn(async () => null);
    const replacement = vi.fn(async () => ({ subject: { type: 'USER' as const, id: 'late' } }));
    const definition: RuntimeFortressPlugin = { name: 'forged-view', resolvePrincipal: original };
    const configured: RuntimeFortressPlugin[] = [definition];
    Object.defineProperty(
      configured,
      Symbol.for('@bajustone/fortress/internal/plugin-capability-view/v1'),
      { value: true },
    );
    if (kind === 'frozen')
      Object.freeze(configured);
    const carrier = {};

    publishPluginMembership(carrier, configured);
    const snapshot = snapshotPluginMembership(carrier);
    definition.resolvePrincipal = replacement;
    const result = await snapshot[0]!.resolvePrincipal!(new Request('https://example.test'), {
      db: createTestAdapter(),
      config: { jwt: { key: SECRET }, database: createTestAdapter() },
    });

    expect(result).toBeNull();
    expect(original).toHaveBeenCalledOnce();
    expect(replacement).not.toHaveBeenCalled();
    expect(snapshot).not.toBe(configured);
  });

  it('snapshots fallback descriptor capabilities on first use', async () => {
    const original = vi.fn(async () => null);
    const replacement = vi.fn(async () => ({ subject: { type: 'USER' as const, id: 'late' } }));
    const middleware = vi.fn(async (_ctx: unknown, _request: unknown, next: () => Promise<void>) => next());
    const definition: RuntimeFortressPlugin = {
      name: 'fixture',
      resolvePrincipal: original,
      middleware: [{ path: '/*', position: 'before-auth', handler: middleware }],
    };
    const fixture = {
      config: {
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [definition],
      } satisfies FortressConfig,
    };

    const snapshot = snapshotPluginMembership(fixture);
    definition.resolvePrincipal = replacement;
    definition.middleware![0]!.path = '/late';
    definition.middleware!.splice(0);

    const result = await snapshot[0]!.resolvePrincipal!(new Request('https://example.test'), {
      db: createTestAdapter(),
      config: fixture.config,
    });
    expect(result).toBeNull();
    expect(original).toHaveBeenCalledOnce();
    expect(replacement).not.toHaveBeenCalled();
    expect(snapshot[0]!.middleware?.[0]?.path).toBe('/*');
    expect(Object.isFrozen(snapshot[0])).toBe(true);
    expect(Object.isFrozen(snapshot[0]!.middleware)).toBe(true);
    expect(Object.isFrozen(definition)).toBe(false);
    expect(Object.isFrozen(definition.middleware)).toBe(false);
  });

  it('copies retained startup metadata without freezing caller inputs', () => {
    const dependencyMethods = ['read'];
    const dependencies = [{ plugin: 'provider', methods: dependencyMethods }];
    const overrideNames = ['login'];
    const constraintFields = ['tenantId'];
    const constraints = [{ type: 'index' as const, fields: constraintFields }];
    const fields = { tenantId: { type: 'string' as const, required: true } };
    const models = [{ name: 'document', fields, constraints }];
    const definition: RuntimeFortressPlugin = {
      name: 'metadata',
      dependencies,
      coreOverrides: overrideNames,
      models,
    };
    const fixture = {
      config: {
        jwt: { key: SECRET },
        database: createTestAdapter(),
        plugins: [definition],
      } satisfies FortressConfig,
    };

    const snapshot = snapshotPluginMembership(fixture)[0]!;
    dependencyMethods[0] = 'late';
    dependencies.splice(0);
    overrideNames[0] = 'late';
    constraintFields[0] = 'late';
    constraints.splice(0);
    fields.tenantId.required = false;
    models.splice(0);

    expect(snapshot.dependencies).toEqual([{ plugin: 'provider', methods: ['read'] }]);
    expect(snapshot.coreOverrides).toEqual(['login']);
    expect(snapshot.models).toEqual([expect.objectContaining({
      name: 'document',
      fields: { tenantId: { type: 'string', required: true } },
      constraints: [{ type: 'index', fields: ['tenantId'] }],
    })]);
    expect(Object.isFrozen(definition)).toBe(false);
    expect(Object.isFrozen(dependencies)).toBe(false);
    expect(Object.isFrozen(overrideNames)).toBe(false);
    expect(Object.isFrozen(models)).toBe(false);
  });

  it('survives independently loaded module copies without mutating caller inputs', async () => {
    const firstCopy = await import('./plugin-membership');
    const configured: RuntimeFortressPlugin[] = [{ name: 'configured' }];
    const config: FortressConfig = {
      jwt: { key: SECRET },
      database: createTestAdapter(),
      plugins: configured,
    };
    const snapshot = Object.freeze([...configured]);
    const instance = { config };

    firstCopy.publishPluginMembership(instance, snapshot);
    expect(Object.isFrozen(configured)).toBe(false);
    expect(config.plugins).toBe(configured);

    configured.splice(0, configured.length, { name: 'late' });
    vi.resetModules();
    const secondCopy = await import('./plugin-membership');

    expect(secondCopy.snapshotPluginMembership(instance).map(plugin => plugin.name)).toEqual(['configured']);
    expect(config.plugins).toBe(configured);
    expect(configured.map(plugin => plugin.name)).toEqual(['late']);
  });
});
