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
    expect(snapshotPluginMembership(carrier)).toBe(configured);

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
