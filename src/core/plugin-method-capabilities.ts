import type { PluginMethod, RuntimeFortressPlugin } from './plugin';
import { Errors } from './errors';

export type PluginMethodMap = Record<string, Record<string, PluginMethod>>;

type ControllerPhase = 'constructing' | 'materialized' | 'active' | 'failed';

export interface PluginMethodController {
  readonly methods: PluginMethodMap;
  record: (surface: object) => void;
  materialize: (plugins: readonly RuntimeFortressPlugin[]) => void;
  activate: () => void;
  fail: () => void;
  resolveForContext: (name: string, initializingPlugin?: string) => Readonly<Record<string, PluginMethod>> | undefined;
}

interface CapturedProperty {
  readonly key: PropertyKey;
  readonly descriptor: PropertyDescriptor;
}

interface CapturedLevel {
  readonly own: boolean;
  readonly properties: readonly CapturedProperty[];
}

function failedView(): TypeError {
  return new TypeError('Fortress plugin method view belongs to a failed construction');
}

function unavailableView(): TypeError {
  return new TypeError('Fortress plugin methods are unavailable until construction succeeds');
}

const functionToString = Function.prototype.toString;

function isIntrinsicObjectPrototype(value: object): boolean {
  if (Reflect.getPrototypeOf(value) !== null)
    return false;
  const constructor = Reflect.getOwnPropertyDescriptor(value, 'constructor');
  if (constructor === undefined
    || !('value' in constructor)
    || typeof constructor.value !== 'function'
    || constructor.value.name !== 'Object'
    || constructor.value.prototype !== value) {
    return false;
  }
  try {
    return Reflect.apply(functionToString, constructor.value, []).includes('[native code]');
  }
  catch {
    return false;
  }
}

/**
 * Capture a methods object without retaining any live property lookup through
 * Fortress-controlled entry points. Captured functions deliberately retain the
 * original returned object as their receiver; state and lookups performed by
 * trusted method code therefore remain live.
 */
function snapshotMethodSurface(
  pluginName: string,
  source: object,
  assertCallable: () => void,
): Record<string, PluginMethod> {
  if (source === Object.prototype || isIntrinsicObjectPrototype(source)) {
    throw Errors.badRequest(
      `Plugin "${pluginName}" methods factory must not return Object.prototype`,
    );
  }

  const levels: CapturedLevel[] = [];
  const visited = new Set<object>();
  let owner: object | null = source;
  let own = true;

  // Capture every key and descriptor before invoking any accessor. A getter's
  // side effects therefore cannot add a new capability or replace a descriptor
  // that has not yet been recorded.
  while (owner !== null && owner !== Object.prototype) {
    // Cross-realm Object.prototype values do not share this module's identity.
    // Recognize only a native Object constructor's terminal prototype so a
    // caller-defined null-prototype layer with a constructor self-link remains
    // part of the effective method surface.
    if (!own && isIntrinsicObjectPrototype(owner))
      break;
    if (visited.has(owner))
      throw Errors.badRequest(`Plugin "${pluginName}" methods object has a cyclic prototype chain`);
    visited.add(owner);
    const properties = Reflect.ownKeys(owner).map((key): CapturedProperty => {
      const descriptor = Reflect.getOwnPropertyDescriptor(owner!, key);
      if (!descriptor) {
        throw Errors.badRequest(
          `Plugin "${pluginName}" method "${String(key)}" could not be captured`,
        );
      }
      return { key, descriptor };
    });
    levels.push({ own, properties });
    own = false;
    owner = Reflect.getPrototypeOf(owner) as object | null;
  }

  // Retain only the nearest descriptor for each effective key. Shadowed
  // accessors are not capabilities and must not run merely because a deeper
  // prototype happens to declare the same name.
  const seen = new Set<PropertyKey>();
  const effectiveLevels = levels.map(level => ({
    ...level,
    properties: level.properties.filter(({ key }) => {
      // A prototype's conventional class constructor is not a plugin method;
      // an explicitly own method named constructor remains valid.
      if (!level.own && key === 'constructor')
        return false;
      if (seen.has(key))
        return false;
      seen.add(key);
      return true;
    }),
  }));

  // Evaluate effective accessors from the surface outward only after the full
  // descriptor set is fixed. This retains own-key evaluation order from the
  // former validation path while preventing any getter from changing which
  // later keys or descriptors Fortress captures.
  const materializedLevels = effectiveLevels.map(level => ({
    ...level,
    properties: level.properties.map(({ key, descriptor }) => {
      const value = 'value' in descriptor
        ? descriptor.value
        : descriptor.get === undefined
          ? undefined
          : Reflect.apply(descriptor.get, source, []);
      if (typeof value !== 'function') {
        throw Errors.badRequest(
          `Plugin "${pluginName}" method "${String(key)}" must be callable`,
        );
      }
      return { key, descriptor, value };
    }),
  }));

  let facade: object | null = null;
  for (let levelIndex = materializedLevels.length - 1; levelIndex >= 0; levelIndex--) {
    const level = materializedLevels[levelIndex]!;
    const layer = Object.create(facade) as Record<PropertyKey, unknown>;
    for (const { key, descriptor, value } of level.properties) {
      let publishedValue = value;
      if (typeof value === 'function') {
        publishedValue = function capturedPluginMethod(this: unknown, ...args: unknown[]): unknown {
          void this;
          assertCallable();
          return Reflect.apply(value, source, args);
        };
      }

      Reflect.defineProperty(layer, key, {
        value: publishedValue,
        enumerable: descriptor.enumerable ?? false,
        configurable: false,
        writable: false,
      });
    }
    facade = Object.freeze(layer);
  }

  // Every source produces at least its own level, even for an empty object.
  return facade as Record<string, PluginMethod>;
}

/** One atomic, construction-owned method view shared by every runtime path. */
export function createPluginMethodController(): PluginMethodController {
  let phase: ControllerPhase = 'constructing';
  const sources: object[] = [];
  const methods = Object.create(null) as PluginMethodMap;

  const assertCallable = (): void => {
    if (phase === 'failed')
      throw failedView();
    if (phase !== 'active')
      throw unavailableView();
  };

  return {
    methods,
    record: (surface) => {
      if (phase !== 'constructing')
        throw new TypeError('Fortress plugin method view cannot accept another surface');
      sources.push(surface);
    },
    materialize: (plugins) => {
      if (phase !== 'constructing' || plugins.length !== sources.length)
        throw new TypeError('Fortress plugin method view cannot be materialized');

      try {
        const entries: Array<readonly [string, Record<string, PluginMethod>]> = [];
        const names = new Set<string>();
        for (let index = 0; index < plugins.length; index++) {
          const plugin = plugins[index]!;
          const surface = sources[index]!;
          const name = plugin.name;
          if (names.has(name))
            throw Errors.badRequest(`Duplicate plugin name "${name}"`);
          names.add(name);
          entries.push([name, snapshotMethodSurface(name, surface, assertCallable)]);
        }

        // Publish only after every surface has been captured successfully. If a
        // later surface fails, no partial facade is reachable through the map.
        for (const [name, facade] of entries) {
          Reflect.defineProperty(methods, name, {
            value: facade,
            enumerable: true,
            configurable: false,
            writable: false,
          });
        }
        Object.freeze(methods);
        phase = 'materialized';
      }
      catch (error) {
        phase = 'failed';
        throw error;
      }
    },
    activate: () => {
      if (phase !== 'materialized')
        throw new TypeError('Fortress plugin method view cannot be activated');
      phase = 'active';
    },
    fail: () => {
      phase = 'failed';
    },
    resolveForContext: (name, initializingPlugin) => {
      if (phase === 'failed')
        throw failedView();
      if (phase !== 'active') {
        if (initializingPlugin) {
          throw Errors.badRequest(
            `Plugin "${initializingPlugin}" cannot resolve plugin "${name}" while plugin methods are initializing; defer lookup until a returned method is called`,
            { details: { plugin: initializingPlugin, requestedPlugin: name } },
          );
        }
        throw unavailableView();
      }
      return methods[name];
    },
  };
}
