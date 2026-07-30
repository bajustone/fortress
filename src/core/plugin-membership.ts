import type { FortressConfig } from './config';
import type { RuntimeFortressPlugin } from './plugin';
import { isPluginCapabilityView, snapshotPluginCapabilities } from './plugin-capabilities';

/**
 * Process-wide registry key. Package consumers can load the ESM core and a CJS
 * adapter (or the reverse), so each bundle's module-local state is not a trust
 * boundary. Both copies share this registry through `globalThis`.
 */
const REGISTRY_KEY = Symbol.for('@bajustone/fortress/internal/plugin-membership-registry/v2');
const INSTANCE_KEY = Symbol.for('@bajustone/fortress/internal/plugin-membership/v1');

type PluginMembership = readonly RuntimeFortressPlugin[];
interface PluginMembershipRecord {
  readonly membership: PluginMembership;
  readonly published: boolean;
}
type MembershipCarrier = object & { readonly config?: Readonly<FortressConfig> };
type MembershipSource = MembershipCarrier | Readonly<FortressConfig>;

function membershipRegistry(): WeakMap<object, PluginMembershipRecord> {
  const existing = Reflect.get(globalThis, REGISTRY_KEY) as unknown;
  if (existing !== undefined) {
    if (!(existing instanceof WeakMap))
      throw new TypeError('Fortress plugin membership registry is invalid');
    return existing as WeakMap<object, PluginMembershipRecord>;
  }

  const registry = new WeakMap<object, PluginMembershipRecord>();
  Object.defineProperty(globalThis, REGISTRY_KEY, {
    value: registry,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  return registry;
}

function immutableCopy(plugins: readonly RuntimeFortressPlugin[]): PluginMembership {
  return isPluginCapabilityView(plugins) ? plugins : snapshotPluginCapabilities(plugins);
}

/**
 * Publish construction-local membership on an internally owned carrier. The
 * symbol is global so a genuine instance crossing ESM/CJS bundle boundaries
 * retains its trust boundary; it is deliberately absent from public
 * declarations. Plugin contexts receive the same property before any factory
 * runs, keeping nested/re-entrant constructions isolated from one another.
 */
export function publishPluginMembership(
  carrier: object,
  plugins: PluginMembership,
): void {
  if (!Array.isArray(plugins))
    throw new TypeError('Fortress plugin membership must be an array');
  // `processPlugins()` is also an internal entry point. Materialize mutable,
  // merely array-frozen, or caller-marked inputs. Only a module-local WeakSet
  // can prove a capability view created by this module instance.
  const snapshot = immutableCopy(plugins);
  const registry = membershipRegistry();
  // Define first: if the carrier is non-extensible or already published, no
  // registry-only proof is left behind. WeakMap#set cannot fail for `carrier`
  // after the data property has been installed successfully.
  Object.defineProperty(carrier, INSTANCE_KEY, {
    value: snapshot,
    enumerable: false,
    configurable: false,
    writable: false,
  });
  registry.set(carrier, Object.freeze({ membership: snapshot, published: true }));
}

/**
 * Resolve immutable membership at a request/factory boundary. Genuine
 * instances return their construction-validated snapshot. Focused capability
 * fixtures get a frozen copy on first use, retained in the shared registry so
 * later calls never re-enumerate a mutated `config.plugins` array.
 */
export function snapshotPluginMembership(carrier: MembershipSource): PluginMembership {
  const registry = membershipRegistry();
  const registered = registry.get(carrier);
  // Never use Reflect.get here: an inherited symbol or accessor is not proof
  // of publication, and invoking a caller-controlled getter would cross the
  // boundary before authenticity has been established.
  const directDescriptor = Object.getOwnPropertyDescriptor(carrier, INSTANCE_KEY);
  if (directDescriptor !== undefined) {
    const direct = 'value' in directDescriptor ? directDescriptor.value as unknown : undefined;
    if (
      !('value' in directDescriptor)
      || !Array.isArray(direct)
      || !Object.isFrozen(direct)
      || registered?.published !== true
      || direct !== registered.membership
    ) {
      throw new TypeError('Fortress plugin membership snapshot is invalid');
    }
    return direct as PluginMembership;
  }

  if (registered) {
    if (registered.published)
      throw new TypeError('Fortress plugin membership snapshot is invalid');
    return registered.membership;
  }

  const nestedConfig = Reflect.get(carrier, 'config') as unknown;
  const config = nestedConfig !== null && typeof nestedConfig === 'object'
    ? nestedConfig as Readonly<FortressConfig>
    : Reflect.has(carrier, 'jwt') && Reflect.has(carrier, 'database')
      ? carrier as Readonly<FortressConfig>
      : undefined;
  if (config) {
    const configured = registry.get(config);
    if (configured) {
      const record = configured.published
        ? Object.freeze({ membership: configured.membership, published: false })
        : configured;
      registry.set(carrier, record);
      return configured.membership;
    }

    const snapshot = immutableCopy(config.plugins ?? []);
    const record = Object.freeze({ membership: snapshot, published: false });
    registry.set(config, record);
    registry.set(carrier, record);
    return snapshot;
  }

  const snapshot = immutableCopy([]);
  registry.set(carrier, Object.freeze({ membership: snapshot, published: false }));
  return snapshot;
}
