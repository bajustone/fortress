import type { AuthService } from './auth/auth-service';
import type { FortressConfig } from './config';
import type { EndpointDefinition } from './endpoint';
import type { IamService } from './iam/iam-service';
import type { FortressPlugin } from './plugin';
import type { InferPlugins } from './plugin-methods-map';
import { authEndpoints } from './auth/auth-endpoints';
import { createAuthService } from './auth/auth-service';
import { Errors } from './errors';
import { iamEndpoints } from './iam/iam-endpoints';
import { createIamService } from './iam/iam-service';
import { processPlugins } from './plugin-runner';

// eslint-disable-next-line ts/no-unsafe-function-type -- fallback type for untyped plugin access
export interface Fortress<TPlugins = Record<string, Record<string, Function>>> {
  auth: AuthService;
  iam: IamService;
  plugins: TPlugins;
  config: Readonly<FortressConfig>;
  /** All endpoint definitions (auth + IAM + plugins) with JSON Schema metadata. */
  endpoints: EndpointDefinition[];
}

/**
 * Type-safe helper to retrieve a plugin's methods from a Fortress instance.
 *
 * Since plugin methods are dynamically typed at runtime, this helper lets
 * consumers provide a known interface for type-safe access without casting.
 *
 * @example
 * ```ts
 * interface TwoFactorMethods {
 *   setup: (userId: number) => Promise<{ secret: string; qrCode: string }>;
 *   verify: (userId: number, code: string) => Promise<boolean>;
 * }
 *
 * const twoFactor = getPluginMethods<TwoFactorMethods>(fortress, 'two-factor');
 * const result = await twoFactor.setup(userId); // fully typed
 * ```
 */
export function getPluginMethods<T>(fortress: Fortress, pluginName: string): T {
  const methods = fortress.plugins[pluginName];
  if (!methods) {
    throw Errors.notFound(`Plugin '${pluginName}' is not registered`);
  }
  return methods as T;
}

const MIN_SECRET_BYTES = 32;

export function createFortress<const T extends readonly FortressPlugin[]>(
  config: FortressConfig & { plugins?: T },
): Fortress<InferPlugins<T>> {
  // Validate JWT secret strength
  const secrets = Array.isArray(config.jwt.secret) ? config.jwt.secret : [config.jwt.secret];
  for (const secret of secrets) {
    if (new TextEncoder().encode(secret).length < MIN_SECRET_BYTES) {
      throw Errors.badRequest(
        `JWT secret must be at least ${MIN_SECRET_BYTES} bytes for HS256 security. Got ${new TextEncoder().encode(secret).length} bytes.`,
      );
    }
  }

  const plugins = config.plugins ?? [];
  const db = config.database;

  // Validate plugin name uniqueness
  const pluginNames = new Set<string>();
  for (const plugin of plugins) {
    if (pluginNames.has(plugin.name)) {
      throw Errors.badRequest(`Duplicate plugin name: '${plugin.name}'`);
    }
    pluginNames.add(plugin.name);
  }

  const auth = createAuthService(db, config, plugins);
  const iam = createIamService(db, config);
  const pluginMethods = processPlugins(plugins, db, config, auth, iam);

  // Wire IAM events → audit log if the plugin is registered
  if (pluginMethods['audit-log']?.logCustomEvent) {
    const logCustomEvent = pluginMethods['audit-log'].logCustomEvent as (event: import('./iam/iam-service').IamEvent) => Promise<void>;
    iam.setIamObserver(event => logCustomEvent(event));
  }

  // Assemble all endpoint definitions: core auth + IAM + plugin routes
  // Deduplicate by method+path — plugin routes take priority over core definitions
  const pluginEndpoints: EndpointDefinition[] = [];
  for (const plugin of plugins) {
    if (plugin.routes) {
      pluginEndpoints.push(...plugin.routes);
    }
  }
  const endpointMap = new Map<string, EndpointDefinition>();
  for (const ep of [...authEndpoints, ...iamEndpoints, ...pluginEndpoints]) {
    endpointMap.set(`${ep.method} ${ep.path}`, ep);
  }
  const endpoints = Array.from(endpointMap.values());

  return {
    auth,
    iam,
    plugins: pluginMethods as InferPlugins<T>,
    config,
    endpoints,
  };
}
