import type {
  CallOptions,
  DatabaseAdapter,
  Fortress,
  FortressAuthRuntime,
  FortressHttpRuntime,
  FortressManifestRuntime,
  FortressMigrationRuntime,
  FortressObservabilityRuntime,
  FortressPlugin,
  FortressPluginRuntime,
  FortressProtectRuntime,
  FortressRuntime,
} from '@bajustone/fortress';
import type { ApiKeyMethods } from '@bajustone/fortress/plugins/api-key';
import type { SvelteKitRequestEvent } from '@bajustone/fortress/sveltekit';
import {
  buildCall,
  createFortress,
  definePlugin,
  endpoint,
  obj,
  protect,
  str,
} from '@bajustone/fortress';
import { mountFortress as mountExpressFortress } from '@bajustone/fortress/express';
import { createHonoMiddleware, mountFortress as mountHonoFortress } from '@bajustone/fortress/hono';
import { apiKey } from '@bajustone/fortress/plugins/api-key';
import { expressRateLimit } from '@bajustone/fortress/plugins/rate-limit/express';
import { honoRateLimit } from '@bajustone/fortress/plugins/rate-limit/hono';
import { svelteKitRateLimit } from '@bajustone/fortress/plugins/rate-limit/sveltekit';
import {
  createSvelteKitHandle,
  fortressActions,
  protectedRoute as svelteKitProtectedRoute,
  toSvelteKitHandler,
} from '@bajustone/fortress/sveltekit';
import {
  checkPublicRoutes,
  checkRouteManifestDrift,
  runFortressChecks,
  smokeTestAuth,
} from '@bajustone/fortress/testing';
import { Hono } from 'hono';

interface ExpressAppBoundary {
  use: Parameters<typeof mountExpressFortress>[0]['use'];
}

type ExpectedFixtureCall = (
  input: { message: string },
  options?: CallOptions,
) => Promise<{ echo: string }>;

/** Compiled unchanged against public source entrypoints and package exports. */
export function acceptsBrandedPluginFromConsumerContract(
  database: DatabaseAdapter,
  expressApp: ExpressAppBoundary,
  event: SvelteKitRequestEvent,
): Fortress {
  const brandedPlugin: FortressPlugin & { readonly name: 'api-key' } = apiKey();
  const fortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [brandedPlugin] as const,
  });

  const methods: ApiKeyMethods = fortress.plugins['api-key'];
  const precise: Fortress<readonly [typeof brandedPlugin]> = fortress;
  void methods;
  void precise;

  // Dynamic plugin lookup is `unknown` unless a runtime validator proves the
  // surface; caller-selected generic assertions are not expressible.
  const resolved = fortress.resolvePlugin('api-key');
  // @ts-expect-error -- dynamic lookup is unknown without validation
  resolved.createKey({ name: 'key' });
  const validated: ApiKeyMethods = fortress.resolvePlugin(
    'api-key',
    (value): value is ApiKeyMethods => typeof value === 'object' && value !== null,
  );
  void validated;
  // @ts-expect-error -- a bare generic assertion without a validator must not compile
  fortress.resolvePlugin<ApiKeyMethods>('api-key');

  // Exercise a concrete plugin call through the namespaced tree without
  // deriving the expected type from the instance itself. Ownership is
  // explicit: plugin callables live under `call.plugins.<name>`.
  const callPlugin = definePlugin({
    name: 'call-fixture',
    methods: () => ({
      fixtureEcho: async ({ message }: { message: string }): Promise<{ echo: string }> => ({ echo: message }),
    }),
    routes: {
      fixtureEcho: endpoint('POST', '/fixture/echo')
        .body(obj({ message: str() }, 'message'))
        .response(200, 'Echo', obj({ echo: str() }, 'echo'))
        .handler('fixtureEcho')
        .build(),
    },
  });
  const callFortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [callPlugin] as const,
  });
  const fixtureEcho: ExpectedFixtureCall = callFortress.call.plugins['call-fixture'].fixtureEcho;
  const fixtureResult: Promise<{ echo: string }> = callFortress.call.plugins['call-fixture'].fixtureEcho({ message: 'hello' });
  // @ts-expect-error -- built output must not degrade to Promise<any>
  const incompatibleFixtureResult: Promise<{ echo: number }> = callFortress.call.plugins['call-fixture'].fixtureEcho({ message: 'hello' });
  void fixtureEcho;
  void fixtureResult;
  void incompatibleFixtureResult;
  // @ts-expect-error -- fixtureEcho's built input requires message
  callFortress.call.plugins['call-fixture'].fixtureEcho({});
  // @ts-expect-error -- core callables are namespaced; login is not at the call root
  void callFortress.call.login;

  const precisePlugins = fortress.plugins;
  const preciseCall = fortress.call;
  // @ts-expect-error -- public declarations expose the created plugin slot as readonly
  fortress.plugins = precisePlugins;
  // @ts-expect-error -- public declarations expose the created call slot as readonly
  fortress.call = preciseCall;

  const erased: Fortress = fortress;
  // @ts-expect-error -- public declarations must prevent replacing a precise plugin surface
  erased.plugins = {};
  // @ts-expect-error -- public declarations must prevent replacing a precise call surface
  erased.call = preciseCall;

  const alias: Fortress = erased;
  const aliasedPlugins = alias.plugins;
  const aliasedCall = alias.call;
  // @ts-expect-error -- aliasing the public facade cannot recover a writable plugin slot
  alias.plugins = aliasedPlugins;
  // @ts-expect-error -- aliasing the public facade cannot recover a writable call slot
  alias.call = aliasedCall;

  // Every concrete instance satisfies every runtime capability interface —
  // the erased boundaries the adapters below accept.
  const httpRuntime: FortressHttpRuntime = fortress;
  const authRuntime: FortressAuthRuntime = fortress;
  const pluginRuntime: FortressPluginRuntime = fortress;
  const manifestRuntime: FortressManifestRuntime = fortress;
  const migrationRuntime: FortressMigrationRuntime = fortress;
  const observabilityRuntime: FortressObservabilityRuntime = fortress;
  const protectRuntime: FortressProtectRuntime = fortress;
  const fullRuntime: FortressRuntime = fortress;
  void [httpRuntime, authRuntime, pluginRuntime, manifestRuntime, migrationRuntime, observabilityRuntime, protectRuntime, fullRuntime];

  mountHonoFortress(new Hono(), fortress);
  mountHonoFortress(new Hono(), { manifest: fortress.manifest, handleRequest: fortress.handleRequest });
  createHonoMiddleware({
    config: fortress.config,
    iam: fortress.iam,
    resolvePrincipal: fortress.resolvePrincipal,
  });
  // @ts-expect-error -- mount boundary requires the manifest it actually reads
  mountHonoFortress(new Hono(), { handleRequest: fortress.handleRequest });
  honoRateLimit(fortress, 'api');
  mountExpressFortress(expressApp, fortress);
  mountExpressFortress(expressApp, { manifest: fortress.manifest, handleRequest: fortress.handleRequest });
  expressRateLimit(fortress, 'api');
  createSvelteKitHandle(fortress);
  createSvelteKitHandle({
    manifest: fortress.manifest,
    handleRequest: fortress.handleRequest,
    auth: fortress.auth,
    iam: fortress.iam,
    config: fortress.config,
    extractAccessToken: fortress.extractAccessToken,
    cookies: fortress.cookies,
    runPluginMiddleware: fortress.runPluginMiddleware,
  });
  toSvelteKitHandler(fortress);
  fortressActions.login(fortress);
  svelteKitProtectedRoute(fortress, 'login', () => ({ ok: true }));
  void svelteKitRateLimit(fortress, 'api', event);
  protect(fortress, 'login', () => ({ ok: true }));
  buildCall(fortress, {});
  checkRouteManifestDrift(fortress);
  checkPublicRoutes(fortress);
  void smokeTestAuth(fortress);
  void runFortressChecks({ fortress, skipMigrations: true, skipAuthSmokeTest: true });

  return fortress;
}
