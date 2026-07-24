import type {
  AnyFortress,
  CallOptions,
  DatabaseAdapter,
  Fortress,
  FortressPlugin,
  InferPlugins,
  TypedCall,
} from '@bajustone/fortress';
import type { ApiKeyMethods } from '@bajustone/fortress/plugins/api-key';
import type { SvelteKitRequestEvent } from '@bajustone/fortress/sveltekit';
import {
  buildCall,
  createFortress,
  endpoint,
  getPluginMethods,
  obj,
  protect,
  str,
} from '@bajustone/fortress';
import { mountFortress as mountExpressFortress } from '@bajustone/fortress/express';
import { mountFortress as mountHonoFortress } from '@bajustone/fortress/hono';
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

/** Compiled against package exports after `tsup` emits declarations. */
export function acceptsBrandedPluginFromBuiltDeclarations(
  database: DatabaseAdapter,
  expressApp: ExpressAppBoundary,
  event: SvelteKitRequestEvent,
): AnyFortress {
  const brandedPlugin: FortressPlugin & { readonly name: 'api-key' } = apiKey();
  const fortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [brandedPlugin],
  });

  const methods: ApiKeyMethods = fortress.plugins['api-key'];
  const precise: Fortress<
    InferPlugins<[typeof brandedPlugin]>,
    TypedCall<[typeof brandedPlugin]>
  > = fortress;
  void methods;
  void precise;

  // Inline plugin routes retain their generics in built declarations. Built-in
  // factories currently erase conditional route records (#10/#11), so this
  // intentionally checks only the strongest independently supported case.
  const callPlugin = {
    name: 'call-fixture',
    routes: {
      fixtureEcho: endpoint('POST', '/fixture/echo')
        .body(obj({ message: str() }, 'message'))
        .response(200, 'Echo', obj({ echo: str() }, 'echo'))
        .handler('fixtureEcho')
        .build(),
    },
  } as const satisfies FortressPlugin;
  const callFortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [callPlugin] as const,
  });
  const fixtureEcho: ExpectedFixtureCall = callFortress.call.fixtureEcho;
  const fixtureResult: Promise<{ echo: string }> = callFortress.call.fixtureEcho({ message: 'hello' });
  // @ts-expect-error -- built output must not degrade to Promise<any>
  const incompatibleFixtureResult: Promise<{ echo: number }> = callFortress.call.fixtureEcho({ message: 'hello' });
  void fixtureEcho;
  void fixtureResult;
  void incompatibleFixtureResult;
  // @ts-expect-error -- fixtureEcho's built input requires message
  callFortress.call.fixtureEcho({});

  const precisePlugins = fortress.plugins;
  const preciseCall = fortress.call;
  // @ts-expect-error -- built declarations expose the created plugin slot as readonly
  fortress.plugins = precisePlugins;
  // @ts-expect-error -- built declarations expose the created call slot as readonly
  fortress.call = preciseCall;

  const erased: AnyFortress = fortress;
  // @ts-expect-error -- built declarations must prevent replacing a precise plugin surface
  erased.plugins = {};
  // @ts-expect-error -- built declarations must prevent replacing a precise call surface
  erased.call = {};

  const alias: Fortress<unknown, unknown> = erased;
  const aliasedPlugins = alias.plugins;
  const aliasedCall = alias.call;
  // @ts-expect-error -- aliasing the built facade cannot recover a writable plugin slot
  alias.plugins = aliasedPlugins;
  // @ts-expect-error -- aliasing the built facade cannot recover a writable call slot
  alias.call = aliasedCall;

  mountHonoFortress(new Hono(), fortress);
  honoRateLimit(fortress, 'api');
  mountExpressFortress(expressApp, fortress);
  expressRateLimit(fortress, 'api');
  createSvelteKitHandle(fortress);
  toSvelteKitHandler(fortress);
  fortressActions.login(fortress);
  svelteKitProtectedRoute(fortress, 'login', () => ({ ok: true }));
  void svelteKitRateLimit(fortress, 'api', event);
  protect(fortress, 'login', () => ({ ok: true }));
  buildCall(fortress, {});
  getPluginMethods<ApiKeyMethods>(fortress, 'api-key');
  checkRouteManifestDrift(fortress);
  checkPublicRoutes(fortress);
  void smokeTestAuth(fortress);
  void runFortressChecks({ fortress, skipMigrations: true, skipAuthSmokeTest: true });

  return fortress;
}
