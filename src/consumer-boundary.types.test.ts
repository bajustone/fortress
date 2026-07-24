import type { DatabaseAdapter } from './adapters/database';
import type { AnyFortress, Fortress, TypedCall } from './core/fortress';
import type { CallOptions } from './core/http/call';
import type { FortressPlugin } from './core/plugin';
import type { InferPlugins } from './core/plugin-methods-map';
import type { ApiKeyMethods } from './plugins/api-key';
import type { SvelteKitRequestEvent } from './sveltekit/types';
import { Hono } from 'hono';
import { describe, expectTypeOf, it } from 'vitest';
import {
  createErrorHandler,
  createAuthMiddleware as createExpressAuthMiddleware,
  createExpressMiddleware,
  createExpressPluginMiddleware,
  createRbacMiddleware as createExpressRbacMiddleware,
  protectedRoute as expressProtectedRoute,
  mountFortress as mountExpressFortress,
} from './express';
import {
  createHonoMiddleware,
  createPluginMiddleware as createHonoPluginMiddleware,
  protectedRoute as honoProtectedRoute,
  mountFortress as mountHonoFortress,
} from './hono';
import {
  buildCall,
  buildRouteManifest,
  createFortress,
  detectRouteManifestDrift,
  endpoint,
  getPluginMethods,
  obj,
  protect,
  resolveProtectedEndpoint,
  str,
} from './index';
import { apiKey } from './plugins/api-key';
import { expressRateLimit } from './plugins/rate-limit/express';
import { honoRateLimit } from './plugins/rate-limit/hono';
import { svelteKitRateLimit } from './plugins/rate-limit/sveltekit';
import {
  clearAuthCookies,
  createSvelteKitHandle,
  fortressActions,
  setAuthCookies,
  protectedRoute as svelteKitProtectedRoute,
  toSvelteKitHandler,
} from './sveltekit';
import {
  checkPublicRoutes,
  checkRouteManifestDrift,
  runFortressChecks,
  smokeTestAuth,
} from './testing/checks';

interface ExpressAppBoundary {
  use: Parameters<typeof mountExpressFortress>[0]['use'];
}

type ExpectedFixtureCall = (
  input: { message: string },
  options?: CallOptions,
) => Promise<{ echo: string }>;

/** Compile-only coverage: this function is deliberately never invoked. */
function acceptsBrandedPluginAtEverySourceBoundary(
  database: DatabaseAdapter,
  expressApp: ExpressAppBoundary,
  event: SvelteKitRequestEvent,
): void {
  const brandedPlugin: FortressPlugin & { readonly name: 'api-key' } = apiKey();
  const fortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [brandedPlugin],
  });

  // The consumer boundary erases only the receiving API's view. The created
  // instance keeps the plugin brand and precise built-in method surface.
  expectTypeOf(fortress).toMatchTypeOf<AnyFortress>();
  expectTypeOf(fortress.plugins['api-key']).toEqualTypeOf<ApiKeyMethods>();
  expectTypeOf(fortress).toEqualTypeOf<
    Fortress<InferPlugins<[typeof brandedPlugin]>, TypedCall<[typeof brandedPlugin]>>
  >();

  // Exercise a concrete plugin call without deriving the expected type from
  // the instance itself. Inline routes retain their generics; built-in plugin
  // factories currently erase conditional route records (#10/#11), so this
  // intentionally does not claim api-key route inference is fixed here.
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
  expectTypeOf(callFortress.call.fixtureEcho).toEqualTypeOf<ExpectedFixtureCall>();
  expectTypeOf(
    callFortress.call.fixtureEcho({ message: 'hello' }),
  ).toEqualTypeOf<Promise<{ echo: string }>>();
  // @ts-expect-error -- fixtureEcho's concretely inferred input requires message
  callFortress.call.fixtureEcho({});

  const precisePlugins = fortress.plugins;
  const preciseCall = fortress.call;
  // @ts-expect-error -- the created plugin surface is constructed once and readonly
  fortress.plugins = precisePlugins;
  // @ts-expect-error -- the created call surface is constructed once and readonly
  fortress.call = preciseCall;

  const erased: AnyFortress = fortress;
  // @ts-expect-error -- an erased consumer must not replace a precise plugin surface
  erased.plugins = {};
  // @ts-expect-error -- an erased consumer must not replace a precise call surface
  erased.call = {};

  // A consumer can alias the erased facade back to its underlying generic
  // interface, but those generic slots must remain readonly there as well.
  const alias: Fortress<unknown, unknown> = erased;
  const aliasedPlugins = alias.plugins;
  const aliasedCall = alias.call;
  // @ts-expect-error -- aliasing cannot recover a writable plugin slot
  alias.plugins = aliasedPlugins;
  // @ts-expect-error -- aliasing cannot recover a writable call slot
  alias.call = aliasedCall;

  const app = new Hono();
  mountHonoFortress(app, fortress);
  createHonoMiddleware(fortress);
  createHonoPluginMiddleware(fortress, 'before-auth');
  honoProtectedRoute(fortress, 'login', () => ({ ok: true }));
  honoRateLimit(fortress, 'api');

  mountExpressFortress(expressApp, fortress);
  createExpressMiddleware(fortress);
  createExpressAuthMiddleware(fortress);
  createExpressRbacMiddleware(fortress);
  createExpressPluginMiddleware(fortress, 'before-auth');
  createErrorHandler(fortress);
  expressProtectedRoute(fortress, 'login', () => ({ ok: true }));
  expressRateLimit(fortress, 'api');

  createSvelteKitHandle(fortress);
  toSvelteKitHandler(fortress);
  fortressActions.login(fortress);
  fortressActions.register(fortress);
  fortressActions.logout(fortress);
  fortressActions.refresh(fortress);
  setAuthCookies(event, fortress, { accessToken: 'access' });
  clearAuthCookies(event, fortress);
  svelteKitProtectedRoute(fortress, 'login', () => ({ ok: true }));
  void svelteKitRateLimit(fortress, 'api', event);

  protect(fortress, 'login', () => ({ ok: true }));
  resolveProtectedEndpoint(fortress, 'login');
  buildCall(fortress, {});
  buildRouteManifest(fortress);
  detectRouteManifestDrift(fortress);
  getPluginMethods(fortress, 'api-key');

  checkRouteManifestDrift(fortress);
  checkPublicRoutes(fortress);
  void smokeTestAuth(fortress);
  void runFortressChecks({ fortress, skipMigrations: true, skipAuthSmokeTest: true });
}

describe('public Fortress consumer boundary types', () => {
  it('accept branded plugin instances without erasing their created type', () => {
    expectTypeOf(acceptsBrandedPluginAtEverySourceBoundary).toBeFunction();
  });
});
