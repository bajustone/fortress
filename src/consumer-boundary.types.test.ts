import type { DatabaseAdapter } from './adapters/database';
import type {
  FortressAuthRuntime,
  FortressHttpRuntime,
  FortressManifestRuntime,
  FortressMigrationRuntime,
  FortressObservabilityRuntime,
  FortressPluginRuntime,
  FortressProtectRuntime,
  FortressRuntime,
} from './core/capabilities';
import type { Fortress } from './core/fortress';
import type { CallOptions } from './core/http/call';
import type { FortressPlugin } from './core/plugin';
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

  // The bare `Fortress` type is the erased supertype of every concrete
  // instantiation; the created instance keeps the plugin brand and precise
  // built-in method surface (ADR 0001 §1).
  expectTypeOf(fortress).toMatchTypeOf<Fortress>();
  expectTypeOf(fortress.plugins['api-key']).toEqualTypeOf<ApiKeyMethods>();
  expectTypeOf(fortress).toEqualTypeOf<Fortress<readonly [typeof brandedPlugin]>>();

  // Dynamic plugin access is `unknown` unless a runtime validator proves the
  // surface; caller-selected generic assertions are not expressible.
  expectTypeOf(fortress.resolvePlugin('api-key')).toBeUnknown();
  const isApiKeyMethods = (value: unknown): value is ApiKeyMethods =>
    typeof value === 'object' && value !== null;
  expectTypeOf(fortress.resolvePlugin('api-key', isApiKeyMethods)).toEqualTypeOf<ApiKeyMethods>();
  // @ts-expect-error -- a bare generic assertion without a validator must not compile
  fortress.resolvePlugin<ApiKeyMethods>('api-key');

  // Exercise a concrete plugin call through the namespaced tree without
  // deriving the expected type from the instance itself. Ownership is
  // explicit: plugin callables live under `call.plugins.<name>` (ADR 0001 §5).
  const callPlugin = {
    name: 'call-fixture',
    routes: {
      fixtureEcho: endpoint('POST', '/fixture/echo')
        .body(obj({ message: str() }, 'message'))
        .response(200, 'Echo', obj({ echo: str() }, 'echo'))
        .handler('fixtureEcho')
        .build(),
    },
    methods: () => ({
      fixtureEcho: async (input: { message: string }): Promise<{ echo: string }> => ({ echo: input.message }),
    }),
  } as const satisfies FortressPlugin;
  const callFortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [callPlugin] as const,
  });
  expectTypeOf(callFortress.call.plugins['call-fixture'].fixtureEcho).toEqualTypeOf<ExpectedFixtureCall>();
  expectTypeOf(
    callFortress.call.plugins['call-fixture'].fixtureEcho({ message: 'hello' }),
  ).toEqualTypeOf<Promise<{ echo: string }>>();
  // @ts-expect-error -- fixtureEcho's concretely inferred input requires message
  callFortress.call.plugins['call-fixture'].fixtureEcho({});
  // Core callables are namespaced too; there is no flat top-level surface.
  // @ts-expect-error -- login lives under call.auth, not at the call root
  void callFortress.call.login;

  const precisePlugins = fortress.plugins;
  const preciseCall = fortress.call;
  // @ts-expect-error -- the created plugin surface is constructed once and readonly
  fortress.plugins = precisePlugins;
  // @ts-expect-error -- the created call surface is constructed once and readonly
  fortress.call = preciseCall;

  const erased: Fortress = fortress;
  // @ts-expect-error -- an erased consumer must not replace a precise plugin surface
  erased.plugins = {};
  // @ts-expect-error -- an erased consumer must not replace a precise call surface
  erased.call = preciseCall;

  // Every concrete instance satisfies every runtime capability (ADR 0001 §4).
  const httpRuntime: FortressHttpRuntime = fortress;
  const authRuntime: FortressAuthRuntime = fortress;
  const pluginRuntime: FortressPluginRuntime = fortress;
  const manifestRuntime: FortressManifestRuntime = fortress;
  const migrationRuntime: FortressMigrationRuntime = fortress;
  const observabilityRuntime: FortressObservabilityRuntime = fortress;
  const protectRuntime: FortressProtectRuntime = fortress;
  const fullRuntime: FortressRuntime = fortress;
  void [httpRuntime, authRuntime, pluginRuntime, manifestRuntime, migrationRuntime, observabilityRuntime, protectRuntime, fullRuntime];

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
