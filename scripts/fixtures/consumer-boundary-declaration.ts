import type {
  AnyFortress,
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
  getPluginMethods,
  protect,
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
