import type {
  DatabaseAdapter,
  FortressConfig,
  FortressPlugin,
  InferPlugins,
} from '@bajustone/fortress';
import type { accountLockout } from '@bajustone/fortress/plugins/account-lockout';
import type { admin } from '@bajustone/fortress/plugins/admin';
import type { ApiKeyConfig } from '@bajustone/fortress/plugins/api-key';
import type { auditLog } from '@bajustone/fortress/plugins/audit-log';
import type { dataIsolation } from '@bajustone/fortress/plugins/data-isolation';
import type { emailVerification } from '@bajustone/fortress/plugins/email-verification';
import type { magicLink } from '@bajustone/fortress/plugins/magic-link';
import type { oauth } from '@bajustone/fortress/plugins/oauth';
import type { openapi } from '@bajustone/fortress/plugins/openapi';
import type { rateLimit } from '@bajustone/fortress/plugins/rate-limit';
import type { socialLogin } from '@bajustone/fortress/plugins/social-login';
import type { TenancyConfig } from '@bajustone/fortress/plugins/tenancy';
import type { twoFactor } from '@bajustone/fortress/plugins/two-factor';
import type { webauthn } from '@bajustone/fortress/plugins/webauthn';
import type { webhook } from '@bajustone/fortress/plugins/webhook';
import { createFortress, definePlugin, endpoint, getPluginMethods, obj, str } from '@bajustone/fortress';
import { apiKey } from '@bajustone/fortress/plugins/api-key';
import { tenancy } from '@bajustone/fortress/plugins/tenancy';

declare module '@bajustone/fortress' {
  interface PluginMethodsMap {
    'legacy-built': { ping: () => 'pong' };
  }
}

type Has<S, N extends keyof S, M extends PropertyKey> = M extends keyof S[N] ? true : false;
type Lacks<S, N extends keyof S, M extends PropertyKey> = M extends keyof S[N] ? false : true;
type Assert<T extends true> = T;
type Surface<F extends (...args: any[]) => any> = InferPlugins<readonly [ReturnType<F>]>;

export type BuiltInContracts = [
  Assert<Has<Surface<typeof accountLockout>, 'account-lockout', 'getLockoutStatus'>>,
  Assert<Has<Surface<typeof admin>, 'admin', 'listUsers'>>,
  Assert<Has<Surface<typeof apiKey>, 'api-key', 'createKey'>>,
  Assert<Has<Surface<typeof auditLog>, 'audit-log', 'getAuditLog'>>,
  Assert<Has<Surface<typeof dataIsolation>, 'data-isolation', 'withoutScope'>>,
  Assert<Has<Surface<typeof emailVerification>, 'email-verification', 'verify'>>,
  Assert<Has<Surface<typeof magicLink>, 'magic-link', 'sendMagicLink'>>,
  Assert<Has<Surface<typeof oauth>, 'oauth', 'createClient'>>,
  Assert<Has<Surface<typeof openapi>, 'openapi', 'generateSpec'>>,
  Assert<Has<Surface<typeof rateLimit>, 'rate-limit', 'check'>>,
  Assert<Has<Surface<typeof socialLogin>, 'social-login', 'getProviders'>>,
  Assert<Has<Surface<typeof tenancy>, 'tenancy', 'createTenant'>>,
  Assert<Has<Surface<typeof twoFactor>, 'two-factor', 'enable'>>,
  Assert<Has<Surface<typeof webauthn>, 'webauthn', 'generateRegistrationOptions'>>,
  Assert<Has<Surface<typeof webhook>, 'webhook', 'emit'>>,
];

export type BuiltInUnknownMethodContracts = [
  Assert<Lacks<Surface<typeof accountLockout>, 'account-lockout', 'missing'>>,
  Assert<Lacks<Surface<typeof admin>, 'admin', 'missing'>>,
  Assert<Lacks<Surface<typeof apiKey>, 'api-key', 'missing'>>,
  Assert<Lacks<Surface<typeof auditLog>, 'audit-log', 'missing'>>,
  Assert<Lacks<Surface<typeof dataIsolation>, 'data-isolation', 'missing'>>,
  Assert<Lacks<Surface<typeof emailVerification>, 'email-verification', 'missing'>>,
  Assert<Lacks<Surface<typeof magicLink>, 'magic-link', 'missing'>>,
  Assert<Lacks<Surface<typeof oauth>, 'oauth', 'missing'>>,
  Assert<Lacks<Surface<typeof openapi>, 'openapi', 'missing'>>,
  Assert<Lacks<Surface<typeof rateLimit>, 'rate-limit', 'missing'>>,
  Assert<Lacks<Surface<typeof socialLogin>, 'social-login', 'missing'>>,
  Assert<Lacks<Surface<typeof tenancy>, 'tenancy', 'missing'>>,
  Assert<Lacks<Surface<typeof twoFactor>, 'two-factor', 'missing'>>,
  Assert<Lacks<Surface<typeof webauthn>, 'webauthn', 'missing'>>,
  Assert<Lacks<Surface<typeof webhook>, 'webhook', 'missing'>>,
];

const thirdParty = definePlugin({
  name: 'built-third-party',
  methods: () => ({
    greet: (name: string) => `Hello ${name}`,
    builtGreeting: async ({ name }: { name: string }): Promise<{ greeting: string }> => ({
      greeting: `Hello ${name}`,
    }),
  }),
  routes: {
    builtGreeting: endpoint('POST', '/built/greeting')
      .body(obj({ name: str() }, 'name'))
      .response(200, 'Greeting', obj({ greeting: str() }, 'greeting'))
      .handler('builtGreeting')
      .build(),
  },
});

definePlugin({
  name: 'built-missing-handler',
  methods: () => ({ real: () => 'ok' }),
  routes: {
    // @ts-expect-error built declarations retain literal route-handler existence checks
    missing: endpoint('GET', '/built-missing').handler('missing').build(),
  },
});

definePlugin({
  name: 'built-mismatched-route-key',
  methods: () => ({ actual: () => 'ok' }),
  routes: {
    // @ts-expect-error built declarations retain route-key/handler-key correlation
    alias: endpoint('GET', '/built-alias').handler('actual').build(),
  },
});

definePlugin({
  name: 'built-incompatible-handler',
  methods: () => ({ echo: () => ({ echoed: 1 }) }),
  routes: {
    // @ts-expect-error built declarations retain route success-response correlation
    echo: endpoint('GET', '/built-echo')
      .response(200, 'Echo', obj({ echoed: str() }, 'echoed'))
      .handler('echo')
      .build(),
  },
});

definePlugin({
  name: 'built-incompatible-accepted-handler',
  methods: () => ({ accepted: () => ({ wrong: 1 }) }),
  routes: {
    // @ts-expect-error built declarations correlate every declared 2xx response
    accepted: endpoint('POST', '/built-accepted')
      .response(202, 'Accepted', obj({ ok: str() }, 'ok'))
      .handler('accepted')
      .build(),
  },
});

definePlugin({
  name: 'built-non-callable',
  // @ts-expect-error built declarations reject non-function method properties
  methods: () => ({ value: 1 }),
});

interface BuiltConcreteMethods { run: () => void }
// @ts-expect-error concrete FortressPlugin contracts require methods
const _missingBuiltMethods: FortressPlugin<'built-concrete', BuiltConcreteMethods> = { name: 'built-concrete' };
void _missingBuiltMethods;

const exactLegacyName = definePlugin({ name: 'legacy-built' });
export type ExactBuiltEmptyContract = Assert<Lacks<InferPlugins<readonly [typeof exactLegacyName]>, 'legacy-built', 'ping'>>;

export function declarationContract(database: DatabaseAdapter, dynamicName: string): void {
  const noPlugins = createFortress({ database, jwt: { key: 'x'.repeat(32) } });
  // @ts-expect-error omitted plugins expose no arbitrary static keys
  void noPlugins.plugins.arbitrary;
  // @ts-expect-error omitted plugins expose no arbitrary known-key lookup
  getPluginMethods(noPlugins, 'arbitrary');

  const erasedConfig: FortressConfig = { database, jwt: { key: 'x'.repeat(32) } };
  const erased = createFortress(erasedConfig);
  void erased.plugins.arbitrary;
  void getPluginMethods(erased, 'arbitrary');

  const empty = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [exactLegacyName] as const });
  // @ts-expect-error exact methodless plugins do not use legacy augmentation
  empty.plugins['legacy-built'].ping();

  const maybeApiConfig: ApiKeyConfig | undefined = undefined;
  void apiKey(maybeApiConfig);
  const maybeTenancyConfig: TenancyConfig | undefined = undefined;
  void tenancy(maybeTenancyConfig);

  const fortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [thirdParty, apiKey({ routes: true }), tenancy()] as const,
  });
  fortress.plugins['built-third-party'].greet('Ada');
  fortress.call.builtGreeting({ name: 'Ada' });
  fortress.call.createKey({ name: 'key' });
  // @ts-expect-error unknown plugin keys are rejected
  void fortress.plugins.missing;
  // @ts-expect-error unknown methods are rejected
  fortress.plugins['built-third-party'].missing();
  // @ts-expect-error disabled tenancy routes do not contribute calls
  fortress.call.createTenant({ name: 'Acme', taxId: 'acme' });

  getPluginMethods(fortress, 'built-third-party').greet('Ada');
  const dynamic = getPluginMethods(fortress, dynamicName);
  // @ts-expect-error dynamic lookup is unknown without validation
  dynamic.greet('Ada');
  getPluginMethods(
    fortress,
    dynamicName,
    (value): value is { greet: (name: string) => string } => typeof value === 'object'
      && value !== null
      && typeof Reflect.get(value, 'greet') === 'function',
  ).greet('Ada');
}

declare const _legacy: FortressPlugin<'legacy-built'>;
export type LegacyBuiltContract = Assert<Has<InferPlugins<readonly [typeof _legacy]>, 'legacy-built', 'ping'>>;
