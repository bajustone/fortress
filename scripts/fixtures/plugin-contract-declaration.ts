import type {
  DatabaseAdapter,
  FortressPlugin,
  InferPlugins,
} from '@bajustone/fortress';
import type { accountLockout } from '@bajustone/fortress/plugins/account-lockout';
import type { admin } from '@bajustone/fortress/plugins/admin';
import type { auditLog } from '@bajustone/fortress/plugins/audit-log';
import type { dataIsolation } from '@bajustone/fortress/plugins/data-isolation';
import type { emailVerification } from '@bajustone/fortress/plugins/email-verification';
import type { magicLink } from '@bajustone/fortress/plugins/magic-link';
import type { oauth } from '@bajustone/fortress/plugins/oauth';
import type { openapi } from '@bajustone/fortress/plugins/openapi';
import type { rateLimit } from '@bajustone/fortress/plugins/rate-limit';
import type { socialLogin } from '@bajustone/fortress/plugins/social-login';
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
  methods: () => ({ greet: (name: string) => `Hello ${name}` }),
  routes: {
    builtGreeting: endpoint('POST', '/built/greeting')
      .body(obj({ name: str() }, 'name'))
      .response(200, 'Greeting', obj({ greeting: str() }, 'greeting'))
      .handler('builtGreeting')
      .build(),
  },
});

export function declarationContract(database: DatabaseAdapter, dynamicName: string): void {
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
