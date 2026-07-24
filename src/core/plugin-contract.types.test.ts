import type { DatabaseAdapter } from '../adapters/database';
import type { accountLockout } from '../plugins/account-lockout';
import type { admin } from '../plugins/admin';
import type { auditLog } from '../plugins/audit-log';
import type { dataIsolation } from '../plugins/data-isolation';
import type { emailVerification } from '../plugins/email-verification';
import type { magicLink } from '../plugins/magic-link';
import type { oauth } from '../plugins/oauth';
import type { openapi } from '../plugins/openapi';
import type { rateLimit } from '../plugins/rate-limit';
import type { socialLogin } from '../plugins/social-login';
import type { twoFactor } from '../plugins/two-factor';
import type { webauthn } from '../plugins/webauthn';
import type { webhook } from '../plugins/webhook';
import type { FortressPlugin } from './plugin';
import type { InferPlugins } from './plugin-methods-map';
import { describe, expect, it } from 'vitest';
import { apiKey } from '../plugins/api-key';
import { tenancy } from '../plugins/tenancy';
import { createFortress, getPluginMethods } from './fortress';
import { definePlugin } from './plugin';
import { endpoint, obj, str } from './schema-builder';

describe('plugin type contracts', () => {
  it('compile without runtime setup', () => {
    expect(true).toBe(true);
  });
});

interface LegacyMethods { ping: () => 'pong' }
declare module './plugin-methods-map' {
  interface PluginMethodsMap { legacy: LegacyMethods }
}

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
type Assert<T extends true> = T;
type Surface<F extends (...args: any[]) => any> = InferPlugins<readonly [ReturnType<F>]>;
type Has<S, N extends keyof S, M extends PropertyKey> = M extends keyof S[N] ? true : false;
type Lacks<S, N extends keyof S, M extends PropertyKey> = M extends keyof S[N] ? false : true;

export type AccountContract = Assert<Has<Surface<typeof accountLockout>, 'account-lockout', 'getLockoutStatus'>>;
export type AdminContract = Assert<Has<Surface<typeof admin>, 'admin', 'listUsers'>>;
export type ApiKeyContract = Assert<Has<Surface<typeof apiKey>, 'api-key', 'createKey'>>;
export type AuditContract = Assert<Has<Surface<typeof auditLog>, 'audit-log', 'getAuditLog'>>;
export type IsolationContract = Assert<Has<Surface<typeof dataIsolation>, 'data-isolation', 'withoutScope'>>;
export type EmailContract = Assert<Has<Surface<typeof emailVerification>, 'email-verification', 'verify'>>;
export type MagicContract = Assert<Has<Surface<typeof magicLink>, 'magic-link', 'sendMagicLink'>>;
export type OAuthContract = Assert<Has<Surface<typeof oauth>, 'oauth', 'createClient'>>;
export type OpenAPIContract = Assert<Has<Surface<typeof openapi>, 'openapi', 'generateSpec'>>;
export type RateContract = Assert<Has<Surface<typeof rateLimit>, 'rate-limit', 'check'>>;
export type SocialContract = Assert<Has<Surface<typeof socialLogin>, 'social-login', 'getProviders'>>;
export type TenancyContract = Assert<Has<Surface<typeof tenancy>, 'tenancy', 'createTenant'>>;
export type TwoFactorContract = Assert<Has<Surface<typeof twoFactor>, 'two-factor', 'enable'>>;
export type WebAuthnContract = Assert<Has<Surface<typeof webauthn>, 'webauthn', 'generateRegistrationOptions'>>;
export type WebhookContract = Assert<Has<Surface<typeof webhook>, 'webhook', 'emit'>>;

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

type AllBuiltIns = InferPlugins<readonly [
  ReturnType<typeof accountLockout>,
  ReturnType<typeof admin>,
  ReturnType<typeof apiKey>,
  ReturnType<typeof auditLog>,
  ReturnType<typeof dataIsolation>,
  ReturnType<typeof emailVerification>,
  ReturnType<typeof magicLink>,
  ReturnType<typeof oauth>,
  ReturnType<typeof openapi>,
  ReturnType<typeof rateLimit>,
  ReturnType<typeof socialLogin>,
  ReturnType<typeof tenancy>,
  ReturnType<typeof twoFactor>,
  ReturnType<typeof webauthn>,
  ReturnType<typeof webhook>,
]>;

export function compileAllBuiltIns(plugins: AllBuiltIns): void {
  plugins['account-lockout'].getLockoutStatus('user');
  plugins.admin.listUsers({});
  plugins['api-key'].createKey({ name: 'key', subject: { type: 'USER', id: '1' } });
  plugins['audit-log'].getAuditLog();
  plugins['data-isolation'].unscoped(async () => undefined);
  plugins['email-verification'].verify('token');
  plugins['magic-link'].sendMagicLink('user@example.com');
  plugins.oauth.createClient({ name: 'client', redirectUris: [], grantTypes: [] });
  plugins.openapi.generateSpec();
  plugins['rate-limit'].listRules();
  plugins['social-login'].getProviders();
  plugins.tenancy.createTenant({ name: 'Acme', taxId: 'acme' });
  plugins['two-factor'].enable('1');
  plugins.webauthn.generateAuthenticationOptions({});
  plugins.webhook.listEventTypes();
  // @ts-expect-error an all-built-ins tuple has no arbitrary plugin key
  void plugins.missing;
  // @ts-expect-error built-in method surfaces have no arbitrary method key
  plugins.openapi.missing();
}

const thirdParty = definePlugin({
  name: 'third-party',
  methods: () => ({ greet: (name: string) => `Hello ${name}` }),
  routes: {
    thirdPartyGreeting: endpoint('POST', '/third-party/greet')
      .body(obj({ name: str() }, 'name'))
      .response(200, 'Greeting', obj({ greeting: str() }, 'greeting'))
      .handler('thirdPartyGreeting')
      .build(),
  },
});

declare const _legacyPlugin: FortressPlugin<'legacy'>;
export type LegacyContract = Assert<Equal<InferPlugins<readonly [typeof _legacyPlugin]>['legacy'], LegacyMethods>>;

interface ExpectedMethods { ok: () => number }
definePlugin({
  name: 'broken',
  // @ts-expect-error implementation does not satisfy the declared method contract
  methods: () => ({ ok: () => 'wrong' }),
} satisfies FortressPlugin<'broken', ExpectedMethods>);

export function compilePluginContracts(database: DatabaseAdapter): void {
  const thirdFortress = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [thirdParty] as const });
  const greeting: Promise<{ greeting: string }> = thirdFortress.call.thirdPartyGreeting({ name: 'Ada' });
  void greeting;
  thirdFortress.plugins['third-party'].greet('Ada');
  // @ts-expect-error callers cannot select an invented result generic
  getPluginMethods<{ invented: () => void }>(thirdFortress, 'third-party');
  // @ts-expect-error unknown third-party method
  thirdFortress.plugins['third-party'].missing();
  // @ts-expect-error unknown third-party route
  thirdFortress.call.missingRoute({});
  // @ts-expect-error route input requires name
  thirdFortress.call.thirdPartyGreeting({});

  const apiRoutes = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [apiKey({ routes: true })] as const });
  apiRoutes.call.createKey({ name: 'key' });
  const apiNoRoutes = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [apiKey()] as const });
  // @ts-expect-error disabled API-key routes do not contribute calls
  apiNoRoutes.call.createKey({ name: 'key' });
  const tenancyRoutesFortress = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [tenancy({ routes: true })] as const });
  tenancyRoutesFortress.call.createTenant({ name: 'Acme', taxId: 'acme' });
  const tenancyNoRoutes = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [tenancy()] as const });
  // @ts-expect-error disabled tenancy routes do not contribute calls
  tenancyNoRoutes.call.createTenant({ name: 'Acme', taxId: 'acme' });
}
