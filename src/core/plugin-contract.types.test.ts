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
import { createFortress } from './fortress';
import { definePlugin } from './plugin';
import { bool, endpoint, obj, str } from './schema-builder';

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
  methods: () => ({
    greet: (name: string) => `Hello ${name}`,
    // Route handlers are correlated: this method's input/return must match
    // the endpoint's declared body and success response.
    thirdPartyGreeting: async (input: { name: string }): Promise<{ greeting: string }> => ({
      greeting: `Hello ${input.name}`,
    }),
  }),
  routes: {
    thirdPartyGreeting: endpoint('POST', '/third-party/greet')
      .body(obj({ name: str() }, 'name'))
      .response(200, 'Greeting', obj({ greeting: str() }, 'greeting'))
      .handler('thirdPartyGreeting')
      .build(),
  },
});

// A route whose handler is not a plugin method is rejected at the
// definition site (RouteHandlerMissing).
definePlugin({
  name: 'missing-handler',
  methods: () => ({ realMethod: () => 'ok' }),
  routes: {
    // @ts-expect-error handler 'ghost' does not name a plugin method
    ghost: endpoint('POST', '/ghost')
      .body(obj({ name: str() }, 'name'))
      .response(200, 'Ok', obj({ ok: str() }, 'ok'))
      .handler('ghost')
      .build(),
  },
});

// A route whose handler exists but cannot accept the endpoint's input or
// produce its declared success response is rejected (RouteHandlerIncompatible).
definePlugin({
  name: 'incompatible-handler',
  methods: () => ({
    echo: async (input: { message: string }): Promise<{ echo: number }> => ({ echo: input.message.length }),
  }),
  routes: {
    // @ts-expect-error method returns { echo: number } but the route declares { echo: string }
    echo: endpoint('POST', '/echo')
      .body(obj({ message: str() }, 'message'))
      .response(200, 'Echo', obj({ echo: str() }, 'echo'))
      .handler('echo')
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
  const greeting: Promise<{ greeting: string }> = thirdFortress.call.plugins['third-party'].thirdPartyGreeting({ name: 'Ada' });
  void greeting;
  thirdFortress.plugins['third-party'].greet('Ada');
  // @ts-expect-error callers cannot select an invented result generic without a validator
  thirdFortress.resolvePlugin<{ invented: () => void }>('third-party');
  // @ts-expect-error unknown third-party method
  thirdFortress.plugins['third-party'].missing();
  // @ts-expect-error unknown third-party route
  thirdFortress.call.plugins['third-party'].missingRoute({});
  // @ts-expect-error route input requires name
  thirdFortress.call.plugins['third-party'].thirdPartyGreeting({});

  const apiRoutes = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [apiKey({ routes: true })] as const });
  apiRoutes.call.plugins['api-key'].createKey({ name: 'key' });
  const apiNoRoutes = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [apiKey()] as const });
  // @ts-expect-error disabled API-key routes contribute no call namespace
  void apiNoRoutes.call.plugins['api-key'];
  const tenancyRoutesFortress = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [tenancy({ routes: true })] as const });
  tenancyRoutesFortress.call.plugins.tenancy.createTenant({ name: 'Acme', taxId: 'acme' });
  const tenancyNoRoutes = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [tenancy()] as const });
  // @ts-expect-error disabled tenancy routes contribute no call namespace
  void tenancyNoRoutes.call.plugins.tenancy;

  // Cross-plugin call collisions are impossible by construction: two plugins
  // may reuse the same route key because each owns its namespace.
  const first = definePlugin({
    name: 'first',
    methods: () => ({ status: async (): Promise<{ ok: boolean }> => ({ ok: true }) }),
    routes: {
      status: endpoint('GET', '/first/status')
        .response(200, 'Status', obj({ ok: bool() }, 'ok'))
        .handler('status')
        .build(),
    },
  });
  const second = definePlugin({
    name: 'second',
    methods: () => ({ status: async (): Promise<{ ok: boolean }> => ({ ok: false }) }),
    routes: {
      status: endpoint('GET', '/second/status')
        .response(200, 'Status', obj({ ok: bool() }, 'ok'))
        .handler('status')
        .build(),
    },
  });
  const both = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [first, second] as const });
  void both.call.plugins.first.status({});
  void both.call.plugins.second.status({});
}
