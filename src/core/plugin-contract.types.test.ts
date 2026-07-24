import type { DatabaseAdapter } from '../adapters/database';
import type { accountLockout } from '../plugins/account-lockout';
import type { auditLog } from '../plugins/audit-log';
import type { dataIsolation } from '../plugins/data-isolation';
import type { emailVerification } from '../plugins/email-verification';
import type { magicLink } from '../plugins/magic-link';
import type { rateLimit } from '../plugins/rate-limit';
import type { socialLogin } from '../plugins/social-login';
import type { twoFactor } from '../plugins/two-factor';
import type { webauthn } from '../plugins/webauthn';
import type { webhook } from '../plugins/webhook';
import type { FortressPlugin } from './plugin';
import type { InferPlugins } from './plugin-methods-map';
import { describe, expect, it } from 'vitest';
import { admin } from '../plugins/admin';
import { apiKey } from '../plugins/api-key';
import { oauth } from '../plugins/oauth';
import { openapi } from '../plugins/openapi';
import { tenancy } from '../plugins/tenancy';
import { defineEndpoints } from './define-endpoints';
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

const composedRoutes = defineEndpoints({
  composedEcho: endpoint('POST', '/composed/echo')
    .body(obj({ message: str() }, 'message'))
    .response(200, 'Echo', obj({ echoed: str() }, 'echoed'))
    .handler('composedEcho')
    .build(),
});

const composedPlugin = definePlugin({
  name: 'composed',
  methods: () => ({
    composedEcho: async ({ message }: { message: string }): Promise<{ echoed: string }> => ({ echoed: message }),
  }),
  routes: composedRoutes,
});

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

definePlugin({
  name: 'function-return',
  methods: () => ({ invalid: async (): Promise<() => string> => () => 'not JSON' }),
  routes: {
    // @ts-expect-error function-valued returns project to never and cannot satisfy a JSON response
    invalid: endpoint('GET', '/invalid-function')
      .response(200, 'Invalid', obj({ value: str() }, 'value'))
      .handler('invalid')
      .build(),
  },
});

definePlugin({
  name: 'nested-function-return',
  methods: () => ({ invalid: async () => ({ value: () => 'not JSON' }) }),
  routes: {
    // @ts-expect-error nested function values are omitted by JSON.stringify and must be rejected
    invalid: endpoint('GET', '/invalid-nested-function')
      .response(200, 'Invalid', obj({ value: str() }, 'value'))
      .handler('invalid')
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
  const noPlugins = createFortress({ database, jwt: { key: 'x'.repeat(32) } });
  // @ts-expect-error omitted plugins produce an exact empty static plugin surface
  void noPlugins.plugins.arbitrary;
  // @ts-expect-error omitted plugins produce an exact empty plugin call surface
  void noPlugins.call.plugins.arbitrary;
  void noPlugins.call.auth.login;
  void noPlugins.call.iam.getRoles;

  const composedFortress = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [composedPlugin] as const });
  const composedResult: Promise<{ echoed: string }> = composedFortress.call.plugins.composed.composedEcho({ message: 'ok' });
  void composedResult;
  // @ts-expect-error defineEndpoints preserves its exact route keys through definePlugin
  void composedFortress.call.plugins.composed.unknown;

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

  const override = definePlugin({
    name: 'override',
    coreOverrides: ['login', 'getRoles'] as const,
    methods: () => ({
      login: async ({ code }: { code: string }): Promise<{ alternate: boolean }> => ({ alternate: code.length > 0 }),
      getRoles: async (): Promise<{ source: string }> => ({ source: 'plugin' }),
    }),
    routes: {
      login: endpoint('POST', '/auth//login/')
        .body(obj({ code: str() }, 'code'))
        .response(200, 'Alternate', obj({ alternate: bool() }, 'alternate'))
        .handler('login')
        .build(),
      getRoles: endpoint('GET', '/iam/roles')
        .response(200, 'Alternate', obj({ source: str() }, 'source'))
        .handler('getRoles')
        .build(),
    },
  });
  const overridden = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [override] as const });
  void overridden.call.plugins.override.login({ code: '123' });
  void overridden.call.plugins.override.getRoles({});
  // @ts-expect-error overridden core auth call is omitted rather than retaining a false contract
  void overridden.call.auth.login;
  // @ts-expect-error overridden core IAM call is omitted rather than retaining a false contract
  void overridden.call.iam.getRoles;
  void overridden.call.auth.me({});

  const unrelatedLoginKey = definePlugin({
    name: 'unrelated-login-key',
    methods: () => ({
      login: async (): Promise<{ ok: boolean }> => ({ ok: true }),
    }),
    routes: {
      login: endpoint('GET', '/custom/login-status')
        .response(200, 'Status', obj({ ok: bool() }, 'ok'))
        .handler('login')
        .build(),
    },
  });
  const unrelated = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [unrelatedLoginKey] as const,
  });
  void unrelated.call.auth.login;
  void unrelated.call.plugins['unrelated-login-key'].login;

  const oauthFortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [oauth({ loginUrl: '/login', consentUrl: '/consent' })] as const,
  });
  // OAuth protocol routes require form/basic/bearer semantics and are not generic JSON callables.
  // @ts-expect-error excluded optional OAuth authorization callable
  void oauthFortress.call.plugins.oauth.handleAuthorizeRequest;
  // @ts-expect-error excluded OAuth protocol callable
  void oauthFortress.call.plugins.oauth.handleTokenRequest;
  // @ts-expect-error excluded OAuth protocol callable
  void oauthFortress.call.plugins.oauth.handleIntrospectRequest;
  // @ts-expect-error excluded OAuth protocol callable
  void oauthFortress.call.plugins.oauth.handleRevokeRequest;
  // @ts-expect-error excluded OAuth protocol callable
  void oauthFortress.call.plugins.oauth.handleUserInfoRequest;
  // @ts-expect-error excluded OAuth protocol callable
  void oauthFortress.call.plugins.oauth.handleDiscovery;
  // @ts-expect-error excluded OAuth protocol callable
  void oauthFortress.call.plugins.oauth.handleJwksRequest;
  // JWT-backed consent-flow routes remain generic callables, and unrelated
  // core calls remain available because OAuth route identities stay exact.
  void oauthFortress.call.plugins.oauth.handleGetFlow;
  void oauthFortress.call.auth.login;
  void oauthFortress.call.auth.me;
  void oauthFortress.call.iam.getRoles;

  const openapiFortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [openapi()] as const,
  });
  // Configurable OpenAPI paths cannot erase unrelated core callables; a
  // runtime collision must use the matching core route key/handler instead.
  void openapiFortress.call.auth.me;
  void openapiFortress.call.iam.getRoles;

  const adminFortress = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [admin()] as const,
  });
  void adminFortress.call.auth.me;
  // @ts-expect-error admin explicitly overrides the core IAM surface
  void adminFortress.call.iam.getRoles;
}
