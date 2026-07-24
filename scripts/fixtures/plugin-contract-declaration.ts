import type {
  DatabaseAdapter,
  FortressPlugin,
  InferEndpointSuccessResponse,
  InferPlugins,
  PluginRouteContext,
} from '@bajustone/fortress';
import type { accountLockout } from '@bajustone/fortress/plugins/account-lockout';
import type { admin } from '@bajustone/fortress/plugins/admin';
import type { ApiKeyConfig } from '@bajustone/fortress/plugins/api-key';
import type { auditLog } from '@bajustone/fortress/plugins/audit-log';
import type { dataIsolation } from '@bajustone/fortress/plugins/data-isolation';
import type { emailVerification } from '@bajustone/fortress/plugins/email-verification';
import type { magicLink } from '@bajustone/fortress/plugins/magic-link';
import type { OAuthConfig } from '@bajustone/fortress/plugins/oauth';
import type { OpenAPIConfig } from '@bajustone/fortress/plugins/openapi';
import type { rateLimit } from '@bajustone/fortress/plugins/rate-limit';
import type { socialLogin } from '@bajustone/fortress/plugins/social-login';
import type { TenancyConfig } from '@bajustone/fortress/plugins/tenancy';
import type { twoFactor } from '@bajustone/fortress/plugins/two-factor';
import type { webauthn } from '@bajustone/fortress/plugins/webauthn';
import type { webhook } from '@bajustone/fortress/plugins/webhook';
import { createFortress, defineEndpoints, definePlugin, endpoint, obj, str } from '@bajustone/fortress';
import { apiKey } from '@bajustone/fortress/plugins/api-key';
import { oauth } from '@bajustone/fortress/plugins/oauth';
import { openapi } from '@bajustone/fortress/plugins/openapi';
import { tenancy } from '@bajustone/fortress/plugins/tenancy';

declare module '@bajustone/fortress' {
  interface PluginMethodsMap {
    'legacy-built': { ping: () => 'pong' };
  }
}

type Equal<A, B> = (<T>() => T extends A ? 1 : 2) extends (<T>() => T extends B ? 1 : 2) ? true : false;
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

const builtRoutes = defineEndpoints({
  builtGreeting: endpoint('POST', '/built/greeting')
    .body(obj({ name: str() }, 'name'))
    .response(200, 'Greeting', obj({ greeting: str() }, 'greeting'))
    .handler('builtGreeting')
    .build(),
});

const exactLegacyName = definePlugin({ name: 'legacy-built' });
export type ExactBuiltEmptyContract = Assert<Lacks<InferPlugins<readonly [typeof exactLegacyName]>, 'legacy-built', 'ping'>>;
const exactUndefinedMethods = definePlugin({ name: 'legacy-built', methods: undefined });
const _enabledOAuth = oauth({ enableConsentApi: true });
export type ExactBuiltUndefinedContract = Assert<Lacks<InferPlugins<readonly [typeof exactUndefinedMethods]>, 'legacy-built', 'ping'>>;

type Empty = Record<never, never>;
type StatusResponse<S extends number> = InferEndpointSuccessResponse<import('@bajustone/fortress').EndpointDefinition<Empty, Empty, Empty, { [K in S]: K }>>;
export type BuiltExactTwoXxContracts = [
  Assert<Equal<StatusResponse<199>, unknown>>,
  Assert<Equal<StatusResponse<200>, 200>>,
  Assert<Equal<StatusResponse<299>, 299>>,
  Assert<Equal<StatusResponse<300>, unknown>>,
  Assert<Equal<StatusResponse<2000>, unknown>>,
];
const _builtReorderedSuccess = endpoint('GET', '/built-reordered-success')
  .response(202, 'Queued', obj({ queued: str() }, 'queued'))
  .response(200, 'Immediate', obj({ ok: str() }, 'ok'))
  .handler('result')
  .build();
export type BuiltReorderedSuccessContract = Assert<Equal<
  InferEndpointSuccessResponse<typeof _builtReorderedSuccess>,
  { ok: string }
>>;

void definePlugin({
  name: 'built-route-only',
  routes: {
    // @ts-expect-error generated declarations require methods for concrete routes
    ping: endpoint('GET', '/built-route-only').handler('ping').build(),
  },
});

definePlugin({
  name: 'built-bad-context',
  methods: () => ({ bad: (_input: { value: string }, _ctx: { request: string }) => ({ ok: 'yes' }) }),
  routes: {
    // @ts-expect-error generated declarations validate PluginRouteContext compatibility
    bad: endpoint('POST', '/built-bad-context').body(obj({ value: str() }, 'value')).response(200, 'ok', obj({ ok: str() }, 'ok')).handler('bad').build(),
  },
});
definePlugin({
  name: 'built-bad-optional-context',
  methods: () => ({ bad: (_input: { value: string }, _ctx?: { request: string }) => ({ ok: 'yes' }) }),
  routes: {
    // @ts-expect-error generated declarations reject optional incompatible context
    bad: endpoint('POST', '/built-bad-optional-context').body(obj({ value: str() }, 'value')).response(200, 'ok', obj({ ok: str() }, 'ok')).handler('bad').build(),
  },
});
definePlugin({
  name: 'built-bad-rest-context',
  methods: () => ({ bad: (_input: { value: string }, ..._rest: string[]) => ({ ok: 'yes' }) }),
  routes: {
    // @ts-expect-error generated declarations reject incompatible rest arguments
    bad: endpoint('POST', '/built-bad-rest-context').body(obj({ value: str() }, 'value')).response(200, 'ok', obj({ ok: str() }, 'ok')).handler('bad').build(),
  },
});
definePlugin({
  name: 'built-bad-trailing',
  methods: () => ({ bad: (_input: { value: string }, _ctx: PluginRouteContext, _required: string) => ({ ok: 'yes' }) }),
  routes: {
    // @ts-expect-error generated declarations reject required trailing handler arguments
    bad: endpoint('POST', '/built-bad-trailing').body(obj({ value: str() }, 'value')).response(200, 'ok', obj({ ok: str() }, 'ok')).handler('bad').build(),
  },
});

const thirdParty = definePlugin({
  name: 'built-third-party',
  methods: () => ({
    greet: (name: string) => `Hello ${name}`,
    // Route handlers are correlated: this method's input/return must match
    // the endpoint's declared body and success response.
    builtGreeting: async (input: { name: string }): Promise<{ greeting: string }> => ({
      greeting: `Hello ${input.name}`,
    }),
  }),
  routes: builtRoutes,
});

definePlugin({
  name: 'built-missing-handler',
  methods: () => ({ real: () => 'ok' }),
  routes: {
    // @ts-expect-error built declarations retain literal handler existence checks
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
  name: 'built-lowest-success-mismatch',
  methods: () => ({ result: () => ({ queued: 'later' }) }),
  routes: {
    // @ts-expect-error generated declarations correlate the body with the lowest numeric 2xx status
    result: endpoint('GET', '/built-lowest-success')
      .response(202, 'Queued', obj({ queued: str() }, 'queued'))
      .response(200, 'Immediate', obj({ ok: str() }, 'ok'))
      .handler('result')
      .build(),
  },
});

function builtWidenedSuccessStatus(status: number): void {
  const _route = endpoint('GET', '/built-widened-success')
    .response(status, 'Dynamic', obj({ dynamic: str() }, 'dynamic'))
    .response(202, 'Queued', obj({ queued: str() }, 'queued'))
    .handler('result')
    .build();
  const conservative: Assert<Equal<InferEndpointSuccessResponse<typeof _route>, unknown>> = true;
  void conservative;
}
void builtWidenedSuccessStatus;

definePlugin({
  name: 'built-non-callable',
  // @ts-expect-error built declarations reject non-function method properties
  methods: () => ({ value: 1 }),
});

interface BuiltConcreteMethods { run: () => void }
// @ts-expect-error concrete FortressPlugin contracts require methods
const _missingBuiltMethods: FortressPlugin<'built-concrete', BuiltConcreteMethods> = { name: 'built-concrete' };
void _missingBuiltMethods;

export function declarationContract(database: DatabaseAdapter, dynamicName: string): void {
  const noPlugins = createFortress({ database, jwt: { key: 'x'.repeat(32) } });
  // @ts-expect-error omitted plugins expose no arbitrary static keys
  void noPlugins.plugins.arbitrary;
  // @ts-expect-error omitted plugins expose no arbitrary call namespaces
  void noPlugins.call.plugins.arbitrary;

  const empty = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [exactLegacyName] as const });
  // @ts-expect-error exact methodless plugins do not use legacy augmentation
  empty.plugins['legacy-built'].ping();
  const explicitUndefined = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [exactUndefinedMethods] as const });
  // @ts-expect-error exact methods:undefined remains methodless
  explicitUndefined.plugins['legacy-built'].ping();

  const widenedPlugin = definePlugin({ name: dynamicName, methods: () => ({ ping: () => 'pong' }) });
  const widenedPluginFortress = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [widenedPlugin] as const });
  // @ts-expect-error widened plugin names do not add a static string index
  widenedPluginFortress.plugins.anyName.ping();
  const anyName: any = dynamicName;
  const anyNamedPlugin = definePlugin({
    name: anyName,
    methods: () => ({ ping: () => ({ value: 'pong' }) }),
    routes: {
      ping: endpoint('GET', '/built-any-name').response(200, 'ok', obj({ value: str() }, 'value')).handler('ping').build(),
    },
  });
  const anyNamedFortress = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [anyNamedPlugin] as const });
  // @ts-expect-error any plugin names do not add a static methods index, including TS 5.0
  anyNamedFortress.plugins.anyName.ping();
  // @ts-expect-error any plugin names do not add a static call index, including TS 5.0
  anyNamedFortress.call.plugins.anyName.ping({});

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
  fortress.call.plugins['built-third-party'].builtGreeting({ name: 'Ada' });
  fortress.call.plugins['api-key'].createKey({ name: 'key' });
  // @ts-expect-error unknown plugin keys are rejected
  void fortress.plugins.missing;
  // @ts-expect-error unknown methods are rejected
  fortress.plugins['built-third-party'].missing();
  // @ts-expect-error disabled tenancy routes contribute no call namespace
  void fortress.call.plugins.tenancy;

  const optionalRoutes = createFortress({
    database,
    jwt: { key: 'x'.repeat(32) },
    plugins: [oauth(), openapi()] as const,
  });
  // @ts-expect-error omitted OAuth consent API contributes no consent callable
  void optionalRoutes.call.plugins.oauth.handleGetFlow;
  // The standalone enabled definition proves the positive conditional route
  // projection without introducing a duplicate runtime plugin name.
  type EnabledConsentCalls = import('@bajustone/fortress').PluginCallTree<readonly [typeof _enabledOAuth]>;
  const enabledConsentCalls = (null as unknown as EnabledConsentCalls).oauth;
  const flow: Promise<{
    flowId: string;
    client: { clientId: string; name: string };
    redirectUri: string;
    scopes: string[];
    state: string;
  }> = enabledConsentCalls.handleGetFlow({ flowId: 'flow' });
  const approved: Promise<{ redirectUrl: string }> = enabledConsentCalls.handleApproveFlow({ flowId: 'flow' });
  void flow;
  void approved;
  // @ts-expect-error enabled consent calls require flowId
  enabledConsentCalls.handleGetFlow({});
  // @ts-expect-error bearer lookup remains implementation-private
  optionalRoutes.plugins.oauth._lookupBearer('token');
  void optionalRoutes.call.plugins.openapi.getUI;
  const undefinedOpenapi = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [openapi(undefined)] as const });
  void undefinedOpenapi.call.plugins.openapi.getUI;
  const titledOpenapi = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [openapi({ title: 'x' })] as const });
  void titledOpenapi.call.plugins.openapi.getUI;
  const omittedDisableUiConfig: Omit<OpenAPIConfig, 'disableUI'> = { title: 'x' };
  const omittedDisableUi = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [openapi(omittedDisableUiConfig)] as const });
  void omittedDisableUi.call.plugins.openapi.getUI;
  const falseUi = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [openapi({ disableUI: false })] as const });
  void falseUi.call.plugins.openapi.getUI;
  const optionalFalseConfig: { disableUI?: false } = {};
  const optionalFalseUi = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [openapi(optionalFalseConfig)] as const });
  void optionalFalseUi.call.plugins.openapi.getUI;
  const noUi = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [openapi({ disableUI: true })] as const });
  // @ts-expect-error literal disableUI removes getUI
  void noUi.call.plugins.openapi.getUI;
  const widenedOauthConfig: OAuthConfig = {};
  const widenedOpenapiConfig: OpenAPIConfig = {};
  const widenedBuiltins = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [oauth(widenedOauthConfig), openapi(widenedOpenapiConfig)] as const });
  // @ts-expect-error widened OAuth config cannot guarantee consent routes
  void widenedBuiltins.call.plugins.oauth.handleGetFlow;
  // @ts-expect-error widened OpenAPI config cannot guarantee getUI
  void widenedBuiltins.call.plugins.openapi.getUI;
  const checkWidenedOpenapiBoolean = (disableUI: boolean): void => {
    const widenedBooleanOpenapi = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [openapi({ disableUI })] as const });
    // @ts-expect-error widened boolean cannot guarantee getUI
    void widenedBooleanOpenapi.call.plugins.openapi.getUI;
  };
  void checkWidenedOpenapiBoolean;
  const maybeEnabledOAuthConfig: { enableConsentApi: true } | undefined = Math.random() > 0.5
    ? { enableConsentApi: true }
    : undefined;
  const maybeEnabledOAuth = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [oauth(maybeEnabledOAuthConfig)] as const });
  // @ts-expect-error undefined may omit consent routes at runtime
  void maybeEnabledOAuth.call.plugins.oauth.handleGetFlow;
  const maybeOpenapiConfig: OpenAPIConfig | undefined = Math.random() > 0.5
    ? { disableUI: false }
    : undefined;
  const maybeOpenapi = createFortress({ database, jwt: { key: 'x'.repeat(32) }, plugins: [openapi(maybeOpenapiConfig)] as const });
  // @ts-expect-error a widened union cannot guarantee getUI exists
  void maybeOpenapi.call.plugins.openapi.getUI;

  const dynamic = fortress.resolvePlugin(dynamicName);
  // @ts-expect-error dynamic lookup is unknown without validation
  dynamic.greet('Ada');
  fortress.resolvePlugin(
    dynamicName,
    (value): value is { greet: (name: string) => string } => typeof value === 'object'
      && value !== null
      && typeof Reflect.get(value, 'greet') === 'function',
  ).greet('Ada');
  // @ts-expect-error a caller-supplied generic without a validator must not compile
  fortress.resolvePlugin<{ greet: (name: string) => string }>(dynamicName);
}

declare const _legacy: FortressPlugin<'legacy-built'>;
export type LegacyBuiltContract = Assert<Has<InferPlugins<readonly [typeof _legacy]>, 'legacy-built', 'ping'>>;
