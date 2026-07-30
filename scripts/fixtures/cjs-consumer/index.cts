/* eslint-disable ts/no-require-imports -- import assignments intentionally force Node16 require.types resolution. */
import fortress = require('@bajustone/fortress');
import crypto = require('@bajustone/fortress/crypto');
import drizzle = require('@bajustone/fortress/drizzle');
import drizzlePg = require('@bajustone/fortress/drizzle/pg');
import express = require('@bajustone/fortress/express');
import fetcher = require('@bajustone/fortress/fetcher');
import hono = require('@bajustone/fortress/hono');
import jwt = require('@bajustone/fortress/jwt');
import otel = require('@bajustone/fortress/otel');
import accountLockoutPlugin = require('@bajustone/fortress/plugins/account-lockout');
import adminPlugin = require('@bajustone/fortress/plugins/admin');
import apiKeyPlugin = require('@bajustone/fortress/plugins/api-key');
import auditLogPlugin = require('@bajustone/fortress/plugins/audit-log');
import dataIsolationPlugin = require('@bajustone/fortress/plugins/data-isolation');
import emailVerificationPlugin = require('@bajustone/fortress/plugins/email-verification');
import magicLinkPlugin = require('@bajustone/fortress/plugins/magic-link');
import oauthPlugin = require('@bajustone/fortress/plugins/oauth');
import openapiPlugin = require('@bajustone/fortress/plugins/openapi');
import rateLimitPlugin = require('@bajustone/fortress/plugins/rate-limit');
import rateLimitExpress = require('@bajustone/fortress/plugins/rate-limit/express');
import rateLimitHono = require('@bajustone/fortress/plugins/rate-limit/hono');
import rateLimitSvelteKit = require('@bajustone/fortress/plugins/rate-limit/sveltekit');
import socialLoginPlugin = require('@bajustone/fortress/plugins/social-login');
import tenancyPlugin = require('@bajustone/fortress/plugins/tenancy');
import twoFactorPlugin = require('@bajustone/fortress/plugins/two-factor');
import webauthnPlugin = require('@bajustone/fortress/plugins/webauthn');
import webhookPlugin = require('@bajustone/fortress/plugins/webhook');
import sveltekit = require('@bajustone/fortress/sveltekit');
import testing = require('@bajustone/fortress/testing');

/**
 * Compile-only CommonJS consumer contract. `import = require` in a `.cts`
 * project using Node16 resolution forces package self-references through each
 * export's `require.types` branch.
 */
export function exerciseCommonJsConsumer(
  database: fortress.DatabaseAdapter,
  honoApp: Parameters<typeof hono.mountFortress>[0],
  expressApp: Parameters<typeof express.mountFortress>[0],
  svelteKitEvent: rateLimitSvelteKit.SvelteKitRateLimitEvent,
): fortress.Fortress {
  const instance: fortress.Fortress = fortress.createFortress({
    database,
    jwt: { key: 'cjs-consumer-contract-secret-key' },
  });
  // @ts-expect-error createFortress requires a database adapter
  fortress.createFortress({ jwt: { key: 'cjs-consumer-contract-secret-key' } });

  const fetchConfig: fetcher.FetchConfig = { baseUrl: 'https://api.example.test' };
  const fetchClient: ReturnType<typeof fetcher.createFetch> = fetcher.createFetch(fetchConfig);

  hono.mountFortress(honoApp, instance);
  const honoMiddleware: ReturnType<typeof hono.createHonoMiddleware> = hono.createHonoMiddleware(instance);
  express.mountFortress(expressApp, instance);
  const svelteKitHandle: ReturnType<typeof sveltekit.createSvelteKitHandle> = sveltekit.createSvelteKitHandle(instance);

  const sqlstate: string | null = drizzle.findSqlstate({ code: '23505' });
  const sqliteTables: Record<string, unknown> = drizzle.fortressSchema;
  const pgTables: Record<string, unknown> = drizzlePg.fortressPgSchema;
  const testAdapter: fortress.MigratableDatabaseAdapter<'sqlite'> = testing.createTestAdapter();

  // Stable CJS-only mutation sentinel: changing only crypto.d.cts to return a
  // number must fail here even with skipLibCheck, while the ESM fixture remains
  // green against crypto.d.ts.
  const normalizedPassword: string = crypto.normalizePasswordInput(' secret ');
  // @ts-expect-error normalizePasswordInput accepts strings only
  crypto.normalizePasswordInput(123);

  const customClaims: Record<string, unknown> = jwt.stripReservedClaims({ role: 'admin' }, 'cjs fixture');
  const telemetry: Promise<fortress.TelemetryProvider> = otel.createOtelTelemetry({ name: 'cjs-fixture' });

  const emailVerificationName: 'email-verification' = emailVerificationPlugin.emailVerification().name;
  const apiKeyName: 'api-key' = apiKeyPlugin.apiKey().name;
  const twoFactorName: 'two-factor' = twoFactorPlugin.twoFactor({
    secretEncryptionKey: '0123456789abcdef0123456789abcdef',
  }).name;
  const socialLoginName: 'social-login' = socialLoginPlugin.socialLogin({ providers: [] }).name;
  const dataIsolationName: 'data-isolation' = dataIsolationPlugin.dataIsolation({ scopes: [] }).name;
  const tenancyName: 'tenancy' = tenancyPlugin.tenancy().name;
  const oauthName: 'oauth' = oauthPlugin.oauth().name;
  const rateLimitName: 'rate-limit' = rateLimitPlugin.rateLimit().name;
  const auditLogName: 'audit-log' = auditLogPlugin.auditLog().name;
  const accountLockoutName: 'account-lockout' = accountLockoutPlugin.accountLockout().name;
  const webauthnName: 'webauthn' = webauthnPlugin.webauthn({
    rpName: 'Fortress CJS fixture',
    rpID: 'example.test',
    origin: 'https://example.test',
  }).name;
  const magicLinkName: 'magic-link' = magicLinkPlugin.magicLink().name;
  const webhookName: 'webhook' = webhookPlugin.webhook().name;
  const openapiName: 'openapi' = openapiPlugin.openapi().name;
  const adminName: 'admin' = adminPlugin.admin().name;

  const honoRateLimit: ReturnType<typeof rateLimitHono.honoRateLimit>
    = rateLimitHono.honoRateLimit(instance, 'api');
  const expressRateLimit: ReturnType<typeof rateLimitExpress.expressRateLimit>
    = rateLimitExpress.expressRateLimit(instance, 'api');
  const svelteKitRateLimit: Promise<void>
    = rateLimitSvelteKit.svelteKitRateLimit(instance, 'api', svelteKitEvent);

  void [
    fetchClient,
    honoMiddleware,
    svelteKitHandle,
    sqlstate,
    sqliteTables,
    pgTables,
    testAdapter,
    normalizedPassword,
    customClaims,
    telemetry,
    emailVerificationName,
    apiKeyName,
    twoFactorName,
    socialLoginName,
    dataIsolationName,
    tenancyName,
    oauthName,
    rateLimitName,
    auditLogName,
    accountLockoutName,
    webauthnName,
    magicLinkName,
    webhookName,
    openapiName,
    adminName,
    honoRateLimit,
    expressRateLimit,
    svelteKitRateLimit,
  ];

  return instance;
}

// eslint-disable-next-line ts/consistent-type-definitions -- numeric literal maps do not satisfy Record<number, unknown> as interfaces
type CjsNullResponses = { 204: null };
type CjsNullEndpoint = fortress.PublishedEndpointDefinition<
  null,
  string,
  number,
  CjsNullResponses,
  'nullCjsPublished',
  'PATCH',
  '/null-cjs-published',
  string,
  boolean,
  bigint
>;
// eslint-disable-next-line ts/consistent-type-definitions -- numeric literal maps do not satisfy Record<number, unknown> as interfaces
type CjsTypedResponses = { 200: { ok: true }; 404: { error: string } };
type CjsTypedMutableEndpoint = fortress.EndpointDefinition<
  { value: string },
  { include: boolean },
  { id: string },
  CjsTypedResponses,
  'typedCjsMutable',
  'POST',
  '/typed-cjs-mutable/:id',
  { value: string | number },
  { include: string | boolean },
  { id: string | number }
>;

/** The same readonly snapshot contract forced through the root `require.types` declaration. */
export function exerciseCommonJsPublishedSnapshots(
  instance: fortress.Fortress,
  nullEndpoint: CjsNullEndpoint,
  mutableEndpoint: CjsTypedMutableEndpoint,
): void {
  const schema: fortress.JSONSchema = { type: 'object', title: 'Mutable schema' };
  const standardSchema = {} as fortress.StandardSchemaV1;
  const declared: fortress.EndpointDefinition = {
    method: 'POST',
    path: '/cjs-published/:id',
    handler: 'cjsPublished',
    meta: {
      summary: 'CJS published fixture',
      tags: ['fixture'],
      security: ['bearer'],
      permission: { resource: 'fixture', action: 'read' },
    },
    input: { body: schema, bodySchema: standardSchema },
    responses: { 200: { description: 'OK', schema } },
  };

  // Configuration-time declarations and direct manifest results stay mutable.
  declared.method = 'PATCH';
  declared.path = '/cjs-adjusted/:id';
  declared.handler = 'cjsAdjusted';
  declared.meta = { summary: 'Adjusted' };
  declared.meta.summary = 'Adjusted again';
  declared.meta.tags = ['adjusted'];
  declared.meta.tags.push('mutable');
  declared.meta.security = ['none'];
  declared.meta.security.splice(0, 1, 'bearer');
  declared.meta.permission = { resource: 'fixture', action: 'write' };
  declared.meta.permission.action = 'adjusted';
  declared.meta.deprecated = true;
  declared.meta.bearerKind = 'jwt';
  declared.meta.dispatchKind = 'oauth';
  declared.input = { body: schema };
  declared.input.body = schema;
  declared.input.query = schema;
  declared.input.params = schema;
  declared.input.bodySchema = standardSchema;
  declared.input.querySchema = standardSchema;
  declared.input.paramsSchema = standardSchema;
  declared.responses = { 201: { description: 'Created', schema } };
  declared.responses[201] = { description: 'Adjusted', schema };
  declared.responses[201]!.description = 'Adjusted again';
  declared.responses[201]!.schema = schema;
  schema.title = 'Still mutable';

  const direct = fortress.buildRouteManifest(instance);
  direct.push({ ...direct[0]! });
  direct.splice(0, 1);
  direct[0]!.path = '/adjusted';
  direct[0]!.security.push('none');
  if (direct[0]!.permission)
    direct[0]!.permission.action = 'adjusted';

  const published = instance.endpoints[0]!;
  // @ts-expect-error published endpoint arrays are frozen in CJS declarations
  instance.endpoints.push(declared);
  // @ts-expect-error published endpoint arrays cannot be spliced
  instance.endpoints.splice(0, 1);
  // @ts-expect-error published methods are frozen
  published.method = 'PATCH';
  // @ts-expect-error published paths are frozen
  published.path = '/changed';
  // @ts-expect-error published handlers are frozen
  published.handler = 'changed';
  // @ts-expect-error published metadata containers are frozen
  published.meta = { summary: 'Changed' };
  // @ts-expect-error published input containers are frozen
  published.input = {};
  // @ts-expect-error published response maps cannot be replaced
  published.responses = {};
  // @ts-expect-error published metadata fields are frozen
  published.meta!.summary = 'Changed';
  // @ts-expect-error published metadata fields are frozen
  published.meta!.description = 'Changed';
  // @ts-expect-error published tag arrays cannot be replaced
  published.meta!.tags = [];
  // @ts-expect-error published tag arrays are frozen
  published.meta!.tags!.push('changed');
  // @ts-expect-error published tag arrays cannot be spliced
  published.meta!.tags!.splice(0, 1);
  // @ts-expect-error published security arrays cannot be replaced
  published.meta!.security = [];
  // @ts-expect-error published security arrays are frozen
  published.meta!.security!.push('none');
  // @ts-expect-error published deprecation metadata is frozen
  published.meta!.deprecated = true;
  // @ts-expect-error published bearer metadata is frozen
  published.meta!.bearerKind = 'oauth';
  // @ts-expect-error published dispatch metadata is frozen
  published.meta!.dispatchKind = 'oauth';
  // @ts-expect-error published permissions cannot be replaced
  published.meta!.permission = { resource: 'changed', action: 'changed' };
  // @ts-expect-error published permission resources are frozen
  published.meta!.permission!.resource = 'changed';
  // @ts-expect-error published permission actions are frozen
  published.meta!.permission!.action = 'changed';
  // @ts-expect-error published input fields cannot be replaced
  published.input!.body = schema;
  // @ts-expect-error published input fields cannot be replaced
  published.input!.query = schema;
  // @ts-expect-error published input fields cannot be replaced
  published.input!.params = schema;
  // @ts-expect-error published Standard Schema references cannot be replaced
  published.input!.bodySchema = standardSchema;
  // @ts-expect-error published Standard Schema references cannot be replaced
  published.input!.querySchema = standardSchema;
  // @ts-expect-error published Standard Schema references cannot be replaced
  published.input!.paramsSchema = standardSchema;
  // @ts-expect-error published response-map entries cannot be replaced
  published.responses![200] = { description: 'Changed' };
  // @ts-expect-error published response-map entries cannot be deleted
  delete published.responses![200];
  // @ts-expect-error published response descriptions are frozen
  published.responses![200]!.description = 'Changed';
  // @ts-expect-error published response schema references cannot be replaced
  published.responses![200]!.schema = schema;
  published.input!.body!.title = 'Schema stays mutable';
  published.responses![200]!.schema!.title = 'Response schema stays mutable';

  const manifestEntry = instance.manifest[0]!;
  const namedManifest: fortress.PublishedRouteManifest = instance.manifest;
  const namedEntry: fortress.PublishedRouteManifestEntry = manifestEntry;
  void [namedManifest, namedEntry];
  // @ts-expect-error published manifest arrays are frozen
  instance.manifest.push(direct[0]!);
  // @ts-expect-error published manifest arrays cannot be spliced
  instance.manifest.splice(0, 1);
  // @ts-expect-error published manifest methods are frozen
  manifestEntry.method = 'PATCH';
  // @ts-expect-error published manifest paths are frozen
  manifestEntry.path = '/changed';
  // @ts-expect-error published manifest handlers are frozen
  manifestEntry.handler = 'changed';
  // @ts-expect-error published manifest owners are frozen
  manifestEntry.plugin = 'changed';
  // @ts-expect-error published manifest classifications are frozen
  manifestEntry.classification = 'public';
  // @ts-expect-error published manifest permissions cannot be replaced
  manifestEntry.permission = { resource: 'changed', action: 'changed' };
  // @ts-expect-error published manifest permission fields are frozen
  manifestEntry.permission!.resource = 'changed';
  // @ts-expect-error published manifest permission fields are frozen
  manifestEntry.permission!.action = 'changed';
  // @ts-expect-error published manifest bearer metadata is frozen
  manifestEntry.bearerKind = 'oauth';
  // @ts-expect-error published manifest security arrays cannot be replaced
  manifestEntry.security = [];
  // @ts-expect-error published manifest security arrays are frozen
  manifestEntry.security.push('none');
  // @ts-expect-error published manifest CSRF metadata is frozen
  manifestEntry.csrfApplicable = false;
  // @ts-expect-error published manifest rate-limit metadata is frozen
  manifestEntry.rateLimited = false;
  // @ts-expect-error published manifest mount metadata is frozen
  manifestEntry.mounted = false;

  instance.toOpenAPI({ endpoints: instance.endpoints });
  fortress.toOpenAPI(instance.endpoints);
  instance.syncPermissionsFromManifest({ endpoints: instance.endpoints });
  fortress.detectRouteManifestDrift(instance, { manifest: instance.manifest });
  testing.checkRouteManifestDrift(instance);
  testing.checkPublicRoutes(instance);
  openapiPlugin.openapi({ additionalEndpoints: instance.endpoints });

  const wildcardRuntime: fortress.FortressManifestRuntime = {
    ...instance,
    endpoints: [nullEndpoint],
  };
  const nullMethod: 'PATCH' = nullEndpoint.method;
  const nullPath: '/null-cjs-published' = nullEndpoint.path;
  fortress.toOpenAPI(wildcardRuntime.endpoints);
  instance.toOpenAPI({ endpoints: wildcardRuntime.endpoints });
  instance.syncPermissionsFromManifest({ endpoints: wildcardRuntime.endpoints });
  fortress.buildRouteManifest(wildcardRuntime);
  fortress.detectRouteManifestDrift(wildcardRuntime);
  openapiPlugin.openapi({ additionalEndpoints: wildcardRuntime.endpoints });
  void [nullMethod, nullPath];

  type TypedPublishedEndpoint = fortress.PublishedEndpointDefinition<
    { value: string },
    { include: boolean },
    { id: string },
    CjsTypedResponses,
    'typedCjsPublished',
    'POST',
    '/typed-cjs-published/:id',
    { value: string | number },
    { include: string | boolean },
    { id: string | number }
  >;
  const isTyped = (
    endpoint: fortress.AnyPublishedEndpointDefinition,
  ): endpoint is TypedPublishedEndpoint => endpoint.handler === 'typedCjsPublished';
  const selected = instance.endpoints.find(isTyped)!;
  const handlerName: fortress.InferEndpointHandler<typeof selected> = 'typedCjsPublished';
  const bodyInput: fortress.InferEndpointBodyInput<typeof selected> = { value: 1 };
  const queryInput: fortress.InferEndpointQueryInput<typeof selected> = { include: 'true' };
  const paramsInput: fortress.InferEndpointParamsInput<typeof selected> = { id: 1 };
  const responses: fortress.InferEndpointResponses<typeof selected> = { 200: { ok: true }, 404: { error: 'missing' } };
  const method: 'POST' = selected.method;
  const path: '/typed-cjs-published/:id' = selected.path;
  // @ts-expect-error CJS body projection must not widen to any
  const wrongBody: fortress.InferEndpointBody<typeof selected> = { value: 1 };
  // @ts-expect-error CJS body-input projection must not widen to any
  const wrongBodyInput: fortress.InferEndpointBodyInput<typeof selected> = { value: false };
  // @ts-expect-error CJS query projection must not widen to any
  const wrongQuery: fortress.InferEndpointQuery<typeof selected> = { include: 'true' };
  // @ts-expect-error CJS query-input projection must not widen to any
  const wrongQueryInput: fortress.InferEndpointQueryInput<typeof selected> = { include: 1 };
  // @ts-expect-error CJS params projection must not widen to any
  const wrongParams: fortress.InferEndpointParams<typeof selected> = { id: 1 };
  // @ts-expect-error CJS params-input projection must not widen to any
  const wrongParamsInput: fortress.InferEndpointParamsInput<typeof selected> = { id: false };
  // @ts-expect-error CJS responses projection must not widen to any
  const wrongResponses: fortress.InferEndpointResponses<typeof selected> = { 200: { ok: false }, 404: { error: 'missing' } };
  // @ts-expect-error CJS handler projection must preserve its literal
  const wrongHandler: fortress.InferEndpointHandler<typeof selected> = 'other';
  // @ts-expect-error CJS method projection must preserve its literal
  const wrongMethod: 'GET' = selected.method;
  // @ts-expect-error CJS path projection must preserve its literal
  const wrongPath: '/other' = selected.path;
  void [
    handlerName,
    bodyInput,
    queryInput,
    paramsInput,
    responses,
    method,
    path,
    wrongBody,
    wrongBodyInput,
    wrongQuery,
    wrongQueryInput,
    wrongParams,
    wrongParamsInput,
    wrongResponses,
    wrongHandler,
    wrongMethod,
    wrongPath,
  ];

  fortress.protect(instance, selected, (ctx) => {
    const body: { value: string } = ctx.body;
    const query: { include: boolean } = ctx.query;
    const params: { id: string } = ctx.params;
    const endpointPath: '/typed-cjs-published/:id' = ctx.endpoint.path;
    // @ts-expect-error CJS published-target contexts expose a frozen path
    ctx.endpoint.path = '/changed';
    // @ts-expect-error CJS published-target contexts expose frozen metadata
    ctx.endpoint.meta = { summary: 'Changed' };
    // @ts-expect-error CJS published-target contexts expose a frozen security array
    ctx.endpoint.meta!.security!.push('none');
    // @ts-expect-error CJS published-target contexts expose a frozen response map
    ctx.endpoint.responses![200] = { description: 'Changed' };
    ctx.respond(404, { error: 'missing' });
    // @ts-expect-error CJS declarations retain response-status inference
    ctx.respond(201, { ok: true });
    // @ts-expect-error CJS declarations retain response-body correlation
    ctx.respond(404, { ok: true });
    return { body, query, params, endpointPath };
  });

  fortress.protect(instance, mutableEndpoint, (ctx) => {
    const body: { value: string } = ctx.body;
    const endpointPath: '/typed-cjs-mutable/:id' = ctx.endpoint.path;
    // @ts-expect-error CJS mutable-target contexts still expose a frozen path
    ctx.endpoint.path = '/changed';
    // @ts-expect-error CJS mutable-target contexts expose frozen metadata
    ctx.endpoint.meta = { summary: 'Changed' };
    // @ts-expect-error CJS mutable-target contexts expose a frozen security array
    ctx.endpoint.meta!.security!.push('none');
    // @ts-expect-error CJS mutable-target contexts expose a frozen response map
    ctx.endpoint.responses![200] = { description: 'Changed' };
    return { body, endpointPath };
  });

  const resolvedMutable = fortress.resolveProtectedEndpoint(instance, mutableEndpoint);
  const resolvedMutablePath: '/typed-cjs-mutable/:id' = resolvedMutable.path;
  // @ts-expect-error CJS eager resolution returns a frozen published projection
  resolvedMutable.path = '/changed';
  void resolvedMutablePath;
}
