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
