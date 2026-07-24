/**
 * API key plugin for fortress.
 *
 * Issues scoped, hashed API keys for users and service accounts, with
 * optional expiry, revocation, and per-key permission scopes. Authenticates
 * incoming requests via `Authorization: ApiKey <key>` or `X-API-Key: <key>`
 * headers and exposes management methods on the fortress instance.
 *
 * HTTP endpoints are opt-in: pass `apiKey({ routes: true })` to mount the
 * self-service routes under `/api-key/keys/*`. The programmatic methods on
 * `fortress.plugins['api-key']` are always available regardless of the flag.
 *
 * Keys are owned by a {@link Subject} — either a USER or a SERVICE_ACCOUNT.
 * When a service account is deleted via core IAM, this plugin's IAM
 * observer hard-deletes every key it owns.
 *
 * @module
 */

import type { EndpointDefinition } from '../../core/endpoint';
import type { IamEvent, IamEventListener } from '../../core/iam/iam-service';
import type { FortressSchema } from '../../core/json-schema';
import type { FortressPlugin, JsonOf, PluginContext, PluginRouteContext } from '../../core/plugin';
import type { Subject } from '../../core/types';
import type { ApiKeyInfo, ApiKeyKnobs, CreateKeyOptions } from './core';
import { Errors } from '../../core/errors';
import { definePlugin } from '../../core/plugin';
import { arr, bool, endpoint, id, nullable, obj, ref, str } from '../../core/schema-builder';
import {
  createKeyForSubject,
  deleteAllKeysForSubject,
  listKeysForSubject,
  resolveApiKey,
  revokeKeyForSubject,
  rotateKeyForSubject,
} from './core';

export type { ApiKeyInfo, ApiKeyRecord } from './core';

export interface ApiKeyConfig {
  /** Prefix for generated keys (default: 'fortress') */
  prefix?: string;
  /** Default expiry in seconds. null = never expires (default: null) */
  defaultExpirySeconds?: number | null;
  /** Maximum active (non-revoked) keys per subject (default: 10) */
  maxKeysPerSubject?: number;
  /**
   * Mount self-service HTTP routes under `/api-key/keys/*`. Default `false`.
   * The programmatic methods on `fortress.plugins['api-key']` are always
   * available; this flag only controls HTTP mounting.
   */
  routes?: boolean;
}

export interface ApiKeyMethods {
  createKey: (
    input: { subject?: Subject; name: string; scopes?: string[]; expiresAt?: Date | string },
    routeCtx?: PluginRouteContext,
  ) => Promise<{ key: string; id: string }>;
  listKeys: (
    input: { subject?: Subject },
    routeCtx?: PluginRouteContext,
  ) => Promise<ApiKeyInfo[]>;
  revokeKey: (
    input: { subject?: Subject; id: string },
    routeCtx?: PluginRouteContext,
  ) => Promise<{ ok: true }>;
  rotateKey: (
    input: { subject?: Subject; id: string },
    routeCtx?: PluginRouteContext,
  ) => Promise<{ key: string; id: string }>;
  resolveKey: (
    rawKey: string,
  ) => Promise<{ subject: Subject; scopes: string[] | null } | null>;
}

// ── Routes ──────────────────────────────────────────────────────────

const errorRef: FortressSchema<unknown> = ref('ErrorResponse');

/* eslint-disable ts/consistent-type-definitions, ts/no-empty-object-type -- alias preserves Record compatibility; empty endpoint phantom slots are intentional */
type ApiKeySelfServiceRoutes = {
  readonly createKey: EndpointDefinition<
    { name: string; scopes?: string[]; expiresAt?: string },
    {},
    {},
    { 201: { key: string; id: string } },
    'createKey'
  >;
  readonly listKeys: EndpointDefinition<{}, {}, {}, { 200: JsonOf<ApiKeyInfo>[] }, 'listKeys'>;
  readonly revokeKey: EndpointDefinition<{}, {}, { id: string }, { 200: { ok: boolean } }, 'revokeKey'>;
  readonly rotateKey: EndpointDefinition<{}, {}, { id: string }, { 200: { key: string; id: string } }, 'rotateKey'>;
};
/* eslint-enable ts/consistent-type-definitions, ts/no-empty-object-type */

const apiKeySelfServiceRoutes: ApiKeySelfServiceRoutes = {
  createKey: endpoint('POST', '/api-key/keys')
    .summary('Create an API key')
    .description('Create a new API key for the authenticated caller. The raw key is returned exactly once — it cannot be retrieved later.')
    .tags('API Keys')
    .security('bearer')
    .body(obj({
      name: str('Human-readable key label'),
      scopes: arr(str(), 'Optional permission scopes attached to the key'),
      expiresAt: str('Optional expiry (ISO 8601 string)'),
    }, 'name'))
    .response(201, 'Key created', obj({
      key: str('Raw API key — shown exactly once, store it immediately'),
      id: id('Database id of the key'),
    }, 'key', 'id'))
    .response(400, 'Bad request', errorRef)
    .response(401, 'Not authenticated', errorRef)
    .handler('createKey')
    .build(),

  listKeys: endpoint('GET', '/api-key/keys')
    .summary('List the caller\'s API keys')
    .description('Return the active (non-revoked) API keys belonging to the authenticated caller. Raw keys and hashes are never returned.')
    .tags('API Keys')
    .security('bearer')
    .response(200, 'Keys', arr(obj({
      id: id('Database id'),
      name: str('Key label'),
      keyPrefix: str('First 12 characters of the key, for identification'),
      scopes: nullable(arr(str('Permission scope'))),
      expiresAt: nullable(str('ISO 8601 expiry')),
      lastUsedAt: nullable(str('ISO 8601 timestamp of last successful resolve')),
      createdAt: str('ISO 8601 creation timestamp'),
    }, 'id', 'name', 'keyPrefix', 'scopes', 'expiresAt', 'lastUsedAt', 'createdAt')))
    .response(401, 'Not authenticated', errorRef)
    .handler('listKeys')
    .build(),

  revokeKey: endpoint('DELETE', '/api-key/keys/:id')
    .summary('Revoke an API key')
    .description('Revoke one of the authenticated caller\'s own API keys. Returns 404 if the id does not belong to the caller.')
    .tags('API Keys')
    .security('bearer')
    .params(obj({ id: str('Key id') }, 'id'))
    .response(200, 'Revoked', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', errorRef)
    .response(404, 'Not found', errorRef)
    .handler('revokeKey')
    .build(),

  rotateKey: endpoint('POST', '/api-key/keys/:id/rotate')
    .summary('Rotate an API key')
    .description('Revoke an existing key and issue a new one with the same name, scopes, and expiry. The new raw key is returned exactly once.')
    .tags('API Keys')
    .security('bearer')
    .params(obj({ id: str('Key id to rotate') }, 'id'))
    .response(200, 'Rotated', obj({
      key: str('New raw API key — shown exactly once'),
      id: id('Database id of the new key'),
    }, 'key', 'id'))
    .response(401, 'Not authenticated', errorRef)
    .response(404, 'Not found', errorRef)
    .handler('rotateKey')
    .build(),
} as const;

// ── Plugin Factory ──────────────────────────────────────────────────

/**
 * API key plugin factory. Returns a {@link FortressPlugin} that issues
 * scoped, hashed API keys, resolves them into request principals via the
 * `Authorization: ApiKey`/`X-API-Key` headers, and exposes management
 * methods on the fortress instance. Pass `{ routes: true }` to mount the
 * self-service HTTP routes under `/api-key/keys/*`.
 */
type ApiKeyPlugin = FortressPlugin<'api-key', ApiKeyMethods, ApiKeySelfServiceRoutes | undefined>;

function createApiKeyPlugin(config: ApiKeyConfig = {}): ApiKeyPlugin {
  const knobs: ApiKeyKnobs = {
    prefix: config.prefix ?? 'fortress',
    defaultExpirySeconds: config.defaultExpirySeconds ?? null,
    maxKeysPerSubject: config.maxKeysPerSubject ?? 10,
  };
  const mountRoutes = config.routes === true;
  let observerRegistered = false;

  return definePlugin({
    name: 'api-key',

    models: [{
      name: 'api_key',
      fields: {
        id: { type: 'number', required: true },
        subjectType: { type: 'string', required: true },
        subjectId: { type: 'number', required: true },
        name: { type: 'string', required: true },
        keyHash: { type: 'string', required: true, unique: true },
        keyPrefix: { type: 'string', required: true },
        scopes: { type: 'string' },
        expiresAt: { type: 'date' },
        lastUsedAt: { type: 'date' },
        isRevoked: { type: 'boolean', required: true },
        createdAt: { type: 'date', required: true },
      },
    }],

    ...(mountRoutes ? { routes: apiKeySelfServiceRoutes } : {}),

    async resolvePrincipal(request: Request, ctx: PluginContext): Promise<{ subject: Subject; scopes?: string[] | null } | null> {
      const auth = request.headers.get('authorization') ?? '';
      const fromAuth = auth.startsWith('ApiKey ') ? auth.slice(7).trim() : null;
      const fromHeader = !fromAuth ? request.headers.get('x-api-key') : null;
      const key = fromAuth ?? fromHeader;
      if (!key)
        return null;
      const resolved = await resolveApiKey(ctx.db, key);
      if (!resolved)
        return null;
      return { subject: resolved.subject, scopes: resolved.scopes };
    },

    methods: (ctx: PluginContext) => {
      // Register the IAM cascade observer exactly once per plugin instance.
      // Done inside `methods` (rather than at factory time) because `ctx.iam`
      // is not wired at factory construction — the Fortress boot order
      // constructs services first, then calls `processPlugins` which invokes
      // this `methods` factory with a fully-populated ctx.
      if (!observerRegistered && ctx.iam) {
        observerRegistered = true;
        const cascade: IamEventListener = async (event: IamEvent) => {
          if (event.eventType === 'SERVICE_ACCOUNT_DELETED' && event.targetId != null) {
            await deleteAllKeysForSubject(ctx.db, {
              type: 'SERVICE_ACCOUNT',
              id: event.targetId,
            });
          }
        };
        ctx.iam.addIamObserver(cascade);
      }

      return {
        async createKey(
          input: { subject?: Subject; name: string; scopes?: string[]; expiresAt?: Date | string },
          routeCtx?: PluginRouteContext,
        ): Promise<{ key: string; id: string }> {
          const subject = resolveCallerSubject(input, routeCtx);
          const options: CreateKeyOptions = {
            name: String(input.name ?? ''),
            scopes: Array.isArray(input.scopes) ? input.scopes.map(String) : undefined,
            expiresAt: coerceDate(input.expiresAt),
          };
          if (!options.name)
            throw Errors.badRequest('name is required');
          return createKeyForSubject(ctx.db, subject, options, knobs);
        },

        async listKeys(
          input: { subject?: Subject },
          routeCtx?: PluginRouteContext,
        ): Promise<ApiKeyInfo[]> {
          const subject = resolveCallerSubject(input, routeCtx);
          return listKeysForSubject(ctx.db, subject);
        },

        async revokeKey(
          input: { subject?: Subject; id: string },
          routeCtx?: PluginRouteContext,
        ): Promise<{ ok: true }> {
          const subject = resolveCallerSubject(input, routeCtx);
          const keyId = String(input.id ?? '');
          if (!keyId)
            throw Errors.badRequest('id is required');
          await revokeKeyForSubject(ctx.db, subject, keyId);
          return { ok: true };
        },

        async rotateKey(
          input: { subject?: Subject; id: string },
          routeCtx?: PluginRouteContext,
        ): Promise<{ key: string; id: string }> {
          const subject = resolveCallerSubject(input, routeCtx);
          const keyId = String(input.id ?? '');
          if (!keyId)
            throw Errors.badRequest('id is required');
          return rotateKeyForSubject(ctx.db, subject, keyId, { prefix: knobs.prefix });
        },

        async resolveKey(
          rawKey: string,
        ): Promise<{ subject: Subject; scopes: string[] | null } | null> {
          return resolveApiKey(ctx.db, rawKey);
        },
      };
    },
  } satisfies FortressPlugin<'api-key', ApiKeyMethods, ApiKeySelfServiceRoutes | undefined>);
}

export function apiKey(config: ApiKeyConfig & { routes: true }): ApiKeyPlugin & { routes: ApiKeySelfServiceRoutes };
export function apiKey(config?: ApiKeyConfig & { routes?: false | undefined }): ApiKeyPlugin;
export function apiKey(config: ApiKeyConfig | undefined): ApiKeyPlugin;
export function apiKey(config: ApiKeyConfig = {}): ApiKeyPlugin {
  return createApiKeyPlugin(config);
}

/**
 * Resolve the caller's subject. Two call paths:
 *
 *  1. HTTP: the dispatcher passes `routeCtx` with the verified principal
 *     (resolved from a JWT or an api-key `resolvePrincipal` pass). Use it
 *     and ignore any `subject` in the body — the client doesn't get to pick
 *     which subject a key is created for.
 *  2. Programmatic (seed scripts, custom server code): no `routeCtx`, so
 *     fall back to `input.subject`. These callers are trusted because they
 *     already hold a reference to `fortress.plugins['api-key']`.
 */
function resolveCallerSubject(
  input: { subject?: Subject },
  routeCtx?: PluginRouteContext,
): Subject {
  if (routeCtx) {
    if (!routeCtx.subject)
      throw Errors.unauthorized('Not authenticated');
    // Do not allow an API key credential to self-manage API keys. A scoped
    // key could otherwise mint/rotate into a broader or unscoped key via the
    // bearer-only self-service routes. Browser/JWT sessions have no
    // credential scopes, so they remain allowed to manage their own keys.
    if (routeCtx.scopes !== undefined)
      throw Errors.forbidden('API keys cannot manage API keys');
    return routeCtx.subject;
  }
  if (!input.subject)
    throw Errors.badRequest('subject is required for programmatic calls');
  return input.subject;
}

function coerceDate(value: Date | string | undefined): Date | undefined {
  if (value == null)
    return undefined;
  if (value instanceof Date)
    return value;
  const parsed = new Date(value);
  if (Number.isNaN(parsed.getTime()))
    throw Errors.badRequest('expiresAt must be a valid date');
  return parsed;
}
