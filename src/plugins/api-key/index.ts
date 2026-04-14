/**
 * API key plugin for fortress.
 *
 * Issues scoped, hashed API keys for service accounts and devices, with
 * optional expiry, revocation, and per-key permission scopes. Authenticates
 * incoming requests via a configurable header and exposes management methods
 * on the fortress instance.
 *
 * HTTP endpoints are opt-in: pass `apiKey({ routes: true })` to mount the
 * self-service routes under `/api-key/keys/*`. The programmatic methods on
 * `fortress.plugins['api-key']` are always available regardless of the flag.
 *
 * @module
 */

import type { EndpointDefinition } from '../../core/endpoint';
import type { FortressPlugin, PluginRouteContext } from '../../core/plugin';
import type { ApiKeyInfo, ApiKeyKnobs, CreateKeyOptions } from './core';
import { Errors } from '../../core/errors';
import { arr, bool, endpoint, int, obj, str } from '../../core/schema-builder';
import {
  createKeyForUser,
  listKeysForUser,
  resolveApiKey,
  revokeKeyForUser,
  rotateKeyForUser,
} from './core';

export type { ApiKeyInfo, ApiKeyRecord } from './core';

export interface ApiKeyConfig {
  /** Prefix for generated keys (default: 'fortress') */
  prefix?: string;
  /** Default expiry in seconds. null = never expires (default: null) */
  defaultExpirySeconds?: number | null;
  /** Maximum active (non-revoked) keys per user (default: 10) */
  maxKeysPerUser?: number;
  /**
   * Mount self-service HTTP routes under `/api-key/keys/*`. Default `false`.
   * The programmatic methods on `fortress.plugins['api-key']` are always
   * available; this flag only controls HTTP mounting.
   */
  routes?: boolean;
}

export interface ApiKeyMethods {
  createKey: (
    input: { userId?: number; name: string; scopes?: string[]; expiresAt?: Date | string },
    routeCtx?: PluginRouteContext,
  ) => Promise<{ key: string; id: number }>;
  listKeys: (
    input: { userId?: number },
    routeCtx?: PluginRouteContext,
  ) => Promise<ApiKeyInfo[]>;
  revokeKey: (
    input: { userId?: number; id: number | string },
    routeCtx?: PluginRouteContext,
  ) => Promise<{ ok: true }>;
  rotateKey: (
    input: { userId?: number; id: number | string },
    routeCtx?: PluginRouteContext,
  ) => Promise<{ key: string; id: number }>;
  resolveKey: (
    rawKey: string,
  ) => Promise<{ userId: number; scopes: string[] | null } | null>;
}

// ── Routes ──────────────────────────────────────────────────────────

const errorRef = { $ref: '#/components/schemas/ErrorResponse' };

const apiKeySelfServiceRoutes: EndpointDefinition[] = [
  endpoint('POST', '/api-key/keys')
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
      id: int('Database id of the key'),
    }, 'key', 'id'))
    .response(400, 'Bad request', errorRef)
    .response(401, 'Not authenticated', errorRef)
    .handler('createKey')
    .build(),

  endpoint('GET', '/api-key/keys')
    .summary('List the caller\'s API keys')
    .description('Return the active (non-revoked) API keys belonging to the authenticated caller. Raw keys and hashes are never returned.')
    .tags('API Keys')
    .security('bearer')
    .response(200, 'Keys', obj({
      keys: arr(obj({
        id: int('Database id'),
        name: str('Key label'),
        keyPrefix: str('First 12 characters of the key, for identification'),
        scopes: arr(str()),
        expiresAt: str('ISO 8601 expiry, if any'),
        lastUsedAt: str('ISO 8601 timestamp of last successful resolve'),
        createdAt: str('ISO 8601 creation timestamp'),
      }, 'id', 'name', 'keyPrefix', 'createdAt')),
    }, 'keys'))
    .response(401, 'Not authenticated', errorRef)
    .handler('listKeys')
    .build(),

  endpoint('DELETE', '/api-key/keys/:id')
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

  endpoint('POST', '/api-key/keys/:id/rotate')
    .summary('Rotate an API key')
    .description('Revoke an existing key and issue a new one with the same name, scopes, and expiry. The new raw key is returned exactly once.')
    .tags('API Keys')
    .security('bearer')
    .params(obj({ id: str('Key id to rotate') }, 'id'))
    .response(200, 'Rotated', obj({
      key: str('New raw API key — shown exactly once'),
      id: int('Database id of the new key'),
    }, 'key', 'id'))
    .response(401, 'Not authenticated', errorRef)
    .response(404, 'Not found', errorRef)
    .handler('rotateKey')
    .build(),
];

// ── Plugin Factory ──────────────────────────────────────────────────

/**
 * API key plugin factory. Returns a {@link FortressPlugin} that issues
 * scoped, hashed API keys and exposes management methods on the fortress
 * instance. Pass `{ routes: true }` to mount the self-service HTTP routes
 * under `/api-key/keys/*`.
 */
export function apiKey(config: ApiKeyConfig = {}): FortressPlugin & { readonly name: 'api-key' } {
  const knobs: ApiKeyKnobs = {
    prefix: config.prefix ?? 'fortress',
    defaultExpirySeconds: config.defaultExpirySeconds ?? null,
    maxKeysPerUser: config.maxKeysPerUser ?? 10,
  };
  const mountRoutes = config.routes === true;

  return {
    name: 'api-key',

    models: [{
      name: 'api_key',
      fields: {
        id: { type: 'number', required: true },
        userId: { type: 'number', required: true, references: { model: 'user', field: 'id' } },
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

    methods: ctx => ({
      async createKey(
        input: { userId?: number; name: string; scopes?: string[]; expiresAt?: Date | string },
        routeCtx?: PluginRouteContext,
      ): Promise<{ key: string; id: number }> {
        const userId = resolveCallerId(input, routeCtx);
        const options: CreateKeyOptions = {
          name: String(input.name ?? ''),
          scopes: Array.isArray(input.scopes) ? input.scopes.map(String) : undefined,
          expiresAt: coerceDate(input.expiresAt),
        };
        if (!options.name)
          throw Errors.badRequest('name is required');
        return createKeyForUser(ctx.db, userId, options, knobs);
      },

      async listKeys(
        input: { userId?: number },
        routeCtx?: PluginRouteContext,
      ): Promise<ApiKeyInfo[]> {
        const userId = resolveCallerId(input, routeCtx);
        return listKeysForUser(ctx.db, userId);
      },

      async revokeKey(
        input: { userId?: number; id: number | string },
        routeCtx?: PluginRouteContext,
      ): Promise<{ ok: true }> {
        const userId = resolveCallerId(input, routeCtx);
        const keyId = Number(input.id);
        if (!Number.isFinite(keyId))
          throw Errors.badRequest('id is required');
        await revokeKeyForUser(ctx.db, userId, keyId);
        return { ok: true };
      },

      async rotateKey(
        input: { userId?: number; id: number | string },
        routeCtx?: PluginRouteContext,
      ): Promise<{ key: string; id: number }> {
        const userId = resolveCallerId(input, routeCtx);
        const keyId = Number(input.id);
        if (!Number.isFinite(keyId))
          throw Errors.badRequest('id is required');
        return rotateKeyForUser(ctx.db, userId, keyId, { prefix: knobs.prefix });
      },

      async resolveKey(
        rawKey: string,
      ): Promise<{ userId: number; scopes: string[] | null } | null> {
        return resolveApiKey(ctx.db, rawKey);
      },
    }),
  };
}

/**
 * Resolve the caller's userId. Two call paths:
 *
 *  1. HTTP: the dispatcher passes `routeCtx` with the verified JWT subject.
 *     Use it and ignore any `userId` in the body — the client doesn't get to
 *     pick which user a key is created for.
 *  2. Programmatic (seed scripts, custom server code): no `routeCtx`, so fall
 *     back to `body.userId`. These callers are trusted because they already
 *     hold a reference to `fortress.plugins['api-key']`.
 */
function resolveCallerId(
  input: { userId?: number },
  routeCtx?: PluginRouteContext,
): number {
  if (routeCtx) {
    if (routeCtx.userId == null)
      throw Errors.unauthorized('User not authenticated');
    return routeCtx.userId;
  }
  if (input.userId == null)
    throw Errors.badRequest('userId is required for programmatic calls');
  return Number(input.userId);
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
