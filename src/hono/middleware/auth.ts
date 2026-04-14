import type { Context, MiddlewareHandler } from 'hono';
import type { DatabaseAdapter } from '../../adapters/database';
import type { Fortress } from '../../core/fortress';
import type { PluginContext } from '../../core/plugin';
import type { Subject, TokenClaims } from '../../core/types';
import { FortressError } from '../../core/errors';
import {
  chainAdapterWrappers,
  collectScopeRules,
  wrapAdapterWithScopeRules,
} from '../../core/plugin-runner';

/**
 * Hono context type augmentation populated by the fortress auth middleware.
 * Pass to `Hono<FortressEnv>` for typed access to fortress request state.
 *
 * `fortressSubject` is the authoritative principal — set for every
 * authenticated request regardless of credential type (JWT, api-key, future
 * OAuth client_credentials, mTLS, ...). `fortressUserId` is a convenience
 * alias populated **only** when the subject is a `USER`; non-USER subjects
 * (e.g. `SERVICE_ACCOUNT` via api-key) leave it `undefined`.
 */
export interface FortressEnv {
  Variables: {
    fortressSubject: Subject;
    fortressUserId?: number;
    fortressClaims?: TokenClaims;
    fortressDb: DatabaseAdapter;
    fortressGetScopedDb: (model: string) => Promise<DatabaseAdapter>;
  };
}

/**
 * Hono middleware that resolves the request principal and populates the
 * Hono context with `fortressSubject`, `fortressUserId` (USER alias),
 * `fortressClaims`, `fortressDb`, and `fortressGetScopedDb`.
 *
 * Principal resolution goes through `fortress.resolvePrincipal`, which
 * tries plugin `resolvePrincipal` hooks (api-key, future OAuth
 * client_credentials, mTLS) first and then falls back to the JWT bearer
 * token (cookie-first, `Authorization: Bearer` second). This means the
 * same Hono app can authenticate browsers (cookies), SPA clients (Bearer),
 * and service accounts (`Authorization: ApiKey ...` or `X-API-Key`)
 * without extra wiring on any route.
 *
 * `fortressDb` has plugin `wrapAdapter` applied (e.g. tenancy schema
 * switching). `fortressGetScopedDb(model)` additionally applies
 * `scopeRules` for the requested model.
 */
export function createAuthMiddleware(
  fortress: Fortress,
): MiddlewareHandler<FortressEnv> {
  return async (c, next) => {
    const resolved = await fortress.resolvePrincipal(c.req.raw);
    if (!resolved) {
      throw new FortressError(
        'UNAUTHORIZED',
        'Missing or invalid credentials',
        401,
      );
    }

    const { subject, claims } = resolved;
    c.set('fortressSubject', subject);
    if (subject.type === 'USER')
      c.set('fortressUserId', subject.id);
    if (claims)
      c.set('fortressClaims', claims);

    // Build request context from headers for plugin adapter wrappers
    const plugins = fortress.config.plugins ?? [];
    const requestContext: Record<string, unknown> = {
      tenantCode: c.req.header('X-Tenant-Code'),
      ipAddress:
        c.req.header('X-Forwarded-For') ?? c.req.header('X-Real-IP'),
      userAgent: c.req.header('User-Agent'),
    };

    // Chain adapter wrappers (e.g., tenancy schema switching)
    const wrappedAdapter = chainAdapterWrappers(
      plugins,
      fortress.config.database,
      requestContext,
    );
    c.set('fortressDb', wrappedAdapter);

    // Lazy scope rule applicator — routes pick the model they need. Scope
    // rules key off the subject id; for non-USER subjects the plugins that
    // care (data-isolation) typically noop, but the call still works.
    const pluginCtx: PluginContext = {
      db: wrappedAdapter,
      config: fortress.config,
    };
    c.set(
      'fortressGetScopedDb',
      async (model: string): Promise<DatabaseAdapter> => {
        const scopeRule = await collectScopeRules(
          plugins,
          subject.id,
          model,
          pluginCtx,
        );
        if (!scopeRule)
          return wrappedAdapter;
        return wrapAdapterWithScopeRules(wrappedAdapter, scopeRule);
      },
    );

    await next();
  };
}

/**
 * Get the authenticated principal from the Hono context. Works for every
 * subject kind (`USER`, `SERVICE_ACCOUNT`, ...).
 */
export function getSubject(c: Context<FortressEnv>): Subject {
  const subject = c.get('fortressSubject');
  if (!subject) {
    throw new FortressError('UNAUTHORIZED', 'Not authenticated', 401);
  }
  return subject;
}

/**
 * Get the authenticated user ID from Hono context. Throws 401 if the
 * request was authenticated by a non-USER subject (e.g. a service account
 * via api-key) — use {@link getSubject} for handlers that need to accept
 * any principal.
 */
export function getUserId(c: Context<FortressEnv>): number {
  const subject = c.get('fortressSubject');
  if (!subject || subject.type !== 'USER') {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return subject.id;
}

/**
 * Get the authenticated user's JWT claims from Hono context. Claims are
 * only populated when the request was authenticated via a JWT — api-key
 * principals have no JWT claims. Throws 401 if unavailable.
 */
export function getClaims(c: Context<FortressEnv>): TokenClaims {
  const claims = c.get('fortressClaims');
  if (!claims) {
    throw new FortressError('UNAUTHORIZED', 'No JWT claims on this request', 401);
  }
  return claims;
}

/**
 * Get the request-scoped database adapter with plugin wrapAdapter applied.
 */
export function getDb(c: Context<FortressEnv>): DatabaseAdapter {
  const db = c.get('fortressDb');
  if (!db) {
    throw new FortressError('UNAUTHORIZED', 'Not authenticated', 401);
  }
  return db;
}

/**
 * Get a model-scoped database adapter with both wrapAdapter and scopeRules applied.
 */
export function getScopedDb(
  c: Context<FortressEnv>,
  model: string,
): Promise<DatabaseAdapter> {
  const fn = c.get('fortressGetScopedDb');
  if (!fn) {
    throw new FortressError('UNAUTHORIZED', 'Not authenticated', 401);
  }
  return fn(model);
}
