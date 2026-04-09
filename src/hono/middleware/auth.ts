import type { Context, MiddlewareHandler } from 'hono';
import type { DatabaseAdapter } from '../../adapters/database';
import type { Fortress } from '../../core/fortress';
import type { PluginContext } from '../../core/plugin';
import type { TokenClaims } from '../../core/types';
import { FortressError } from '../../core/errors';
import {
  chainAdapterWrappers,
  collectScopeRules,
  wrapAdapterWithScopeRules,
} from '../../core/plugin-runner';

/**
 * Hono context type augmentation populated by the fortress auth middleware.
 * Pass to `Hono<FortressEnv>` for typed access to the per-request state
 * (`fortressUserId`, `fortressClaims`, `fortressDb`, `fortressGetScopedDb`).
 */
/**
 * Hono context type augmentation populated by the fortress auth middleware.
 * Pass to `Hono<FortressEnv>` for typed access to fortress request state.
 */
export interface FortressEnv {
  Variables: {
    fortressUserId: number;
    fortressClaims: TokenClaims;
    fortressDb: DatabaseAdapter;
    fortressGetScopedDb: (model: string) => Promise<DatabaseAdapter>;
  };
}

/**
 * Hono middleware that extracts and verifies JWT from the Authorization header.
 * Sets `fortressUserId`, `fortressClaims`, `fortressDb`, and `fortressGetScopedDb`
 * on the Hono context.
 *
 * `fortressDb` has plugin wrapAdapter applied (e.g., tenancy schema switching).
 * `fortressGetScopedDb(model)` additionally applies scopeRules for a specific model.
 */
export function createAuthMiddleware(
  fortress: Fortress,
): MiddlewareHandler<FortressEnv> {
  return async (c, next) => {
    const header = c.req.header('Authorization');
    const bearerTokenPrefix = 'Bearer ';
    if (!header?.startsWith(bearerTokenPrefix)) {
      throw new FortressError(
        'UNAUTHORIZED',
        'Missing or invalid Authorization header',
        401,
      );
    }

    const token = header.slice(bearerTokenPrefix.length);
    const claims = await fortress.auth.verifyToken(token);

    c.set('fortressUserId', claims.sub);
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

    // Lazy scope rule applicator — routes pick the model they need
    const pluginCtx: PluginContext = {
      db: wrappedAdapter,
      config: fortress.config,
    };
    c.set(
      'fortressGetScopedDb',
      async (model: string): Promise<DatabaseAdapter> => {
        const scopeRule = await collectScopeRules(
          plugins,
          claims.sub,
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
 * Get the authenticated user ID from Hono context.
 */
export function getUserId(c: Context<FortressEnv>): number {
  const userId = c.get('fortressUserId');
  if (!userId) {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return userId;
}

/**
 * Get the authenticated user's JWT claims from Hono context.
 */
export function getClaims(c: Context<FortressEnv>): TokenClaims {
  const claims = c.get('fortressClaims');
  if (!claims) {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return claims;
}

/**
 * Get the request-scoped database adapter with plugin wrapAdapter applied.
 */
export function getDb(c: Context<FortressEnv>): DatabaseAdapter {
  const db = c.get('fortressDb');
  if (!db) {
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
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
    throw new FortressError('UNAUTHORIZED', 'User not authenticated', 401);
  }
  return fn(model);
}
