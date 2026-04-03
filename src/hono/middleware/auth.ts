import type { Context, MiddlewareHandler } from 'hono';
import type { Fortress } from '../../core/fortress';
import type { TokenClaims } from '../../core/types';
import { FortressError } from '../../core/errors';

export interface FortressEnv {
  Variables: {
    fortressUserId: number;
    fortressClaims: TokenClaims;
  };
}

/**
 * Hono middleware that extracts and verifies JWT from the Authorization header.
 * Sets `fortressUserId` and `fortressClaims` on the Hono context.
 */
export function createAuthMiddleware(fortress: Fortress): MiddlewareHandler<FortressEnv> {
  return async (c, next) => {
    const header = c.req.header('Authorization');
    if (!header?.startsWith('Bearer ')) {
      throw new FortressError('UNAUTHORIZED', 'Missing or invalid Authorization header', 401);
    }

    const token = header.slice(7);
    const claims = await fortress.auth.verifyToken(token);

    c.set('fortressUserId', claims.sub);
    c.set('fortressClaims', claims);

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
