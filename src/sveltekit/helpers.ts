/**
 * Read fortress request context from a SvelteKit `RequestEvent`.
 *
 * Each helper throws `FortressError('UNAUTHORIZED')` when the field is
 * missing — typically because the auth handle hook didn't populate
 * `event.locals.fortress.userId` (i.e. the request was anonymous).
 */

import type { DatabaseAdapter } from '../adapters/database';
import type { TokenClaims } from '../core/types';
import type { FortressLocals, SvelteKitRequestEvent } from './types';
import { Errors } from '../core/errors';

type EventWithFortress = SvelteKitRequestEvent<FortressLocals>;

/** Read the authenticated user ID, throwing 401 if missing. */
export function getUserId(event: EventWithFortress): number {
  const id = event.locals.fortress?.userId;
  if (id == null)
    throw Errors.unauthorized('Not authenticated');
  return id;
}

/** Read the verified JWT claims, throwing 401 if missing. */
export function getClaims(event: EventWithFortress): TokenClaims {
  const claims = event.locals.fortress?.claims;
  if (!claims)
    throw Errors.unauthorized('Not authenticated');
  return claims;
}

/** Read the per-request DB adapter (with plugin wrappers applied). */
export function getDb(event: EventWithFortress): DatabaseAdapter {
  const db = event.locals.fortress?.db;
  if (!db)
    throw Errors.unauthorized('Not authenticated');
  return db;
}

/**
 * Read the per-request DB adapter scoped to a specific model. Applies any
 * active row-level scope rules from data-isolation plugins.
 */
export function getScopedDb(event: EventWithFortress, model: string): Promise<DatabaseAdapter> {
  const fn = event.locals.fortress?.getScopedDb;
  if (!fn)
    throw Errors.unauthorized('Not authenticated');
  return fn(model);
}
