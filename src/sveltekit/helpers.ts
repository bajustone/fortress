/**
 * Read fortress request context from a SvelteKit `RequestEvent`.
 *
 * Each helper throws `FortressError('UNAUTHORIZED')` when the field is
 * missing — typically because the auth handle hook didn't populate
 * `event.locals.fortress.userId` (i.e. the request was anonymous).
 */

import type { DatabaseAdapter } from '../adapters/database';
import type { Subject, TokenClaims } from '../core/types';
import type { FortressLocals, SvelteKitRequestEvent } from './types';
import { Errors } from '../core/errors';

type EventWithFortress = SvelteKitRequestEvent<FortressLocals>;

/**
 * Read the resolved principal from the event, throwing 401 if missing.
 * Works for every subject kind (`USER`, `SERVICE_ACCOUNT`, ...).
 */
export function getSubject(event: EventWithFortress): Subject {
  const subject = event.locals.fortress?.subject;
  if (!subject)
    throw Errors.unauthorized('Not authenticated');
  return subject;
}

/**
 * Read the authenticated user ID. Throws 401 when the request was
 * authenticated by a non-USER subject (e.g. a service account via
 * api-key) — use {@link getSubject} for handlers that accept any
 * principal.
 */
export function getUserId(event: EventWithFortress): string {
  const subject = event.locals.fortress?.subject;
  if (!subject || subject.type !== 'USER')
    throw Errors.unauthorized('User not authenticated');
  return subject.id;
}

/**
 * Read the verified JWT claims. Only populated when the request was
 * authenticated via a JWT — api-key principals have no JWT claims and
 * this helper throws 401.
 */
export function getClaims(event: EventWithFortress): TokenClaims {
  const claims = event.locals.fortress?.claims;
  if (!claims)
    throw Errors.unauthorized('No JWT claims on this request');
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
