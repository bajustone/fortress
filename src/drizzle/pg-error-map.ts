/**
 * Postgres SQLSTATE → {@link FortressError} translation for the Drizzle
 * adapter.
 *
 * Drizzle wraps driver-level errors (`postgres`, `pg`) before re-throwing,
 * so a Postgres constraint violation typically surfaces as a generic
 * `DrizzleQueryError` with the real driver error tucked under
 * `error.cause`. {@link findSqlstate} walks the cause chain up to a small
 * fixed depth looking for any object whose own `code` field matches the
 * 5-character SQLSTATE pattern.
 *
 * The mapping table covers the constraint/concurrency states that almost
 * every CRUD endpoint cares about. Anything not in the table is re-thrown
 * unchanged so callers can still observe the raw driver error.
 *
 * This module is **PG-only**. Other dialects pass through unchanged via
 * the `dialect` guard in {@link rethrowPgError}; SQLite/MySQL constraint
 * mapping is intentionally out of scope until there's a real consumer.
 */

import type { FortressError } from '../core/errors';
import type { DrizzleDialect } from './adapter';
import { Errors } from '../core/errors';

/** How many `cause` levels to walk while hunting for the SQLSTATE. */
const MAX_CAUSE_DEPTH = 6;

const SQLSTATE_PATTERN = /^[0-9A-Z]{5}$/;

/**
 * SQLSTATE → factory that produces the matched {@link FortressError}.
 *
 * Each entry maps a Postgres error class to the canonical Fortress HTTP
 * status so downstream `protect()` middleware emits a stable wire response
 * without the host writing a try/catch.
 *
 * | SQLSTATE | Meaning              | Fortress error          | HTTP |
 * | -------- | -------------------- | ----------------------- | ---- |
 * | `23505`  | unique_violation     | `CONFLICT`              | 409  |
 * | `23503`  | foreign_key_violation| `UNPROCESSABLE_ENTITY`  | 422  |
 * | `23502`  | not_null_violation   | `BAD_REQUEST`           | 400  |
 * | `23514`  | check_violation      | `UNPROCESSABLE_ENTITY`  | 422  |
 * | `40001`  | serialization_failure| `CONFLICT`              | 409  |
 * | `40P01`  | deadlock_detected    | `CONFLICT`              | 409  |
 * | `57014`  | query_canceled       | `SERVICE_UNAVAILABLE`   | 503  |
 */
const PG_SQLSTATE_MAP: Record<string, (cause: unknown) => FortressError> = {
  '23505': cause => Errors.conflict('Resource already exists', { cause }),
  '23503': cause => Errors.unprocessable('Referenced resource does not exist', { cause }),
  '23502': _cause => Errors.badRequest('Required field is missing'),
  '23514': cause => Errors.unprocessable('Constraint check failed', { cause }),
  '40001': cause => Errors.conflict('Serialization failure, retry the request', { cause }),
  '40P01': cause => Errors.conflict('Deadlock detected, retry the request', { cause }),
  '57014': cause => Errors.serviceUnavailable('Query canceled', { cause }),
};

interface MaybeCoded {
  code?: unknown;
  cause?: unknown;
}

/**
 * Walk the `cause` chain of an unknown thrown value looking for a property
 * named `code` that smells like a Postgres SQLSTATE (5 uppercase
 * alphanumerics, e.g. `23505`, `40P01`). Returns the first match it finds
 * or `null` when none is present within {@link MAX_CAUSE_DEPTH} hops.
 */
export function findSqlstate(err: unknown): string | null {
  let current: unknown = err;
  for (let i = 0; i < MAX_CAUSE_DEPTH; i++) {
    if (current === null || typeof current !== 'object')
      return null;
    const candidate = (current as MaybeCoded).code;
    if (typeof candidate === 'string' && SQLSTATE_PATTERN.test(candidate))
      return candidate;
    current = (current as MaybeCoded).cause;
  }
  return null;
}

/**
 * If `err` originated from Postgres and carries a SQLSTATE in
 * {@link PG_SQLSTATE_MAP}, throw the matching {@link FortressError};
 * otherwise re-throw `err` unchanged.
 *
 * No-op for non-`pg` dialects so a mixed-dialect call site can route
 * through this helper without branching.
 */
export function rethrowPgError(err: unknown, dialect: DrizzleDialect): never {
  if (dialect !== 'pg')
    throw err;
  const sqlstate = findSqlstate(err);
  const factory = sqlstate ? PG_SQLSTATE_MAP[sqlstate] : undefined;
  if (factory)
    throw factory(err);
  throw err;
}
