/**
 * Database constraint-error → {@link FortressError} translation for the
 * Drizzle adapter.
 *
 * Drizzle wraps driver-level errors before re-throwing, so a constraint
 * violation typically surfaces as a generic `DrizzleQueryError` with the
 * real driver error tucked under `error.cause`. Both matchers walk the
 * cause chain up to a small fixed depth: {@link findSqlstate} looks for a
 * Postgres 5-character SQLSTATE `code`, and the SQLite matcher looks for a
 * `SQLITE_CONSTRAINT_*` code or the driver's constraint message.
 *
 * The mapping tables cover the constraint/concurrency states that almost
 * every CRUD endpoint cares about. Anything not in the table is re-thrown
 * unchanged so callers can still observe the raw driver error.
 *
 * {@link rethrowDbError} routes on the adapter `dialect`: Postgres via
 * SQLSTATE, SQLite via constraint code/message. Unique violations map to
 * `CONFLICT` (409) on both dialects so a mixed-dialect call site gets a
 * stable wire response without branching.
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
  message?: unknown;
  cause?: unknown;
}

/**
 * SQLite constraint matchers. better-sqlite3 and bun:sqlite both surface a
 * `SQLITE_CONSTRAINT_*` `code`; older builds only set the message, so each
 * entry matches either. Tested against `${code} ${message}` at every level
 * of the cause chain.
 */
const SQLITE_CONSTRAINT_MAP: { match: RegExp; factory: (cause: unknown) => FortressError }[] = [
  {
    match: /SQLITE_CONSTRAINT_(?:UNIQUE|PRIMARYKEY)|UNIQUE constraint failed/i,
    factory: cause => Errors.conflict('Resource already exists', { cause }),
  },
  {
    match: /SQLITE_CONSTRAINT_FOREIGNKEY|FOREIGN KEY constraint failed/i,
    factory: cause => Errors.unprocessable('Referenced resource does not exist', { cause }),
  },
  {
    match: /SQLITE_CONSTRAINT_NOTNULL|NOT NULL constraint failed/i,
    factory: _cause => Errors.badRequest('Required field is missing'),
  },
];

/**
 * Walk the `cause` chain looking for a SQLite constraint violation, testing
 * each level's `code`/`message` against {@link SQLITE_CONSTRAINT_MAP}.
 * Returns the matching {@link FortressError} or `null` when none is found
 * within {@link MAX_CAUSE_DEPTH} hops.
 */
function mapSqliteConstraint(err: unknown): FortressError | null {
  let current: unknown = err;
  for (let i = 0; i < MAX_CAUSE_DEPTH; i++) {
    if (current === null || typeof current !== 'object')
      return null;
    const coded = current as MaybeCoded;
    const code = typeof coded.code === 'string' ? coded.code : '';
    const message = typeof coded.message === 'string' ? coded.message : '';
    const haystack = `${code} ${message}`;
    for (const { match, factory } of SQLITE_CONSTRAINT_MAP) {
      if (match.test(haystack))
        return factory(err);
    }
    current = coded.cause;
  }
  return null;
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
 * Translate a driver constraint error into a {@link FortressError} for the
 * given `dialect`, then throw it. Postgres routes through
 * {@link PG_SQLSTATE_MAP} by SQLSTATE; SQLite through
 * {@link SQLITE_CONSTRAINT_MAP} by constraint code/message. Errors that
 * don't match a known constraint are re-thrown unchanged so callers can
 * still observe the raw driver error.
 */
export function rethrowDbError(err: unknown, dialect: DrizzleDialect): never {
  if (dialect === 'pg') {
    const sqlstate = findSqlstate(err);
    const factory = sqlstate ? PG_SQLSTATE_MAP[sqlstate] : undefined;
    if (factory)
      throw factory(err);
    throw err;
  }
  if (dialect === 'sqlite') {
    const mapped = mapSqliteConstraint(err);
    if (mapped)
      throw mapped;
    throw err;
  }
  throw err;
}
