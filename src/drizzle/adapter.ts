import type { Column, SQL, Table } from 'drizzle-orm';
import type { DatabaseDialect, MigratableDatabaseAdapter } from '../adapters/database';
import type { WhereClause } from '../adapters/database/types';

import { AsyncLocalStorage } from 'node:async_hooks';
import { and, eq, getTableColumns, gt, gte, inArray, isNull, like, lt, lte, ne, sql } from 'drizzle-orm';
import { Errors } from '../core/errors';
import { rethrowDbError } from './pg-error-map';
import { fortressPgSchema } from './pg/schema';
import { fortressSchema } from './schema';

export type DrizzleDialect = DatabaseDialect;

/** Table overrides shared by the dialect-specific Drizzle factories. */
export interface DrizzleAdapterOptions {
  /** Override default Fortress table definitions with your own Drizzle tables. */
  tables?: Partial<Record<string, Table>>;
}

/**
 * The SQLite and PostgreSQL schema modules are static Fortress-owned manifests.
 * A missing entry is a programming/declaration error, not an absent table that
 * can safely flow into Drizzle and fail later as an unrelated query error.
 */
function requireSchemaTable(schema: Record<string, Table>, property: string): Table {
  const table = schema[property];
  if (table === undefined)
    throw new Error(`Fortress Drizzle schema is missing required table '${property}'`);
  return table;
}

function buildTableMap(schema: Record<string, Table>): Record<string, Table> {
  return {
    schema_version: requireSchemaTable(schema, 'schemaVersion'),
    user: requireSchemaTable(schema, 'users'),
    login_identifier: requireSchemaTable(schema, 'loginIdentifiers'),
    refresh_token: requireSchemaTable(schema, 'refreshTokens'),
    auth_continuation: requireSchemaTable(schema, 'authContinuations'),
    group: requireSchemaTable(schema, 'groups'),
    group_user: requireSchemaTable(schema, 'groupUsers'),
    service_account: requireSchemaTable(schema, 'serviceAccounts'),
    resource: requireSchemaTable(schema, 'resources'),
    permission: requireSchemaTable(schema, 'permissions'),
    role: requireSchemaTable(schema, 'roles'),
    role_permission: requireSchemaTable(schema, 'rolePermissions'),
    role_binding: requireSchemaTable(schema, 'roleBindings'),
    direct_permission_binding: requireSchemaTable(schema, 'directPermissionBindings'),
    email_verification_token: requireSchemaTable(schema, 'emailVerificationTokens'),
    magic_link_token: requireSchemaTable(schema, 'magicLinkTokens'),
    api_key: requireSchemaTable(schema, 'apiKeys'),
    two_factor_secret: requireSchemaTable(schema, 'twoFactorSecrets'),
    backup_code: requireSchemaTable(schema, 'backupCodes'),
    trusted_device: requireSchemaTable(schema, 'trustedDevices'),
    social_account: requireSchemaTable(schema, 'socialAccounts'),
    tenant: requireSchemaTable(schema, 'tenants'),
    tenant_user: requireSchemaTable(schema, 'tenantUsers'),
    oauth_client: requireSchemaTable(schema, 'oauthClients'),
    oauth_authorization_code: requireSchemaTable(schema, 'oauthAuthorizationCodes'),
    oauth_access_token: requireSchemaTable(schema, 'oauthAccessTokens'),
    oauth_refresh_token: requireSchemaTable(schema, 'oauthRefreshTokens'),
    oauth_pending_flow: requireSchemaTable(schema, 'oauthPendingFlows'),
    oauth_signing_key: requireSchemaTable(schema, 'oauthSigningKeys'),
    user_scope_assignment: requireSchemaTable(schema, 'userScopeAssignments'),
    account_lockout: requireSchemaTable(schema, 'accountLockouts'),
    audit_log: requireSchemaTable(schema, 'auditLogs'),
    audit_chain_state: requireSchemaTable(schema, 'auditChainState'),
    webhook_endpoint: requireSchemaTable(schema, 'webhookEndpoints'),
    webhook_delivery: requireSchemaTable(schema, 'webhookDeliveries'),
    webauthn_credential: requireSchemaTable(schema, 'webauthnCredentials'),
    webauthn_challenge: requireSchemaTable(schema, 'webauthnChallenges'),
  };
}

const SQLITE_DEFAULT_TABLE_MAP = buildTableMap(fortressSchema);
const PG_DEFAULT_TABLE_MAP = buildTableMap(fortressPgSchema);

function getColumn(table: Table, field: string, model: string): Column {
  const columns = getTableColumns(table);
  // Try exact match first. Retain the narrowed lookup rather than indexing a
  // second time, because callers may supply arbitrary field names.
  const exactColumn = columns[field];
  if (exactColumn)
    return exactColumn;

  // Convert snake_case field names to camelCase column references.
  const camelCase = field.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
  const camelCaseColumn = columns[camelCase];
  if (camelCaseColumn)
    return camelCaseColumn;

  throw Errors.badRequest(`Unknown field: ${field} on model/table '${model}'`, {
    details: { model, field },
  });
}

function buildWhereCondition(table: Table, where: WhereClause[], model: string): SQL | undefined {
  // A missing/empty where would compile to `.where(undefined)`, which matches
  // EVERY row — a silent full-table update/delete footgun. findMany/count
  // guard the empty case before calling (an unfiltered read is legal); the
  // mutating paths (update/delete) and findOne pass their required where here
  // directly, so rejecting empty here fails those closed.
  if (where.length === 0)
    throw Errors.badRequest('A non-empty where clause is required (empty where would match all rows)');
  const conditions = where.map((clause) => {
    const column = getColumn(table, clause.field, model);

    switch (clause.operator) {
      case '=':
        return eq(column, clause.value as any);
      case '!=':
        return ne(column, clause.value as any);
      case 'in':
        return inArray(column, clause.value as any[]);
      case 'gt':
        return gt(column, clause.value as any);
      case 'lt':
        return lt(column, clause.value as any);
      case 'gte':
        return gte(column, clause.value as any);
      case 'lte':
        return lte(column, clause.value as any);
      case 'like':
        return like(column, clause.value as string);
      case 'isNull':
        return isNull(column);
      default:
        throw Errors.badRequest(`Unsupported operator: ${clause.operator}`);
    }
  });

  return conditions.length === 1 ? conditions[0] : and(...conditions);
}

/** Replace undefined values with null for database compatibility. */
function sanitizeData(data: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    result[key] = value === undefined ? null : value;
  }
  return result;
}

/**
 * Return true if a column name names a subject-id at the fortress API
 * surface (RFC 7519 §4.1.2). Used to translate the database-native id type
 * (commonly bigserial/integer) to fortress's opaque string-id contract on
 * read — see {@link stringifyIds}.
 *
 * Matches:
 *   - `id` exactly (every model's primary key)
 *   - any camelCase field ending in `Id` (`userId`, `roleId`, `tenantId`, …)
 *
 * Does NOT match:
 *   - `tokenId`-like fields that are already strings in the schema (the
 *     transform is a no-op on strings, so this is safe)
 *   - timestamp fields (no `Id` suffix)
 */
const ID_FIELD_RE = /[a-z]Id$/;
function isIdField(key: string): boolean {
  return key === 'id' || ID_FIELD_RE.test(key);
}

/**
 * Recursively stringify every id-like field in a row. Pure function, runs
 * on every read path (findOne, findMany, rawQuery, create.returning,
 * update.returning, delete.returning) so consumers always see string ids
 * regardless of whether the underlying column is `integer`, `bigserial`,
 * `uuid`, or `text`.
 *
 * - Numbers and bigints ⇒ stringified via `String(...)`.
 * - Strings ⇒ passed through unchanged.
 * - `null`/`undefined` ⇒ passed through (nullable FKs).
 * - Arrays and nested objects are walked (rawQuery results may nest).
 */
function stringifyIds<T>(row: T): T {
  if (row == null || typeof row !== 'object')
    return row;
  if (Array.isArray(row))
    return row.map(stringifyIds) as unknown as T;
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(row as Record<string, unknown>)) {
    if (isIdField(key) && (typeof value === 'number' || typeof value === 'bigint')) {
      out[key] = String(value);
    }
    else if (value && typeof value === 'object' && !(value instanceof Date)) {
      out[key] = stringifyIds(value);
    }
    else {
      out[key] = value;
    }
  }
  return out as T;
}

/**
 * Return an array element only after the caller has established its bounds.
 * This keeps an impossible internal indexing failure distinct from a user-facing
 * fallback: callers retain their existing validation and query semantics.
 */
function requireArrayEntry<T>(values: readonly T[], index: number, description: string): T {
  const value = values[index];
  if (value === undefined)
    throw new Error(`Missing ${description} at index ${index}`);
  return value;
}

function buildRawSql(sqlText: string, params: unknown[] = []): SQL {
  if (params.length === 0)
    return sql.raw(sqlText);

  if (sqlText.includes('?')) {
    const parts = sqlText.split('?');
    if (parts.length - 1 !== params.length) {
      throw Errors.badRequest(`rawQuery placeholder count (${parts.length - 1}) does not match params (${params.length})`);
    }
    // The count check above proves both entries exist for every parameter.
    // Keep that proof adjacent to each dynamic lookup instead of supplying a
    // value-changing fallback for malformed SQL.
    let query: SQL = sql.raw(requireArrayEntry(parts, 0, 'raw SQL segment'));
    for (const [index, parameter] of params.entries()) {
      const nextPart = requireArrayEntry(parts, index + 1, 'raw SQL segment');
      query = sql`${query}${parameter}${sql.raw(nextPart)}`;
    }
    return query;
  }

  throw Errors.badRequest(
    'rawQuery uses ? positional placeholders on every dialect; params were provided but no ? placeholders were found',
  );
}

function normalizeRawRows<T>(result: unknown): T[] {
  if (Array.isArray(result))
    return result as T[];
  const rows = (result as { rows?: unknown })?.rows;
  if (Array.isArray(rows))
    return rows as T[];
  return [];
}

function sqliteStatementReturnsRows(sqlText: string): boolean {
  const normalized = sqlText.trimStart().toLowerCase();
  return normalized.startsWith('select')
    || normalized.startsWith('with')
    || normalized.startsWith('pragma')
    || normalized.includes(' returning ');
}

/**
 * Minimal Drizzle DB interface — accepts any Drizzle database instance.
 * Drizzle DB types vary by dialect (BunSQLiteDatabase, PostgresJsDatabase, etc.)
 * so we use a loose structural type rather than importing a specific one.
 */
// eslint-disable-next-line ts/no-unsafe-function-type -- Drizzle DB methods have dialect-specific signatures
interface DrizzleDB { insert: Function; select: Function; update: Function; delete: Function; transaction: Function }

function createDialectDrizzleAdapter<D extends DrizzleDialect>(
  db: DrizzleDB,
  dialect: D,
  options: DrizzleAdapterOptions = {},
): MigratableDatabaseAdapter<D> {
  const defaults = dialect === 'pg' ? PG_DEFAULT_TABLE_MAP : SQLITE_DEFAULT_TABLE_MAP;
  const tableMap: Record<string, Table> = { ...defaults, ...(options.tables as Record<string, Table>) };
  const isSqlite = dialect === 'sqlite';
  // SQLite drivers used by Drizzle (better-sqlite3 / bun:sqlite) expose a
  // single synchronous connection. Manual async transactions must therefore
  // be serialized: an `await` between BEGIN and COMMIT would otherwise allow a
  // second request to issue BEGIN on the same connection. SQLite is
  // single-writer anyway, so this preserves correctness with predictable
  // queuing semantics.
  let sqliteTxChain: Promise<unknown> = Promise.resolve();
  const sqliteTxContext = new AsyncLocalStorage<boolean>();

  // Finding #16: a standalone (non-transaction) op touches the single SQLite
  // connection immediately, so a plain write issued while a transaction is
  // mid-BEGIN…COMMIT would interleave into that open transaction and be caught
  // by its ROLLBACK. Route every standalone op through the SAME chain that
  // serializes transactions. Ops already running inside a transaction callback
  // bypass the queue — they must run directly on the open transaction rather
  // than deadlock behind the tx that owns the chain.
  function serializeSqlite<T>(op: () => Promise<T>): Promise<T> {
    if (!isSqlite || sqliteTxContext.getStore())
      return op();
    const result = sqliteTxChain.then(op, op);
    sqliteTxChain = result.catch(() => undefined);
    return result;
  }

  /** Execute a query expecting a single row (or undefined). SQLite uses .get(), PG awaits the query. */
  async function execOne<T>(query: any): Promise<T | undefined> {
    const row = isSqlite
      ? (query.get() as T | undefined)
      : ((await query) as T[])[0];
    return row === undefined ? undefined : stringifyIds(row);
  }

  /** Execute a query expecting an array of rows. SQLite uses .all(), PG awaits the query. */
  async function execMany<T>(query: any): Promise<T[]> {
    const rows = isSqlite
      ? (query.all() as T[])
      : ((await query) as T[]);
    return rows.map(stringifyIds);
  }

  /** Execute a query where the result is discarded. SQLite uses .run(), PG awaits the query. */
  async function execRun(query: any): Promise<void> {
    if (isSqlite) {
      query.run();
      return;
    }
    await query;
  }

  function getTable(model: string): Table {
    const table = tableMap[model];
    if (!table) {
      throw Errors.badRequest(`Unknown model: ${model}`);
    }
    return table;
  }

  /** Build an adapter backed by a specific Drizzle instance (db or tx). */
  function buildAdapter(drizzle: DrizzleDB): MigratableDatabaseAdapter<D> {
    const self: MigratableDatabaseAdapter<D> = {
      get dialect() { return dialect; },

      async create<T>(params: { model: string; data: Record<string, unknown> }): Promise<T> {
        return serializeSqlite<T>(async () => {
          const table = getTable(params.model);
          try {
            const result = await execOne<T>((drizzle as any).insert(table).values(sanitizeData(params.data) as any).returning());
            return result as T;
          }
          catch (err) {
            // Translate driver constraint errors (pg SQLSTATEs, sqlite
            // SQLITE_CONSTRAINT_*) into the matching FortressError so
            // unique-violation / FK-violation / etc. surface as CONFLICT /
            // UNPROCESSABLE_ENTITY without every host writing the same try/catch.
            rethrowDbError(err, dialect);
          }
        });
      },

      async findOne<T>(params: { model: string; where: WhereClause[] }): Promise<T | null> {
        return serializeSqlite<T | null>(async () => {
          const table = getTable(params.model);
          const condition = buildWhereCondition(table, params.where, params.model);
          const result = await execOne<T>((drizzle as any).select().from(table).where(condition).limit(1));
          return (result as T) ?? null;
        });
      },

      async findMany<T>(params: {
        model: string;
        where?: WhereClause[];
        limit?: number;
        offset?: number;
        sortBy?: { field: string; direction: 'asc' | 'desc' };
      }): Promise<T[]> {
        return serializeSqlite<T[]>(async () => {
          const table = getTable(params.model);
          let query = (drizzle as any).select().from(table).$dynamic();

          if (params.where && params.where.length > 0) {
            const condition = buildWhereCondition(table, params.where, params.model);
            query = query.where(condition);
          }

          if (params.sortBy) {
            const column = getColumn(table, params.sortBy.field, params.model);
            query = query.orderBy(
              params.sortBy.direction === 'desc' ? sql`${column} desc` : sql`${column} asc`,
            );
          }

          if (params.limit) {
            query = query.limit(params.limit);
          }

          if (params.offset) {
            query = query.offset(params.offset);
          }

          return execMany<T>(query);
        });
      },

      async update<T>(params: { model: string; where: WhereClause[]; data: Record<string, unknown> }): Promise<T | null> {
        return serializeSqlite<T | null>(async () => {
          const table = getTable(params.model);
          const condition = buildWhereCondition(table, params.where, params.model);
          const query = (drizzle as any).update(table).set(sanitizeData(params.data) as any).where(condition).returning();
          try {
            // SQLite drivers only step the statement for rows that are read from
            // RETURNING. Use .all() so UPDATEs that match multiple rows actually
            // apply to every row (family/session revocation depends on this),
            // while preserving the adapter contract of returning one row/null.
            if (isSqlite) {
              const rows = (query.all() as T[]).map(stringifyIds);
              return rows[0] ?? null;
            }
            const result = await execOne<T>(query);
            return (result as T) ?? null;
          }
          catch (err) {
            rethrowDbError(err, dialect);
          }
        });
      },

      async delete(params: { model: string; where: WhereClause[] }): Promise<void> {
        return serializeSqlite<void>(async () => {
          const table = getTable(params.model);
          const condition = buildWhereCondition(table, params.where, params.model);
          try {
            await execRun((drizzle as any).delete(table).where(condition));
          }
          catch (err) {
            // FK violation on delete is the common case here — surfaces as
            // UNPROCESSABLE_ENTITY rather than a raw driver error.
            rethrowDbError(err, dialect);
          }
        });
      },

      async count(params: { model: string; where?: WhereClause[] }): Promise<number> {
        return serializeSqlite<number>(async () => {
          const table = getTable(params.model);
          let query = (drizzle as any).select({ count: sql<number>`count(*)` }).from(table).$dynamic();

          if (params.where && params.where.length > 0) {
            const condition = buildWhereCondition(table, params.where, params.model);
            query = query.where(condition);
          }

          const result = await execOne<{ count: number | string }>(query);
          return Number(result?.count) || 0;
        });
      },

      async rawQuery<T>(sqlText: string, params?: unknown[]): Promise<T[]> {
        return serializeSqlite<T[]>(async () => {
          const query = buildRawSql(sqlText, params ?? []);
          if (isSqlite) {
            if (typeof (drizzle as any).all === 'function' && sqliteStatementReturnsRows(sqlText))
              return normalizeRawRows<T>((drizzle as any).all(query)).map(stringifyIds);
            if (typeof (drizzle as any).run === 'function') {
              (drizzle as any).run(query);
              return [];
            }
            if (typeof (drizzle as any).execute === 'function')
              return normalizeRawRows<T>(await (drizzle as any).execute(query)).map(stringifyIds);
            throw Errors.badRequest('rawQuery is not supported by this SQLite Drizzle driver');
          }
          if (typeof (drizzle as any).execute !== 'function')
            throw Errors.badRequest('rawQuery is not supported by this Drizzle driver');
          return normalizeRawRows<T>(await (drizzle as any).execute(query)).map(stringifyIds);
        });
      },

      async transaction<T>(fn: (tx: MigratableDatabaseAdapter<D>) => Promise<T>): Promise<T> {
        if (dialect === 'sqlite') {
          // SQLite transactions are serialized on one connection. A nested
          // tx.transaction(...) from inside the callback would otherwise be
          // queued behind the still-open outer transaction while the outer
          // callback awaits it: a self-deadlock. Detect that context and fail
          // clearly instead of hanging.
          if (sqliteTxContext.getStore()) {
            throw Errors.badRequest('Nested transactions are not supported by the SQLite Drizzle adapter');
          }

          const run = async (): Promise<T> => {
            (drizzle as any).run(sql`BEGIN IMMEDIATE`);
            try {
              const result = await sqliteTxContext.run(true, () => fn(self));
              (drizzle as any).run(sql`COMMIT`);
              return result;
            }
            catch (error) {
              (drizzle as any).run(sql`ROLLBACK`);
              throw error;
            }
          };

          const result = sqliteTxChain.then(run, run);
          sqliteTxChain = result.catch(() => undefined);
          return result;
        }

        // PostgreSQL: use Drizzle's native async transaction
        return (drizzle as any).transaction(async (tx: DrizzleDB) => {
          const txAdapter = buildAdapter(tx);
          return fn(txAdapter);
        });
      },
    };

    return self;
  }

  return buildAdapter(db);
}

/** Create a migration-capable SQLite adapter backed by a Drizzle instance. */
export function createSqliteDrizzleAdapter(
  db: DrizzleDB,
  options?: DrizzleAdapterOptions,
): MigratableDatabaseAdapter<'sqlite'> {
  return createDialectDrizzleAdapter(db, 'sqlite', options);
}

/** Create a migration-capable PostgreSQL adapter backed by a Drizzle instance. */
export function createPostgresDrizzleAdapter(
  db: DrizzleDB,
  options?: DrizzleAdapterOptions,
): MigratableDatabaseAdapter<'pg'> {
  return createDialectDrizzleAdapter(db, 'pg', options);
}
