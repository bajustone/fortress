import type { Column, SQL, Table } from 'drizzle-orm';
import type { DatabaseAdapter } from '../adapters/database';
import type { WhereClause } from '../adapters/database/types';

import { and, eq, getTableColumns, gt, gte, inArray, lt, lte, ne, sql } from 'drizzle-orm';
import { Errors } from '../core/errors';
import { fortressSchema } from './schema';

export type DrizzleDialect = 'sqlite' | 'pg' | 'mysql';

export interface DrizzleAdapterOptions {
  /** Override default fortress table definitions with your own Drizzle tables */
  tables?: Partial<Record<string, Table>>;
  /** Database dialect — controls data sanitization (default: 'sqlite') */
  dialect?: DrizzleDialect;
}

// Default model-to-table mapping (SQLite fortress tables)
const DEFAULT_TABLE_MAP: Record<string, Table> = {
  user: fortressSchema.users,
  login_identifier: fortressSchema.loginIdentifiers,
  refresh_token: fortressSchema.refreshTokens,
  group: fortressSchema.groups,
  group_user: fortressSchema.groupUsers,
  resource: fortressSchema.resources,
  permission: fortressSchema.permissions,
  role: fortressSchema.roles,
  role_permission: fortressSchema.rolePermissions,
  role_binding: fortressSchema.roleBindings,
  email_verification_token: fortressSchema.emailVerificationTokens,
  api_key: fortressSchema.apiKeys,
  two_factor_secret: fortressSchema.twoFactorSecrets,
  backup_code: fortressSchema.backupCodes,
  trusted_device: fortressSchema.trustedDevices,
  social_account: fortressSchema.socialAccounts,
};

function getColumn(table: Table, field: string): Column {
  const columns = getTableColumns(table);
  // Try exact match first
  if (columns[field])
    return columns[field];

  // Convert snake_case field names to camelCase column references
  const camelCase = field.replace(/_([a-z])/g, (_, c: string) => c.toUpperCase());
  if (columns[camelCase])
    return columns[camelCase];

  throw Errors.badRequest(`Unknown field: ${field} on table`);
}

function buildWhereCondition(table: Table, where: WhereClause[]): SQL | undefined {
  const conditions = where.map((clause) => {
    const column = getColumn(table, clause.field);

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
      default:
        throw Errors.badRequest(`Unsupported operator: ${clause.operator}`);
    }
  });

  return conditions.length === 1 ? conditions[0] : and(...conditions);
}

/**
 * Sanitize data values for SQLite compatibility.
 * SQLite doesn't support Date objects or booleans natively.
 * PostgreSQL and MySQL handle them fine — skip sanitization for those dialects.
 */
function sanitizeForSqlite(data: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(data)) {
    if (value instanceof Date) {
      result[key] = value.toISOString();
    }
    else if (typeof value === 'boolean') {
      result[key] = value ? 1 : 0;
    }
    else if (value === undefined) {
      result[key] = null;
    }
    else {
      result[key] = value;
    }
  }
  return result;
}

/**
 * Minimal Drizzle DB interface — accepts any Drizzle database instance.
 * Drizzle DB types vary by dialect (BunSQLiteDatabase, PostgresJsDatabase, etc.)
 * so we use a loose structural type rather than importing a specific one.
 */
// eslint-disable-next-line ts/no-unsafe-function-type -- Drizzle DB methods have dialect-specific signatures
interface DrizzleDB { insert: Function; select: Function; update: Function; delete: Function; transaction: Function }

/**
 * Create a DatabaseAdapter backed by any Drizzle instance.
 * Works with PostgreSQL, MySQL, and SQLite (bun:sqlite, better-sqlite3).
 *
 * @param db - Any Drizzle database instance
 * @param options - Optional table overrides and dialect configuration
 */
export function createDrizzleAdapter(db: DrizzleDB, options?: DrizzleAdapterOptions): DatabaseAdapter {
  const dialect = options?.dialect ?? 'sqlite';
  const tableMap: Record<string, Table> = { ...DEFAULT_TABLE_MAP, ...(options?.tables as Record<string, Table>) };
  const sanitize = dialect === 'sqlite' ? sanitizeForSqlite : (d: Record<string, unknown>) => d;

  function getTable(model: string): Table {
    const table = tableMap[model];
    if (!table) {
      throw Errors.badRequest(`Unknown model: ${model}`);
    }
    return table;
  }

  /** Build a DatabaseAdapter backed by a specific Drizzle instance (db or tx) */
  function buildAdapter(drizzle: DrizzleDB): DatabaseAdapter {
    const self: DatabaseAdapter = {
      async create<T>(params: { model: string; data: Record<string, unknown> }): Promise<T> {
        const table = getTable(params.model);
        const result = (drizzle as any).insert(table).values(sanitize(params.data) as any).returning().get();
        return result as T;
      },

      async findOne<T>(params: { model: string; where: WhereClause[] }): Promise<T | null> {
        const table = getTable(params.model);
        const condition = buildWhereCondition(table, params.where);
        const result = (drizzle as any).select().from(table).where(condition).get();
        return (result as T) ?? null;
      },

      async findMany<T>(params: {
        model: string;
        where?: WhereClause[];
        limit?: number;
        offset?: number;
        sortBy?: { field: string; direction: 'asc' | 'desc' };
      }): Promise<T[]> {
        const table = getTable(params.model);
        let query = (drizzle as any).select().from(table).$dynamic();

        if (params.where && params.where.length > 0) {
          const condition = buildWhereCondition(table, params.where);
          query = query.where(condition);
        }

        if (params.sortBy) {
          const column = getColumn(table, params.sortBy.field);
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

        return query.all() as T[];
      },

      /** @see DatabaseAdapter.update for no-match behavior documentation */
      async update<T>(params: { model: string; where: WhereClause[]; data: Record<string, unknown> }): Promise<T> {
        const table = getTable(params.model);
        const condition = buildWhereCondition(table, params.where);
        const result = (drizzle as any).update(table).set(sanitize(params.data) as any).where(condition).returning().get();
        return result as T;
      },

      async delete(params: { model: string; where: WhereClause[] }): Promise<void> {
        const table = getTable(params.model);
        const condition = buildWhereCondition(table, params.where);
        (drizzle as any).delete(table).where(condition).run();
      },

      async count(params: { model: string; where?: WhereClause[] }): Promise<number> {
        const table = getTable(params.model);
        let query = (drizzle as any).select({ count: sql<number>`count(*)` }).from(table).$dynamic();

        if (params.where && params.where.length > 0) {
          const condition = buildWhereCondition(table, params.where);
          query = query.where(condition);
        }

        const result = query.get();
        return (result as any)?.count ?? 0;
      },

      async transaction<T>(fn: (tx: DatabaseAdapter) => Promise<T>): Promise<T> {
        if (dialect === 'sqlite') {
          // SQLite (better-sqlite3, bun:sqlite) transactions are synchronous.
          // Drizzle's SQLite .transaction() doesn't support async callbacks.
          // We use a manual BEGIN/COMMIT/ROLLBACK approach for async compatibility.
          (drizzle as any).run(sql`BEGIN`);
          try {
            const result = await fn(self);
            (drizzle as any).run(sql`COMMIT`);
            return result;
          }
          catch (error) {
            (drizzle as any).run(sql`ROLLBACK`);
            throw error;
          }
        }

        // PostgreSQL/MySQL: use Drizzle's native async transaction
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
