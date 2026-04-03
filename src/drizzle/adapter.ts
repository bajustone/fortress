import type { BaseSQLiteDatabase, SQLiteColumn, SQLiteTableWithColumns } from 'drizzle-orm/sqlite-core';
import type { DatabaseAdapter } from '../adapters/database';
import type { WhereClause } from '../adapters/database/types';

import { and, eq, gt, gte, inArray, lt, lte, ne, sql } from 'drizzle-orm';
import { Errors } from '../core/errors';
import { fortressSchema } from './schema';

type DrizzleDb = BaseSQLiteDatabase<'sync' | 'async', unknown, Record<string, unknown>>;

// Map model names to their Drizzle table definitions
const MODEL_TABLE_MAP: Record<string, SQLiteTableWithColumns<any>> = {
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
};

function getTable(model: string): SQLiteTableWithColumns<any> {
  const table = MODEL_TABLE_MAP[model];
  if (!table) {
    throw Errors.badRequest(`Unknown model: ${model}`);
  }
  return table;
}

function getColumn(table: SQLiteTableWithColumns<any>, field: string): SQLiteColumn {
  const columns = table as unknown as Record<string, SQLiteColumn>;
  // Try exact match first, then camelCase conversion
  if (columns[field])
    return columns[field];

  // Convert snake_case field names to camelCase column references
  const camelCase = field.replace(/_([a-z])/g, (_, c) => c.toUpperCase());
  if (columns[camelCase])
    return columns[camelCase];

  throw Errors.badRequest(`Unknown field: ${field} on table`);
}

function buildWhereCondition(table: SQLiteTableWithColumns<any>, where: WhereClause[]): ReturnType<typeof and> {
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
 * Converts Date → ISO string, boolean �� 0/1.
 */
function sanitizeData(data: Record<string, unknown>): Record<string, unknown> {
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
 * Create a DatabaseAdapter backed by a Drizzle SQLite instance.
 * Works with bun:sqlite (in-memory or file), better-sqlite3, etc.
 */
export function createDrizzleAdapter(db: DrizzleDb): DatabaseAdapter {
  const adapter: DatabaseAdapter = {
    async create<T>(params: { model: string; data: Record<string, unknown> }): Promise<T> {
      const table = getTable(params.model);
      const result = db.insert(table).values(sanitizeData(params.data) as any).returning().get();
      return result as T;
    },

    async findOne<T>(params: { model: string; where: WhereClause[] }): Promise<T | null> {
      const table = getTable(params.model);
      const condition = buildWhereCondition(table, params.where);
      const result = db.select().from(table).where(condition).get();
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
      let query = db.select().from(table).$dynamic();

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

    async update<T>(params: { model: string; where: WhereClause[]; data: Record<string, unknown> }): Promise<T> {
      const table = getTable(params.model);
      const condition = buildWhereCondition(table, params.where);
      const result = db.update(table).set(sanitizeData(params.data) as any).where(condition).returning().get();
      return result as T;
    },

    async delete(params: { model: string; where: WhereClause[] }): Promise<void> {
      const table = getTable(params.model);
      const condition = buildWhereCondition(table, params.where);
      db.delete(table).where(condition).run();
    },

    async count(params: { model: string; where?: WhereClause[] }): Promise<number> {
      const table = getTable(params.model);
      let query = db.select({ count: sql<number>`count(*)` }).from(table).$dynamic();

      if (params.where && params.where.length > 0) {
        const condition = buildWhereCondition(table, params.where);
        query = query.where(condition);
      }

      const result = query.get();
      return (result as any)?.count ?? 0;
    },

    async transaction<T>(fn: (tx: DatabaseAdapter) => Promise<T>): Promise<T> {
      // SQLite transactions in Drizzle use db.transaction()
      // For simplicity, we run within the same connection (SQLite is single-writer)
      return fn(adapter);
    },
  };

  return adapter;
}
