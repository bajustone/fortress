import type { WhereClause } from './types';

export type { CoreOperator, ScopeRule, WhereClause } from './types';

/**
 * Generic CRUD database adapter interface fortress uses to talk to any
 * datastore. Implement seven required methods (create, findOne, findMany,
 * update, delete, count, transaction) and optionally `rawQuery` for
 * performance-critical multi-table operations.
 */
export interface DatabaseAdapter {
  create: <T>(params: {
    model: string;
    data: Record<string, unknown>;
  }) => Promise<T>;

  findOne: <T>(params: {
    model: string;
    where: WhereClause[];
  }) => Promise<T | null>;

  findMany: <T>(params: {
    model: string;
    where?: WhereClause[];
    limit?: number;
    offset?: number;
    sortBy?: { field: string; direction: 'asc' | 'desc' };
  }) => Promise<T[]>;

  /**
   * Update rows matching the where clause.
   * Returns the updated row, or null if no rows matched the where clause.
   */
  update: <T>(params: {
    model: string;
    where: WhereClause[];
    data: Record<string, unknown>;
  }) => Promise<T | null>;

  delete: (params: {
    model: string;
    where: WhereClause[];
  }) => Promise<void>;

  count: (params: {
    model: string;
    where?: WhereClause[];
  }) => Promise<number>;

  transaction: <T>(fn: (tx: DatabaseAdapter) => Promise<T>) => Promise<T>;

  /**
   * Optional: raw query for performance-critical multi-table operations.
   *  Adapters that implement this get optimized IAM queries.
   *  Others fall back to multiple findMany calls.
   *  @param sql SQL string using `?` positional placeholders on every dialect
   *  @param params Positional parameters matching the `?` placeholders
   */
  rawQuery?: <T>(sql: string, params?: unknown[]) => Promise<T[]>;

  /** Database dialect hint for adapters that implement rawQuery */
  readonly dialect?: 'sqlite' | 'pg';
}
