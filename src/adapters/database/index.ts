import type { WhereClause } from './types';

export type { CoreOperator, ScopeRule, WhereClause } from './types';

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

  update: <T>(params: {
    model: string;
    where: WhereClause[];
    data: Record<string, unknown>;
  }) => Promise<T>;

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
   */
  rawQuery?: <T>(sql: string, params?: unknown[]) => Promise<T[]>;
}
