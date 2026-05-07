import type { Column, SQL, Table } from 'drizzle-orm';
import type { DatabaseAdapter } from '../adapters/database';
import type { WhereClause } from '../adapters/database/types';

import { and, eq, getTableColumns, gt, gte, inArray, like, lt, lte, ne, sql } from 'drizzle-orm';
import { Errors } from '../core/errors';
import { fortressPgSchema } from './pg/schema';
import { fortressSchema } from './schema';

export type DrizzleDialect = 'sqlite' | 'pg' | 'mysql';

export interface DrizzleAdapterOptions {
  /** Override default fortress table definitions with your own Drizzle tables */
  tables?: Partial<Record<string, Table>>;
  /** Database dialect — controls query execution and default table definitions (default: 'sqlite') */
  dialect?: DrizzleDialect;
}

function buildTableMap(schema: typeof fortressSchema | typeof fortressPgSchema): Record<string, Table> {
  return {
    user: schema.users,
    login_identifier: schema.loginIdentifiers,
    refresh_token: schema.refreshTokens,
    group: schema.groups,
    group_user: schema.groupUsers,
    service_account: schema.serviceAccounts,
    resource: schema.resources,
    permission: schema.permissions,
    role: schema.roles,
    role_permission: schema.rolePermissions,
    role_binding: schema.roleBindings,
    direct_permission_binding: schema.directPermissionBindings,
    email_verification_token: schema.emailVerificationTokens,
    magic_link_token: schema.magicLinkTokens,
    api_key: schema.apiKeys,
    two_factor_secret: schema.twoFactorSecrets,
    backup_code: schema.backupCodes,
    trusted_device: schema.trustedDevices,
    social_account: schema.socialAccounts,
    tenant: schema.tenants,
    tenant_user: schema.tenantUsers,
    oauth_client: schema.oauthClients,
    oauth_authorization_code: schema.oauthAuthorizationCodes,
    oauth_access_token: schema.oauthAccessTokens,
    oauth_refresh_token: schema.oauthRefreshTokens,
    oauth_pending_flow: schema.oauthPendingFlows,
    oauth_signing_key: schema.oauthSigningKeys,
    user_scope_assignment: schema.userScopeAssignments,
    account_lockout: schema.accountLockouts,
    audit_log: schema.auditLogs,
    webhook_endpoint: schema.webhookEndpoints,
    webhook_delivery: schema.webhookDeliveries,
    webauthn_credential: schema.webauthnCredentials,
    webauthn_challenge: schema.webauthnChallenges,
  };
}

const SQLITE_DEFAULT_TABLE_MAP = buildTableMap(fortressSchema);
const PG_DEFAULT_TABLE_MAP = buildTableMap(fortressPgSchema);

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
      case 'like':
        return like(column, clause.value as string);
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
  const defaults = dialect === 'pg' ? PG_DEFAULT_TABLE_MAP : SQLITE_DEFAULT_TABLE_MAP;
  const tableMap: Record<string, Table> = { ...defaults, ...(options?.tables as Record<string, Table>) };
  const isSqlite = dialect === 'sqlite';

  /** Execute a query expecting a single row (or undefined). SQLite uses .get(), PG/MySQL awaits the query. */
  async function execOne<T>(query: any): Promise<T | undefined> {
    if (isSqlite)
      return query.get() as T | undefined;
    const rows = await query;
    return (rows as T[])[0];
  }

  /** Execute a query expecting an array of rows. SQLite uses .all(), PG/MySQL awaits the query. */
  async function execMany<T>(query: any): Promise<T[]> {
    if (isSqlite)
      return query.all() as T[];
    return await query as T[];
  }

  /** Execute a query where the result is discarded. SQLite uses .run(), PG/MySQL awaits the query. */
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

  /** Build a DatabaseAdapter backed by a specific Drizzle instance (db or tx) */
  function buildAdapter(drizzle: DrizzleDB): DatabaseAdapter {
    const self: DatabaseAdapter = {
      async create<T>(params: { model: string; data: Record<string, unknown> }): Promise<T> {
        const table = getTable(params.model);
        const result = await execOne<T>((drizzle as any).insert(table).values(sanitizeData(params.data) as any).returning());
        return result as T;
      },

      async findOne<T>(params: { model: string; where: WhereClause[] }): Promise<T | null> {
        const table = getTable(params.model);
        const condition = buildWhereCondition(table, params.where);
        const result = await execOne<T>((drizzle as any).select().from(table).where(condition));
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

        return execMany<T>(query);
      },

      async update<T>(params: { model: string; where: WhereClause[]; data: Record<string, unknown> }): Promise<T | null> {
        const table = getTable(params.model);
        const condition = buildWhereCondition(table, params.where);
        const result = await execOne<T>((drizzle as any).update(table).set(sanitizeData(params.data) as any).where(condition).returning());
        return (result as T) ?? null;
      },

      async delete(params: { model: string; where: WhereClause[] }): Promise<void> {
        const table = getTable(params.model);
        const condition = buildWhereCondition(table, params.where);
        await execRun((drizzle as any).delete(table).where(condition));
      },

      async count(params: { model: string; where?: WhereClause[] }): Promise<number> {
        const table = getTable(params.model);
        let query = (drizzle as any).select({ count: sql<number>`count(*)` }).from(table).$dynamic();

        if (params.where && params.where.length > 0) {
          const condition = buildWhereCondition(table, params.where);
          query = query.where(condition);
        }

        const result = await execOne<{ count: number | string }>(query);
        return Number(result?.count) || 0;
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
