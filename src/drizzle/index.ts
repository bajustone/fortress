/**
 * Drizzle ORM adapter for fortress.
 *
 * Works with any Drizzle database instance — PostgreSQL, MySQL, or SQLite.
 * Use the SQLite-flavoured `fortressSchema` aggregate for SQLite, or import
 * `@bajustone/fortress/drizzle/pg` for the PostgreSQL flavour. Tables are
 * exported via the aggregate (typed as `Record<string, AnySQLiteTable>`) so
 * the public API stays statically typed for JSR; consumers who want
 * column-level inference should declare their own Drizzle schema and pass it
 * via the `tables` option.
 *
 * @example
 * ```ts
 * import { drizzle } from 'drizzle-orm/postgres-js';
 * import { createDrizzleAdapter } from '@bajustone/fortress/drizzle';
 *
 * const db = drizzle(sql);
 * const adapter = createDrizzleAdapter(db, { dialect: 'pg' });
 * ```
 *
 * @module
 */

export { createDrizzleAdapter } from './adapter';
export type { DrizzleAdapterOptions, DrizzleDialect } from './adapter';
export { findSqlstate, rethrowPgError } from './pg-error-map';
// Re-export only the schema objects — individual table exports cause JSR "slow types"
// errors because sqliteTable()/pgTable() return types are too complex for JSR to infer.
// Consumers access tables via: fortressSchema.users, fortressPgSchema.roles, etc.
export { fortressPgSchema } from './pg/schema';
export { fortressSchema } from './schema';
