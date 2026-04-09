/**
 * PostgreSQL-flavoured fortress Drizzle schema.
 *
 * Exposes {@link fortressPgSchema}, the aggregate of every fortress table
 * defined with `pgTable`. Pass it (or your own override) to drizzle-kit for
 * migration generation. The fortress drizzle adapter consumes tables
 * generically, so you typically don't need to import this directly unless
 * you're generating migrations.
 *
 * @module
 */

export { fortressPgSchema } from './schema';
