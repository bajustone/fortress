import type {
  DatabaseAdapter,
  MigratableDatabaseAdapter,
  MigrateOptions,
} from '@bajustone/fortress';
import {
  createFortress,
  detectMigrationDrift,
  getMigrationStatus,
  migrateDown,
  migrateUp,
} from '@bajustone/fortress';
import * as drizzleEntry from '@bajustone/fortress/drizzle';
import {
  createPostgresDrizzleAdapter,
  createSqliteDrizzleAdapter,
} from '@bajustone/fortress/drizzle';
import { checkMigrationDrift } from '@bajustone/fortress/testing';
import Database from 'better-sqlite3';
import { drizzle as drizzleSqlite } from 'drizzle-orm/better-sqlite3';
import { drizzle as drizzlePostgres } from 'drizzle-orm/postgres-js';
import postgres from 'postgres';

const sqlite = createSqliteDrizzleAdapter(drizzleSqlite(new Database(':memory:')));
const postgresClient = postgres('postgres://user:pass@localhost/database');
const pg = createPostgresDrizzleAdapter(drizzlePostgres(postgresClient));

const sqliteDialect: 'sqlite' = sqlite.dialect;
const pgDialect: 'pg' = pg.dialect;
const sqliteCapability: MigratableDatabaseAdapter<'sqlite'> = sqlite;
const pgCapability: MigratableDatabaseAdapter<'pg'> = pg;
void [sqliteDialect, pgDialect, sqliteCapability, pgCapability];

sqlite.transaction(async (tx) => {
  const dialect: 'sqlite' = tx.dialect;
  await tx.rawQuery('SELECT 1');
  return dialect;
});
pg.transaction(async (tx) => {
  const dialect: 'pg' = tx.dialect;
  await tx.rawQuery('SELECT 1');
  return dialect;
});

void getMigrationStatus(sqlite);
void migrateUp(sqlite);
void migrateUp(sqlite, 5);
void migrateDown(pg);
void migrateDown(pg, 2);
void detectMigrationDrift(pg);
void checkMigrationDrift(sqlite);

// The ambiguous factory was removed; callers must choose a dialect-specific factory.
// @ts-expect-error createDrizzleAdapter is intentionally absent from the public entrypoint
void drizzleEntry.createDrizzleAdapter;

declare const crudOnly: DatabaseAdapter;
createFortress({ database: crudOnly, jwt: { key: 'x'.repeat(32) } });
// @ts-expect-error standalone migration APIs require dialect and rawQuery capabilities
void getMigrationStatus(crudOnly);
// @ts-expect-error standalone migration APIs require dialect and rawQuery capabilities
void migrateUp(crudOnly);
// @ts-expect-error standalone migration APIs require dialect and rawQuery capabilities
void migrateDown(crudOnly);
// @ts-expect-error standalone migration APIs require dialect and rawQuery capabilities
void detectMigrationDrift(crudOnly);
// @ts-expect-error standalone migration checks require dialect and rawQuery capabilities
void checkMigrationDrift(crudOnly);

const migrateOptions: MigrateOptions = {
  targetVersion: 5,
  // @ts-expect-error migration dialect is derived exclusively from the adapter
  dialect: 'pg',
};
void migrateOptions;
