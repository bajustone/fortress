# Migration 0002 — Initial Fortress schema

Introduced: 2026-06-08

## Summary

Creates every Fortress-owned table, index, and constraint — everything
except the `fortress_schema_version` checkpoint installed by `0001`. This
is the baseline that lets `migrateUp` provision a brand-new database
(SQLite or PostgreSQL) end-to-end through the adapter's `rawQuery`, with
no Drizzle or `drizzle-kit` dependency at runtime.

The migration is the SQL-first source of truth for the schema:

- `src/testing/index.ts` builds the in-memory test adapter from this DDL.
- The column-drift checker (`detectMigrationDrift`) parses expected
  columns out of this DDL.

So the test adapter and a production `migrateUp` cannot drift.

## Forward

Run via the migration runner (recommended — it also stamps the version
row):

```ts
import { migrateUp } from '@bajustone/fortress';

await migrateUp(adapter); // applies 0001 + 0002, stamps version 2
```

Or apply the bundled SQL directly:

- SQLite: `migrations/sqlite/0002_initial_schema.sql`
- PostgreSQL: `migrations/pg/0002_initial_schema.sql`

All statements are `CREATE TABLE IF NOT EXISTS` / `CREATE [UNIQUE] INDEX
IF NOT EXISTS`, so applying it to a database that already has the Fortress
tables (e.g. provisioned from the Drizzle schema) is a no-op.

## Rollback

```ts
import { migrateDown } from '@bajustone/fortress';

await migrateDown(adapter, 1); // roll back to version 1
```

Or apply `migrations/{sqlite,pg}/0002_initial_schema.down.sql`.

> **Destructive.** The down step drops every Fortress table (PostgreSQL
> uses `CASCADE`). It deletes all users, tokens, roles, and audit history.
> Back up first and only do this on a database you intend to re-provision.

## Backfill / cleanup

None. On a fresh database this is the initial install. On a database whose
tables were already provisioned from the Drizzle schema, the forward step
is a no-op and only the version row changes.

## Migrating from a pre-0002 database

If you deployed an earlier Fortress version and provisioned tables from
the Drizzle schema (the previous documented path):

1. Pull this version.
2. Run `migrateUp(adapter)`. The `IF NOT EXISTS` guards mean existing
   tables are left untouched; the version row advances to 2.
3. Run `detectMigrationDrift(adapter)` and confirm both `missingTables`
   and `missingColumns` are empty. If `missingColumns` is non-empty, your
   tables predate a column added in a later schema change — apply the
   listed columns (the bundled DDL is the reference) and re-check.

## Validation

```ts
import { detectMigrationDrift, getMigrationStatus, hasMigrationDrift } from '@bajustone/fortress';

const status = await getMigrationStatus(adapter);
console.log(status.currentVersion, status.latestVersion); // 2 2

const drift = await detectMigrationDrift(adapter);
console.log(hasMigrationDrift(drift)); // false
```
