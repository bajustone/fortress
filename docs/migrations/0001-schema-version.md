# Migration 0001 — Schema version tracking

Introduced: 2026-06-08

## Summary

Adds the `fortress_schema_version` singleton table. Fortress migration tooling uses this table to compare a live database against bundled migrations.

## Forward

SQLite:

```sql
CREATE TABLE IF NOT EXISTS fortress_schema_version (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version INTEGER NOT NULL,
  applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);
```

PostgreSQL:

```sql
CREATE TABLE IF NOT EXISTS fortress_schema_version (
  id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version integer NOT NULL,
  applied_at timestamp NOT NULL DEFAULT now()
);
```

Then insert/update singleton row `id = 1, version = 1`.

## Rollback

```sql
DROP TABLE IF EXISTS fortress_schema_version;
```

## Backfill / cleanup

No data backfill is required. Existing Fortress tables are not modified by this migration.

## Validation

```ts
import { getMigrationStatus } from '@bajustone/fortress';

const status = await getMigrationStatus(fortress.config.database);
console.log(status.currentVersion, status.latestVersion);
```
