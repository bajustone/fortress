# Fortress migration upgrade guide

This guide is the operational counterpart to the per-release notes under
`docs/migrations/<version>.md`. It describes how to run, verify, and roll
back Fortress migrations across releases.

## Migration sources of truth

- **Bundled migrations:** `migrations/{sqlite,pg}/<version>_<name>.sql`
  and `<version>_<name>.down.sql`. Committed to the repo for review and
  auditability. Mirrored as string constants in
  `src/core/migrations/migrations.ts` so the runtime works without disk
  access (serverless, bundled CLIs).
- **Expected table list:** `FORTRESS_TABLES` in
  `src/core/migrations/migrations.ts`. Drives the live-DB drift checker.
  Kept in sync with `src/drizzle/schema.ts`, `src/drizzle/pg/schema.ts`,
  and `src/testing/index.ts`; the engine test fails if the test adapter
  ever stops creating one of these tables.
- **Schema-version table:** `fortress_schema_version` (single row,
  `id = 1`). The applied baseline is whatever `version` holds; missing
  table means version 0.

## Runtime API

```ts
import {
  detectMigrationDrift,
  getMigrationStatus,
  hasMigrationDrift,
  migrateDown,
  migrateUp,
} from '@bajustone/fortress';

const status = await getMigrationStatus(adapter);
//   { dialect, currentVersion, latestVersion, pending, applied, upToDate, hasVersionTable }

const up = await migrateUp(adapter);
//   { fromVersion, toVersion, applied: FortressMigration[] }

const down = await migrateDown(adapter, 'sqlite', 0);
//   rolls back to version 0

const drift = await detectMigrationDrift(adapter);
//   { currentVersion, latestVersion, missingVersionTable, unknownFutureVersion,
//     pendingVersions, missingTables }
if (hasMigrationDrift(drift)) throw new Error('Schema drift detected');
```

Pass an explicit `dialect` when the adapter does not advertise one (most
non-Drizzle adapters). Both `migrateUp` and `migrateDown` are idempotent
and safe to run on every deploy.

## CLI

```sh
fortress migrate:status
fortress migrate:up
fortress migrate:down
fortress migrate:diff
fortress migrate:check     # exits non-zero on drift; suitable for CI
```

The CLI commands operate on the bundled migration catalog and do **not**
connect to a database — they report what the runtime would apply. Run
the runtime API against your live database from application code (the
CLI cannot access secrets or per-environment connection strings safely).

## Drift signals (`detectMigrationDrift`)

| Field | Meaning | Recommended action |
|---|---|---|
| `missingVersionTable` | `fortress_schema_version` does not exist | Run `migrateUp` |
| `pendingVersions` | Migrations the runtime has but the DB has not applied | Run `migrateUp` |
| `unknownFutureVersion` | DB is at a higher version than the bundled migrations | Upgrade the Fortress version before deploying |
| `missingTables` | Any `FORTRESS_TABLES` entry not present in the DB | Provision the DB from `src/drizzle/schema.ts` / `src/testing/index.ts` or finish the migration run |

`missingTables` is the broadest check — it catches the case where the
version table claims everything is applied but a table is genuinely
missing (manual DROP, partial restore, drizzle-kit catching up). Wire
`hasMigrationDrift()` into your deploy preflight and your CI smoke
tests.

## Current baseline (v0.1.x)

The committed `0001_schema_version` migration only installs the
`fortress_schema_version` table — Fortress tables are still provisioned
from the Drizzle schema definitions (`src/drizzle/{,pg/}schema.ts`) the
first time you deploy. The drift checker reports this state honestly:
on a fresh database with no Fortress tables, `missingTables` lists every
expected table even after `migrateUp` runs.

A full initial-schema migration is in progress — it will be generated
from the Drizzle schemas via `drizzle-kit` so the SQL stays mechanically
in sync with the source of truth. Until then, treat the schema-version
checkpoint as the upgrade marker, not the only thing the drift checker
covers.

### Provisioning a new database today

1. Run your Drizzle schema setup (or `createTestAdapter()` for tests) to
   create the Fortress tables.
2. Call `migrateUp(adapter)` to stamp `fortress_schema_version` at the
   latest bundled version.
3. Call `detectMigrationDrift(adapter)` to confirm `missingTables` is
   empty.

### Upgrading an existing database

1. Pull the new Fortress version.
2. Read the version-specific notes in `docs/migrations/<version>.md` for
   forward/rollback/backfill steps.
3. Call `migrateUp(adapter)` on application start (or in a one-shot
   deploy job).
4. Confirm via `migrate:check` / `hasMigrationDrift()` that the
   database is at the expected version with no missing tables.

## Rollback

`migrateDown(adapter, dialect, targetVersion)` rolls the schema back to
the supplied version (default `0`). Each migration's `.down.sql` is
applied in reverse order. The version row is updated last, so a failed
rollback leaves the previous version recorded — re-run after fixing the
underlying issue.

Always take a backup before rolling back across an irreversible change
(table drops, column drops, type narrowing). The bundled
`0001_schema_version` down step drops the version table; that is safe
because it only removes the checkpoint, not any application data.

## Custom / additional migrations

The bundled catalog covers Fortress-owned tables. Application-owned
tables (e.g. tenant-specific business tables, audit-log partitions) are
out of scope — keep them in your own migration tool of choice. The
adapter's `rawQuery` is available if you need to call into the same DB
connection from your own scripts.
