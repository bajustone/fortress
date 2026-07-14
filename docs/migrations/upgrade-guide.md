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
//     pendingVersions, missingTables, missingColumns, missingIndexes }
if (hasMigrationDrift(drift)) throw new Error('Schema drift detected');
```

Pass an explicit `dialect` when the adapter does not advertise one (most
non-Drizzle adapters). Both `migrateUp` and `migrateDown` are idempotent and safe to run on every
deploy. Mutation runs acquire a database-backed lock, re-read the checkpoint
only after locking, and execute transactionally. The engine maintains
`fortress_migration_journal` with one SHA-256 checksum per applied migration;
legacy checkpoints are backfilled once, while later missing or changed rows
fail closed before any schema mutation.

## CLI

```sh
fortress migrate:status
fortress migrate:down
fortress migrate:diff
fortress migrate:check     # exits non-zero on drift; suitable for CI
```

The CLI commands operate on the bundled migration catalog and do **not**
connect to a database. Migration v6 includes a Unicode-aware data step, so
`fortress migrate:up` intentionally refuses to emit SQL-only output that would
skip cleanup. Run the runtime API against your live database from application
code; it executes data steps and constraints atomically using the configured
adapter.

## Drift signals (`detectMigrationDrift`)

| Field | Meaning | Recommended action |
|---|---|---|
| `missingVersionTable` | `fortress_schema_version` does not exist | Run `migrateUp` |
| `pendingVersions` | Migrations the runtime has but the DB has not applied | Run `migrateUp` |
| `unknownFutureVersion` | DB is at a higher version than the bundled migrations | Upgrade the Fortress version before deploying |
| `missingTables` | Any `FORTRESS_TABLES` entry not present in the DB | Run `migrateUp`, or finish the interrupted migration run |
| `missingColumns` | A table that exists but is missing a column the bundled DDL defines | Apply the migration that adds the column (or recreate the table from the bundled DDL) |
| `missingIndexes` | A required hot-path index is absent | Apply the owning migration or restore the named index |

`missingTables`, `missingColumns`, and `missingIndexes` are the deep checks — they catch the
case where the version table claims everything is applied but the schema
is genuinely incomplete (manual DROP, partial restore, a table created
from an older schema dump). Expected columns are parsed straight out of
the bundled migration DDL, so the check works for any adapter — not just
Drizzle. Wire `hasMigrationDrift()` into your deploy preflight and your CI
smoke tests.

## Current migration catalog

Ten migrations ship today:

- **`0001_schema_version`** — installs the schema checkpoint.
- **`0002_initial_schema`** — creates the original Fortress schema.
- **`0003_auth_continuation`** — adds pending-auth/session metadata.
- **`0004_tenant_default_unique`** — enforces one default tenant membership.
- **`0005_hot_indexes_timestamptz`** — adds hot indexes and UTC-safe PostgreSQL timestamps.
- **`0006_canonical_email`** — performs runtime Unicode email cleanup and installs case-insensitive uniqueness.
- **`0007_audit_chain_anchor`** — installs the permanent zero-entry sentinel and persists the terminal audit hash/count so tail or full-chain deletion is detectable.
- **`0008_two_factor_hardening`** — adds durable continuation failure counters, invalidation/cooldown metadata, and the indexed per-account failure lookup used by MFA throttling.
- **`0009_encrypt_totp_secrets`** — removes legacy plaintext TOTP enrolments, backup codes, and trusted devices. SQL cannot encrypt legacy seeds with the application-held key, so affected users must re-enrol; new seeds are stored as AES-256-GCM envelopes.
- **`0010_bigint_append_only_ids`** — widens PostgreSQL identifiers and sequences on unbounded/churn-heavy token, audit, webhook-delivery, and WebAuthn-challenge tables to bigint. SQLite identifiers are already signed 64-bit. Narrowing rollback is intentionally unsupported.

If `fortress_audit_log` already contains rows written without hash chaining, migration 0007 intentionally leaves the anchor at zero; SQL cannot establish a trustworthy cryptographic history. Before serving auth traffic with `auditLog({ hashChain: true })`, archive and externally attest those rows, create the hash-chain-enabled Fortress instance during a maintenance window, and call `await fortress.plugins['audit-log'].rebaselineChain()`. The method transactionally accepts only an uninitialized zero anchor and fully unchained rows, links them deterministically, advances the anchor, and verifies the result. See [Audit Log Plugin](../plugins/audit-log.md#enabling-hash-chaining-on-an-existing-log).

The migrations are the SQL-first source of truth: `src/testing/index.ts`
derives the test adapter's schema from them, and the column-drift checker
parses expected columns from them, so the test adapter and a production
`migrateUp` cannot diverge.

### Provisioning a new database

1. Point Fortress at an empty database (any adapter with `rawQuery`).
2. Call `migrateUp(adapter)` — this creates the checkpoint table, all
   Fortress tables, and stamps `fortress_schema_version` at the latest
   version.
3. Call `detectMigrationDrift(adapter)` to confirm `missingTables` and
   `missingColumns` are empty.

> Drizzle users may still provision tables directly from
> `src/drizzle/{,pg/}schema.ts` if they prefer to own schema management;
> `migrateUp` is idempotent (`CREATE TABLE IF NOT EXISTS`) and will simply
> stamp the version row in that case.

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
(table drops, column drops, type narrowing). The `0001_schema_version`
down step only removes the checkpoint table. **`0002_initial_schema`'s
down step drops every Fortress table** (PostgreSQL uses `CASCADE`), so
rolling back below version 2 is destructive — it deletes all users,
tokens, roles, and audit history. Only do this against a database you
intend to re-provision, and back up first.

## Custom / additional migrations

The bundled catalog covers Fortress-owned tables. Application-owned
tables (e.g. tenant-specific business tables, audit-log partitions) are
out of scope — keep them in your own migration tool of choice. The
adapter's `rawQuery` is available if you need to call into the same DB
connection from your own scripts.
