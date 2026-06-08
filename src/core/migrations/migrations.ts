export type MigrationDialect = 'sqlite' | 'pg';

export interface FortressMigration {
  version: number;
  name: string;
  dialect: MigrationDialect;
  up: string;
  down: string;
}

const SQLITE_0001_UP = `
CREATE TABLE IF NOT EXISTS fortress_schema_version (
  id INTEGER PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version INTEGER NOT NULL,
  applied_at INTEGER NOT NULL DEFAULT (unixepoch())
);

INSERT INTO fortress_schema_version (id, version, applied_at)
VALUES (1, 1, unixepoch())
ON CONFLICT(id) DO UPDATE SET version = max(fortress_schema_version.version, excluded.version), applied_at = excluded.applied_at;
`.trim();

const SQLITE_0001_DOWN = `
DROP TABLE IF EXISTS fortress_schema_version;
`.trim();

const PG_0001_UP = `
CREATE TABLE IF NOT EXISTS fortress_schema_version (
  id integer PRIMARY KEY DEFAULT 1 CHECK (id = 1),
  version integer NOT NULL,
  applied_at timestamp NOT NULL DEFAULT now()
);

INSERT INTO fortress_schema_version (id, version, applied_at)
VALUES (1, 1, now())
ON CONFLICT (id) DO UPDATE SET version = greatest(fortress_schema_version.version, excluded.version), applied_at = excluded.applied_at;
`.trim();

const PG_0001_DOWN = `
DROP TABLE IF EXISTS fortress_schema_version;
`.trim();

export const fortressMigrations: Record<MigrationDialect, FortressMigration[]> = {
  sqlite: [
    { version: 1, name: 'schema_version', dialect: 'sqlite', up: SQLITE_0001_UP, down: SQLITE_0001_DOWN },
  ],
  pg: [
    { version: 1, name: 'schema_version', dialect: 'pg', up: PG_0001_UP, down: PG_0001_DOWN },
  ],
};

export function getFortressMigrations(dialect: MigrationDialect): FortressMigration[] {
  return [...fortressMigrations[dialect]].sort((a, b) => a.version - b.version);
}

export function getLatestMigrationVersion(dialect: MigrationDialect): number {
  return getFortressMigrations(dialect).at(-1)?.version ?? 0;
}

/**
 * Canonical list of every Fortress-owned table. Used by
 * {@link detectMigrationDrift} to surface live-DB drift beyond just the
 * `fortress_schema_version` checkpoint — any of these tables missing in
 * the target database signals an incomplete or stale migration state.
 *
 * Keep in sync with `src/drizzle/{schema,pg/schema}.ts` and
 * `src/testing/index.ts`. The list is asserted by
 * `src/core/migrations/engine.test.ts` against the test adapter so an
 * accidental drop/add is caught at test time.
 */
export const FORTRESS_TABLES: readonly string[] = [
  'fortress_schema_version',
  'fortress_user',
  'fortress_login_identifier',
  'fortress_refresh_token',
  'fortress_group',
  'fortress_group_user',
  'fortress_service_account',
  'fortress_resource',
  'fortress_permission',
  'fortress_role',
  'fortress_role_permission',
  'fortress_role_binding',
  'fortress_direct_permission_binding',
  'fortress_email_verification_token',
  'fortress_magic_link_token',
  'fortress_api_key',
  'fortress_two_factor_secret',
  'fortress_backup_code',
  'fortress_trusted_device',
  'fortress_social_account',
  'fortress_tenant',
  'fortress_tenant_user',
  'fortress_oauth_client',
  'fortress_oauth_authorization_code',
  'fortress_oauth_access_token',
  'fortress_oauth_refresh_token',
  'fortress_oauth_pending_flow',
  'fortress_oauth_signing_key',
  'fortress_user_scope_assignment',
  'fortress_account_lockout',
  'fortress_audit_log',
  'fortress_webhook_endpoint',
  'fortress_webhook_delivery',
  'fortress_webauthn_credential',
  'fortress_webauthn_challenge',
] as const;
