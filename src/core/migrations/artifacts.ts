import type { FortressMigration, MigrationDialect } from './migrations';
import { getFortressMigrations } from './migrations';

export type MigrationArtifactDirection = 'up' | 'down';

const ARTIFACT_DIALECTS = ['pg', 'sqlite'] as const satisfies readonly MigrationDialect[];
const SAFE_MIGRATION_NAME_RE = /^[a-z0-9][a-z0-9_]*$/;

function versionLabel(version: number): string {
  return String(version).padStart(4, '0');
}

function validateMigration(migration: FortressMigration, dialect: MigrationDialect): void {
  if (migration.dialect !== dialect)
    throw new Error(`Migration ${migration.version} dialect does not match catalog '${dialect}'`);
  if (!Number.isSafeInteger(migration.version) || migration.version <= 0)
    throw new Error(`Migration version must be a positive safe integer: ${migration.version}`);
  if (!SAFE_MIGRATION_NAME_RE.test(migration.name))
    throw new Error(`Unsafe migration name '${migration.name}'`);
  if (!migration.up.trim() || !migration.down.trim())
    throw new Error(`Migration ${migration.version} (${migration.name}) is missing up/down SQL`);
  if (migration.beforeUp && !migration.dataStep)
    throw new Error(`Migration ${migration.version} (${migration.name}) must name its runtime data step`);
}

export function migrationArtifactPath(
  migration: FortressMigration,
  direction: MigrationArtifactDirection,
): string {
  const suffix = direction === 'down' ? '.down.sql' : '.sql';
  return `migrations/${migration.dialect}/${versionLabel(migration.version)}_${migration.name}${suffix}`;
}

/** Render one deterministic, reviewable projection of the runtime migration catalog. */
export function renderMigrationArtifact(
  migration: FortressMigration,
  direction: MigrationArtifactDirection,
): string {
  validateMigration(migration, migration.dialect);
  const lines = [
    '-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.',
    `-- dialect: ${migration.dialect}`,
    `-- version: ${versionLabel(migration.version)}`,
    `-- name: ${migration.name}`,
    `-- direction: ${direction}`,
  ];
  if (direction === 'up' && migration.dataStep) {
    lines.push(
      `-- runtime-data-step: ${migration.dataStep}`,
      '-- WARNING: this SQL does not perform the runtime data step; use `fortress migrate:up --module <path>`.',
    );
  }
  const sql = direction === 'up' ? migration.up : migration.down;
  return `${lines.join('\n')}\n\n${sql}\n`;
}

/** Complete expected artifact path/content set for every bundled dialect. */
export function getExpectedMigrationArtifacts(): ReadonlyMap<string, string> {
  const artifacts = new Map<string, string>();
  for (const dialect of ARTIFACT_DIALECTS) {
    const versions = new Set<number>();
    for (const migration of getFortressMigrations(dialect)) {
      validateMigration(migration, dialect);
      if (versions.has(migration.version))
        throw new Error(`Duplicate migration version ${migration.version} for ${dialect}`);
      versions.add(migration.version);
      for (const direction of ['up', 'down'] as const) {
        const path = migrationArtifactPath(migration, direction);
        if (artifacts.has(path))
          throw new Error(`Duplicate migration artifact path '${path}'`);
        artifacts.set(path, renderMigrationArtifact(migration, direction));
      }
    }
  }
  return artifacts;
}

/** Render an offline SQL review bundle. It is not a substitute for runtime data steps. */
export function renderMigrationSqlExport(
  dialect: MigrationDialect,
  direction: MigrationArtifactDirection,
): string {
  const migrations = getFortressMigrations(dialect);
  const ordered = direction === 'up' ? migrations : [...migrations].reverse();
  return ordered.map(migration => renderMigrationArtifact(migration, direction)).join('\n');
}
