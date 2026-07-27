import { mkdir, mkdtemp, readdir, readFile, rm, symlink, writeFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';
import {
  checkMigrationArtifacts,
  generateMigrationArtifacts,
  hasMigrationArtifactDrift,
} from './artifact-files';
import {
  getExpectedMigrationArtifacts,
  renderMigrationArtifact,
  renderMigrationSqlExport,
} from './artifacts';
import { getFortressMigrations } from './migrations';

const temporaryRoots: string[] = [];

async function temporaryRoot(): Promise<string> {
  const root = await mkdtemp(resolve(tmpdir(), 'fortress-migrations-'));
  temporaryRoots.push(root);
  return root;
}

afterEach(async () => {
  await Promise.all(temporaryRoots.splice(0).map(root => rm(root, { recursive: true, force: true })));
});

describe('migration SQL artifacts', () => {
  it('renders the complete deterministic catalog projection', () => {
    const artifacts = getExpectedMigrationArtifacts();
    expect(artifacts.size).toBe(40);
    expect([...artifacts.keys()]).toEqual([
      ...[...artifacts.keys()].filter(path => path.startsWith('migrations/pg/')),
      ...[...artifacts.keys()].filter(path => path.startsWith('migrations/sqlite/')),
    ]);

    const migration = getFortressMigrations('sqlite')[5]!;
    const rendered = renderMigrationArtifact(migration, 'up');
    expect(rendered).toBe([
      '-- Generated from src/core/migrations/migrations.ts by `bun run generate:migrations`; DO NOT EDIT.',
      '-- dialect: sqlite',
      '-- version: 0006',
      '-- name: canonical_email',
      '-- direction: up',
      '-- runtime-data-step: normalize-email-v2',
      '-- WARNING: this SQL does not perform the runtime data step; use `fortress migrate:up --module <path>`.',
      '',
      migration.up,
      '',
    ].join('\n'));
    expect(rendered.endsWith(`${migration.up}\n`)).toBe(true);
    expect(rendered).toContain('INSERT INTO fortress_email_migration_ready');
    expect(renderMigrationArtifact(migration, 'down')).not.toContain('runtime-data-step');
  });

  it('exports up in ascending order and down in descending order', () => {
    const up = renderMigrationSqlExport('pg', 'up');
    const down = renderMigrationSqlExport('pg', 'down');
    expect(up.indexOf('-- version: 0001')).toBeLessThan(up.indexOf('-- version: 0010'));
    expect(down.indexOf('-- version: 0010')).toBeLessThan(down.indexOf('-- version: 0001'));
    expect(up).toContain('-- runtime-data-step: normalize-email-v2');
  });

  it('rejects symlinked managed directories without writing outside the root', async () => {
    for (const managedPath of ['migrations', 'migrations/sqlite']) {
      const root = await temporaryRoot();
      const external = await temporaryRoot();
      if (managedPath.includes('/'))
        await mkdir(resolve(root, 'migrations'));
      await symlink(external, resolve(root, managedPath), 'dir');

      await expect(checkMigrationArtifacts(root)).rejects.toThrow('must not be a symlink');
      await expect(generateMigrationArtifacts(root)).rejects.toThrow('must not be a symlink');
      expect(await readdir(external)).toEqual([]);
    }
  });

  it('replaces an artifact symlink without modifying its target', async () => {
    const root = await temporaryRoot();
    const external = await temporaryRoot();
    await generateMigrationArtifacts(root);
    const path = [...getExpectedMigrationArtifacts().keys()][0]!;
    const target = resolve(external, 'target.sql');
    await writeFile(target, '-- external\n');
    await rm(resolve(root, path));
    await symlink(target, resolve(root, path));

    expect((await checkMigrationArtifacts(root)).mismatched).toContain(path);
    await generateMigrationArtifacts(root);
    expect(await readFile(target, 'utf8')).toBe('-- external\n');
    expect(await readFile(resolve(root, path), 'utf8')).toBe(getExpectedMigrationArtifacts().get(path));
  });

  it('generates idempotently and classifies missing, mismatched, and extra files', async () => {
    const root = await temporaryRoot();
    await generateMigrationArtifacts(root);
    expect(hasMigrationArtifactDrift(await checkMigrationArtifacts(root))).toBe(false);

    const expected = getExpectedMigrationArtifacts();
    const [missing, mismatched] = [...expected.keys()];
    const preserved = await readFile(resolve(root, mismatched!), 'utf8');
    await rm(resolve(root, missing!));
    await writeFile(resolve(root, mismatched!), `${preserved}-- mutation\n`);
    await writeFile(resolve(root, 'migrations/sqlite/9999_extra.sql'), '-- extra\n');

    const drift = await checkMigrationArtifacts(root);
    expect(drift).toEqual({
      missing: [missing],
      mismatched: [mismatched],
      extra: ['migrations/sqlite/9999_extra.sql'],
    });
    expect(await readFile(resolve(root, mismatched!), 'utf8')).toBe(`${preserved}-- mutation\n`);

    await generateMigrationArtifacts(root);
    expect(hasMigrationArtifactDrift(await checkMigrationArtifacts(root))).toBe(false);
    expect(await readFile(resolve(root, mismatched!), 'utf8')).toBe(preserved);
    await generateMigrationArtifacts(root);
    expect(hasMigrationArtifactDrift(await checkMigrationArtifacts(root))).toBe(false);
  });
});
