import { lstat, mkdir, readdir, readFile, rename, rm, writeFile } from 'node:fs/promises';
import { dirname, relative, resolve, sep } from 'node:path';
import { getExpectedMigrationArtifacts } from './artifacts';

export interface MigrationArtifactDrift {
  missing: string[];
  mismatched: string[];
  extra: string[];
}

function toPosix(path: string): string {
  return path.split(sep).join('/');
}

async function assertManagedDirectoriesAreSafe(root: string): Promise<void> {
  for (const path of ['migrations', 'migrations/pg', 'migrations/sqlite']) {
    const absolute = resolve(root, path);
    try {
      const stats = await lstat(absolute);
      if (stats.isSymbolicLink())
        throw new Error(`Managed migration path must not be a symlink: ${path}`);
      if (!stats.isDirectory())
        throw new Error(`Managed migration path must be a directory: ${path}`);
    }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT')
        throw error;
    }
  }
}

async function scanSqlFiles(
  root: string,
  directory: string,
  files: Set<string>,
  symlinks: Set<string>,
): Promise<void> {
  let entries;
  try {
    entries = await readdir(directory, { withFileTypes: true });
  }
  catch (error) {
    if ((error as NodeJS.ErrnoException).code === 'ENOENT')
      return;
    throw error;
  }
  for (const entry of entries) {
    const absolute = resolve(directory, entry.name);
    const path = toPosix(relative(root, absolute));
    if (entry.isSymbolicLink()) {
      if (entry.name.endsWith('.sql')) {
        files.add(path);
        symlinks.add(path);
      }
      continue;
    }
    if (entry.isDirectory()) {
      await scanSqlFiles(root, absolute, files, symlinks);
    }
    else if (entry.isFile() && entry.name.endsWith('.sql')) {
      files.add(path);
    }
  }
}

export async function checkMigrationArtifacts(root: string): Promise<MigrationArtifactDrift> {
  await assertManagedDirectoriesAreSafe(root);
  const expected = getExpectedMigrationArtifacts();
  const actual = new Set<string>();
  const symlinks = new Set<string>();
  await scanSqlFiles(root, resolve(root, 'migrations'), actual, symlinks);

  const missing: string[] = [];
  const mismatched: string[] = [];
  for (const [path, content] of expected) {
    if (!actual.has(path)) {
      missing.push(path);
      continue;
    }
    if (symlinks.has(path)) {
      mismatched.push(path);
      continue;
    }
    const current = await readFile(resolve(root, path), 'utf8');
    if (current !== content)
      mismatched.push(path);
  }
  const extra = [...actual].filter(path => !expected.has(path));
  return {
    missing: missing.sort(),
    mismatched: mismatched.sort(),
    extra: extra.sort(),
  };
}

export function hasMigrationArtifactDrift(drift: MigrationArtifactDrift): boolean {
  return drift.missing.length > 0 || drift.mismatched.length > 0 || drift.extra.length > 0;
}

export async function generateMigrationArtifacts(root: string): Promise<void> {
  const expected = getExpectedMigrationArtifacts();
  const drift = await checkMigrationArtifacts(root);
  for (const path of drift.extra)
    await rm(resolve(root, path), { force: true });

  for (const [path, content] of expected) {
    const absolute = resolve(root, path);
    let unchanged = false;
    try {
      const stats = await lstat(absolute);
      unchanged = stats.isFile() && !stats.isSymbolicLink()
        && await readFile(absolute, 'utf8') === content;
      if (!unchanged && stats.isSymbolicLink())
        await rm(absolute, { force: true });
    }
    catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'ENOENT')
        throw error;
    }
    if (unchanged)
      continue;
    await mkdir(dirname(absolute), { recursive: true });
    const temporary = `${absolute}.tmp-${process.pid}-${crypto.randomUUID()}`;
    await writeFile(temporary, content, 'utf8');
    await rename(temporary, absolute);
  }
}
