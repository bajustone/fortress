import { spawnSync } from 'node:child_process';
import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import {
  collectStringLeaves,
  isForbiddenProjectPath,
  normalizePath,
} from './publication-policy.mjs';

export function readJson(path) {
  return JSON.parse(readFileSync(path, 'utf8'));
}

function listFiles(directory, root, files) {
  for (const entry of readdirSync(directory, { withFileTypes: true })) {
    const absolute = join(directory, entry.name);
    if (entry.isDirectory())
      listFiles(absolute, root, files);
    else if (entry.isFile())
      files.push(normalizePath(relative(root, absolute)));
  }
}

// Derived from the migration definitions, never from the `migrations/` tree.
// Scanning the filesystem would make the expectation self-referential: a
// migration dropped from the catalog and regenerated would leave the tree
// self-consistent and publish a short set unnoticed.
export function expectedMigrationFiles(root) {
  const result = spawnSync('bun', [join(root, 'scripts', 'generate-migrations.ts'), '--list'], {
    cwd: root,
    encoding: 'utf8',
  });
  if (result.status !== 0) {
    throw new Error(
      `Unable to read the canonical migration catalog\n${String(result.stdout)}\n${String(result.stderr)}`,
    );
  }
  const paths = JSON.parse(String(result.stdout));
  if (!Array.isArray(paths) || paths.length === 0 || paths.some(path => typeof path !== 'string'))
    throw new Error('Canonical migration catalog reported no usable artifact paths');
  return paths.map(normalizePath).sort();
}

// Excluded material must not be demanded back: the manifests deliberately drop
// tests, snapshots, and generated HTML, so requiring every file on disk would
// report a file we must not ship as "missing".
export function publicDocumentationFiles(root) {
  const files = [];
  for (const directory of ['docs', 'examples'])
    listFiles(join(root, directory), root, files);
  return files.filter(path => !isForbiddenProjectPath(path)).sort();
}

export function npmRequiredTargets(packageJson) {
  return new Set([
    'package.json',
    'README.md',
    'LICENSE',
    'SECURITY.md',
    'CHANGELOG.md',
    ...collectStringLeaves(packageJson.bin),
    ...collectStringLeaves(packageJson.main),
    ...collectStringLeaves(packageJson.module),
    ...collectStringLeaves(packageJson.types),
    ...collectStringLeaves(packageJson.exports),
  ]);
}

export function jsrRequiredTargets(jsrJson) {
  return new Set([
    'jsr.json',
    'README.md',
    'LICENSE',
    'SECURITY.md',
    'CHANGELOG.md',
    ...collectStringLeaves(jsrJson.exports),
  ]);
}
