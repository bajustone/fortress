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

function isPlainObject(value) {
  if (typeof value !== 'object' || value === null || Array.isArray(value))
    return false;
  const prototype = Object.getPrototypeOf(value);
  return prototype === Object.prototype || prototype === null;
}

function assertManifestEntry(entry, source) {
  if (!isPlainObject(entry))
    throw new Error(`npm pack --json ${source} is not an object manifest`);
  if (typeof entry.name !== 'string' || entry.name.length === 0)
    throw new Error(`npm pack --json ${source} has no package name`);
  if (typeof entry.filename !== 'string' || entry.filename.length === 0)
    throw new Error(`npm pack --json ${source} has no tarball filename`);
  if (!Array.isArray(entry.files))
    throw new Error(`npm pack --json ${source} has no file list`);
  for (const file of entry.files) {
    if (!isPlainObject(file) || typeof file.path !== 'string' || file.path.length === 0)
      throw new Error(`npm pack --json ${source} lists a file without a path`);
  }
  return entry;
}

// npm 11 and earlier print `npm pack --json` as an array of manifests; npm 12
// prints an object keyed by package name. Only the container changed, so the
// entry is normalized rather than reinterpreted. Exactly one manifest is
// required in both shapes: taking the first of several would let a tarball we
// did not intend to publish satisfy the publication policy.
export function normalizePackManifest(parsed) {
  if (Array.isArray(parsed)) {
    if (parsed.length !== 1)
      throw new Error(`npm pack --json returned ${parsed.length} manifests; expected exactly 1`);
    return assertManifestEntry(parsed[0], 'manifest');
  }
  if (!isPlainObject(parsed))
    throw new Error('npm pack --json returned neither a manifest array nor a keyed manifest object');

  // Own enumerable keys only, so a manifest reached through the prototype
  // chain cannot stand in for a packed package.
  const names = Object.keys(parsed);
  if (names.length !== 1)
    throw new Error(`npm pack --json returned ${names.length} manifests; expected exactly 1`);
  const [name] = names;
  const entry = assertManifestEntry(parsed[name], `manifest "${name}"`);
  if (entry.name !== name)
    throw new Error(`npm pack --json keyed manifest "${name}" describes package "${entry.name}"`);
  return entry;
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
