import { readdirSync, readFileSync } from 'node:fs';
import { join, relative } from 'node:path';
import { collectStringLeaves, normalizePath } from './publication-policy.mjs';

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

export function expectedMigrationFiles(root) {
  const files = [];
  listFiles(join(root, 'migrations'), root, files);
  return files.filter(path => path.endsWith('.sql')).sort();
}

export function publicDocumentationFiles(root) {
  const files = [];
  for (const directory of ['docs', 'examples'])
    listFiles(join(root, directory), root, files);
  return files.sort();
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
