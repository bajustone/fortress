import { relative, sep } from 'node:path';

const ROOT_PUBLIC_FILES = new Set([
  'CHANGELOG.md',
  'LICENSE',
  'README.md',
  'SECURITY.md',
  'package.json',
]);
const JSR_EXTRA_ROOT_FILES = new Set(['jsr.json']);
const NPM_ALLOWED_ROOTS = ['bin/', 'dist/', 'docs/', 'examples/', 'migrations/', 'src/'];
const JSR_ALLOWED_ROOTS = ['docs/', 'examples/', 'migrations/', 'src/'];
const TEST_FILE_RE = /(?:^|\/)[^/]+\.(?:integration-test|test|spec)\.[cm]?[jt]sx?$/i;
const SNAPSHOT_RE = /(?:^|\/)__snapshots__\/|\.snap$/i;
// Mirrors the `**/__tests__/**` exclusions in package.json and jsr.json. Test
// filenames alone miss this layout, which both registries would otherwise ship.
const TEST_DIRECTORY_RE = /(?:^|\/)__tests__\//i;
const HTML_RE = /\.html$/i;
const ROOT_PROJECT_DOCUMENT_RE = /^(?:audit|context|plan|planning|progress)(?:[-_.].*)?\.(?:md|html)$/i;
const RUST_FILE_RE = /(?:^|\/)(?:Cargo\.(?:toml|lock)|rust-toolchain(?:\.toml)?|rustfmt\.toml|clippy\.toml|[^/]+\.rs)$/i;
const RUST_METADATA_RE = /(?:^|\/)\.cargo(?:\/|$)/i;
const TOKEN_SPLIT_RE = /[-_.]/;
const STRIP_DOT_SLASH_RE = /^\.\//;
const MIGRATION_ARTIFACT_RE = /^migrations\/(?:pg|sqlite)\/.+\.sql$/;

export function normalizePath(path) {
  return path.replace(STRIP_DOT_SLASH_RE, '').split(sep).join('/');
}

export function collectStringLeaves(value) {
  if (typeof value === 'string')
    return [normalizePath(value)];
  if (!value || typeof value !== 'object')
    return [];
  return Object.values(value).flatMap(collectStringLeaves);
}

function hasRustPathToken(path) {
  return normalizePath(path)
    .split('/')
    .some(segment => segment.toLowerCase().split(TOKEN_SPLIT_RE).includes('rust'));
}

function isRootProjectDocument(path) {
  return !path.includes('/') && ROOT_PROJECT_DOCUMENT_RE.test(path);
}

function isRustOrGeneratedHtml(path) {
  return HTML_RE.test(path)
    || RUST_FILE_RE.test(path)
    || RUST_METADATA_RE.test(path)
    || hasRustPathToken(path);
}

export function isForbiddenProjectPath(path) {
  const normalized = normalizePath(path);
  return TEST_FILE_RE.test(normalized)
    || TEST_DIRECTORY_RE.test(normalized)
    || SNAPSHOT_RE.test(normalized)
    || isRootProjectDocument(normalized)
    || isRustOrGeneratedHtml(normalized);
}

export function validatePublicationFiles({
  registry,
  files,
  requiredTargets,
  expectedMigrations,
}) {
  const normalizedFiles = new Set(Array.from(files, normalizePath));
  const errors = [];
  const allowedRoots = registry === 'npm' ? NPM_ALLOWED_ROOTS : JSR_ALLOWED_ROOTS;
  const allowedRootFiles = registry === 'npm'
    ? ROOT_PUBLIC_FILES
    : new Set([...ROOT_PUBLIC_FILES, ...JSR_EXTRA_ROOT_FILES]);

  for (const path of [...normalizedFiles].sort()) {
    if (isForbiddenProjectPath(path))
      errors.push(`forbidden ${registry} file: ${path}`);
    if (!allowedRootFiles.has(path) && !allowedRoots.some(root => path.startsWith(root)))
      errors.push(`unexpected ${registry} file: ${path}`);
  }

  for (const path of [...requiredTargets, ...expectedMigrations].map(normalizePath).sort()) {
    if (!normalizedFiles.has(path))
      errors.push(`missing ${registry} file: ${path}`);
  }

  if (registry === 'npm') {
    if (!normalizedFiles.has('bin/fortress.ts'))
      errors.push('missing npm CLI: bin/fortress.ts');
  }
  else {
    for (const path of normalizedFiles) {
      if (path === 'bin' || path.startsWith('bin/'))
        errors.push(`JSR must not publish the npm-only CLI: ${path}`);
      if (path === 'dist' || path.startsWith('dist/'))
        errors.push(`JSR must publish source entrypoints, not npm build output: ${path}`);
    }
  }

  const actualMigrations = [...normalizedFiles]
    .filter(path => MIGRATION_ARTIFACT_RE.test(path))
    .sort();
  const expected = Array.from(expectedMigrations, normalizePath).sort();
  for (const path of actualMigrations) {
    if (!expected.includes(path))
      errors.push(`unexpected ${registry} migration artifact: ${path}`);
  }
  return [...new Set(errors)].sort();
}

export function validateTrackedRepositoryFiles(files) {
  const errors = [];
  for (const path of Array.from(files, normalizePath).sort()) {
    if (isRustOrGeneratedHtml(path))
      errors.push(`Rust or generated HTML material must not be tracked on the TypeScript branch: ${path}`);
    // .gitignore globs are a convenience and cannot express the case-insensitive
    // suffix forms, so this check is the enforcing gate for planning material.
    else if (isRootProjectDocument(path))
      errors.push(`Root project planning documents are inputs, not repository assets: ${path}`);
  }
  return errors;
}

export function relativeFileUrlPath(root, absolutePath) {
  const path = normalizePath(relative(root, absolutePath));
  if (!path || path === '..' || path.startsWith('../'))
    throw new Error(`Published file resolves outside the repository: ${absolutePath}`);
  return path;
}
