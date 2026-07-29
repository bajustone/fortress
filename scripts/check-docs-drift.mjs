import { readdirSync, readFileSync } from 'node:fs';
import { extname, join, relative } from 'node:path';
import { fileURLToPath } from 'node:url';
import { findDocumentationDrift } from './docs-drift-policy.mjs';

const TEST_FILE_RE = /\.(?:test|spec|integration-test)\.ts$/;

const root = fileURLToPath(new URL('..', import.meta.url));
const files = {
  'README.md': readFileSync(join(root, 'README.md'), 'utf8'),
  'scripts/fixtures/readme-hono-adapter-declaration.ts': readFileSync(
    join(root, 'scripts/fixtures/readme-hono-adapter-declaration.ts'),
    'utf8',
  ),
};

function collect(directory, extensions) {
  const absoluteDirectory = join(root, directory);
  for (const entry of readdirSync(absoluteDirectory, { withFileTypes: true })) {
    const absolutePath = join(absoluteDirectory, entry.name);
    if (entry.isDirectory()) {
      collect(relative(root, absolutePath), extensions);
      continue;
    }
    if (!extensions.has(extname(entry.name)) || TEST_FILE_RE.test(entry.name))
      continue;
    const path = relative(root, absolutePath).split('\\').join('/');
    files[path] = readFileSync(absolutePath, 'utf8');
  }
}

collect('src', new Set(['.ts']));
collect('docs', new Set(['.md']));
collect('examples', new Set(['.md', '.ts']));

const packageVersion = JSON.parse(readFileSync(join(root, 'package.json'), 'utf8')).version;
const errors = findDocumentationDrift(files, packageVersion);

if (errors.length > 0) {
  console.error(`✖ documentation drift detected:\n${errors.map(error => `  - ${error}`).join('\n')}`);
  process.exit(1);
}

console.log(`✔ documentation examples and guidance are current (${Object.keys(files).length} files)`);
