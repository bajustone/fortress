import { existsSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const REQUIRED_ARTIFACTS = [
  'dist/index.d.ts',
  'dist/index.d.cts',
  'dist/testing.js',
  'dist/testing.cjs',
];

function parseRoot(args) {
  const rootIndex = args.indexOf('--root');
  if (rootIndex === -1)
    return fileURLToPath(new URL('..', import.meta.url));
  if (!args[rootIndex + 1])
    throw new Error('--root requires a directory');
  return resolve(args[rootIndex + 1]);
}

const root = parseRoot(process.argv.slice(2));
const missing = REQUIRED_ARTIFACTS.filter(path => !existsSync(resolve(root, path)));

if (missing.length > 0) {
  console.error(
    `✖ built package artifacts are missing:\n${missing.map(path => `  - ${path}`).join('\n')}\n`
    + '  Run `bun run build` before a standalone built-package check, or run\n'
    + '  `bun run check:built-package` to build and validate from a clean checkout.',
  );
  process.exit(1);
}

console.log('✔ required built-package artifacts are present');
