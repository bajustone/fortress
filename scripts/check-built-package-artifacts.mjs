import { existsSync, readFileSync } from 'node:fs';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

function parseRoot(args) {
  const rootIndex = args.indexOf('--root');
  if (rootIndex === -1)
    return fileURLToPath(new URL('..', import.meta.url));
  if (!args[rootIndex + 1])
    throw new Error('--root requires a directory');
  return resolve(args[rootIndex + 1]);
}

function collectStringLeaves(value) {
  if (typeof value === 'string')
    return [value];
  if (!value || typeof value !== 'object')
    return [];
  return Object.values(value).flatMap(collectStringLeaves);
}

function requiredArtifacts(root) {
  const packagePath = resolve(root, 'package.json');
  if (!existsSync(packagePath))
    throw new Error(`package manifest is missing: ${packagePath}`);
  const pkg = JSON.parse(readFileSync(packagePath, 'utf8'));
  return [...new Set([
    ...collectStringLeaves(pkg.exports),
    pkg.main,
    pkg.types,
  ])]
    .filter(path => typeof path === 'string' && path.startsWith('./dist/'))
    .map(path => path.slice(2))
    .sort();
}

let root;
let required;
try {
  root = parseRoot(process.argv.slice(2));
  required = requiredArtifacts(root);
}
catch (error) {
  console.error(`✖ cannot inspect built package artifacts: ${error instanceof Error ? error.message : String(error)}`);
  process.exit(1);
}

const missing = required.filter(path => !existsSync(resolve(root, path)));
if (missing.length > 0) {
  console.error(
    `✖ built package artifacts are missing:\n${missing.map(path => `  - ${path}`).join('\n')}\n`
    + '  Run `bun run build` before a standalone built-package check, or run\n'
    + '  `bun run check:built-package` to build and validate from a clean checkout.',
  );
  process.exit(1);
}

console.log(`✔ all ${required.length} exported built-package artifacts are present`);
