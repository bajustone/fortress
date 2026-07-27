import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  expectedMigrationFiles,
  jsrRequiredTargets,
  publicDocumentationFiles,
  readJson,
} from './publication-files.mjs';
import {
  relativeFileUrlPath,
  validatePublicationFiles,
} from './publication-policy.mjs';

const DENO_VERSION = '2.9.4';
const root = process.cwd();
const npx = process.platform === 'win32' ? 'npx.cmd' : 'npx';
const result = spawnSync(npx, ['--yes', `deno@${DENO_VERSION}`, 'publish', '--dry-run', '--allow-dirty'], {
  cwd: root,
  encoding: 'utf8',
  env: { ...process.env, NO_COLOR: '1' },
});
const output = `${String(result.stdout)}\n${String(result.stderr)}`;
if (result.status !== 0)
  throw new Error(`Deno/JSR dry run failed\n${output}`);

const lines = output.split(/\r?\n/);
const starts = lines
  .map((line, index) => line.startsWith('Simulating publish of ') && line.endsWith(' with files:') ? index : -1)
  .filter(index => index >= 0);
const completions = lines
  .map((line, index) => line === 'Success Dry run complete' ? index : -1)
  .filter(index => index >= 0);
if (starts.length !== 1 || completions.length !== 1 || completions[0] <= starts[0]) {
  throw new Error(
    'Deno/JSR dry-run output format changed: expected one file-list marker and one success marker',
  );
}

const files = new Set();
for (const line of lines.slice(starts[0] + 1, completions[0])) {
  const match = line.match(/^\s+(file:\/\/\/.+) \([^)]+\)$/);
  if (!match)
    continue;
  files.add(relativeFileUrlPath(root, fileURLToPath(match[1])));
}
if (files.size === 0)
  throw new Error('Deno/JSR dry run reported an empty publication manifest');

const jsrJson = readJson(resolve(root, 'jsr.json'));
const expectedMigrations = expectedMigrationFiles(root);
const policyErrors = validatePublicationFiles({
  registry: 'jsr',
  files,
  requiredTargets: new Set([
    ...jsrRequiredTargets(jsrJson),
    ...publicDocumentationFiles(root),
  ]),
  expectedMigrations,
});
if (policyErrors.length > 0) {
  throw new Error(
    `JSR publication manifest violates policy:\n${policyErrors.map(error => `  - ${error}`).join('\n')}`,
  );
}
console.log(`✔ JSR publication manifest is intentional (Deno ${DENO_VERSION}; ${files.size} files; no CLI; ${expectedMigrations.length} migrations)`);
