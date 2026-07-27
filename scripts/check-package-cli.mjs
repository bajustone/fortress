import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import {
  expectedMigrationFiles,
  npmRequiredTargets,
  publicDocumentationFiles,
  readJson,
} from './publication-files.mjs';
import { validatePublicationFiles } from './publication-policy.mjs';

const root = process.cwd();
const temporary = mkdtempSync(join(tmpdir(), 'fortress-package-cli-'));

function run(command, args, options = {}) {
  const result = spawnSync(command, args, { encoding: 'utf8', ...options });
  if (result.status !== 0) {
    throw new Error(
      `${command} ${args.join(' ')} failed\n${String(result.stdout)}\n${String(result.stderr)}`,
    );
  }
  return result;
}

try {
  const packed = run('npm', [
    'pack',
    '.',
    '--json',
    '--ignore-scripts',
    '--pack-destination',
    temporary,
  ]);
  const [manifest] = JSON.parse(String(packed.stdout));
  if (!manifest || !Array.isArray(manifest.files) || typeof manifest.filename !== 'string')
    throw new Error('npm pack returned an invalid JSON manifest');
  const files = new Set(manifest.files.map(file => file.path));
  const packageJson = readJson(resolve(root, 'package.json'));
  const expectedMigrations = expectedMigrationFiles(root);
  const policyErrors = validatePublicationFiles({
    registry: 'npm',
    files,
    requiredTargets: new Set([
      ...npmRequiredTargets(packageJson),
      ...publicDocumentationFiles(root),
    ]),
    expectedMigrations,
  });
  if (policyErrors.length > 0)
    throw new Error(`npm publication manifest violates policy:\n${policyErrors.map(error => `  - ${error}`).join('\n')}`);

  const archive = join(temporary, manifest.filename);
  run('tar', ['-xzf', archive, '-C', temporary]);
  symlinkSync(resolve(root, 'node_modules'), join(temporary, 'package', 'node_modules'), 'dir');
  const cli = run('bun', [join(temporary, 'package', 'bin', 'fortress.ts'), '--help']);
  if (!String(cli.stdout).includes('migrate:up'))
    throw new Error('Packed CLI help did not include migrate:up');
  console.log(`✔ npm publication manifest is intentional (${files.size} files; runnable Bun CLI; ${expectedMigrations.length} migrations)`);
}
finally {
  rmSync(temporary, { recursive: true, force: true });
}
