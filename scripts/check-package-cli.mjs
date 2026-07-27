import { spawnSync } from 'node:child_process';
import { mkdtempSync, rmSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';

const MIGRATION_ARTIFACT_RE = /^migrations\/(?:pg|sqlite)\/.+\.sql$/;
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
  const files = new Set(manifest.files.map(file => file.path));
  if (!files.has('bin/fortress.ts'))
    throw new Error('Packed npm package is missing bin/fortress.ts');
  const migrationFiles = [...files].filter(path => MIGRATION_ARTIFACT_RE.test(path));
  if (migrationFiles.length !== 40)
    throw new Error(`Packed npm package contains ${migrationFiles.length} migration artifacts; expected 40`);

  const archive = join(temporary, manifest.filename);
  run('tar', ['-xzf', archive, '-C', temporary]);
  symlinkSync(resolve('node_modules'), join(temporary, 'package', 'node_modules'), 'dir');
  const cli = run('bun', [join(temporary, 'package', 'bin', 'fortress.ts'), '--help']);
  if (!String(cli.stdout).includes('migrate:up'))
    throw new Error('Packed CLI help did not include migrate:up');
  console.log('✔ npm package includes a runnable Bun CLI and all 40 migration artifacts');
}
finally {
  rmSync(temporary, { recursive: true, force: true });
}
