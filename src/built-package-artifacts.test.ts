import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { dirname, join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const repositoryRoot = resolve(import.meta.dirname, '..');
const script = join(repositoryRoot, 'scripts/check-built-package-artifacts.mjs');
const temporaryRoots: string[] = [];
const fixtureArtifacts = [
  'dist/index.d.ts',
  'dist/index.js',
  'dist/hono.d.ts',
  'dist/hono.js',
  'dist/testing.cjs',
];

function temporaryRoot(): string {
  const root = mkdtempSync(join(tmpdir(), 'fortress-built-package-'));
  temporaryRoots.push(root);
  writeFileSync(join(root, 'package.json'), JSON.stringify({
    main: './dist/index.js',
    types: './dist/index.d.ts',
    exports: {
      './hono': {
        import: {
          types: './dist/hono.d.ts',
          default: './dist/hono.js',
        },
      },
      './testing': {
        require: {
          default: './dist/testing.cjs',
        },
      },
    },
  }));
  return root;
}

function writeArtifacts(root: string, artifacts = fixtureArtifacts): void {
  for (const path of artifacts) {
    const absolutePath = join(root, path);
    mkdirSync(dirname(absolutePath), { recursive: true });
    writeFileSync(absolutePath, '');
  }
}

function run(root: string): ReturnType<typeof spawnSync> {
  return spawnSync(process.execPath, [script, '--root', root], { encoding: 'utf8' });
}

afterEach(() => {
  for (const root of temporaryRoots.splice(0))
    rmSync(root, { recursive: true, force: true });
});

describe('built-package artifact preflight', () => {
  it('fails immediately with an actionable clean-checkout message', () => {
    const result = run(temporaryRoot());
    const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;

    expect(result.status).toBe(1);
    expect(output).toContain('built package artifacts are missing');
    expect(output).toContain('bun run check:built-package');
    expect(output).not.toContain('TS2307');
    expect(output).not.toContain('ERR_MODULE_NOT_FOUND');
  });

  it('derives every required artifact from package exports', () => {
    const root = temporaryRoot();
    writeArtifacts(root, fixtureArtifacts.filter(path => path !== 'dist/hono.d.ts'));

    const result = run(root);
    expect(result.status).toBe(1);
    expect(result.stderr).toContain('dist/hono.d.ts');
  });

  it('accepts a complete exported package surface', () => {
    const root = temporaryRoot();
    writeArtifacts(root);

    const result = run(root);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('exported built-package artifacts are present');
  });

  it('keeps standalone declaration and testing checks guarded', () => {
    const pkg = JSON.parse(readFileSync(join(repositoryRoot, 'package.json'), 'utf8'));

    for (const name of [
      'check:consumer-contract:package',
      'check:declarations:ts50',
      'check:testing-esm',
    ]) {
      expect(pkg.scripts[name], name).toContain('check:built-package-artifacts');
    }
  });
});
