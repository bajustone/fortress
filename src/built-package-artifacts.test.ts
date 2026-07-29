import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join, resolve } from 'node:path';
import { afterEach, describe, expect, it } from 'vitest';

const script = resolve(import.meta.dirname, '../scripts/check-built-package-artifacts.mjs');
const temporaryRoots: string[] = [];

function temporaryRoot(): string {
  const root = mkdtempSync(join(tmpdir(), 'fortress-built-package-'));
  temporaryRoots.push(root);
  return root;
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

  it('accepts the declaration and testing entrypoint artifacts', () => {
    const root = temporaryRoot();
    for (const path of [
      'dist/index.d.ts',
      'dist/index.d.cts',
      'dist/testing.js',
      'dist/testing.cjs',
    ]) {
      const absolutePath = join(root, path);
      mkdirSync(resolve(absolutePath, '..'), { recursive: true });
      writeFileSync(absolutePath, '');
    }

    const result = run(root);
    expect(result.status).toBe(0);
    expect(result.stdout).toContain('required built-package artifacts are present');
  });
});
