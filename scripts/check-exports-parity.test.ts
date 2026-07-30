import { readFileSync } from 'node:fs';
import { join } from 'node:path';
import { describe, expect, it } from 'vitest';
import { validateExportsParity } from './check-exports-parity';

function rootExport(entry = 'index') {
  return {
    import: {
      types: `./dist/${entry}.d.ts`,
      default: `./dist/${entry}.js`,
    },
    require: {
      types: `./dist/${entry}.d.cts`,
      default: `./dist/${entry}.cjs`,
    },
  };
}

function validPackage() {
  return {
    types: './dist/index.d.ts',
    main: './dist/index.cjs',
    exports: { '.': rootExport() },
  };
}

const validJsr = { exports: { '.': './src/index.ts' } };
const entries = new Set(['index', 'fetcher']);

describe('validateExportsParity', () => {
  it('accepts a complete four-branch export bound to its tsup entry', () => {
    expect(validateExportsParity(validPackage(), validJsr, entries)).toEqual([]);
  });

  it('rejects missing and non-object branches with deterministic diagnostics', () => {
    const missing = validPackage();
    delete (missing.exports['.'] as { require?: unknown }).require;
    expect(validateExportsParity(missing, validJsr, entries)).toContain(
      '✖ export "." require: expected an object with types/default leaves, got <missing>',
    );

    const nonObject = validPackage();
    (nonObject.exports['.'] as { import: unknown }).import = './dist/index.js';
    expect(validateExportsParity(nonObject, validJsr, entries)).toContain(
      '✖ export "." import: expected an object with types/default leaves, got "./dist/index.js"',
    );
  });

  it('rejects leading top-level conditions that can shadow import/require', () => {
    const pkg = validPackage();
    pkg.exports['.'] = {
      node: './dist/fetcher.cjs',
      ...rootExport(),
    } as typeof pkg.exports['.'];

    expect(validateExportsParity(pkg, validJsr, entries)).toContain(
      '✖ export "." conditions: expected ordered keys ["import","require"], got ["node","import","require"]',
    );
  });

  it('rejects branch-local shadow conditions', () => {
    const pkg = validPackage();
    pkg.exports['.'].import = {
      node: './dist/fetcher.d.ts',
      ...pkg.exports['.'].import,
    } as typeof pkg.exports['.']['import'];

    expect(validateExportsParity(pkg, validJsr, entries)).toContain(
      '✖ export "." import conditions: expected ordered keys ["types","default"], got ["node","types","default"]',
    );
  });

  it('rejects reordered types/default conditions', () => {
    const pkg = validPackage();
    pkg.exports['.'].import = {
      default: './dist/index.js',
      types: './dist/index.d.ts',
    };

    expect(validateExportsParity(pkg, validJsr, entries)).toContain(
      '✖ export "." import conditions: expected ordered keys ["types","default"], got ["default","types"]',
    );
  });

  it('rejects missing, non-string, and wrong-but-existing leaves', () => {
    const missing = validPackage();
    delete (missing.exports['.'].require as { types?: unknown }).types;
    expect(validateExportsParity(missing, validJsr, entries)).toContain(
      '✖ export "." require.types: expected "./dist/index.d.cts", got <missing>',
    );

    const nonString = validPackage();
    (nonString.exports['.'].require as { types: unknown }).types = 42;
    expect(validateExportsParity(nonString, validJsr, entries)).toContain(
      '✖ export "." require.types: expected "./dist/index.d.cts", got 42',
    );

    const crossMapped = validPackage();
    crossMapped.exports['.'].require.types = './dist/fetcher.d.cts';
    expect(validateExportsParity(crossMapped, validJsr, entries)).toContain(
      '✖ export "." require.types: expected "./dist/index.d.cts", got "./dist/fetcher.d.cts"',
    );
  });

  it('rejects a whole-export alias even when the aliased tsup entry exists', () => {
    const aliased = validPackage();
    aliased.exports['.'] = rootExport('fetcher');

    expect(validateExportsParity(aliased, validJsr, entries)).toEqual(expect.arrayContaining([
      '✖ export "." import.types: expected "./dist/index.d.ts", got "./dist/fetcher.d.ts"',
      '✖ export "." import.default: expected "./dist/index.js", got "./dist/fetcher.js"',
      '✖ export "." require.types: expected "./dist/index.d.cts", got "./dist/fetcher.d.cts"',
      '✖ export "." require.default: expected "./dist/index.cjs", got "./dist/fetcher.cjs"',
    ]));
  });

  it('rejects missing tsup entries', () => {
    expect(validateExportsParity(validPackage(), validJsr, new Set())).toContain(
      '✖ export ".": expected tsup entry "index", but it is not configured',
    );
  });

  it('rejects root types and main drift', () => {
    const pkg = { ...validPackage(), types: './dist/fetcher.d.ts', main: './dist/fetcher.cjs' };
    expect(validateExportsParity(pkg, validJsr, entries)).toEqual(expect.arrayContaining([
      '✖ package.json "types": expected "./dist/index.d.ts" to match export \'.\' import.types, got "./dist/fetcher.d.ts"',
      '✖ package.json "main": expected "./dist/index.cjs" to match export \'.\' require.default, got "./dist/fetcher.cjs"',
    ]));
  });

  it('requires both manifests to retain their root export', () => {
    const pkg = { ...validPackage(), exports: {} };
    const jsr = { exports: {} };

    expect(validateExportsParity(pkg, jsr, entries)).toEqual(expect.arrayContaining([
      '✖ package.json "exports": required root export "." is missing',
      '✖ jsr.json "exports": required root export "." is missing',
    ]));
  });

  it('preserves bidirectional JSR/npm key parity', () => {
    const pkg = validPackage();
    pkg.exports['./fetcher' as '.'] = rootExport('fetcher');
    const problems = validateExportsParity(pkg, validJsr, entries);
    expect(problems.some(problem => problem.includes('package.json "exports" are not in jsr.json'))).toBe(true);

    const jsrExtra = { exports: { '.': './src/index.ts', './fetcher': './src/fetcher/index.ts' } };
    expect(validateExportsParity(validPackage(), jsrExtra, entries)
      .some(problem => problem.includes('MISSING from package.json "exports"'))).toBe(true);
  });

  it('keeps the CJS fixture in lockstep with every npm export key', () => {
    const repositoryRoot = join(import.meta.dirname, '..');
    const pkg = JSON.parse(readFileSync(join(repositoryRoot, 'package.json'), 'utf8')) as {
      exports: Record<string, unknown>;
    };
    const fixture = readFileSync(join(repositoryRoot, 'scripts/fixtures/cjs-consumer/index.cts'), 'utf8');
    const imported = new Set(
      Array.from(fixture.matchAll(/require\('(@bajustone\/fortress[^']*)'\)/g), match => match[1]),
    );
    const expected = Object.keys(pkg.exports).map(key =>
      key === '.' ? '@bajustone/fortress' : `@bajustone/fortress/${key.slice(2)}`);

    expect(expected).toHaveLength(29);
    expect(imported).toEqual(new Set(expected));
  });
});
