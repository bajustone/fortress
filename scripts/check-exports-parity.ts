import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Publish guard: JSR and npm expose the same subpaths, every npm condition maps
// to the exact artifact emitted for that subpath, and tsup owns the matching
// entry. Exact paths matter: a wrong-but-existing declaration can otherwise
// make one module system type-check against another subpath's public API.
const root = join(import.meta.dirname, '..');

// `src/foo/index.ts` | `src/foo.ts` → entry name `foo` (array-form tsup entries).
const TSUP_ARRAY_ENTRY_RE = /(?:^|\/)src\/(.+?)(?:\/index)?\.[cm]?ts$/;

type JsonRecord = Record<string, unknown>;

function asRecord(value: unknown): JsonRecord | undefined {
  return value !== null && typeof value === 'object' && !Array.isArray(value)
    ? value as JsonRecord
    : undefined;
}

function render(value: unknown): string {
  if (value === undefined)
    return '<missing>';
  const encoded = JSON.stringify(value);
  return encoded === undefined ? String(value) : encoded;
}

function exportEntry(key: string): string {
  return key === '.' ? 'index' : key.startsWith('./') ? key.slice(2) : key;
}

interface ExpectedLeaf {
  branch: 'import' | 'require';
  leaf: 'types' | 'default';
  path: string;
}

function expectedLeaves(entry: string): ExpectedLeaf[] {
  return [
    { branch: 'import', leaf: 'types', path: `./dist/${entry}.d.ts` },
    { branch: 'import', leaf: 'default', path: `./dist/${entry}.js` },
    { branch: 'require', leaf: 'types', path: `./dist/${entry}.d.cts` },
    { branch: 'require', leaf: 'default', path: `./dist/${entry}.cjs` },
  ];
}

function hasExactOrderedKeys(record: JsonRecord, expected: readonly string[]): boolean {
  const actual = Object.keys(record);
  return actual.length === expected.length && actual.every((key, index) => key === expected[index]);
}

/** Return deterministic, aggregated manifest/tsup parity diagnostics. */
export function validateExportsParity(
  pkgValue: unknown,
  jsrValue: unknown,
  tsupEntryNames: ReadonlySet<string>,
): string[] {
  const pkg = asRecord(pkgValue) ?? {};
  const jsr = asRecord(jsrValue) ?? {};
  const pkgExports = asRecord(pkg.exports) ?? {};
  const jsrExports = asRecord(jsr.exports) ?? {};
  const pkgKeys = Object.keys(pkgExports);
  const jsrKeys = Object.keys(jsrExports);
  const pkgSet = new Set(pkgKeys);
  const jsrSet = new Set(jsrKeys);
  const problems: string[] = [];

  if (!pkgSet.has('.'))
    problems.push('✖ package.json "exports": required root export "." is missing');
  if (!jsrSet.has('.'))
    problems.push('✖ jsr.json "exports": required root export "." is missing');

  const missingFromNpm = jsrKeys.filter(key => !pkgSet.has(key));
  const extraInNpm = pkgKeys.filter(key => !jsrSet.has(key));
  if (missingFromNpm.length > 0) {
    problems.push(
      `✖ ${missingFromNpm.length} subpath(s) in jsr.json are MISSING from package.json "exports" `
      + `(npm consumers get a 404):\n    ${missingFromNpm.join('\n    ')}`,
    );
  }
  if (extraInNpm.length > 0) {
    problems.push(
      `✖ ${extraInNpm.length} subpath(s) in package.json "exports" are not in jsr.json:\n    ${extraInNpm.join('\n    ')}`,
    );
  }

  for (const key of pkgKeys) {
    const entry = exportEntry(key);
    const target = asRecord(pkgExports[key]);
    if (!target) {
      problems.push(`✖ export ${render(key)}: expected an object with import/require branches, got ${render(pkgExports[key])}`);
    }
    else {
      const expectedTargetKeys = ['import', 'require'] as const;
      if (!hasExactOrderedKeys(target, expectedTargetKeys)) {
        problems.push(
          `✖ export ${render(key)} conditions: expected ordered keys ${render(expectedTargetKeys)}, `
          + `got ${render(Object.keys(target))}`,
        );
      }
      for (const branchName of expectedTargetKeys) {
        const branch = asRecord(target[branchName]);
        if (!branch) {
          problems.push(
            `✖ export ${render(key)} ${branchName}: expected an object with types/default leaves, got ${render(target[branchName])}`,
          );
          continue;
        }
        const expectedBranchKeys = ['types', 'default'] as const;
        if (!hasExactOrderedKeys(branch, expectedBranchKeys)) {
          problems.push(
            `✖ export ${render(key)} ${branchName} conditions: expected ordered keys ${render(expectedBranchKeys)}, `
            + `got ${render(Object.keys(branch))}`,
          );
        }
        for (const expected of expectedLeaves(entry).filter(leaf => leaf.branch === branchName)) {
          const actual = branch[expected.leaf];
          if (actual !== expected.path) {
            problems.push(
              `✖ export ${render(key)} ${branchName}.${expected.leaf}: `
              + `expected ${render(expected.path)}, got ${render(actual)}`,
            );
          }
        }
      }
    }

    if (!tsupEntryNames.has(entry))
      problems.push(`✖ export ${render(key)}: expected tsup entry ${render(entry)}, but it is not configured`);
  }

  const expectedRootTypes = './dist/index.d.ts';
  if (pkg.types !== expectedRootTypes) {
    problems.push(
      `✖ package.json "types": expected ${render(expectedRootTypes)} to match export '.' import.types, got ${render(pkg.types)}`,
    );
  }
  const expectedRootMain = './dist/index.cjs';
  if (pkg.main !== expectedRootMain) {
    problems.push(
      `✖ package.json "main": expected ${render(expectedRootMain)} to match export '.' require.default, got ${render(pkg.main)}`,
    );
  }

  return problems;
}

function readJson(file: string): unknown {
  return JSON.parse(readFileSync(join(root, file), 'utf-8')) as unknown;
}

async function configuredTsupEntries(): Promise<Set<string>> {
  const tsupMod = await import(join(root, 'tsup.config.ts'));
  const configs = Array.isArray(tsupMod.default) ? tsupMod.default : [tsupMod.default];
  const names = new Set<string>();
  for (const raw of configs) {
    const config = typeof raw === 'function' ? await raw({}) : raw;
    const entry: unknown = config?.entry;
    if (Array.isArray(entry)) {
      for (const path of entry) {
        const match = String(path).match(TSUP_ARRAY_ENTRY_RE);
        if (match?.[1])
          names.add(match[1]);
      }
    }
    else {
      const entryRecord = asRecord(entry);
      if (entryRecord) {
        for (const name of Object.keys(entryRecord))
          names.add(name);
      }
    }
  }
  return names;
}

async function main(): Promise<void> {
  const pkg = readJson('package.json');
  const jsr = readJson('jsr.json');
  const tsupEntries = await configuredTsupEntries();
  const problems = validateExportsParity(pkg, jsr, tsupEntries);
  if (problems.length > 0) {
    console.error(
      `${problems.join('\n')}\n\nFix package.json "exports" and/or tsup.config.ts "entry" `
      + 'so jsr.json, all npm import/require branches, root fallbacks, and tsup agree.',
    );
    process.exitCode = 1;
    return;
  }

  const exportCount = Object.keys(asRecord(asRecord(pkg)?.exports) ?? {}).length;
  console.log(`✔ exports in strict structural sync: ${exportCount} subpaths across jsr.json, package.json, and tsup.config.ts`);
}

if (import.meta.main)
  await main();
