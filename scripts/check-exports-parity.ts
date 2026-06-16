import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Publish guard: JSR publishes every subpath listed in jsr.json "exports", but
// npm consumers only get what package.json "exports" maps — and each of those
// must point at a dist artifact that tsup actually builds. If the three drift,
// npm consumers hit a bare 404 on a documented subpath (e.g. `@bajustone/fortress/plugins/admin`)
// even though it resolves fine on JSR. This check keeps jsr.json ⇄ package.json ⇄ tsup in lockstep.
const root = join(import.meta.dirname, '..');

// `src/foo/index.ts` | `src/foo.ts` → entry name `foo` (array-form tsup entries).
const TSUP_ARRAY_ENTRY_RE = /(?:^|\/)src\/(.+?)(?:\/index)?\.[cm]?ts$/;
// `./dist/plugins/admin.js` → dist entry name `plugins/admin`.
const DIST_ENTRY_RE = /^\.\/dist\/(.+)\.[cm]?js$/;

function readJson(file: string): any {
  return JSON.parse(readFileSync(join(root, file), 'utf-8'));
}

const pkg = readJson('package.json');
const jsr = readJson('jsr.json');

const jsrKeys = Object.keys(jsr.exports ?? {});
const pkgKeys = Object.keys(pkg.exports ?? {});
const jsrSet = new Set(jsrKeys);
const pkgSet = new Set(pkgKeys);

// 1) Every JSR subpath must also be an npm subpath, and vice versa.
const missingFromNpm = jsrKeys.filter(k => !pkgSet.has(k));
const extraInNpm = pkgKeys.filter(k => !jsrSet.has(k));

// 2) Every npm export must resolve to a dist file that tsup is configured to build.
const tsupMod = await import(join(root, 'tsup.config.ts'));
const configs = Array.isArray(tsupMod.default) ? tsupMod.default : [tsupMod.default];
const tsupEntryNames = new Set<string>();
for (const raw of configs) {
  const c = typeof raw === 'function' ? await raw({}) : raw;
  const entry = c?.entry;
  if (Array.isArray(entry)) {
    for (const p of entry) {
      const m = String(p).match(TSUP_ARRAY_ENTRY_RE);
      if (m)
        tsupEntryNames.add(m[1]);
    }
  }
  else if (entry && typeof entry === 'object') {
    for (const k of Object.keys(entry)) tsupEntryNames.add(k);
  }
}

function distEntryName(exp: unknown): string | null {
  const p = typeof exp === 'string' ? exp : (exp as any)?.import?.default ?? (exp as any)?.default;
  if (typeof p !== 'string')
    return null;
  const m = p.match(DIST_ENTRY_RE);
  return m ? m[1] : null;
}

const missingTsupEntries = pkgKeys
  .map(k => ({ key: k, name: distEntryName(pkg.exports[k]) }))
  .filter(({ name }) => name && !tsupEntryNames.has(name));

const problems: string[] = [];
if (missingFromNpm.length) {
  problems.push(
    `✖ ${missingFromNpm.length} subpath(s) in jsr.json are MISSING from package.json "exports" `
    + `(npm consumers get a 404):\n    ${missingFromNpm.join('\n    ')}`,
  );
}
if (extraInNpm.length) {
  problems.push(
    `✖ ${extraInNpm.length} subpath(s) in package.json "exports" are not in jsr.json:\n    ${extraInNpm.join('\n    ')}`,
  );
}
if (missingTsupEntries.length) {
  problems.push(
    `✖ ${missingTsupEntries.length} npm export(s) point at a dist file with no matching tsup entry `
    + `(the subpath won't exist after build):\n    ${missingTsupEntries.map(p => `${p.key} → expected tsup entry '${p.name}'`).join('\n    ')}`,
  );
}

if (problems.length) {
  console.error(`${problems.join('\n')}\n\nFix package.json "exports" and/or tsup.config.ts "entry" so all three (jsr.json, package.json, tsup) agree.`);
  process.exit(1);
}

console.log(`✔ exports in sync: ${pkgKeys.length} subpaths across jsr.json, package.json, and tsup.config.ts`);
