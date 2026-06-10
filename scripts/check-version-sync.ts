import { readFileSync } from 'node:fs';
import { join } from 'node:path';

// Publish guard: JSR publishes from jsr.json, while package.json drives npm,
// the git tag, and the changelog. If the two versions drift, `jsr publish`
// ships the wrong (or an already-taken) version and the release silently never
// reaches the registry. Fail loudly before publishing so the bump is fixed
// first (the `version` lifecycle script keeps them in sync — see changelog.ts).
const root = join(import.meta.dirname, '..');

function read(file: string): string {
  return JSON.parse(readFileSync(join(root, file), 'utf-8')).version;
}

const pkgVersion = read('package.json');
const jsrVersion = read('jsr.json');

if (pkgVersion !== jsrVersion) {
  console.error(
    `✖ version drift: package.json is ${pkgVersion} but jsr.json is ${jsrVersion}.\n`
    + `  Run the version bump (which syncs both) before publishing, or set\n`
    + `  jsr.json "version" to ${pkgVersion} manually.`,
  );
  process.exit(1);
}

console.log(`✔ version in sync: ${pkgVersion}`);
