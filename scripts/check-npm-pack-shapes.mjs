import { spawnSync } from 'node:child_process';
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { normalizePackManifest } from './publication-files.mjs';

// `npm pack --json` changed container shape in npm 12: npm 11 prints an array
// of manifests, npm 12 prints an object keyed by package name. The unit tests
// pin the parser against recorded fixtures; this check proves those recordings
// still match what the real CLIs emit. It packs a tiny synthetic package rather
// than this repository so the two extra CLI downloads stay cheap, and it is
// deliberately kept out of `check:package-cli`/`check:release` so the everyday
// package checks remain offline.
const ARRAY_CLI = '11.9.0';
const KEYED_CLI = '12.0.2';
const fixtureName = '@fortress-fixture/pack-shape';
const fixtureVersion = '1.0.0';
const expectedFiles = ['index.js', 'lib/nested.txt', 'package.json'];

const workspace = mkdtempSync(join(tmpdir(), 'fortress-pack-shapes-'));
const fixture = join(workspace, 'package');
const output = join(workspace, 'tarballs');

function writeFixture() {
  mkdirSync(join(fixture, 'lib'), { recursive: true });
  mkdirSync(output, { recursive: true });
  writeFileSync(join(fixture, 'package.json'), `${JSON.stringify({
    name: fixtureName,
    version: fixtureVersion,
    private: false,
    main: 'index.js',
    files: ['index.js', 'lib'],
  }, null, 2)}\n`);
  writeFileSync(join(fixture, 'index.js'), 'export const packShapeFixture = true;\n');
  writeFileSync(join(fixture, 'lib', 'nested.txt'), 'nested\n');
}

function pack(cliVersion) {
  const result = spawnSync('npx', [
    '--yes',
    `npm@${cliVersion}`,
    'pack',
    '.',
    '--json',
    '--ignore-scripts',
    '--pack-destination',
    output,
  ], { cwd: fixture, encoding: 'utf8' });
  if (result.status !== 0) {
    throw new Error(
      `npm@${cliVersion} pack failed\n${String(result.stdout)}\n${String(result.stderr)}`,
    );
  }
  return JSON.parse(String(result.stdout));
}

function packageContent(manifest) {
  return {
    name: manifest.name,
    version: manifest.version,
    filename: manifest.filename,
    files: manifest.files.map(file => file.path).sort(),
  };
}

try {
  writeFixture();

  const arrayOutput = pack(ARRAY_CLI);
  const keyedOutput = pack(KEYED_CLI);

  if (!Array.isArray(arrayOutput) || arrayOutput.length !== 1)
    throw new Error(`npm@${ARRAY_CLI} no longer emits a single-manifest array`);
  if (Array.isArray(keyedOutput) || typeof keyedOutput !== 'object' || keyedOutput === null)
    throw new Error(`npm@${KEYED_CLI} no longer emits a keyed manifest object`);
  if (Object.keys(keyedOutput).join() !== fixtureName)
    throw new Error(`npm@${KEYED_CLI} keyed its manifest as ${Object.keys(keyedOutput).join()}`);

  const fromArray = packageContent(normalizePackManifest(arrayOutput));
  const fromKeyed = packageContent(normalizePackManifest(keyedOutput));

  if (JSON.stringify(fromArray) !== JSON.stringify(fromKeyed)) {
    throw new Error(
      `normalized package content differs between CLIs\n  npm@${ARRAY_CLI}: ${JSON.stringify(fromArray)}\n  npm@${KEYED_CLI}: ${JSON.stringify(fromKeyed)}`,
    );
  }
  if (fromArray.name !== fixtureName || fromArray.version !== fixtureVersion)
    throw new Error(`normalized manifest describes ${fromArray.name}@${fromArray.version}`);
  if (fromArray.files.join() !== expectedFiles.join())
    throw new Error(`normalized manifest listed ${fromArray.files.join()}`);

  console.log(
    `✔ npm pack JSON normalizes across CLIs (npm@${ARRAY_CLI} array, npm@${KEYED_CLI} keyed object; `
    + `${fromArray.files.length} files in ${fromArray.filename})`,
  );
}
finally {
  rmSync(workspace, { recursive: true, force: true });
}
