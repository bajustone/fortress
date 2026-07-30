import { spawnSync } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

const root = fileURLToPath(new URL('..', import.meta.url));
const require = createRequire(import.meta.url);
const config = resolve(root, 'scripts/fixtures/express4-consumer/tsconfig.json');
const TS_DIAGNOSTIC_RE = /error TS\d+:/;

function readPackage(relativePath) {
  const path = resolve(root, relativePath, 'package.json');
  return { path, value: JSON.parse(readFileSync(path, 'utf8')) };
}

function fail(message, detail = '') {
  console.error(`✖ Express 4 declaration contract failed: ${message}${detail ? `\n${detail}` : ''}`);
  process.exit(1);
}

let runtime;
let expressTypes;
let coreTypes;
try {
  runtime = readPackage('node_modules/express4');
  expressTypes = readPackage('node_modules/@types/express4');
  coreTypes = readPackage('node_modules/@types/express4/node_modules/@types/express-serve-static-core');
}
catch (error) {
  fail(
    'aliased Express 4 packages are missing; run `bun install --frozen-lockfile`',
    error instanceof Error ? error.message : String(error),
  );
}

if (runtime.value.name !== 'express' || runtime.value.version !== '4.21.2')
  fail(`expected express4 alias to resolve express@4.21.2, got ${runtime.value.name}@${runtime.value.version}`);
if (expressTypes.value.name !== '@types/express' || expressTypes.value.version !== '4.17.23') {
  fail(
    `expected @types/express4 alias to resolve @types/express@4.17.23, `
    + `got ${expressTypes.value.name}@${expressTypes.value.version}`,
  );
}
if (coreTypes.value.name !== '@types/express-serve-static-core' || !String(coreTypes.value.version).startsWith('4.')) {
  fail(
    'expected the aliased Express 4 types to install a nested express-serve-static-core v4, '
    + `got ${coreTypes.value.name}@${coreTypes.value.version}`,
  );
}

const tsc = require.resolve('typescript/lib/tsc.js');
const result = spawnSync(process.execPath, [
  tsc,
  '-p',
  config,
  '--traceResolution',
  '--pretty',
  'false',
], {
  cwd: root,
  encoding: 'utf8',
  maxBuffer: 32 * 1024 * 1024,
});
const trace = `${result.stdout ?? ''}\n${result.stderr ?? ''}`.replaceAll('\\', '/');
if (result.status !== 0) {
  const diagnostics = trace.split('\n').filter(line => TS_DIAGNOSTIC_RE.test(line));
  fail(
    `TypeScript exited with status ${result.status ?? 'unknown'}`,
    diagnostics.length > 0 ? diagnostics.join('\n') : trace.split('\n').slice(-40).join('\n'),
  );
}

const expressResolution = trace.match(
  /Module name 'express4' was successfully resolved to '([^']+)' with Package ID '@types\/express\/index\.d\.ts@([^']+)'/,
);
if (!expressResolution) {
  fail(
    'trace did not contain a successful express4 → @types/express package resolution record',
  );
}
const resolvedExpressPath = expressResolution[1];
const resolvedExpressVersion = expressResolution[2];
if (!resolvedExpressPath.endsWith('/node_modules/@types/express4/index.d.ts') || resolvedExpressVersion !== '4.17.23') {
  fail(
    'express4 selected the wrong declaration package',
    `selected ${resolvedExpressPath} with package version ${resolvedExpressVersion}`,
  );
}

const coreResolution = trace.match(
  /Type reference directive 'express-serve-static-core' was successfully resolved to '([^']+)' with Package ID '@types\/express-serve-static-core\/index\.d\.ts@([^']+)'/,
);
if (!coreResolution) {
  fail(
    'trace did not contain a successful express-serve-static-core package resolution record',
  );
}
const resolvedCorePath = coreResolution[1];
const resolvedCoreVersion = coreResolution[2];
const expectedCoreSuffix = '/node_modules/@types/express4/node_modules/@types/express-serve-static-core/index.d.ts';
if (!resolvedCorePath.endsWith(expectedCoreSuffix) || !resolvedCoreVersion.startsWith('4.')) {
  fail(
    'Express 4 resolved an ambient or incompatible express-serve-static-core instead of nested v4',
    `selected ${resolvedCorePath} with package version ${resolvedCoreVersion}`,
  );
}

console.log(
  `✔ Express ${runtime.value.version} / @types ${expressTypes.value.version} package declarations compile `
  + `with nested express-serve-static-core ${coreTypes.value.version} (selected ${resolvedCoreVersion})`,
);
