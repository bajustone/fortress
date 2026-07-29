import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { createRequire } from 'node:module';
import { fileURLToPath } from 'node:url';
import { assertNoRuntimeImport } from './scan-module-imports.mjs';

// Scanned before loading: a stray test-framework import would otherwise fail
// during module evaluation with an unrelated error instead of naming the cause.
// Loading alone could never prove the bundle is vitest-free anyway, since CI
// installs devDependencies and the import would resolve regardless.
for (const artifact of ['../dist/testing.js', '../dist/testing.cjs']) {
  const source = readFileSync(fileURLToPath(new URL(artifact, import.meta.url)), 'utf-8');
  assertNoRuntimeImport(source, 'vitest', artifact.replace('../', ''));
}

const testing = await import('../dist/testing.js');
const testingCjs = createRequire(import.meta.url)('../dist/testing.cjs');
assert.equal(typeof testing.createTestAdapter, 'function');
assert.equal(typeof testingCjs.createTestAdapter, 'function');
// Adapter conformance is public API and must be reachable from both formats.
assert.equal(typeof testing.runAdapterTests, 'function');
assert.equal(typeof testingCjs.runAdapterTests, 'function');

const db = testing.createTestAdapter();
const user = await db.create({
  model: 'user',
  data: {
    email: 'esm-import@fortress.test',
    name: 'ESM import',
    passwordHash: 'hash',
    isActive: true,
  },
});
assert.equal(typeof user.id, 'string');
assert.equal(user.email, 'esm-import@fortress.test');
const cjsUser = await testingCjs.createTestAdapter().create({
  model: 'user',
  data: {
    email: 'cjs-import@fortress.test',
    name: 'CJS import',
    passwordHash: 'hash',
    isActive: true,
  },
});
assert.equal(typeof cjsUser.id, 'string');
console.log('✔ dist/testing exposes runAdapterTests, creates adapters under Node ESM and CJS, and imports no vitest');
