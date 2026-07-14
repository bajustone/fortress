import assert from 'node:assert/strict';
import { createRequire } from 'node:module';

const testing = await import('../dist/testing.js');
const testingCjs = createRequire(import.meta.url)('../dist/testing.cjs');
assert.equal(typeof testing.createTestAdapter, 'function');
assert.equal(typeof testingCjs.createTestAdapter, 'function');

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
console.log('✔ dist/testing imports and creates adapters under Node ESM and CJS');
