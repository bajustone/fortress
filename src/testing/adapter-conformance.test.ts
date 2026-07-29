import { beforeEach, describe, expect, it } from 'vitest';
import { assertStringId, runAdapterTests } from './adapter-conformance';
import { createTestAdapter } from './index';

describe('conformance regression guards', () => {
  it('rejects a deliberately broken numeric-id adapter result', () => {
    expect(() => assertStringId({ id: 123 })).toThrow(/non-string id \(number\)/);
  });
});

// Run conformance tests against the built-in test adapter
describe('adapter conformance: createTestAdapter', () => {
  runAdapterTests(createTestAdapter, { beforeEach, describe, it });
});
