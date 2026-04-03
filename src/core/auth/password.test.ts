import { describe, expect, it } from 'vitest';

import { createDefaultHasher } from './password';

describe('defaultHasher', () => {
  const hasher = createDefaultHasher();

  it('hashes a password and returns an encoded string', async () => {
    const hash = await hasher.hash('my-password');
    expect(hash).toBeTruthy();
    expect(hash).toContain('$argon2id$');
  });

  it('produces different hashes for the same password (random salt)', async () => {
    const hash1 = await hasher.hash('same-password');
    const hash2 = await hasher.hash('same-password');
    expect(hash1).not.toBe(hash2);
  });

  it('verifies a correct password', async () => {
    const hash = await hasher.hash('correct-password');
    const result = await hasher.verify(hash, 'correct-password');
    expect(result).toBe(true);
  });

  it('rejects an incorrect password', async () => {
    const hash = await hasher.hash('correct-password');
    const result = await hasher.verify(hash, 'wrong-password');
    expect(result).toBe(false);
  });

  it('returns false for malformed hash instead of throwing', async () => {
    const result = await hasher.verify('not-a-valid-hash', 'any-password');
    expect(result).toBe(false);
  });
});
