import { describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { getActiveSigningKey } from './jwks';

describe('oauth signing keys', () => {
  it('reuses the active NULL-rotated key instead of generating per issuance', async () => {
    const database = createTestAdapter();
    const first = await getActiveSigningKey(database);
    const second = await getActiveSigningKey(database);

    expect(second.kid).toBe(first.kid);
    await expect(database.count({ model: 'oauth_signing_key' })).resolves.toBe(1);
  });
});
