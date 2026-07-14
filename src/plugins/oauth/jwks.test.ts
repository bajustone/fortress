import { describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { getActiveSigningKey, listJwks, rotateSigningKey } from './jwks';

describe('oauth signing keys', () => {
  it('reuses the active NULL-rotated key instead of generating per issuance', async () => {
    const database = createTestAdapter();
    const first = await getActiveSigningKey(database);
    const second = await getActiveSigningKey(database);

    expect(second.kid).toBe(first.kid);
    await expect(database.count({ model: 'oauth_signing_key' })).resolves.toBe(1);
  });

  it('rotates keys, publishes the retired key during grace, and prunes it afterward', async () => {
    const database = createTestAdapter();
    const first = await getActiveSigningKey(database);
    const second = await rotateSigningKey(database, 3600);

    expect(second.kid).not.toBe(first.kid);
    expect((await listJwks(database, 3600)).keys.map(key => key.kid)).toEqual([second.kid, first.kid]);

    await database.update({
      model: 'oauth_signing_key',
      where: [{ field: 'kid', operator: '=', value: first.kid }],
      data: { rotatedAt: new Date(Date.now() - 7200_000) },
    });
    await rotateSigningKey(database, 3600);
    expect((await listJwks(database, 3600)).keys.map(key => key.kid)).not.toContain(first.kid);
    await expect(database.count({ model: 'oauth_signing_key' })).resolves.toBe(2);
  });
});
