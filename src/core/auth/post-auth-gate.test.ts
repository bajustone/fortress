import type { FortressPlugin } from '../plugin';
import type { AuthEvent } from './auth-service';
import { describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { Errors } from '../errors';
import { createFortress } from '../fortress';

const SECRET = 'post-auth-gate-test-secret-32chars';

function factorPlugin(
  name: string,
  reason: 'two-factor' | 'webauthn',
  expectedCompletion: string,
  onVerify?: () => void,
): FortressPlugin {
  return {
    name,
    hooks: {
      postAuthGate: {
        reason,
        async evaluate() {
          return { pluginData: { factor: reason } };
        },
        async verify(_ctx, completion) {
          onVerify?.();
          if (completion !== expectedCompletion)
            throw Errors.unauthorized('Invalid factor proof');
        },
      },
    },
  };
}

async function seedUser(fortress: ReturnType<typeof createFortress>): Promise<void> {
  await fortress.auth.createUser({
    email: 'gated@example.com',
    name: 'Gated User',
    password: 'password-123456',
  });
}

describe('post-auth gate', () => {
  it('holds before token issuance and completes exactly once', async () => {
    const database = createTestAdapter();
    let afterLoginCalls = 0;
    const fortress = createFortress({
      jwt: { key: SECRET },
      database,
      plugins: [
        {
          name: 'observer',
          hooks: {
            afterLogin: async (_ctx, result) => {
              afterLoginCalls++;
              return result;
            },
          },
        },
        factorPlugin('factor', 'two-factor', '123456'),
      ],
    });
    await seedUser(fortress);
    const events: AuthEvent[] = [];
    fortress.auth.addAuthObserver(event => void events.push(event));

    const pending = await fortress.auth.login('gated@example.com', 'password-123456');
    expect(pending).toMatchObject({
      status: 'pending',
      accessToken: null,
      refreshToken: null,
      pending: { reason: 'two-factor' },
      pluginData: { factor: 'two-factor' },
    });
    expect(await database.count({ model: 'refresh_token' })).toBe(0);
    expect(await database.count({ model: 'auth_continuation' })).toBe(1);
    const storedContinuation = await database.findOne<{ tokenHash: string }>({
      model: 'auth_continuation',
      where: [{ field: 'userId', operator: '=', value: pending.user.id }],
    });
    expect(events.map(event => event.eventType)).toContain('LOGIN_PENDING');
    expect(events.map(event => event.eventType)).not.toContain('LOGIN_SUCCESS');
    expect(afterLoginCalls).toBe(0);

    if (pending.status !== 'pending' || !pending.pending)
      throw new Error('Expected pending auth challenge');
    expect(storedContinuation?.tokenHash).not.toBe(pending.pending.continuationToken);

    await expect(
      fortress.auth.completePendingAuth(pending.pending.continuationToken, 'wrong'),
    ).rejects.toThrow('Invalid factor proof');
    expect(events.some(event => event.eventType === 'MFA_VERIFY_FAILURE' && event.method === '2fa')).toBe(true);
    expect(await database.count({
      model: 'auth_continuation',
      where: [{ field: 'consumedAt', operator: 'isNull', value: null }],
    })).toBe(1);

    const completed = await fortress.auth.completePendingAuth(
      pending.pending.continuationToken,
      '123456',
    );
    expect(completed).toMatchObject({
      status: 'success',
      method: 'two-factor',
      user: { email: 'gated@example.com' },
    });
    expect(completed.accessToken).toBeTruthy();
    expect(completed.refreshToken).toBeTruthy();
    expect('passwordHash' in completed.user).toBe(false);
    expect(await database.count({ model: 'refresh_token' })).toBe(1);
    expect(events.some(event => event.eventType === 'MFA_VERIFY_SUCCESS' && event.method === '2fa')).toBe(true);
    expect(events.some(event => event.eventType === 'LOGIN_SUCCESS' && event.method === '2fa')).toBe(true);
    expect(afterLoginCalls).toBe(1);

    await expect(
      fortress.auth.completePendingAuth(pending.pending.continuationToken, '123456'),
    ).rejects.toThrow('Invalid or expired auth continuation');
    expect(await database.count({ model: 'refresh_token' })).toBe(1);
  });

  it('reruns remaining gates after one factor completes', async () => {
    const database = createTestAdapter();
    const fortress = createFortress({
      jwt: { key: SECRET },
      database,
      plugins: [
        factorPlugin('totp', 'two-factor', 'totp-ok'),
        factorPlugin('passkey', 'webauthn', 'passkey-ok'),
      ],
    });
    await seedUser(fortress);

    const first = await fortress.auth.login('gated@example.com', 'password-123456');
    if (first.status !== 'pending' || !first.pending)
      throw new Error('Expected first pending auth challenge');
    expect(first.pending.reason).toBe('two-factor');

    const second = await fortress.auth.completePendingAuth(first.pending.continuationToken, 'totp-ok');
    if (second.status !== 'pending' || !second.pending)
      throw new Error('Expected second pending auth challenge');
    expect(second.pending.reason).toBe('webauthn');
    expect(await database.count({ model: 'refresh_token' })).toBe(0);

    const completed = await fortress.auth.completePendingAuth(second.pending.continuationToken, 'passkey-ok');
    expect(completed.status).toBe('success');
    expect(await database.count({ model: 'refresh_token' })).toBe(1);
  });

  it('allows only one concurrent completion to issue a session', async () => {
    const database = createTestAdapter();
    let verifyCalls = 0;
    const fortress = createFortress({
      jwt: { key: SECRET },
      database,
      plugins: [factorPlugin('factor', 'two-factor', 'ok', () => verifyCalls++)],
    });
    await seedUser(fortress);

    const pending = await fortress.auth.login('gated@example.com', 'password-123456');
    if (pending.status !== 'pending' || !pending.pending)
      throw new Error('Expected pending auth challenge');

    const results = await Promise.allSettled([
      fortress.auth.completePendingAuth(pending.pending.continuationToken, 'ok'),
      fortress.auth.completePendingAuth(pending.pending.continuationToken, 'ok'),
    ]);
    expect(results.filter(result => result.status === 'fulfilled')).toHaveLength(1);
    expect(results.filter(result => result.status === 'rejected')).toHaveLength(1);
    expect(verifyCalls).toBe(1);
    expect(await database.count({ model: 'refresh_token' })).toBe(1);
  });
});
