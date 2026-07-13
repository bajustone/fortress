import type { Fortress } from '../fortress';
import type { AuthEvent } from './auth-service';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';
import { assertSuccess } from '../types';

let fortress: Fortress;
const SECRET = 'auth-observer-test-secret-32chars!!';

async function seed(): Promise<void> {
  await fortress.auth.createUser({
    email: 'auth-obs@example.com',
    name: 'Observer User',
    password: 'password-123456',
  });
}

describe('addAuthObserver', () => {
  beforeEach(() => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
    });
  });

  it('emits REGISTER on createUser', async () => {
    const events: AuthEvent[] = [];
    fortress.auth.addAuthObserver(e => void events.push(e));

    await fortress.auth.createUser({
      email: 'register@example.com',
      name: 'Reg User',
      password: 'password-123456',
    });

    const reg = events.find(e => e.eventType === 'REGISTER');
    expect(reg).toBeDefined();
    expect(reg?.outcome).toBe('success');
    expect(reg?.actorId).toBeTruthy();
    expect(reg?.identifier).toBe('register@example.com');
  });

  it('emits LOGIN_SUCCESS with actorId + identifier', async () => {
    await seed();
    const events: AuthEvent[] = [];
    fortress.auth.addAuthObserver(e => void events.push(e));

    await fortress.auth.login('auth-obs@example.com', 'password-123456');

    const success = events.find(e => e.eventType === 'LOGIN_SUCCESS');
    expect(success).toBeDefined();
    expect(success?.outcome).toBe('success');
    expect(success?.identifier).toBe('auth-obs@example.com');
    expect(success?.actorId).toBeTruthy();
    expect(success?.method).toBe('password');
  });

  it('emits LOGIN_FAILURE on bad credentials with error.code', async () => {
    await seed();
    const events: AuthEvent[] = [];
    fortress.auth.addAuthObserver(e => void events.push(e));

    await expect(
      fortress.auth.login('auth-obs@example.com', 'wrong-password'),
    ).rejects.toThrow();

    const failure = events.find(e => e.eventType === 'LOGIN_FAILURE');
    expect(failure).toBeDefined();
    expect(failure?.outcome).toBe('failure');
    expect(failure?.identifier).toBe('auth-obs@example.com');
    expect(failure?.error?.code).toBe('UNAUTHORIZED');
  });

  it('emits TOKEN_REFRESH on successful refresh', async () => {
    await seed();
    const login = await fortress.auth.login('auth-obs@example.com', 'password-123456');
    assertSuccess(login);
    const events: AuthEvent[] = [];
    fortress.auth.addAuthObserver(e => void events.push(e));

    await fortress.auth.refresh(login.refreshToken as string);

    const refresh = events.find(e => e.eventType === 'TOKEN_REFRESH');
    expect(refresh).toBeDefined();
    expect(refresh?.outcome).toBe('success');
    expect(refresh?.actorId).toBeTruthy();
  });

  it('emits TOKEN_REUSE_DETECTED on reuse of a revoked refresh token', async () => {
    await seed();
    const login = await fortress.auth.login('auth-obs@example.com', 'password-123456');
    assertSuccess(login);
    await fortress.auth.refresh(login.refreshToken as string);
    const events: AuthEvent[] = [];
    fortress.auth.addAuthObserver(e => void events.push(e));

    await expect(
      fortress.auth.refresh(login.refreshToken as string),
    ).rejects.toThrow();

    const reuse = events.find(e => e.eventType === 'TOKEN_REUSE_DETECTED');
    expect(reuse).toBeDefined();
    expect(reuse?.metadata?.tokenFamily).toBeDefined();
  });

  it('commits hard fingerprint revocation and emits before rejecting', async () => {
    const database = createTestAdapter();
    const hardened = createFortress({
      jwt: {
        key: SECRET,
        validateRefreshFingerprint: true,
      },
      database,
    });
    await hardened.auth.createUser({
      email: 'fingerprint-hard@example.com',
      name: 'Fingerprint Hard',
      password: 'password-123456',
    });
    const login = await hardened.auth.login(
      'fingerprint-hard@example.com',
      'password-123456',
      { userAgent: 'browser-a' },
    );
    assertSuccess(login);
    const events: AuthEvent[] = [];
    hardened.auth.addAuthObserver(event => void events.push(event));

    await expect(
      hardened.auth.refresh(login.refreshToken as string, { userAgent: 'browser-b' }),
    ).rejects.toThrow('Refresh token fingerprint mismatch');

    expect(events.some(event => event.eventType === 'TOKEN_FINGERPRINT_MISMATCH')).toBe(true);
    const rows = await database.findMany<{ isRevoked: boolean }>({ model: 'refresh_token' });
    expect(rows.every(row => row.isRevoked)).toBe(true);
  });

  it('emits LOGOUT with actorId', async () => {
    await seed();
    const login = await fortress.auth.login('auth-obs@example.com', 'password-123456');
    assertSuccess(login);
    const events: AuthEvent[] = [];
    fortress.auth.addAuthObserver(e => void events.push(e));

    await fortress.auth.logout(login.refreshToken as string);

    const logout = events.find(e => e.eventType === 'LOGOUT');
    expect(logout).toBeDefined();
    expect(logout?.actorId).toBeTruthy();
  });

  it('fires multiple observers in registration order', async () => {
    await seed();
    const order: string[] = [];
    fortress.auth.addAuthObserver(() => void order.push('first'));
    fortress.auth.addAuthObserver(() => void order.push('second'));

    await fortress.auth.login('auth-obs@example.com', 'password-123456');

    // Each observer fires per event — we only care about relative order
    // of first vs second for the same event.
    const loginIdx = order.findIndex(v => v === 'first');
    const afterFirst = order.slice(loginIdx + 1);
    expect(afterFirst[0]).toBe('second');
  });

  it('unsubscribe stops the observer from being invoked', async () => {
    await seed();
    const events: AuthEvent[] = [];
    const off = fortress.auth.addAuthObserver(e => void events.push(e));

    off();
    await fortress.auth.login('auth-obs@example.com', 'password-123456');

    expect(events).toHaveLength(0);
  });

  it('observer exceptions do not break the auth flow', async () => {
    await seed();
    fortress.auth.addAuthObserver(() => {
      throw new Error('observer bug');
    });

    // Login should still succeed — the error is caught inside the listener list.
    const result = await fortress.auth.login('auth-obs@example.com', 'password-123456');
    assertSuccess(result);
    expect(result.status).toBe('success');
    expect(result.accessToken).toBeTruthy();
  });
});
