import type { Fortress } from '../fortress';

import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

const SECRET = 'impersonation-test-secret-32chars!!';

let fortress: Fortress;
let adminId: number;
let targetId: number;

beforeEach(async () => {
  fortress = createFortress({
    jwt: { secret: SECRET },
    database: createTestAdapter(),
  });

  const admin = await fortress.auth.createUser({
    email: 'admin@example.com',
    name: 'Admin User',
    password: 'admin-pass-123',
  });
  adminId = admin.id;

  const target = await fortress.auth.createUser({
    email: 'target@example.com',
    name: 'Target User',
    password: 'target-pass-123',
  });
  targetId = target.id;
});

describe('impersonation', () => {
  it('returns an access token with act claim containing admin userId', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId);
    const claims = await fortress.auth.verifyToken(result.accessToken as string);

    expect(claims.act).toEqual({ sub: adminId });
  });

  it('token has the target user sub, name, and groups', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId);
    const claims = await fortress.auth.verifyToken(result.accessToken as string);

    expect(claims.sub).toBe(targetId);
    expect(claims.name).toBe('Target User');
    expect(claims.groups).toEqual([]);
  });

  it('does not issue a refresh token', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId);

    expect(result.refreshToken).toBeNull();
  });

  it('includes impersonation metadata in pluginData', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId);

    expect(result.pluginData).toEqual({
      impersonation: {
        adminUserId: adminId,
        reason: null,
        expiresInSeconds: 3600,
      },
    });
  });

  it('uses custom expiry when provided', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId, { expirySeconds: 600 });
    const claims = await fortress.auth.verifyToken(result.accessToken as string);

    expect(result.pluginData).toMatchObject({
      impersonation: { expiresInSeconds: 600 },
    });
    // Token lifetime should be roughly 600 seconds
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(600);
    expect(claims.exp - claims.iat).toBeGreaterThanOrEqual(599);
  });

  it('throws NOT_FOUND if target user does not exist', async () => {
    await expect(fortress.auth.impersonate(adminId, 99999)).rejects.toThrow('Target user not found');
  });

  it('includes reason in pluginData when provided', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId, {
      reason: 'Debugging user account issue #1234',
    });

    expect(result.pluginData).toMatchObject({
      impersonation: {
        adminUserId: adminId,
        reason: 'Debugging user account issue #1234',
      },
    });
  });

  it('returns the target user object without passwordHash', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId);

    expect(result.user.id).toBe(targetId);
    expect(result.user.email).toBe('target@example.com');
    expect(result.user.name).toBe('Target User');
    expect((result.user as unknown as Record<string, unknown>).passwordHash).toBeUndefined();
  });
});
