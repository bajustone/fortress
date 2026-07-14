import type { Fortress } from '../fortress';

import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

const SECRET = 'impersonation-test-secret-32chars!!';

let fortress: Fortress;
let adminId: string;
let targetId: string;

beforeEach(async () => {
  fortress = createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
  });

  const admin = await fortress.auth.createUser({
    email: 'admin@example.com',
    name: 'Admin User',
    password: 'admin-pass-1234',
  });
  adminId = admin.id;

  const target = await fortress.auth.createUser({
    email: 'target@example.com',
    name: 'Target User',
    password: 'target-pass-123',
  });
  targetId = target.id;

  await fortress.iam.bindPermissionToUser(adminId, {
    resource: 'fortress',
    action: 'impersonate',
  });
});

describe('impersonation', () => {
  it('direct service call denies an admin without fortress:impersonate', async () => {
    const other = await fortress.auth.createUser({
      email: 'other-admin@example.com',
      name: 'Other Admin',
      password: 'other-pass-1234',
    });

    await expect(fortress.auth.impersonate(other.id, targetId))
      .rejects
      .toThrow('Insufficient permissions');
  });

  it('http route denies a user without fortress:impersonate', async () => {
    const user = await fortress.auth.createUser({
      email: 'plain@example.com',
      name: 'Plain User',
      password: 'plain-pass-1234',
    });
    const token = await fortress.auth.signToken({
      sub: user.id,
      subjectType: 'USER',
      name: user.name,
      groups: [],
      iss: 'fortress',
    });

    const response = await fortress.handleRequest(new Request('http://localhost/auth/impersonate', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${token}`,
        'content-type': 'application/json',
      },
      body: JSON.stringify({ targetUserId: targetId }),
    }));

    expect(response.status).toBe(403);
  });

  it('returns an access token with act claim containing admin userId', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId);
    if (result.status !== 'impersonation')
      throw new Error('Expected impersonation result');
    const claims = await fortress.auth.verifyToken(result.accessToken as string);

    expect(claims.act).toEqual({ sub: adminId, subjectType: 'USER' });
  });

  it('token has the target user sub, name, and groups', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId);
    if (result.status !== 'impersonation')
      throw new Error('Expected impersonation result');
    const claims = await fortress.auth.verifyToken(result.accessToken as string);

    expect(claims.sub).toBe(targetId);
    expect(claims.name).toBe('Target User');
    expect(claims.groups).toEqual([]);
  });

  it('does not issue a refresh token', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId);
    if (result.status !== 'impersonation')
      throw new Error('Expected impersonation result');

    expect(result.refreshToken).toBeNull();
  });

  it('includes impersonation metadata in pluginData', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId);
    if (result.status !== 'impersonation')
      throw new Error('Expected impersonation result');

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
    if (result.status !== 'impersonation')
      throw new Error('Expected impersonation result');
    const claims = await fortress.auth.verifyToken(result.accessToken as string);

    expect(result.pluginData).toMatchObject({
      impersonation: { expiresInSeconds: 600 },
    });
    // Token lifetime should be roughly 600 seconds
    expect(claims.exp - claims.iat).toBeLessThanOrEqual(600);
    expect(claims.exp - claims.iat).toBeGreaterThanOrEqual(599);
  });

  it('throws NOT_FOUND if target user does not exist or is inactive', async () => {
    await expect(fortress.auth.impersonate(adminId, '99999')).rejects.toThrow('Target user not found');

    await fortress.auth.updateUser(targetId, { isActive: false });
    await expect(fortress.auth.impersonate(adminId, targetId)).rejects.toThrow('Target user not found');
  });

  it('includes reason in pluginData when provided', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId, {
      reason: 'Debugging user account issue #1234',
    });
    if (result.status !== 'impersonation')
      throw new Error('Expected impersonation result');

    expect(result.pluginData).toMatchObject({
      impersonation: {
        adminUserId: adminId,
        reason: 'Debugging user account issue #1234',
      },
    });
  });

  it('returns the target user object without passwordHash', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId);
    if (result.status !== 'impersonation')
      throw new Error('Expected impersonation result');

    expect(result.user.id).toBe(targetId);
    expect(result.user.email).toBe('target@example.com');
    expect(result.user.name).toBe('Target User');
    expect((result.user as unknown as Record<string, unknown>).passwordHash).toBeUndefined();
  });

  // M4 regression: caller-supplied `expirySeconds` must be clamped to a
  // configured maximum so an admin can't mint a years-long act token.
  it('clamps oversized expirySeconds to the configured cap (M4)', async () => {
    const result = await fortress.auth.impersonate(adminId, targetId, {
      expirySeconds: 60 * 60 * 24 * 365 * 10, // 10 years
    });
    if (result.status !== 'impersonation')
      throw new Error('Expected impersonation result');
    const impersonationData = (result.pluginData as { impersonation?: { expiresInSeconds?: number } } | undefined)?.impersonation;
    // Default cap is 3600s.
    expect(impersonationData?.expiresInSeconds).toBeLessThanOrEqual(3600);
  });
});
