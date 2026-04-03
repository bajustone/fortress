import type { Fortress } from './core/fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createFortress } from './core/fortress';
import { createTestAdapter } from './testing';

let fortress: Fortress;

beforeEach(() => {
  fortress = createFortress({
    jwt: { secret: 'integration-test-secret-32chars!!' },
    database: createTestAdapter(),
  });
});

describe('auth integration', () => {
  it('creates a user and logs in', async () => {
    const user = await fortress.auth.createUser({
      email: 'alice@example.com',
      name: 'Alice',
      password: 'secure-password-123',
    });

    expect(user.id).toBeDefined();
    expect(user.email).toBe('alice@example.com');
    expect(user.name).toBe('Alice');

    const result = await fortress.auth.login('alice@example.com', 'secure-password-123');

    expect(result.user.email).toBe('alice@example.com');
    expect(result.accessToken).toBeTruthy();
    expect(result.refreshToken).toBeTruthy();
  });

  it('rejects invalid credentials', async () => {
    await fortress.auth.createUser({
      email: 'bob@example.com',
      name: 'Bob',
      password: 'correct-password',
    });

    await expect(
      fortress.auth.login('bob@example.com', 'wrong-password'),
    ).rejects.toThrow('Invalid credentials');
  });

  it('rejects login for non-existent user', async () => {
    await expect(
      fortress.auth.login('nobody@example.com', 'any-password'),
    ).rejects.toThrow('Invalid credentials');
  });

  it('verifies a signed token', async () => {
    await fortress.auth.createUser({
      email: 'carol@example.com',
      name: 'Carol',
      password: 'password-123',
    });

    const { accessToken } = await fortress.auth.login('carol@example.com', 'password-123');
    const claims = await fortress.auth.verifyToken(accessToken!);

    expect(claims.name).toBe('Carol');
    expect(claims.iss).toBe('fortress');
    expect(claims.exp).toBeGreaterThan(claims.iat);
  });

  it('refreshes tokens', async () => {
    await fortress.auth.createUser({
      email: 'dave@example.com',
      name: 'Dave',
      password: 'password-123',
    });

    const login = await fortress.auth.login('dave@example.com', 'password-123');
    const refreshed = await fortress.auth.refresh(login.refreshToken!);

    expect(refreshed.accessToken).toBeTruthy();
    expect(refreshed.refreshToken).toBeTruthy();
    // Refresh token must be different (new random bytes)
    expect(refreshed.refreshToken).not.toBe(login.refreshToken);
    // Access tokens may be identical if generated in the same second (same iat/exp)
    // — that's fine, the important thing is we got a valid new token
  });

  it('detects refresh token reuse', async () => {
    await fortress.auth.createUser({
      email: 'eve@example.com',
      name: 'Eve',
      password: 'password-123',
    });

    const login = await fortress.auth.login('eve@example.com', 'password-123');
    const oldRefreshToken = login.refreshToken!;

    // Use the refresh token (rotates it)
    await fortress.auth.refresh(oldRefreshToken);

    // Try to reuse the old token — should detect reuse
    await expect(fortress.auth.refresh(oldRefreshToken)).rejects.toThrow('Token reuse detected');
  });

  it('logout invalidates refresh token', async () => {
    await fortress.auth.createUser({
      email: 'frank@example.com',
      name: 'Frank',
      password: 'password-123',
    });

    const login = await fortress.auth.login('frank@example.com', 'password-123');
    await fortress.auth.logout(login.refreshToken!);

    // Trying to refresh with logged out token should fail
    await expect(fortress.auth.refresh(login.refreshToken!)).rejects.toThrow('Token reuse detected');
  });

  it('me() returns user by id', async () => {
    const created = await fortress.auth.createUser({
      email: 'grace@example.com',
      name: 'Grace',
      password: 'password-123',
    });

    const user = await fortress.auth.me(created.id);
    expect(user.name).toBe('Grace');
    expect(user.email).toBe('grace@example.com');
  });
});

describe('iAM integration', () => {
  it('creates groups and adds users', async () => {
    const user = await fortress.auth.createUser({
      email: 'ian@example.com',
      name: 'Ian',
      password: 'password-123',
    });

    const group = await fortress.iam.createGroup('editors', 'Content editors');
    expect(group.name).toBe('editors');

    await fortress.iam.addUserToGroup(group.id, user.id);
  });

  it('creates roles with permissions and checks access', async () => {
    // Create a user
    const user = await fortress.auth.createUser({
      email: 'jane@example.com',
      name: 'Jane',
      password: 'password-123',
    });

    // Create a role with permissions
    const role = await fortress.iam.createRole('editor', [
      { resource: 'post', action: 'create' },
      { resource: 'post', action: 'read' },
      { resource: 'post', action: 'update' },
    ]);

    // Bind role directly to user
    await fortress.iam.bindRoleToUser(user.id, role.id);

    // Check permissions
    const canCreate = await fortress.iam.checkPermission(user.id, 'post', 'create');
    const canRead = await fortress.iam.checkPermission(user.id, 'post', 'read');
    const canDelete = await fortress.iam.checkPermission(user.id, 'post', 'delete');

    expect(canCreate).toBe(true);
    expect(canRead).toBe(true);
    expect(canDelete).toBe(false); // not in the role
  });

  it('permissions work through group membership', async () => {
    const user = await fortress.auth.createUser({
      email: 'kate@example.com',
      name: 'Kate',
      password: 'password-123',
    });

    const group = await fortress.iam.createGroup('admins');
    await fortress.iam.addUserToGroup(group.id, user.id);

    const role = await fortress.iam.createRole('admin-role', [
      { resource: 'user', action: 'create' },
      { resource: 'user', action: 'delete' },
    ]);

    await fortress.iam.bindRoleToGroup(group.id, role.id);

    // User should have permissions via group
    const canCreate = await fortress.iam.checkPermission(user.id, 'user', 'create');
    const canDelete = await fortress.iam.checkPermission(user.id, 'user', 'delete');
    const canUpdate = await fortress.iam.checkPermission(user.id, 'user', 'update');

    expect(canCreate).toBe(true);
    expect(canDelete).toBe(true);
    expect(canUpdate).toBe(false);
  });

  it('user with no roles has no permissions', async () => {
    const user = await fortress.auth.createUser({
      email: 'larry@example.com',
      name: 'Larry',
      password: 'password-123',
    });

    const allowed = await fortress.iam.checkPermission(user.id, 'anything', 'read');
    expect(allowed).toBe(false);
  });
});

describe('plugin integration', () => {
  it('runs afterLogin hooks', async () => {
    let hookCalled = false;

    const f = createFortress({
      jwt: { secret: 'integration-test-secret-32chars!!' },
      database: createTestAdapter(),
      plugins: [
        {
          name: 'test-hook',
          hooks: {
            async afterLogin(_ctx, result) {
              hookCalled = true;
              return { ...result, pluginData: { customField: 'from-plugin' } };
            },
          },
        },
      ],
    });

    await f.auth.createUser({
      email: 'plugin@example.com',
      name: 'Plugin Test',
      password: 'password-123',
    });

    const result = await f.auth.login('plugin@example.com', 'password-123');

    expect(hookCalled).toBe(true);
    expect(result.pluginData?.customField).toBe('from-plugin');
  });

  it('beforeLogin hook can block login', async () => {
    const f = createFortress({
      jwt: { secret: 'integration-test-secret-32chars!!' },
      database: createTestAdapter(),
      plugins: [
        {
          name: 'blocker',
          hooks: {
            async beforeLogin() {
              return { stop: true, response: { blocked: true, reason: 'maintenance' } };
            },
          },
        },
      ],
    });

    await f.auth.createUser({
      email: 'blocked@example.com',
      name: 'Blocked',
      password: 'password-123',
    });

    const result = await f.auth.login('blocked@example.com', 'password-123');
    expect((result as any).blocked).toBe(true);
    expect((result as any).reason).toBe('maintenance');
  });
});
