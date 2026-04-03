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

describe('multi-key login', () => {
  it('auto-creates email login identifier on user creation', async () => {
    const user = await fortress.auth.createUser({
      email: 'multi@example.com',
      name: 'Multi User',
      password: 'password-123',
    });

    const identifiers = await fortress.auth.getLoginIdentifiers(user.id);
    expect(identifiers).toHaveLength(1);
    expect(identifiers[0].type).toBe('email');
    expect(identifiers[0].value).toBe('multi@example.com');
  });

  it('allows login with phone after adding phone identifier', async () => {
    const user = await fortress.auth.createUser({
      email: 'phone-user@example.com',
      name: 'Phone User',
      password: 'password-123',
    });

    await fortress.auth.addLoginIdentifier(user.id, 'phone', '+250788123456');

    // Login with phone
    const result = await fortress.auth.login('+250788123456', 'password-123');
    expect(result.user.name).toBe('Phone User');
    expect(result.accessToken).toBeTruthy();
  });

  it('allows login with username after adding username identifier', async () => {
    const user = await fortress.auth.createUser({
      email: 'username-user@example.com',
      name: 'Username User',
      password: 'password-123',
    });

    await fortress.auth.addLoginIdentifier(user.id, 'username', 'alice');

    // Login with username
    const result = await fortress.auth.login('alice', 'password-123');
    expect(result.user.name).toBe('Username User');
  });

  it('still allows login with email', async () => {
    await fortress.auth.createUser({
      email: 'email-login@example.com',
      name: 'Email User',
      password: 'password-123',
    });

    const result = await fortress.auth.login('email-login@example.com', 'password-123');
    expect(result.user.name).toBe('Email User');
  });

  it('can remove a login identifier', async () => {
    const user = await fortress.auth.createUser({
      email: 'remove-id@example.com',
      name: 'Remove ID',
      password: 'password-123',
    });

    await fortress.auth.addLoginIdentifier(user.id, 'phone', '+250788999999');
    await fortress.auth.removeLoginIdentifier(user.id, 'phone', '+250788999999');

    // Phone login should fail now (falls back to email lookup, which won't match a phone)
    await expect(
      fortress.auth.login('+250788999999', 'password-123'),
    ).rejects.toThrow('Invalid credentials');
  });

  it('multiple identifiers all share the same password', async () => {
    const user = await fortress.auth.createUser({
      email: 'shared@example.com',
      name: 'Shared Password',
      password: 'same-password',
    });

    await fortress.auth.addLoginIdentifier(user.id, 'phone', '+250781111111');
    await fortress.auth.addLoginIdentifier(user.id, 'username', 'shared_user');

    // All three work with the same password
    const r1 = await fortress.auth.login('shared@example.com', 'same-password');
    const r2 = await fortress.auth.login('+250781111111', 'same-password');
    const r3 = await fortress.auth.login('shared_user', 'same-password');

    expect(r1.user.id).toBe(user.id);
    expect(r2.user.id).toBe(user.id);
    expect(r3.user.id).toBe(user.id);
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
