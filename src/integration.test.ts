import type { Fortress } from './core/fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { hashToken } from './core/auth/refresh-token';
import { createFortress } from './core/fortress';
import { createTestAdapter } from './testing';

let fortress: Fortress;

beforeEach(() => {
  fortress = createFortress({
    jwt: { key: 'integration-test-secret-32chars!!' },
    database: createTestAdapter(),
  });
});

describe('auth integration', () => {
  it('creates a user and logs in', async () => {
    const user = await fortress.auth.createUser({
      email: 'alice@example.com',
      name: 'Alice',
      password: 'secure-password-123456',
    });

    expect(user.id).toBeDefined();
    expect(user.email).toBe('alice@example.com');
    expect(user.name).toBe('Alice');

    const result = await fortress.auth.login('alice@example.com', 'secure-password-123456');

    expect(result.user.email).toBe('alice@example.com');
    expect(result.accessToken).toBeTruthy();
    expect(result.refreshToken).toBeTruthy();
  });

  it('seeds refresh-family session metadata at issuance', async () => {
    const database = createTestAdapter();
    const localFortress = createFortress({
      jwt: { key: 'integration-test-secret-32chars!!' },
      database,
    });
    const user = await localFortress.auth.createUser({
      email: 'session-metadata@example.com',
      name: 'Session Metadata',
      password: 'secure-password-123456',
    });

    await localFortress.auth.login('session-metadata@example.com', 'secure-password-123456');
    const stored = await database.findOne<{
      familyCreatedAt: Date;
      lastActiveAt: Date;
      successorTokenHash: string | null;
      rotatedAt: Date | null;
    }>({
      model: 'refresh_token',
      where: [{ field: 'userId', operator: '=', value: user.id }],
    });

    expect(stored?.familyCreatedAt).toBeInstanceOf(Date);
    expect(stored?.lastActiveAt).toBeInstanceOf(Date);
    expect(stored?.familyCreatedAt.getTime()).toBe(stored?.lastActiveAt.getTime());
    expect(stored?.successorTokenHash).toBeNull();
    expect(stored?.rotatedAt).toBeNull();
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

  it('rejects duplicate email on createUser', async () => {
    await fortress.auth.createUser({
      email: 'dupe@example.com',
      name: 'First',
      password: 'password-123456',
    });

    await expect(
      fortress.auth.createUser({
        email: 'dupe@example.com',
        name: 'Second',
        password: 'password-456',
      }),
    ).rejects.toThrow('A user with this email already exists');
  });

  it('verifies a signed token', async () => {
    await fortress.auth.createUser({
      email: 'carol@example.com',
      name: 'Carol',
      password: 'password-123456',
    });

    const login = await fortress.auth.login('carol@example.com', 'password-123456');
    const claims = await fortress.auth.verifyToken(login.accessToken as string);

    expect(claims.name).toBe('Carol');
    expect(claims.iss).toBe('fortress');
    expect(claims.exp).toBeGreaterThan(claims.iat);
  });

  it('refreshes tokens', async () => {
    await fortress.auth.createUser({
      email: 'dave@example.com',
      name: 'Dave',
      password: 'password-123456',
    });

    const login = await fortress.auth.login('dave@example.com', 'password-123456');
    const refreshed = await fortress.auth.refresh(login.refreshToken as string);

    expect(refreshed.accessToken).toBeTruthy();
    expect(refreshed.refreshToken).toBeTruthy();
    // Refresh token must be different (new random bytes)
    expect(refreshed.refreshToken).not.toBe(login.refreshToken as string);
    // Access tokens may be identical if generated in the same second (same iat/exp)
    // — that's fine, the important thing is we got a valid new token
  });

  it('strict refresh concurrency: one winner, loser is treated as replay and revokes the family', async () => {
    await fortress.auth.createUser({
      email: 'concurrent-refresh@example.com',
      name: 'Concurrent',
      password: 'password-123456',
    });

    const login = await fortress.auth.login('concurrent-refresh@example.com', 'password-123456');
    const oldRefreshToken = login.refreshToken as string;

    const results = await Promise.allSettled([
      fortress.auth.refresh(oldRefreshToken),
      fortress.auth.refresh(oldRefreshToken),
    ]);

    const fulfilled = results.filter(r => r.status === 'fulfilled') as PromiseFulfilledResult<{ refreshToken: string }>[];
    const rejected = results.filter(r => r.status === 'rejected') as PromiseRejectedResult[];
    expect(fulfilled).toHaveLength(1);
    expect(rejected).toHaveLength(1);
    expect(String(rejected[0].reason)).toMatch(/Token reuse detected/);

    // Fortress deliberately uses strict replay semantics: the losing
    // duplicate invalidates the entire token family, including the winner's
    // freshly issued refresh token. This favours theft detection over a
    // concurrency grace window.
    await expect(fortress.auth.refresh(fulfilled[0].value.refreshToken)).rejects.toThrow('Token reuse detected');
  });

  it('graces a concurrent double-refresh and returns the same successor', async () => {
    const database = createTestAdapter();
    const graceful = createFortress({
      jwt: {
        key: 'integration-test-secret-32chars!!',
        session: { refreshGraceSeconds: 30 },
      },
      database,
    });
    await graceful.auth.createUser({
      email: 'grace-refresh@example.com',
      name: 'Grace Refresh',
      password: 'password-123456',
    });
    const login = await graceful.auth.login('grace-refresh@example.com', 'password-123456');
    const events: string[] = [];
    graceful.auth.addAuthObserver(event => void events.push(event.eventType));

    const [first, second] = await Promise.all([
      graceful.auth.refresh(login.refreshToken as string),
      graceful.auth.refresh(login.refreshToken as string),
    ]);

    expect(first.refreshToken).toBe(second.refreshToken);
    expect(events).toContain('TOKEN_REUSE_GRACED');
    await expect(graceful.auth.refresh(first.refreshToken)).resolves.toMatchObject({
      refreshToken: expect.any(String),
    });
  });

  it('recovers grace retries across JWT signing-key rotation', async () => {
    const keys = [
      'refresh-key-a-at-least-thirty-two-bytes',
    ];
    const rotating = createFortress({
      jwt: { key: keys, session: { refreshGraceSeconds: 30 } },
      database: createTestAdapter(),
    });
    await rotating.auth.createUser({
      email: 'rotating-grace@example.com',
      name: 'Rotating Grace',
      password: 'password-123456',
    });
    const login = await rotating.auth.login('rotating-grace@example.com', 'password-123456');
    const successor = await rotating.auth.refresh(login.refreshToken as string);

    keys.unshift('refresh-key-b-at-least-thirty-two-bytes');
    const retry = await rotating.auth.refresh(login.refreshToken as string);
    expect(retry.refreshToken).toBe(successor.refreshToken);
  });

  it('honors disabled, warn, and hard fingerprint modes during grace recovery', async () => {
    for (const mode of [undefined, 'warn', true] as const) {
      const database = createTestAdapter();
      const configured = createFortress({
        jwt: {
          key: 'integration-test-secret-32chars!!',
          session: { refreshGraceSeconds: 30 },
          ...(mode === undefined ? {} : { validateRefreshFingerprint: mode }),
        },
        database,
      });
      await configured.auth.createUser({
        email: `fingerprint-${String(mode)}@example.com`,
        name: 'Fingerprint',
        password: 'password-123456',
      });
      const login = await configured.auth.login(
        `fingerprint-${String(mode)}@example.com`,
        'password-123456',
        { userAgent: 'browser-a' },
      );
      const successor = await configured.auth.refresh(login.refreshToken as string, { userAgent: 'browser-a' });
      const retry = configured.auth.refresh(login.refreshToken as string, { userAgent: 'browser-b' });

      if (mode === true) {
        await expect(retry).rejects.toMatchObject({ code: 'TOKEN_REUSE' });
        await expect(configured.auth.refresh(successor.refreshToken)).rejects.toMatchObject({ code: 'TOKEN_REUSE' });
      }
      else {
        await expect(retry).resolves.toMatchObject({ refreshToken: successor.refreshToken });
      }
    }
  });

  it('enforces idle and absolute session caps with distinct errors', async () => {
    const database = createTestAdapter();
    const capped = createFortress({
      jwt: {
        key: 'integration-test-secret-32chars!!',
        session: { idleTimeoutSeconds: 60, absoluteTimeoutSeconds: 120 },
      },
      database,
    });
    const events: string[] = [];
    capped.auth.addAuthObserver(event => void events.push(event.eventType));
    const user = await capped.auth.createUser({
      email: 'session-caps@example.com',
      name: 'Session Caps',
      password: 'password-123456',
    });

    const idleLogin = await capped.auth.login('session-caps@example.com', 'password-123456');
    await database.update({
      model: 'refresh_token',
      where: [{ field: 'userId', operator: '=', value: user.id }],
      data: { lastActiveAt: new Date(Date.now() - 61_000) },
    });
    await expect(capped.auth.refresh(idleLogin.refreshToken as string)).rejects.toMatchObject({
      code: 'SESSION_IDLE_TIMEOUT',
    });
    expect(events).toContain('SESSION_EXPIRED_IDLE');

    const absoluteLogin = await capped.auth.login('session-caps@example.com', 'password-123456');
    await database.update({
      model: 'refresh_token',
      where: [
        { field: 'userId', operator: '=', value: user.id },
        { field: 'isRevoked', operator: '=', value: false },
      ],
      data: {
        familyCreatedAt: new Date(Date.now() - 121_000),
        lastActiveAt: new Date(),
      },
    });
    await expect(capped.auth.refresh(absoluteLogin.refreshToken as string)).rejects.toMatchObject({
      code: 'SESSION_ABSOLUTE_TIMEOUT',
    });
    expect(events).toContain('SESSION_EXPIRED_ABSOLUTE');
  });

  it('enforces session caps on grace-window retries', async () => {
    const database = createTestAdapter();
    const capped = createFortress({
      jwt: {
        key: 'integration-test-secret-32chars!!',
        session: {
          refreshGraceSeconds: 30,
          idleTimeoutSeconds: 60,
          absoluteTimeoutSeconds: 120,
        },
      },
      database,
    });
    const user = await capped.auth.createUser({
      email: 'grace-caps@example.com',
      name: 'Grace Caps',
      password: 'password-123456',
    });

    const idleLogin = await capped.auth.login('grace-caps@example.com', 'password-123456');
    await capped.auth.refresh(idleLogin.refreshToken as string);
    await database.update({
      model: 'refresh_token',
      where: [
        { field: 'userId', operator: '=', value: user.id },
        { field: 'isRevoked', operator: '=', value: false },
      ],
      data: { lastActiveAt: new Date(Date.now() - 61_000) },
    });
    await expect(capped.auth.refresh(idleLogin.refreshToken as string)).rejects.toMatchObject({
      code: 'SESSION_IDLE_TIMEOUT',
    });

    const absoluteLogin = await capped.auth.login('grace-caps@example.com', 'password-123456');
    await capped.auth.refresh(absoluteLogin.refreshToken as string);
    await database.update({
      model: 'refresh_token',
      where: [
        { field: 'userId', operator: '=', value: user.id },
        { field: 'isRevoked', operator: '=', value: false },
      ],
      data: { familyCreatedAt: new Date(Date.now() - 121_000) },
    });
    await expect(capped.auth.refresh(absoluteLogin.refreshToken as string)).rejects.toMatchObject({
      code: 'SESSION_ABSOLUTE_TIMEOUT',
    });
  });

  it('revokes the oldest session when maxSessionsPerUser is reached', async () => {
    const database = createTestAdapter();
    const limited = createFortress({
      jwt: {
        key: 'integration-test-secret-32chars!!',
        session: { maxSessionsPerUser: 1 },
      },
      database,
    });
    await limited.auth.createUser({
      email: 'session-limit@example.com',
      name: 'Session Limit',
      password: 'password-123456',
    });
    const first = await limited.auth.login('session-limit@example.com', 'password-123456');
    const second = await limited.auth.login('session-limit@example.com', 'password-123456');

    await expect(limited.auth.refresh(first.refreshToken as string)).rejects.toMatchObject({ code: 'TOKEN_REUSE' });
    await expect(limited.auth.refresh(second.refreshToken as string)).resolves.toMatchObject({
      refreshToken: expect.any(String),
    });
  });

  it('enforces maxSessionsPerUser under concurrent login and by family age', async () => {
    const database = createTestAdapter();
    const limited = createFortress({
      jwt: {
        key: 'integration-test-secret-32chars!!',
        session: { maxSessionsPerUser: 2 },
      },
      database,
    });
    const user = await limited.auth.createUser({
      email: 'session-race@example.com',
      name: 'Session Race',
      password: 'password-123456',
    });

    const concurrent = await Promise.all([
      limited.auth.login('session-race@example.com', 'password-123456'),
      limited.auth.login('session-race@example.com', 'password-123456'),
      limited.auth.login('session-race@example.com', 'password-123456'),
    ]);
    expect(await database.count({
      model: 'refresh_token',
      where: [{ field: 'isRevoked', operator: '=', value: false }],
    })).toBe(2);

    const oldest = concurrent[1];
    const oldestHash = await hashToken(oldest.refreshToken as string);
    await database.update({
      model: 'refresh_token',
      where: [{ field: 'tokenHash', operator: '=', value: oldestHash }],
      data: { familyCreatedAt: new Date(Date.now() - 60_000) },
    });
    const rotatedOldest = await limited.auth.refresh(oldest.refreshToken as string);
    const newest = await limited.auth.login('session-race@example.com', 'password-123456');

    await expect(limited.auth.refresh(rotatedOldest.refreshToken)).rejects.toMatchObject({ code: 'TOKEN_REUSE' });
    await expect(limited.auth.refresh(newest.refreshToken as string)).resolves.toBeDefined();
    expect(user.id).toBeTruthy();
  });

  it('detects refresh token reuse', async () => {
    await fortress.auth.createUser({
      email: 'eve@example.com',
      name: 'Eve',
      password: 'password-123456',
    });

    const login = await fortress.auth.login('eve@example.com', 'password-123456');
    const oldRefreshToken = login.refreshToken as string;

    // Use the refresh token (rotates it)
    await fortress.auth.refresh(oldRefreshToken);

    // Try to reuse the old token — should detect reuse
    await expect(fortress.auth.refresh(oldRefreshToken)).rejects.toThrow('Token reuse detected');
  });

  it('logout invalidates refresh token', async () => {
    await fortress.auth.createUser({
      email: 'frank@example.com',
      name: 'Frank',
      password: 'password-123456',
    });

    const login = await fortress.auth.login('frank@example.com', 'password-123456');
    await fortress.auth.logout(login.refreshToken as string);

    // Trying to refresh with logged out token should fail
    await expect(fortress.auth.refresh(login.refreshToken as string)).rejects.toThrow('Token reuse detected');
  });

  it('me() returns user by id', async () => {
    const created = await fortress.auth.createUser({
      email: 'grace@example.com',
      name: 'Grace',
      password: 'password-123456',
    });

    const user = await fortress.auth.me(created.id);
    expect(user.name).toBe('Grace');
    expect(user.email).toBe('grace@example.com');
    expect((user as any).passwordHash).toBeUndefined();
  });
});

describe('multi-key login', () => {
  it('auto-creates email login identifier on user creation', async () => {
    const user = await fortress.auth.createUser({
      email: 'multi@example.com',
      name: 'Multi User',
      password: 'password-123456',
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
      password: 'password-123456',
    });

    await fortress.auth.addLoginIdentifier(user.id, 'phone', '+250788123456');

    // Login with phone
    const result = await fortress.auth.login('+250788123456', 'password-123456');
    expect(result.user.name).toBe('Phone User');
    expect(result.accessToken).toBeTruthy();
  });

  it('allows login with username after adding username identifier', async () => {
    const user = await fortress.auth.createUser({
      email: 'username-user@example.com',
      name: 'Username User',
      password: 'password-123456',
    });

    await fortress.auth.addLoginIdentifier(user.id, 'username', 'alice');

    // Login with username
    const result = await fortress.auth.login('alice', 'password-123456');
    expect(result.user.name).toBe('Username User');
  });

  it('still allows login with email', async () => {
    await fortress.auth.createUser({
      email: 'email-login@example.com',
      name: 'Email User',
      password: 'password-123456',
    });

    const result = await fortress.auth.login('email-login@example.com', 'password-123456');
    expect(result.user.name).toBe('Email User');
  });

  it('can remove a login identifier', async () => {
    const user = await fortress.auth.createUser({
      email: 'remove-id@example.com',
      name: 'Remove ID',
      password: 'password-123456',
    });

    await fortress.auth.addLoginIdentifier(user.id, 'phone', '+250788999999');
    await fortress.auth.removeLoginIdentifier(user.id, 'phone', '+250788999999');

    // Phone login should fail now (falls back to email lookup, which won't match a phone)
    await expect(
      fortress.auth.login('+250788999999', 'password-123456'),
    ).rejects.toThrow('Invalid credentials');
  });

  it('multiple identifiers all share the same password', async () => {
    const user = await fortress.auth.createUser({
      email: 'shared@example.com',
      name: 'Shared Password',
      password: 'same-password-123',
    });

    await fortress.auth.addLoginIdentifier(user.id, 'phone', '+250781111111');
    await fortress.auth.addLoginIdentifier(user.id, 'username', 'shared_user');

    // All three work with the same password
    const r1 = await fortress.auth.login('shared@example.com', 'same-password-123');
    const r2 = await fortress.auth.login('+250781111111', 'same-password-123');
    const r3 = await fortress.auth.login('shared_user', 'same-password-123');

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
      password: 'password-123456',
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
      password: 'password-123456',
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
    const canCreate = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'create');
    const canRead = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'read');
    const canDelete = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'post', 'delete');

    expect(canCreate).toBe(true);
    expect(canRead).toBe(true);
    expect(canDelete).toBe(false); // not in the role
  });

  it('permissions work through group membership', async () => {
    const user = await fortress.auth.createUser({
      email: 'kate@example.com',
      name: 'Kate',
      password: 'password-123456',
    });

    const group = await fortress.iam.createGroup('admins');
    await fortress.iam.addUserToGroup(group.id, user.id);

    const role = await fortress.iam.createRole('admin-role', [
      { resource: 'user', action: 'create' },
      { resource: 'user', action: 'delete' },
    ]);

    await fortress.iam.bindRoleToGroup(group.id, role.id);

    // User should have permissions via group
    const canCreate = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'user', 'create');
    const canDelete = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'user', 'delete');
    const canUpdate = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'user', 'update');

    expect(canCreate).toBe(true);
    expect(canDelete).toBe(true);
    expect(canUpdate).toBe(false);
  });

  it('user with no roles has no permissions', async () => {
    const user = await fortress.auth.createUser({
      email: 'larry@example.com',
      name: 'Larry',
      password: 'password-123456',
    });

    const allowed = await fortress.iam.checkPermission({ type: 'USER', id: user.id }, 'anything', 'read');
    expect(allowed).toBe(false);
  });
});

describe('plugin integration', () => {
  it('runs afterLogin hooks', async () => {
    let hookCalled = false;

    const f = createFortress({
      jwt: { key: 'integration-test-secret-32chars!!' },
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
      password: 'password-123456',
    });

    const result = await f.auth.login('plugin@example.com', 'password-123456');

    expect(hookCalled).toBe(true);
    expect(result.pluginData?.customField).toBe('from-plugin');
  });

  it('beforeLogin hook can block login', async () => {
    const f = createFortress({
      jwt: { key: 'integration-test-secret-32chars!!' },
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
      password: 'password-123456',
    });

    const result = await f.auth.login('blocked@example.com', 'password-123456');
    expect((result as any).blocked).toBe(true);
    expect((result as any).reason).toBe('maintenance');
  });
});
