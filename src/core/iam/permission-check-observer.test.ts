import type { Fortress } from '../fortress';
import type { PermissionCheckEvent } from './iam-service';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

let fortress: Fortress;
const SECRET = 'perm-check-observer-test-32chars!!';

async function seedUserAndRole(): Promise<{ userId: string }> {
  const user = await fortress.auth.createUser({
    email: 'perm@example.com',
    name: 'Perm User',
    password: 'password-123456',
  });
  const role = await fortress.iam.createRole('editor', [
    { resource: 'post', action: 'read' },
  ]);
  await fortress.iam.bindRoleToUser(user.id, role.id);
  return { userId: user.id };
}

describe('addPermissionCheckObserver', () => {
  beforeEach(() => {
    fortress = createFortress({
      jwt: { key: SECRET },
      database: createTestAdapter(),
      rbac: { cache: { ttlSeconds: 30, maxEntries: 100 } },
    });
  });

  it('fires synchronously on every checkPermission call with cached flag', async () => {
    const { userId } = await seedUserAndRole();
    const events: PermissionCheckEvent[] = [];
    fortress.iam.addPermissionCheckObserver(e => void events.push(e));

    const allow1 = await fortress.iam.checkPermission({ type: 'USER', id: userId }, 'post', 'read');
    const allow2 = await fortress.iam.checkPermission({ type: 'USER', id: userId }, 'post', 'read');

    expect(allow1).toBe(true);
    expect(allow2).toBe(true);
    expect(events).toHaveLength(2);

    // First call: cache miss; second call: cache hit.
    expect(events[0]?.cached).toBe(false);
    expect(events[1]?.cached).toBe(true);

    // Common fields.
    for (const ev of events) {
      expect(ev.subjectType).toBe('USER');
      expect(ev.subjectId).toBe(userId);
      expect(ev.resource).toBe('post');
      expect(ev.action).toBe('read');
      expect(ev.allowed).toBe(true);
      expect(ev.durationSeconds).toBeGreaterThan(0);
    }
  });

  it('records allowed=false when the subject lacks permission', async () => {
    const { userId } = await seedUserAndRole();
    const events: PermissionCheckEvent[] = [];
    fortress.iam.addPermissionCheckObserver(e => void events.push(e));

    const denied = await fortress.iam.checkPermission({ type: 'USER', id: userId }, 'post', 'delete');

    expect(denied).toBe(false);
    expect(events).toHaveLength(1);
    expect(events[0]?.allowed).toBe(false);
  });

  it('returns an unsubscribe function', async () => {
    const { userId } = await seedUserAndRole();
    const events: PermissionCheckEvent[] = [];
    const off = fortress.iam.addPermissionCheckObserver(e => void events.push(e));
    off();

    await fortress.iam.checkPermission({ type: 'USER', id: userId }, 'post', 'read');
    expect(events).toHaveLength(0);
  });

  it('observer exceptions do not break the permission check', async () => {
    const { userId } = await seedUserAndRole();
    fortress.iam.addPermissionCheckObserver(() => {
      throw new Error('observer bug');
    });

    const allowed = await fortress.iam.checkPermission({ type: 'USER', id: userId }, 'post', 'read');
    expect(allowed).toBe(true);
  });
});
