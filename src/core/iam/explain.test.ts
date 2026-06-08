/**
 * Tests for `explainPermission` (P1-8 operator-debugging helper).
 */

import { describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';
import { explainPermission } from './explain';

const SECRET = 'explain-test-secret-at-least-32-bytes!';

function setup() {
  const fortress = createFortress({
    jwt: { secret: SECRET },
    database: createTestAdapter(),
  });
  return { fortress };
}

describe('explainPermission', () => {
  it('returns allowed=false with no sources for a user with no bindings', async () => {
    const { fortress } = setup();
    const user = await fortress.auth.createUser({
      email: 'noperm@example.com',
      name: 'Noperm',
      password: 'noperm-password-1234',
    });
    const result = await explainPermission(
      fortress.config.database,
      fortress.iam,
      { type: 'USER', id: user.id },
      'article',
      'read',
    );
    expect(result.allowed).toBe(false);
    expect(result.sources).toEqual([]);
    expect(result.roleBindings).toEqual([]);
    expect(result.groupMemberships).toEqual([]);
  });

  it('attributes a permission granted via a role binding', async () => {
    const { fortress } = setup();
    const user = await fortress.auth.createUser({
      email: 'role@example.com',
      name: 'Role User',
      password: 'role-password-1234',
    });
    const role = await fortress.iam.createRole('editor', [
      { resource: 'article', action: 'create' },
      { resource: 'article', action: 'update' },
    ]);
    await fortress.iam.bindRoleToUser(user.id, role.id);

    const explain = await explainPermission(
      fortress.config.database,
      fortress.iam,
      { type: 'USER', id: user.id },
      'article',
      'create',
    );
    expect(explain.allowed).toBe(true);
    expect(explain.sources).toHaveLength(1);
    expect(explain.sources[0].via).toBe('role');
    expect(explain.sources[0].role).toBe('editor');
    expect(explain.sources[0].permission.resource).toBe('article');
    expect(explain.sources[0].permission.action).toBe('create');
    expect(explain.roleBindings.map(rb => rb.role)).toEqual(['editor']);
  });

  it('attributes a permission granted via a direct binding', async () => {
    const { fortress } = setup();
    const user = await fortress.auth.createUser({
      email: 'direct@example.com',
      name: 'Direct',
      password: 'direct-password-1234',
    });
    await fortress.iam.bindPermissionToUser(user.id, { resource: 'article', action: 'publish' });

    const explain = await explainPermission(
      fortress.config.database,
      fortress.iam,
      { type: 'USER', id: user.id },
      'article',
      'publish',
    );
    expect(explain.allowed).toBe(true);
    expect(explain.sources).toHaveLength(1);
    expect(explain.sources[0].via).toBe('direct-user');
  });

  it('attributes a permission inherited via a group role binding', async () => {
    const { fortress } = setup();
    const user = await fortress.auth.createUser({
      email: 'group@example.com',
      name: 'Group',
      password: 'group-password-1234',
    });
    const group = await fortress.iam.createGroup('eng', 'Engineering');
    await fortress.iam.addUserToGroup(group.id, user.id);
    const role = await fortress.iam.createRole('viewer', [
      { resource: 'article', action: 'read' },
    ]);
    await fortress.iam.bindRoleToGroup(group.id, role.id);

    const explain = await explainPermission(
      fortress.config.database,
      fortress.iam,
      { type: 'USER', id: user.id },
      'article',
      'read',
    );
    expect(explain.allowed).toBe(true);
    expect(explain.sources).toHaveLength(1);
    expect(explain.sources[0].via).toBe('role');
    expect(explain.sources[0].role).toBe('viewer');
    expect(explain.sources[0].group).toEqual({ id: group.id, name: 'eng' });
    expect(explain.groupMemberships).toEqual([{ id: group.id, name: 'eng' }]);
  });

  it('applies DENY > ALLOW precedence', async () => {
    const { fortress } = setup();
    const user = await fortress.auth.createUser({
      email: 'deny@example.com',
      name: 'Deny',
      password: 'deny-password-1234',
    });
    const allowRole = await fortress.iam.createRole('allow-articles', [
      { resource: 'article', action: 'delete' },
    ]);
    await fortress.iam.bindRoleToUser(user.id, allowRole.id);
    // Direct DENY overrides the role grant.
    await fortress.iam.bindPermissionToUser(user.id, {
      resource: 'article',
      action: 'delete',
      effect: 'DENY',
    });

    const explain = await explainPermission(
      fortress.config.database,
      fortress.iam,
      { type: 'USER', id: user.id },
      'article',
      'delete',
    );
    expect(explain.allowed).toBe(false);
    expect(explain.sources.length).toBeGreaterThanOrEqual(2);
    expect(explain.sources.some(s => s.permission.effect === 'DENY')).toBe(true);
    expect(explain.sources.some(s => (s.permission.effect ?? 'ALLOW') === 'ALLOW')).toBe(true);
  });
});
