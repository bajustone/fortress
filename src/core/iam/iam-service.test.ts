import type { Fortress } from '../fortress';
import { beforeEach, describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';

const SECRET = 'iam-service-test-secret-32chars!';

describe('iam-service: isSystem flag', () => {
  let fortress: Fortress;

  beforeEach(() => {
    fortress = createFortress({
      jwt: { secret: SECRET },
      database: createTestAdapter(),
    });
  });

  it('creates a role with isSystem flag', async () => {
    const role = await fortress.iam.createRole(
      'super-admin',
      [{ resource: 'users', action: 'read' }],
      'System admin role',
    );

    expect(role.id).toBeDefined();
    expect(role.name).toBe('super-admin');
    // By default isSystem should be false (or falsy in SQLite)
    expect(role.isSystem).toBeFalsy();
  });

  it('deleteRole throws for system roles', async () => {
    // Create a role, then manually set isSystem via raw DB
    const role = await fortress.iam.createRole(
      'built-in-admin',
      [{ resource: 'users', action: 'manage' }],
    );

    // Mark as system role via database update
    await fortress.config.database.update({
      model: 'role',
      where: [{ field: 'id', operator: '=', value: role.id }],
      data: { isSystem: true },
    });

    await expect(fortress.iam.deleteRole(role.id)).rejects.toThrow(
      'Cannot delete a system role',
    );
  });

  it('deleteRole succeeds for non-system roles', async () => {
    const role = await fortress.iam.createRole(
      'temp-role',
      [{ resource: 'reports', action: 'read' }],
    );

    await expect(fortress.iam.deleteRole(role.id)).resolves.toBeUndefined();
  });
});
