import type { Fortress } from '../fortress';
import { describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';
import { endpoint, obj, str } from '../schema-builder';

const SECRET = 'permission-sync-test-secret-3232!';

async function buildFortress(): Promise<Fortress> {
  const fortress = createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
    routes: {
      listSchools: endpoint('GET', '/schools')
        .summary('List schools')
        .security('bearer')
        .permission('school', 'list')
        .response(200, 'OK', obj({ data: str() }, 'data'))
        .handler('listSchools')
        .build(),
      readSchool: endpoint('GET', '/schools/:id')
        .summary('Read school')
        .security('bearer')
        .permission('school', 'read')
        .params(obj({ id: str() }, 'id'))
        .response(200, 'OK', obj({ data: str() }, 'data'))
        .handler('readSchool')
        .build(),
      createSchool: endpoint('POST', '/schools')
        .summary('Create school')
        .security('bearer')
        .permission('school', 'create')
        .response(201, 'Created', obj({ data: str() }, 'data'))
        .handler('createSchool')
        .build(),
      // Endpoint without a permission declaration — should be ignored.
      ping: endpoint('GET', '/ping')
        .summary('Ping')
        .security('none')
        .response(200, 'OK', obj({ ok: str() }, 'ok'))
        .handler('ping')
        .build(),
    },
  });
  await fortress.migrate();
  return fortress;
}

describe('fortress.syncPermissionsFromManifest', () => {
  it('discovers unique (resource, action) pairs and creates each permission', async () => {
    const fortress = await buildFortress();
    const result = await fortress.syncPermissionsFromManifest();

    // Default scope is fortress.endpoints, which includes the 3 host
    // perms plus the system permissions declared on fortress's own
    // auth/IAM endpoints. We assert the host perms made it in and that
    // every discovered perm was created (none existed before).
    expect(result.discovered).toBeGreaterThanOrEqual(3);
    expect(result.created).toBe(result.discovered);
    expect(result.existing).toBe(0);

    const perms = await fortress.iam.listPermissions();
    const keys = perms.map(p => `${p.resource}:${p.action}`);
    expect(keys).toContain('school:create');
    expect(keys).toContain('school:list');
    expect(keys).toContain('school:read');
  });

  it('is idempotent on a partially seeded database', async () => {
    const fortress = await buildFortress();
    await fortress.iam.createPermission({ resource: 'school', action: 'list' });

    const first = await fortress.syncPermissionsFromManifest();
    // The pre-seeded school:list is the only existing perm; everything
    // else discovered should be a fresh insert.
    expect(first.existing).toBe(1);
    expect(first.created).toBe(first.discovered - 1);

    // Re-running adds nothing.
    const second = await fortress.syncPermissionsFromManifest();
    expect(second.created).toBe(0);
    expect(second.existing).toBe(second.discovered);
  });

  it('binds manifest-discovered permissions onto a role when spec is "*"', async () => {
    const fortress = await buildFortress();
    // A stale/unrelated permission in the DB must not be pulled in by '*'.
    await fortress.iam.createPermission({ resource: 'stale', action: 'delete' });

    const result = await fortress.syncPermissionsFromManifest({
      defaultRoles: { admin: '*' },
    });

    expect(result.roles.admin?.created).toBe(true);
    expect(result.roles.admin?.bound).toBe(result.discovered);

    const roles = await fortress.iam.getRoles();
    const admin = roles.find(r => r.name === 'admin');
    expect(admin).toBeDefined();
    const detail = await fortress.iam.getRole(admin!.id);
    expect(detail.permissions.length).toBe(result.discovered);
    // Spot-check that the host perms are among them and stale DB-only perms are not.
    const keys = detail.permissions.map(p => `${p.resource}:${p.action}`);
    expect(keys).toContain('school:create');
    expect(keys).not.toContain('stale:delete');
  });

  it('binds only the listed permissions when spec is a string list', async () => {
    const fortress = await buildFortress();
    const result = await fortress.syncPermissionsFromManifest({
      defaultRoles: { member: ['school:read', 'school:list'] },
    });

    expect(result.roles.member?.bound).toBe(2);

    const roles = await fortress.iam.getRoles();
    const member = roles.find(r => r.name === 'member')!;
    const detail = await fortress.iam.getRole(member.id);
    const keys = detail.permissions.map(p => `${p.resource}:${p.action}`).sort();
    expect(keys).toEqual(['school:list', 'school:read']);
  });

  it('only grants on re-run — never revokes', async () => {
    const fortress = await buildFortress();
    await fortress.syncPermissionsFromManifest({
      defaultRoles: { member: ['school:read', 'school:list', 'school:create'] },
    });

    // Subsequent call asks for fewer perms — existing should stay, but the
    // report should not count already-bound permissions as newly bound.
    const second = await fortress.syncPermissionsFromManifest({
      defaultRoles: { member: ['school:read'] },
    });
    expect(second.roles.member?.bound).toBe(0);

    const roles = await fortress.iam.getRoles();
    const member = roles.find(r => r.name === 'member')!;
    const detail = await fortress.iam.getRole(member.id);
    const keys = detail.permissions.map(p => `${p.resource}:${p.action}`).sort();
    expect(keys).toEqual(['school:create', 'school:list', 'school:read']);
  });

  it('rejects an invalid role-permission spec', async () => {
    const fortress = await buildFortress();
    await expect(
      fortress.syncPermissionsFromManifest({ defaultRoles: { admin: ['nocolon'] } }),
    ).rejects.toThrow(/Invalid permission spec/);
  });

  it('accepts an explicit endpoints array', async () => {
    const fortress = await buildFortress();
    const result = await fortress.syncPermissionsFromManifest({
      endpoints: [
        endpoint('GET', '/x')
          .summary('x')
          .security('bearer')
          .permission('widget', 'twiddle')
          .response(200, 'OK')
          .handler('x')
          .build(),
      ],
    });
    expect(result.discovered).toBe(1);
    expect(result.created).toBe(1);
  });
});
