/**
 * Manifest-driven permission seeding.
 *
 * `endpoint().permission(resource, action)` declares the permission an
 * endpoint needs, but a freshly migrated database has no `Permission` row
 * for it. Every consumer used to write the same seed script: walk
 * `fortress.endpoints`, dedupe `(resource, action)` pairs, call
 * `iam.createPermission(...)` for each, optionally bind defaults onto a
 * couple of well-known roles.
 *
 * This module replaces that script. It's idempotent (re-runs safely on a
 * partially seeded DB) and exposed on the {@link Fortress} instance as
 * `fortress.syncPermissionsFromManifest()`.
 */

import type { EndpointDefinition } from '../endpoint';
import type { Permission } from '../types';
import type { IamService } from './iam-service';
import { Errors } from '../errors';

/** Options accepted by {@link runPermissionSync}. */
export interface PermissionSyncOptions {
  /**
   * Endpoints to scan for `meta.permission` declarations. Defaults to the
   * full set registered on the Fortress instance when called via
   * {@link import('../fortress').Fortress.syncPermissionsFromManifest}.
   */
  endpoints?: EndpointDefinition[];

  /**
   * Optional role-name → permissions map. For each role:
   *
   * - `'*'` binds every permission discovered in `endpoints` to the role.
   * - `['resource:action', ...]` binds only the named permissions (one
   *   string per `(resource, action)` pair, colon-separated).
   *
   * Roles are created on demand; existing roles get any missing
   * permissions added. Permissions on a role that aren't requested here
   * are left in place \u2014 this only grants, never revokes.
   *
   * ```ts
   * await fortress.syncPermissionsFromManifest({\n   *   defaultRoles: {\n   *     admin: '*',\n   *     member: ['school:read', 'school:list'],\n   *   },\n   * });\n   * ```
   */
  defaultRoles?: Record<string, '*' | readonly string[]>;
}

/** Result returned by {@link runPermissionSync}. */
export interface PermissionSyncResult {
  /** Number of unique `(resource, action)` pairs discovered. */
  discovered: number;
  /**
   * Number of permissions that already existed in the database before
   * the sync started. (The adapter's `findOrCreatePermission` doesn't
   * distinguish, so this is computed by counting pre-existing
   * permissions; new inserts = `discovered - existing`.)
   */
  existing: number;
  /** Number of new permission rows inserted by this sync run. */
  created: number;
  /**
   * Roles touched by `defaultRoles`, keyed by role name. `bound` is the
   * number of permission bindings newly added during this sync run.
   * Already-bound permissions do not double-count.
   */
  roles: Record<string, { created: boolean; bound: number }>;
}

interface PermissionKey {
  resource: string;
  action: string;
}

function collectUniquePermissions(endpoints: EndpointDefinition[]): PermissionKey[] {
  const seen = new Set<string>();
  const result: PermissionKey[] = [];
  for (const ep of endpoints) {
    const perm = ep.meta?.permission;
    if (!perm)
      continue;
    const key = `${perm.resource}:${perm.action}`;
    if (seen.has(key))
      continue;
    seen.add(key);
    result.push({ resource: perm.resource, action: perm.action });
  }
  return result;
}

function parseRolePermSpec(spec: string): PermissionKey {
  const colon = spec.indexOf(':');
  if (colon < 1 || colon === spec.length - 1) {
    throw Errors.badRequest(
      `Invalid permission spec '${spec}'; expected '<resource>:<action>'`,
    );
  }
  return { resource: spec.slice(0, colon), action: spec.slice(colon + 1) };
}

function dedupePermissions(perms: readonly PermissionKey[]): PermissionKey[] {
  const seen = new Set<string>();
  const result: PermissionKey[] = [];
  for (const perm of perms) {
    const key = `${perm.resource}:${perm.action}`;
    if (seen.has(key))
      continue;
    seen.add(key);
    result.push(perm);
  }
  return result;
}

/**
 * Seed permissions from a set of endpoints and (optionally) bind them onto
 * default roles. Safe to call repeatedly. See {@link PermissionSyncOptions}
 * for shape.
 */
export async function runPermissionSync(
  iam: IamService,
  endpoints: EndpointDefinition[],
  opts: PermissionSyncOptions = {},
): Promise<PermissionSyncResult> {
  const unique = collectUniquePermissions(endpoints);

  // Snapshot existing permissions so we can report created vs. existing.
  // `findOrCreatePermission` upserts, so we can't tell after the fact.
  const before: Permission[] = await iam.listPermissions();
  const existingKeys = new Set(before.map((p: Permission) => `${p.resource}:${p.action}`));

  for (const perm of unique)
    await iam.createPermission(perm);

  const existing = unique.filter(p => existingKeys.has(`${p.resource}:${p.action}`)).length;
  const created = unique.length - existing;

  const rolesReport: Record<string, { created: boolean; bound: number }> = {};

  if (opts.defaultRoles) {
    const allRoles = await iam.getRoles();
    const rolesByName = new Map(allRoles.map(r => [r.name, r] as const));

    for (const [roleName, spec] of Object.entries(opts.defaultRoles)) {
      let permsToBind: PermissionKey[];
      if (spec === '*') {
        // `*` means every permission discovered from the supplied endpoint
        // manifest, not every permission that happens to exist in the DB.
        permsToBind = unique;
      }
      else {
        permsToBind = (spec as readonly string[]).map(parseRolePermSpec);
      }
      permsToBind = dedupePermissions(permsToBind);

      const existingRole = rolesByName.get(roleName);
      let roleCreated = false;
      let roleId: number;
      if (existingRole) {
        roleId = existingRole.id;
      }
      else {
        // createRole both inserts the role and binds the supplied
        // permissions in one call, so we can skip the explicit bind loop
        // below for the create path.
        const role = await iam.createRole(roleName, permsToBind);
        roleId = role.id;
        roleCreated = true;
      }

      let bound = 0;
      if (!roleCreated) {
        const roleDetail = await iam.getRole(roleId);
        const existingRolePerms = new Set(
          roleDetail.permissions.map((p: Permission) => `${p.resource}:${p.action}`),
        );
        for (const perm of permsToBind) {
          const key = `${perm.resource}:${perm.action}`;
          if (existingRolePerms.has(key))
            continue;
          await iam.addPermissionToRole(roleId, perm);
          existingRolePerms.add(key);
          bound++;
        }
      }
      else {
        bound = permsToBind.length;
      }

      rolesReport[roleName] = { created: roleCreated, bound };
    }
  }

  return { discovered: unique.length, existing, created, roles: rolesReport };
}
