/**
 * Permission debugging helper (P1-8).
 *
 * Answers the operator-console question "why does subject X have (or not
 * have) permission `resource:action`?" by walking the same data the
 * permission evaluator uses — direct bindings, role bindings, group
 * memberships (for USER subjects) — and emitting a structured
 * explanation listing every grant + its source.
 *
 * Designed as a free function rather than a new {@link IamService} method
 * to keep the surface narrow and the DB queries explicit.
 *
 * @module
 */

import type { DatabaseAdapter } from '../../adapters/database';
import type { Permission, PermissionContext, Role, Subject } from '../types';
import type { IamService } from './iam-service';

export interface PermissionExplanationSource {
  /** Where the grant came from. */
  via: 'direct-user' | 'direct-group' | 'direct-service-account' | 'role';
  /** Role name when `via === 'role'`. */
  role?: string;
  /** Group id/name when the grant flows through a group (USER subjects only). */
  group?: { id: string; name: string };
  /** The matching permission row. */
  permission: Permission;
}

export interface PermissionExplanation {
  subject: Subject;
  resource: string;
  action: string;
  /** Final verdict from the configured IAM evaluation mode and condition context. */
  allowed: boolean;
  /** Every grant source that matched, including DENYs. */
  sources: PermissionExplanationSource[];
  /** Roles the subject is bound to (whether or not their permissions matched). */
  roleBindings: Array<{ role: string; tenantId?: string | null }>;
  /** Groups the subject belongs to (USER only). */
  groupMemberships: Array<{ id: string; name: string }>;
}

interface RoleBindingRow {
  roleId: string;
  tenantId: string | null;
  subjectType: 'USER' | 'GROUP' | 'SERVICE_ACCOUNT';
  subjectId: string;
}

interface DirectPermissionBindingRow {
  permissionId: string;
  tenantId: string | null;
  subjectType: 'USER' | 'GROUP' | 'SERVICE_ACCOUNT';
  subjectId: string;
}

interface GroupMembershipRow {
  groupId: string;
  userId: string;
}

interface GroupRow {
  id: string;
  name: string;
}

function permissionMatches(perm: Permission, resource: string, action: string): boolean {
  const matchPart = (declared: string, actual: string): boolean => declared === actual || declared === '*';
  return matchPart(perm.resource, resource) && matchPart(perm.action, action);
}

async function loadGroupMemberships(
  db: DatabaseAdapter,
  userId: string,
): Promise<GroupRow[]> {
  const memberships = await db.findMany<GroupMembershipRow>({
    model: 'group_user',
    where: [{ field: 'userId', operator: '=', value: userId }],
  });
  if (memberships.length === 0)
    return [];
  return db.findMany<GroupRow>({
    model: 'group',
    where: [{ field: 'id', operator: 'in', value: memberships.map(m => m.groupId) }],
  });
}

async function loadRoleBindings(
  db: DatabaseAdapter,
  subject: { type: 'USER' | 'GROUP' | 'SERVICE_ACCOUNT'; id: string },
): Promise<RoleBindingRow[]> {
  return db.findMany<RoleBindingRow>({
    model: 'role_binding',
    where: [
      { field: 'subjectType', operator: '=', value: subject.type },
      { field: 'subjectId', operator: '=', value: subject.id },
    ],
  });
}

async function loadDirectBindings(
  db: DatabaseAdapter,
  subject: { type: 'USER' | 'GROUP' | 'SERVICE_ACCOUNT'; id: string },
): Promise<DirectPermissionBindingRow[]> {
  return db.findMany<DirectPermissionBindingRow>({
    model: 'direct_permission_binding',
    where: [
      { field: 'subjectType', operator: '=', value: subject.type },
      { field: 'subjectId', operator: '=', value: subject.id },
    ],
  });
}

async function loadPermissionsByIds(
  db: DatabaseAdapter,
  ids: string[],
): Promise<Map<string, Permission>> {
  if (ids.length === 0)
    return new Map();
  const rows = await db.findMany<Permission>({
    model: 'permission',
    where: [{ field: 'id', operator: 'in', value: ids }],
  });
  return new Map(rows.map(row => [row.id, row]));
}

async function loadRolePermissions(
  db: DatabaseAdapter,
  roleIds: string[],
): Promise<Map<string, string[]>> {
  if (roleIds.length === 0)
    return new Map();
  const links = await db.findMany<{ roleId: string; permissionId: string }>({
    model: 'role_permission',
    where: [{ field: 'roleId', operator: 'in', value: roleIds }],
  });
  const out = new Map<string, string[]>();
  for (const link of links) {
    const list = out.get(link.roleId) ?? [];
    list.push(link.permissionId);
    out.set(link.roleId, list);
  }
  return out;
}

async function loadRoles(db: DatabaseAdapter, ids: string[]): Promise<Map<string, Role>> {
  if (ids.length === 0)
    return new Map();
  const rows = await db.findMany<Role>({
    model: 'role',
    where: [{ field: 'id', operator: 'in', value: ids }],
  });
  return new Map(rows.map(row => [row.id, row]));
}

/**
 * Explain why a subject does (or does not) have a permission. Walks
 * direct bindings, role bindings, and group memberships (USER only) and
 * lists every matching grant with its source so operators can debug
 * unexpected allow/deny results.
 *
 * @param db - Database adapter (typically `fortress.config.database`).
 * @param iam - IAM service used for the authoritative verdict, including
 *   configured evaluation mode, conditions, cache semantics, and inactive
 *   service-account handling.
 */
export async function explainPermission(
  db: DatabaseAdapter,
  iam: IamService,
  subject: Subject,
  resource: string,
  action: string,
  context?: PermissionContext,
): Promise<PermissionExplanation> {
  const sources: PermissionExplanationSource[] = [];

  // ── Group memberships (USER only) ──────────────────────────────────
  const groupMemberships: GroupRow[] = subject.type === 'USER'
    ? await loadGroupMemberships(db, subject.id)
    : [];

  // ── Role bindings: subject + inherited via groups ──────────────────
  const directRoleBindings = await loadRoleBindings(db, subject);
  const groupRoleBindings = await Promise.all(
    groupMemberships.map(group => loadRoleBindings(db, { type: 'GROUP', id: group.id })),
  );
  // Map of roleId → { binding, viaGroup? }
  const allRoleSources: Array<{ binding: RoleBindingRow; viaGroup?: GroupRow }> = [
    ...directRoleBindings.map(binding => ({ binding })),
    ...groupRoleBindings.flatMap((bindings, idx) =>
      bindings.map(binding => ({ binding, viaGroup: groupMemberships[idx] })),
    ),
  ];
  const roleIds = [...new Set(allRoleSources.map(s => s.binding.roleId))];
  const rolesById = await loadRoles(db, roleIds);
  const rolePermIds = await loadRolePermissions(db, roleIds);

  // ── Direct permission bindings: subject + inherited via groups ─────
  const directBindings = await loadDirectBindings(db, subject);
  const groupDirectBindings = await Promise.all(
    groupMemberships.map(group => loadDirectBindings(db, { type: 'GROUP', id: group.id })),
  );
  const allDirectSources: Array<{ binding: DirectPermissionBindingRow; viaGroup?: GroupRow }> = [
    ...directBindings.map(binding => ({ binding })),
    ...groupDirectBindings.flatMap((bindings, idx) =>
      bindings.map(binding => ({ binding, viaGroup: groupMemberships[idx] })),
    ),
  ];

  // ── Resolve every referenced permission row in one query ───────────
  const permissionIds = new Set<string>();
  for (const list of rolePermIds.values()) {
    for (const id of list) permissionIds.add(id);
  }
  for (const source of allDirectSources) permissionIds.add(source.binding.permissionId);
  const permsById = await loadPermissionsByIds(db, [...permissionIds]);

  // ── Direct grants ──────────────────────────────────────────────────
  for (const { binding, viaGroup } of allDirectSources) {
    const perm = permsById.get(binding.permissionId);
    if (!perm || !permissionMatches(perm, resource, action))
      continue;
    sources.push({
      via: viaGroup
        ? 'direct-group'
        : subject.type === 'SERVICE_ACCOUNT'
          ? 'direct-service-account'
          : 'direct-user',
      ...(viaGroup ? { group: { id: viaGroup.id, name: viaGroup.name } } : {}),
      permission: perm,
    });
  }

  // ── Role-based grants ──────────────────────────────────────────────
  for (const { binding, viaGroup } of allRoleSources) {
    const role = rolesById.get(binding.roleId);
    if (!role)
      continue;
    const permIds = rolePermIds.get(binding.roleId) ?? [];
    for (const permId of permIds) {
      const perm = permsById.get(permId);
      if (!perm || !permissionMatches(perm, resource, action))
        continue;
      sources.push({
        via: 'role',
        role: role.name,
        ...(viaGroup ? { group: { id: viaGroup.id, name: viaGroup.name } } : {}),
        permission: perm,
      });
    }
  }

  // Reuse the authoritative evaluator so explanation verdicts cannot drift
  // from checkPermission's configured mode, conditions, or subject gates.
  const allowed = await iam.checkPermission(subject, resource, action, context);

  // Flatten role bindings for the result.
  const roleBindings = allRoleSources
    .map(s => ({ role: rolesById.get(s.binding.roleId)?.name ?? `role#${s.binding.roleId}`, tenantId: s.binding.tenantId }))
    .filter((entry, idx, arr) => arr.findIndex(e => e.role === entry.role && e.tenantId === entry.tenantId) === idx);

  return {
    subject,
    resource,
    action,
    allowed,
    sources,
    roleBindings,
    groupMemberships: groupMemberships.map(group => ({ id: group.id, name: group.name })),
  };
}
