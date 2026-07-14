/**
 * Compute the {@link PolicyPlan} that reconciles the live IAM state with
 * a declarative {@link PolicyDocument}.
 *
 * The diff is intentionally additive-by-default: missing resources,
 * actions, roles, permissions, groups, and service accounts produce
 * `create-*` / `add-*` ops. Deletions only appear when `prune: true` is
 * passed — most operators want their first apply to be safe.
 *
 * @module
 */

import type { IamService } from '../iam/iam-service';
import type { Permission, Role, ServiceAccount } from '../types';
import type {
  DiffPolicyOptions,
  PolicyDocument,
  PolicyOp,
  PolicyPermission,
  PolicyPlan,
} from './types';
import { Errors } from '../errors';

function permissionKey(perm: { resource: string; action: string; effect?: string }): string {
  return `${perm.resource}::${perm.action}::${perm.effect ?? 'ALLOW'}`;
}

function describePerm(perm: PolicyPermission): string {
  return `${perm.resource}:${perm.action}${perm.effect && perm.effect !== 'ALLOW' ? ` (${perm.effect})` : ''}`;
}

/**
 * Compute the diff between a {@link PolicyDocument} (desired state) and
 * the live IAM state. Pass the returned {@link PolicyPlan} to
 * {@link applyPolicyPlan} to reconcile.
 */
export async function diffPolicy(
  policy: PolicyDocument,
  iam: IamService,
  options: DiffPolicyOptions = {},
): Promise<PolicyPlan> {
  const declaredCount = (policy.resources?.length ?? 0)
    + (policy.roles?.length ?? 0)
    + (policy.groups?.length ?? 0)
    + (policy.serviceAccounts?.length ?? 0);
  if (options.prune && declaredCount === 0 && !options.allowEmptyPrune) {
    throw Errors.badRequest(
      'Refusing to prune with an empty policy; pass allowEmptyPrune: true to acknowledge deleting all managed IAM state',
    );
  }
  const ops: PolicyOp[] = [];

  // ── Resources ──────────────────────────────────────────────────────
  const existingResources = await iam.getResources();
  const existingResourceMap = existingResources.resources;
  const declaredResourceNames = new Set<string>();

  for (const resource of policy.resources ?? []) {
    declaredResourceNames.add(resource.name);
    const existing = existingResourceMap[resource.name];
    if (!existing) {
      ops.push({
        kind: 'create-resource',
        resource,
        description: `Create resource '${resource.name}' with actions [${resource.actions.join(', ')}]`,
      });
      continue;
    }
    const existingActions = new Set(existing.actions);
    for (const action of resource.actions) {
      if (!existingActions.has(action)) {
        ops.push({
          kind: 'add-resource-action',
          resource: resource.name,
          action,
          description: `Add action '${action}' to resource '${resource.name}'`,
        });
      }
    }
  }
  // Note: we don't prune resources/actions even with `prune: true` because
  // dropping a resource cascades to permissions/role-bindings. Operators
  // should remove unused resources manually via the admin API.

  // ── Roles ──────────────────────────────────────────────────────────
  const existingRoles = await iam.getRoles();
  const existingRoleByName = new Map<string, Role>(existingRoles.map(role => [role.name, role]));
  const declaredRoleNames = new Set<string>();

  for (const role of policy.roles ?? []) {
    declaredRoleNames.add(role.name);
    const existing = existingRoleByName.get(role.name);
    if (!existing) {
      ops.push({
        kind: 'create-role',
        role,
        description: `Create role '${role.name}' with ${role.permissions.length} permission(s)`,
      });
      continue;
    }
    if ((existing.description ?? '') !== (role.description ?? '')) {
      ops.push({
        kind: 'update-role-description',
        role: role.name,
        from: existing.description ?? undefined,
        to: role.description,
        description: `Update description on role '${role.name}'`,
      });
    }
    const detail = await iam.getRole(existing.id);
    const existingPerms = new Map<string, Permission>(
      detail.permissions.map(perm => [permissionKey(perm), perm]),
    );
    const desiredPerms = new Map<string, PolicyPermission>(
      role.permissions.map(perm => [permissionKey(perm), perm]),
    );
    for (const [key, perm] of desiredPerms) {
      if (!existingPerms.has(key)) {
        ops.push({
          kind: 'add-role-permission',
          role: role.name,
          permission: perm,
          description: `Add permission ${describePerm(perm)} to role '${role.name}'`,
        });
      }
    }
    for (const [key, perm] of existingPerms) {
      if (!desiredPerms.has(key)) {
        ops.push({
          kind: 'remove-role-permission',
          role: role.name,
          permission: {
            resource: perm.resource,
            action: perm.action,
            effect: perm.effect,
          },
          description: `Remove permission ${perm.resource}:${perm.action} from role '${role.name}'`,
        });
      }
    }
  }
  if (options.prune) {
    for (const role of existingRoles) {
      if (role.isSystem)
        continue;
      if (!declaredRoleNames.has(role.name)) {
        ops.push({
          kind: 'delete-role',
          role: role.name,
          description: `Delete role '${role.name}' (prune)`,
        });
      }
    }
  }

  // ── Groups ─────────────────────────────────────────────────────────
  const { groups: existingGroups } = await iam.listGroups({ limit: 10_000 });
  const existingGroupByName = new Map(existingGroups.map(group => [group.name, group]));
  const declaredGroupNames = new Set<string>();
  for (const group of policy.groups ?? []) {
    declaredGroupNames.add(group.name);
    const existing = existingGroupByName.get(group.name);
    if (!existing) {
      ops.push({
        kind: 'create-group',
        group,
        description: `Create group '${group.name}'`,
      });
      continue;
    }
    if ((existing.description ?? '') !== (group.description ?? '')) {
      ops.push({
        kind: 'update-group-description',
        group: group.name,
        from: existing.description ?? undefined,
        to: group.description,
        description: `Update description on group '${group.name}'`,
      });
    }
  }
  if (options.prune) {
    for (const group of existingGroups) {
      if (!declaredGroupNames.has(group.name)) {
        ops.push({
          kind: 'delete-group',
          group: group.name,
          description: `Delete group '${group.name}' (prune)`,
        });
      }
    }
  }

  // ── Service accounts ───────────────────────────────────────────────
  const { serviceAccounts: existingSAs } = await iam.listServiceAccounts({ limit: 10_000 });
  const existingSaByName = new Map<string, ServiceAccount>(existingSAs.map(sa => [sa.name, sa]));
  const declaredSaNames = new Set<string>();

  for (const sa of policy.serviceAccounts ?? []) {
    declaredSaNames.add(sa.name);
    const existing = existingSaByName.get(sa.name);
    if (!existing) {
      ops.push({
        kind: 'create-service-account',
        serviceAccount: sa,
        description: `Create service account '${sa.name}'`,
      });
      // bind roles after create — emit binding ops too.
      for (const roleName of sa.roles ?? []) {
        ops.push({
          kind: 'bind-service-account-role',
          serviceAccount: sa.name,
          role: roleName,
          description: `Bind role '${roleName}' to service account '${sa.name}'`,
        });
      }
      continue;
    }
    const changes: Record<string, unknown> = {};
    if (sa.displayName !== undefined && existing.displayName !== sa.displayName)
      changes.displayName = sa.displayName;
    if (sa.description !== undefined && existing.description !== sa.description)
      changes.description = sa.description;
    if (sa.isActive !== undefined && existing.isActive !== sa.isActive)
      changes.isActive = sa.isActive;
    if (Object.keys(changes).length > 0) {
      ops.push({
        kind: 'update-service-account',
        serviceAccount: sa.name,
        changes,
        description: `Update fields on service account '${sa.name}'`,
      });
    }
    // Policies manage global SA bindings. Read the authoritative binding rows
    // rather than inferring roles from effective permissions (which is
    // ambiguous for shared/direct permissions and invisible for empty roles).
    const desiredRoles = new Set(sa.roles ?? []);
    const allRoles = await iam.getRoles();
    const roleByName = new Map(allRoles.map(role => [role.name, role]));
    const roleNameById = new Map(allRoles.map(role => [role.id, role.name]));
    const bindings = await iam.listRoleBindingsForSubject(
      { type: 'SERVICE_ACCOUNT', id: existing.id },
      null,
    );
    const currentRoleNames = new Set(
      bindings
        .map(binding => roleNameById.get(binding.roleId))
        .filter((name): name is string => name !== undefined),
    );
    for (const desired of desiredRoles) {
      if (
        !currentRoleNames.has(desired)
        && (roleByName.has(desired) || declaredRoleNames.has(desired))
      ) {
        ops.push({
          kind: 'bind-service-account-role',
          serviceAccount: sa.name,
          role: desired,
          description: `Bind role '${desired}' to service account '${sa.name}'`,
        });
      }
    }
    if (options.prune) {
      for (const current of currentRoleNames) {
        if (!desiredRoles.has(current)) {
          ops.push({
            kind: 'unbind-service-account-role',
            serviceAccount: sa.name,
            role: current,
            description: `Unbind role '${current}' from service account '${sa.name}' (prune)`,
          });
        }
      }
    }
  }
  if (options.prune) {
    for (const sa of existingSAs) {
      if (!declaredSaNames.has(sa.name)) {
        ops.push({
          kind: 'delete-service-account',
          serviceAccount: sa.name,
          description: `Delete service account '${sa.name}' (prune)`,
        });
      }
    }
  }

  return { ops, inSync: ops.length === 0 };
}
