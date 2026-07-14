/**
 * Execute a {@link PolicyPlan} against an {@link IamService}.
 *
 * Ops are applied in dependency-safe order (resources before roles before
 * service accounts) so a single `applyPolicyPlan` call can bring a fresh
 * database to the declared state in one shot.
 *
 * @module
 */

import type { IamService } from '../iam/iam-service';
import type { PolicyOp, PolicyPlan } from './types';
import { Errors } from '../errors';

/** Result of {@link applyPolicyPlan}. */
export interface ApplyPolicyResult {
  applied: PolicyOp[];
  skipped: PolicyOp[];
  errors: { op: PolicyOp; message: string }[];
}

const OP_ORDER: Record<PolicyOp['kind'], number> = {
  'create-resource': 0,
  'add-resource-action': 1,
  'create-role': 2,
  'update-role-description': 3,
  'add-role-permission': 4,
  'remove-role-permission': 5,
  'create-group': 6,
  'update-group-description': 7,
  'create-service-account': 8,
  'update-service-account': 9,
  'bind-service-account-role': 10,
  'unbind-service-account-role': 11,
  'delete-role': 12,
  'delete-group': 13,
  'delete-service-account': 14,
};

/**
 * Apply every op in the plan, sorted by op kind so dependencies are
 * satisfied (resources before roles, roles before service-account
 * bindings). Returns a structured result so the caller can log success
 * vs. failure per op.
 */
export async function applyPolicyPlan(
  plan: PolicyPlan,
  iam: IamService,
): Promise<ApplyPolicyResult> {
  const ops = [...plan.ops].sort((a, b) => OP_ORDER[a.kind] - OP_ORDER[b.kind]);
  const applied: PolicyOp[] = [];
  const skipped: PolicyOp[] = [];
  const errors: { op: PolicyOp; message: string }[] = [];

  // Caches to avoid repeated lookups across ops in the same apply pass.
  const roleIdByName = new Map<string, string>();
  const groupIdByName = new Map<string, string>();
  const saIdByName = new Map<string, string>();

  const resolveRoleId = async (name: string): Promise<string> => {
    if (roleIdByName.has(name))
      return roleIdByName.get(name)!;
    const roles = await iam.getRoles();
    for (const role of roles) roleIdByName.set(role.name, role.id);
    const id = roleIdByName.get(name);
    if (id == null)
      throw Errors.notFound(`Role '${name}' not found`);
    return id;
  };

  const resolveGroupId = async (name: string): Promise<string> => {
    if (groupIdByName.has(name))
      return groupIdByName.get(name)!;
    const { groups } = await iam.listGroups({ limit: 10_000 });
    for (const group of groups) groupIdByName.set(group.name, group.id);
    const id = groupIdByName.get(name);
    if (id == null)
      throw Errors.notFound(`Group '${name}' not found`);
    return id;
  };

  const resolveSaId = async (name: string): Promise<string> => {
    if (saIdByName.has(name))
      return saIdByName.get(name)!;
    const { serviceAccounts } = await iam.listServiceAccounts({ limit: 10_000 });
    for (const sa of serviceAccounts) saIdByName.set(sa.name, sa.id);
    const id = saIdByName.get(name);
    if (id == null)
      throw Errors.notFound(`Service account '${name}' not found`);
    return id;
  };

  for (const op of ops) {
    try {
      switch (op.kind) {
        case 'create-resource':
        case 'add-resource-action': {
          // Both go through pushResources via getResources merge: get current
          // resources, layer the change, push.
          const current = await iam.getResources();
          const next = { resources: { ...current.resources } };
          if (op.kind === 'create-resource') {
            next.resources[op.resource.name] = {
              actions: [...op.resource.actions],
              description: op.resource.description,
            };
          }
          else {
            const existing = next.resources[op.resource] ?? { actions: [] };
            next.resources[op.resource] = {
              ...existing,
              actions: existing.actions.includes(op.action)
                ? existing.actions
                : [...existing.actions, op.action],
            };
          }
          await iam.pushResources(next);
          applied.push(op);
          break;
        }
        case 'create-role': {
          const role = await iam.createRole(op.role.name, op.role.permissions.map(perm => ({
            resource: perm.resource,
            action: perm.action,
            effect: perm.effect,
          })), op.role.description);
          roleIdByName.set(op.role.name, role.id);
          applied.push(op);
          break;
        }
        case 'update-role-description': {
          const roleId = await resolveRoleId(op.role);
          await iam.updateRole(roleId, { description: op.to ?? null });
          applied.push(op);
          break;
        }
        case 'add-role-permission': {
          const roleId = await resolveRoleId(op.role);
          await iam.addPermissionToRole(roleId, {
            resource: op.permission.resource,
            action: op.permission.action,
            effect: op.permission.effect,
          });
          applied.push(op);
          break;
        }
        case 'remove-role-permission': {
          const roleId = await resolveRoleId(op.role);
          await iam.removePermissionFromRole(roleId, {
            resource: op.permission.resource,
            action: op.permission.action,
            effect: op.permission.effect,
          });
          applied.push(op);
          break;
        }
        case 'delete-role': {
          const roleId = await resolveRoleId(op.role);
          await iam.deleteRole(roleId);
          roleIdByName.delete(op.role);
          applied.push(op);
          break;
        }
        case 'create-group': {
          const group = await iam.createGroup(op.group.name, op.group.description);
          groupIdByName.set(op.group.name, group.id);
          applied.push(op);
          break;
        }
        case 'update-group-description': {
          const groupId = await resolveGroupId(op.group);
          await iam.updateGroup(groupId, { description: op.to });
          applied.push(op);
          break;
        }
        case 'delete-group': {
          const groupId = await resolveGroupId(op.group);
          await iam.deleteGroup(groupId);
          groupIdByName.delete(op.group);
          applied.push(op);
          break;
        }
        case 'create-service-account': {
          const sa = await iam.createServiceAccount({
            name: op.serviceAccount.name,
            displayName: op.serviceAccount.displayName,
            description: op.serviceAccount.description,
          });
          // `isActive` defaults to true at create-time; only emit an update
          // when the policy explicitly disables the account.
          if (op.serviceAccount.isActive === false) {
            await iam.updateServiceAccount(sa.id, { isActive: false });
          }
          saIdByName.set(op.serviceAccount.name, sa.id);
          applied.push(op);
          break;
        }
        case 'update-service-account': {
          const saId = await resolveSaId(op.serviceAccount);
          await iam.updateServiceAccount(saId, op.changes as {
            displayName?: string | null;
            description?: string | null;
            isActive?: boolean;
          });
          applied.push(op);
          break;
        }
        case 'bind-service-account-role': {
          const saId = await resolveSaId(op.serviceAccount);
          const roleId = await resolveRoleId(op.role);
          await iam.bindRoleToServiceAccount(saId, roleId);
          applied.push(op);
          break;
        }
        case 'unbind-service-account-role': {
          const saId = await resolveSaId(op.serviceAccount);
          const roleId = await resolveRoleId(op.role);
          await iam.unbindRoleFromServiceAccount(saId, roleId, null);
          applied.push(op);
          break;
        }
        case 'delete-service-account': {
          const saId = await resolveSaId(op.serviceAccount);
          await iam.deleteServiceAccount(saId);
          saIdByName.delete(op.serviceAccount);
          applied.push(op);
          break;
        }
      }
    }
    catch (err) {
      errors.push({ op, message: err instanceof Error ? err.message : String(err) });
    }
  }

  return { applied, skipped, errors };
}

/**
 * Compatibility helper that applies only the resource operations in a plan.
 * The file-path argument is retained for source compatibility but no file is
 * written; resource updates are applied directly through the IAM service.
 */
export async function applyResourceOps(
  plan: PolicyPlan,
  iam: IamService,
  _syncResourceFile: string,
): Promise<void> {
  const resourceOps = plan.ops.filter(op => op.kind === 'create-resource' || op.kind === 'add-resource-action');
  if (resourceOps.length === 0)
    return;
  const current = await iam.getResources();
  const next = { resources: { ...current.resources } };
  for (const op of resourceOps) {
    if (op.kind === 'create-resource') {
      next.resources[op.resource.name] = {
        actions: [...op.resource.actions],
        description: op.resource.description,
      };
    }
    else if (op.kind === 'add-resource-action') {
      const existing = next.resources[op.resource] ?? { actions: [] };
      next.resources[op.resource] = {
        ...existing,
        actions: existing.actions.includes(op.action)
          ? existing.actions
          : [...existing.actions, op.action],
      };
    }
  }
  await iam.pushResources(next);
}
