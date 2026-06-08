/**
 * Declarative policy types for policy-as-code (P1-7).
 *
 * A policy file declares the desired state of Fortress-owned IAM
 * resources: resources/actions, roles + permissions, groups, and
 * service accounts (with their role bindings). The diff/apply pipeline
 * computes the operations needed to reconcile the live database with the
 * declared state.
 *
 * What's covered:
 * - Resources + actions (extends today's `fortress.resources.json`).
 * - Roles with permission lists.
 * - Groups (declared shells; user memberships managed via runtime APIs).
 * - Service accounts with role bindings.
 *
 * What's intentionally NOT covered:
 * - OAuth clients (have secrets; manage via admin endpoints).
 * - User accounts / user-group memberships (user data, not policy).
 * - Tenant data and per-tenant role bindings (large scale; declare in
 *   per-tenant policy files if needed).
 *
 * @module
 */

/** Resource definition (action list shared with the existing `fortress.resources.json` shape). */
export interface PolicyResource {
  name: string;
  actions: string[];
  description?: string;
}

/** Permission entry inside a role declaration. `effect` defaults to ALLOW. */
export interface PolicyPermission {
  resource: string;
  action: string;
  effect?: 'ALLOW' | 'DENY';
}

/** Role declaration. Permissions are the *complete* desired set for the role; extras are removed on apply. */
export interface PolicyRole {
  name: string;
  description?: string;
  permissions: PolicyPermission[];
}

/** Group declaration. User memberships are intentionally not managed via policy files. */
export interface PolicyGroup {
  name: string;
  description?: string;
}

/** Service-account declaration. Roles list is the complete desired binding set; extras are unbound on apply. */
export interface PolicyServiceAccount {
  name: string;
  displayName?: string;
  description?: string;
  isActive?: boolean;
  /** Role names to bind to this service account. Bindings outside this list are removed on apply. */
  roles?: string[];
}

/** Top-level policy document. */
export interface PolicyDocument {
  resources?: PolicyResource[];
  roles?: PolicyRole[];
  groups?: PolicyGroup[];
  serviceAccounts?: PolicyServiceAccount[];
}

/** Single op produced by `diffPolicy`. Tag is human-readable; `description` flattens for logs. */
export type PolicyOp
  = | { kind: 'create-resource'; resource: PolicyResource; description: string }
    | { kind: 'add-resource-action'; resource: string; action: string; description: string }
    | { kind: 'create-role'; role: PolicyRole; description: string }
    | { kind: 'update-role-description'; role: string; from?: string; to?: string; description: string }
    | { kind: 'add-role-permission'; role: string; permission: PolicyPermission; description: string }
    | { kind: 'remove-role-permission'; role: string; permission: PolicyPermission; description: string }
    | { kind: 'delete-role'; role: string; description: string }
    | { kind: 'create-group'; group: PolicyGroup; description: string }
    | { kind: 'update-group-description'; group: string; from?: string; to?: string; description: string }
    | { kind: 'delete-group'; group: string; description: string }
    | { kind: 'create-service-account'; serviceAccount: PolicyServiceAccount; description: string }
    | { kind: 'update-service-account'; serviceAccount: string; changes: Record<string, unknown>; description: string }
    | { kind: 'bind-service-account-role'; serviceAccount: string; role: string; description: string }
    | { kind: 'unbind-service-account-role'; serviceAccount: string; role: string; description: string }
    | { kind: 'delete-service-account'; serviceAccount: string; description: string };

/** Diff result returned by `diffPolicy`. */
export interface PolicyPlan {
  ops: PolicyOp[];
  /** `true` when there is nothing to reconcile. */
  inSync: boolean;
}

/** Options for `diffPolicy`. */
export interface DiffPolicyOptions {
  /**
   * Prune resources/roles/groups/service-accounts present in the database
   * but absent from the policy file. Default `false` — apply only adds
   * and updates unless the operator opts in to deletions.
   */
  prune?: boolean;
}
