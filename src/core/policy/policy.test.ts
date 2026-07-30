/**
 * Policy-as-code end-to-end tests (P1-7).
 */

import type { PolicyDocument } from './types';
import { describe, expect, it } from 'vitest';
import { createTestAdapter } from '../../testing';
import { createFortress } from '../fortress';
import { applyPolicyPlan } from './apply';
import { diffPolicy } from './diff';

const SECRET = 'policy-test-secret-at-least-32-bytes!';

function freshFortress() {
  return createFortress({
    jwt: { key: SECRET },
    database: createTestAdapter(),
  });
}

const basePolicy: PolicyDocument = {
  roles: [
    {
      name: 'editor',
      description: 'Can edit articles',
      permissions: [
        { resource: 'article', action: 'create' },
        { resource: 'article', action: 'update' },
      ],
    },
  ],
  groups: [
    { name: 'engineering', description: 'Engineering team' },
  ],
  serviceAccounts: [
    { name: 'ci-bot', displayName: 'CI Bot', isActive: true, roles: ['editor'] },
  ],
};

describe('policy-as-code', () => {
  it('diff against an empty IAM produces create ops for everything declared', async () => {
    const fortress = freshFortress();
    const plan = await diffPolicy(basePolicy, fortress.iam);
    expect(plan.inSync).toBe(false);
    const kinds = plan.ops.map(op => op.kind).sort();
    expect(kinds).toContain('create-role');
    expect(kinds).toContain('create-group');
    expect(kinds).toContain('create-service-account');
    expect(kinds).toContain('bind-service-account-role');
  });

  it('apply runs every op and leaves the diff in-sync', async () => {
    const fortress = freshFortress();
    const plan = await diffPolicy(basePolicy, fortress.iam);
    const result = await applyPolicyPlan(plan, fortress.iam);
    expect(result.errors).toEqual([]);
    expect(result.applied.length).toBeGreaterThan(0);

    const second = await diffPolicy(basePolicy, fortress.iam);
    expect(second.inSync).toBe(true);
  });

  it('applies resource operations in memory and converges without filesystem access', async () => {
    const fortress = freshFortress();
    const policy: PolicyDocument = {
      resources: [{ name: 'article', description: 'Articles', actions: ['read', 'write'] }],
    };

    const result = await applyPolicyPlan(await diffPolicy(policy, fortress.iam), fortress.iam);
    expect(result.errors).toEqual([]);
    expect(result.applied.map(op => op.kind)).toEqual(['create-resource']);
    expect((await fortress.iam.getResources()).resources.article).toMatchObject({
      description: 'Articles',
      actions: ['read', 'write'],
    });
    expect((await diffPolicy(policy, fortress.iam)).inSync).toBe(true);
  });

  it('clears role descriptions and converges', async () => {
    const fortress = freshFortress();
    await applyPolicyPlan(await diffPolicy(basePolicy, fortress.iam), fortress.iam);
    const editorRole = requireAt(requireValue(basePolicy.roles, 'base policy roles'), 0, 'base editor policy role');
    const cleared: PolicyDocument = {
      ...basePolicy,
      roles: [{ ...editorRole, description: undefined }],
    };

    const result = await applyPolicyPlan(await diffPolicy(cleared, fortress.iam), fortress.iam);
    expect(result.errors).toEqual([]);
    expect((await diffPolicy(cleared, fortress.iam)).inSync).toBe(true);
    expect((await fortress.iam.getRoles()).find(role => role.name === 'editor')?.description).toBeNull();
  });

  it('tracks real service-account bindings to zero-permission roles', async () => {
    const fortress = freshFortress();
    const policy: PolicyDocument = {
      roles: [{ name: 'empty-role', permissions: [] }],
      serviceAccounts: [{ name: 'empty-role-bot', roles: ['empty-role'] }],
    };

    const result = await applyPolicyPlan(await diffPolicy(policy, fortress.iam), fortress.iam);
    expect(result.errors).toEqual([]);
    expect((await diffPolicy(policy, fortress.iam, { prune: true })).inSync).toBe(true);
  });

  it('binds a newly declared role to an existing service account in one plan', async () => {
    const fortress = freshFortress();
    await fortress.iam.createServiceAccount({ name: 'existing-bot' });
    const policy: PolicyDocument = {
      roles: [{ name: 'new-role', permissions: [] }],
      serviceAccounts: [{ name: 'existing-bot', roles: ['new-role'] }],
    };

    const plan = await diffPolicy(policy, fortress.iam);
    expect(plan.ops.map(op => op.kind)).toEqual(expect.arrayContaining([
      'create-role',
      'bind-service-account-role',
    ]));
    const result = await applyPolicyPlan(plan, fortress.iam);
    expect(result.errors).toEqual([]);
    expect((await diffPolicy(policy, fortress.iam)).inSync).toBe(true);
  });

  it('global policy unbinding preserves tenant-scoped role bindings', async () => {
    const fortress = freshFortress();
    const role = await fortress.iam.createRole('scoped-role', []);
    const serviceAccount = await fortress.iam.createServiceAccount({ name: 'scoped-bot' });
    await fortress.iam.bindRoleToServiceAccount(serviceAccount.id, role.id);
    await fortress.iam.bindRoleToServiceAccount(serviceAccount.id, role.id, 'tenant-a');
    const policy: PolicyDocument = {
      roles: [{ name: 'scoped-role', permissions: [] }],
      serviceAccounts: [{ name: 'scoped-bot', roles: [] }],
    };

    const result = await applyPolicyPlan(
      await diffPolicy(policy, fortress.iam, { prune: true }),
      fortress.iam,
    );
    expect(result.errors).toEqual([]);
    const remaining = await fortress.iam.listRoleBindingsForSubject({
      type: 'SERVICE_ACCOUNT',
      id: serviceAccount.id,
    });
    expect(remaining.map(binding => binding.tenantId)).toEqual(['tenant-a']);
  });

  it('unbinds retained service accounts before pruning their old role', async () => {
    const fortress = freshFortress();
    const initial: PolicyDocument = {
      roles: [{ name: 'old-role', permissions: [] }],
      serviceAccounts: [{ name: 'retained-bot', roles: ['old-role'] }],
    };
    await applyPolicyPlan(await diffPolicy(initial, fortress.iam), fortress.iam);
    const next: PolicyDocument = {
      roles: [],
      serviceAccounts: [{ name: 'retained-bot', roles: [] }],
    };

    const plan = await diffPolicy(next, fortress.iam, { prune: true });
    expect(plan.ops.map(op => op.kind)).toEqual(expect.arrayContaining([
      'unbind-service-account-role',
      'delete-role',
    ]));
    const result = await applyPolicyPlan(plan, fortress.iam);
    expect(result.errors).toEqual([]);
    expect((await diffPolicy(next, fortress.iam, { prune: true })).inSync).toBe(true);
  });

  it('add-role-permission op is emitted when the policy widens a role', async () => {
    const fortress = freshFortress();
    await applyPolicyPlan(await diffPolicy(basePolicy, fortress.iam), fortress.iam);

    const editorRole = requireAt(requireValue(basePolicy.roles, 'base policy roles'), 0, 'base editor policy role');
    const widened: PolicyDocument = {
      ...basePolicy,
      roles: [
        {
          ...editorRole,
          permissions: [
            ...editorRole.permissions,
            { resource: 'article', action: 'delete' },
          ],
        },
      ],
    };
    const plan = await diffPolicy(widened, fortress.iam);
    const ops = plan.ops.map(op => op.kind);
    expect(ops).toContain('add-role-permission');
    const result = await applyPolicyPlan(plan, fortress.iam);
    expect(result.errors).toEqual([]);
    expect((await diffPolicy(widened, fortress.iam)).inSync).toBe(true);
  });

  it('remove-role-permission op is emitted when the policy narrows a role', async () => {
    const fortress = freshFortress();
    await applyPolicyPlan(await diffPolicy(basePolicy, fortress.iam), fortress.iam);

    const editorRole = requireAt(requireValue(basePolicy.roles, 'base policy roles'), 0, 'base editor policy role');
    const narrowed: PolicyDocument = {
      ...basePolicy,
      roles: [
        {
          ...editorRole,
          permissions: [{ resource: 'article', action: 'create' }],
        },
      ],
    };
    const plan = await diffPolicy(narrowed, fortress.iam);
    expect(plan.ops.some(op => op.kind === 'remove-role-permission')).toBe(true);
    const result = await applyPolicyPlan(plan, fortress.iam);
    expect(result.errors).toEqual([]);
    expect((await diffPolicy(narrowed, fortress.iam)).inSync).toBe(true);
  });

  it('requires explicit acknowledgement before pruning with an empty policy', async () => {
    const fortress = freshFortress();
    await applyPolicyPlan(await diffPolicy(basePolicy, fortress.iam), fortress.iam);

    // Empty policy with prune should delete role/group/SA.
    const empty: PolicyDocument = {};
    await expect(diffPolicy(empty, fortress.iam, { prune: true })).rejects.toThrow('allowEmptyPrune');
    const plan = await diffPolicy(empty, fortress.iam, { prune: true, allowEmptyPrune: true });
    const kinds = plan.ops.map(op => op.kind).sort();
    expect(kinds).toContain('delete-role');
    expect(kinds).toContain('delete-group');
    expect(kinds).toContain('delete-service-account');

    const result = await applyPolicyPlan(plan, fortress.iam);
    expect(result.errors).toEqual([]);
    expect((await diffPolicy(empty, fortress.iam, {
      prune: true,
      allowEmptyPrune: true,
    })).inSync).toBe(true);
  });
});

function requireValue<T>(value: T | undefined, description: string): T {
  if (value === undefined)
    throw new Error(`Expected ${description}`);
  return value;
}

function requireAt<T>(values: readonly T[], index: number, description: string): T {
  return requireValue(values[index], description);
}
