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

  it('add-role-permission op is emitted when the policy widens a role', async () => {
    const fortress = freshFortress();
    await applyPolicyPlan(await diffPolicy(basePolicy, fortress.iam), fortress.iam);

    const widened: PolicyDocument = {
      ...basePolicy,
      roles: [
        {
          ...basePolicy.roles![0],
          permissions: [
            ...basePolicy.roles![0].permissions,
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

    const narrowed: PolicyDocument = {
      ...basePolicy,
      roles: [
        {
          ...basePolicy.roles![0],
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

  it('prune: true emits delete ops for undeclared entities', async () => {
    const fortress = freshFortress();
    await applyPolicyPlan(await diffPolicy(basePolicy, fortress.iam), fortress.iam);

    // Empty policy with prune should delete role/group/SA.
    const empty: PolicyDocument = {};
    const plan = await diffPolicy(empty, fortress.iam, { prune: true });
    const kinds = plan.ops.map(op => op.kind).sort();
    expect(kinds).toContain('delete-role');
    expect(kinds).toContain('delete-group');
    expect(kinds).toContain('delete-service-account');

    const result = await applyPolicyPlan(plan, fortress.iam);
    expect(result.errors).toEqual([]);
    expect((await diffPolicy(empty, fortress.iam, { prune: true })).inSync).toBe(true);
  });
});
