# Policy-as-code (P1-7)

Fortress's IAM (roles, permissions, groups, service accounts) can be
declared in a JSON policy file and reconciled against the live database
via a `diff` / `apply` workflow. This is the policy-as-code answer to
the existing imperative `fortress.iam.*` calls, designed for the same
CI/Ops audience as the route-manifest and migration drift checkers.

## File format

Default file: `fortress.policy.json` in the working directory.
Environment-specific override:
`fortress.policy.<env>.json`, picked when `FORTRESS_ENV` is set (the env
file fully **replaces** the base — no implicit merging).

See [`examples/policy/fortress.policy.json`](../examples/policy/fortress.policy.json)
for a complete example. Minimum shape:

```jsonc
{
  "resources": [
    { "name": "article", "actions": ["create", "read", "update", "delete"] }
  ],
  "roles": [
    {
      "name": "editor",
      "description": "Authors and edits articles",
      "permissions": [
        { "resource": "article", "action": "create" },
        { "resource": "article", "action": "update" }
      ]
    }
  ],
  "groups": [
    { "name": "engineering", "description": "Engineering team" }
  ],
  "serviceAccounts": [
    { "name": "ci-bot", "displayName": "CI", "isActive": true, "roles": ["editor"] }
  ]
}
```

### What's covered

| Entity | Declared keys | Reconciled by `applyPolicyPlan` |
|---|---|---|
| Resources | `name`, `actions[]`, `description` | Creates missing resources; adds missing actions to existing resources |
| Roles | `name`, `description`, `permissions[]` | Creates missing roles; updates description; adds + removes permissions |
| Groups | `name`, `description` | Creates missing groups; updates description |
| Service accounts | `name`, `displayName`, `description`, `isActive`, `roles[]` | Creates missing SAs; updates fields; binds + unbinds roles |

### What's intentionally NOT covered

- **OAuth clients.** They have secrets — manage via the admin endpoints.
- **User accounts / user → group memberships.** User data, not policy.
  Provision users via signup or admin endpoints; manage memberships via
  `fortress.iam.addUserToGroup(...)`.
- **Per-tenant role bindings.** Manage via the admin endpoints; the
  global policy file is the wrong fit for per-tenant scale.
- **Resource deletions / action removals.** Dropping a resource cascades
  to permissions and role bindings; require explicit operator action.

## Diff + apply workflow

The same three-step loop you'd use for migrations or manifests:

```ts
import { createFortress, loadPolicy, diffPolicy, applyPolicyPlan } from '@bajustone/fortress';
import config from './fortress.config';

const fortress = createFortress(config);
const { policy } = loadPolicy();        // reads fortress.policy.json (or env override)
const plan = await diffPolicy(policy, fortress.iam);
if (!plan.inSync) {
  console.log('Plan:');
  for (const op of plan.ops) console.log(' -', op.description);

  const result = await applyPolicyPlan(plan, fortress.iam);
  if (result.errors.length) {
    console.error('Some ops failed:', result.errors);
    process.exit(1);
  }
}
```

### Pruning (deletes)

`diffPolicy(policy, iam, { prune: true })` emits `delete-role`,
`delete-group`, `delete-service-account`, and `unbind-service-account-role`
ops for entities present in the database but absent from the policy
file. System roles (`isSystem === true`) are never deleted.

Run the un-pruned diff first to review, then add `prune: true` when
the diff matches your intent.

### Resource ops require the sync file

`applyPolicyPlan` covers roles, groups, and service accounts directly.
Resource-creation ops require writing through `fortress.resources.json`
(the existing `iam.syncResources('push')` path); use the
`applyResourceOps(plan, iam, 'fortress.resources.json')` helper to write
the merged file and push it. Most repos check that file in and reuse the
existing `fortress sync:push` workflow.

## CLI

The CLI exposes one offline command (no DB required) plus three
how-to printers because the diff/apply/check commands need your
configured `Fortress` instance:

```sh
fortress policy:summary [--file <path>] [--env <name>]   # offline; prints declared counts
fortress policy:diff                                     # prints code snippet for in-app usage
fortress policy:apply                                    # prints code snippet
fortress policy:check                                    # prints code snippet
```

`fortress policy:summary` is useful in CI to assert the file parses
and to print a quick inventory; the actual diff/apply runs from a
small script in your repo that knows your DB connection.

## CI gate

Add a `policy:check` step to your CI workflow that runs against an
ephemeral DB seeded from production policy:

```ts
// scripts/policy-check.ts
import { createFortress, loadPolicy, diffPolicy } from '@bajustone/fortress';
import { createTestAdapter } from '@bajustone/fortress/testing';
import { applyPolicyPlan } from '@bajustone/fortress';

const fortress = createFortress({
  database: createTestAdapter(),
  jwt: { secret: process.env.FORTRESS_JWT_SECRET! },
});

const { policy } = loadPolicy();
// Bootstrap from the policy itself so the diff result reflects only the
// drift between two consecutive policy revisions.
await applyPolicyPlan(await diffPolicy(policy, fortress.iam), fortress.iam);

const after = await diffPolicy(policy, fortress.iam);
if (!after.inSync) {
  console.error('Policy reconciliation is not converging:', after.ops);
  process.exit(1);
}
console.log(`Policy in sync (${policy.roles?.length ?? 0} role(s), ${policy.serviceAccounts?.length ?? 0} service account(s)).`);
```

Run it as a step in `.github/workflows/fortress-ci.yml` alongside
`fortress manifest:check` and `fortress migrate:check`.

## API reference

| Export | Kind | Purpose |
|---|---|---|
| `loadPolicy(options?)` | function | Read + parse the policy file (env-aware) |
| `resolvePolicyPath(options?)` | function | Resolve the file path that `loadPolicy` would use |
| `diffPolicy(policy, iam, options?)` | function | Compute the plan to reconcile live IAM with `policy` |
| `applyPolicyPlan(plan, iam)` | function | Apply every op in the plan; returns `applied` / `errors` |
| `applyResourceOps(plan, iam, syncFile)` | function | Apply resource-only ops via the existing sync path |
| `PolicyDocument`, `PolicyRole`, ... | types | Type-only exports for callers that read the file themselves |

All exported from the package root.
