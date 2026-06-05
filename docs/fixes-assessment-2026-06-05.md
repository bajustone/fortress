# Fortress Fixes Assessment

Date: 2026-06-05  
Repository: `/Users/bajustone/dev/fortress`

## Validation Run

The current working tree was checked with:

```bash
bun run typecheck
bun run lint
bun run test
bun run test:integration
bun test src/plugins/api-key/api-key.test.ts
```

Results:

- `bun run typecheck` passed.
- `bun run lint` passed.
- `bun run test` passed: 946 tests across 66 files.
- `bun run test:integration` passed: 66 tests across 2 files.
- `bun test src/plugins/api-key/api-key.test.ts` passed: 34 tests.

## Summary Verdict

The fixes are a strong step forward. The most important P0 issues are partially or mostly addressed:

- API-key scope data now flows into principal resolution and IAM checks.
- Built-in impersonation route now declares an explicit permission.
- Core refresh-token rotation is much safer through transaction + conditional update.
- OAuth refresh-token rotation is also safer.
- Permission identity now includes effect and conditions.
- Drizzle adapter now exposes a `rawQuery` path for optimized IAM resolution.

However, I would not call the P0 work fully complete yet. The biggest remaining concern is that **API-key scopes are only enforced when an IAM permission check runs**. Bearer-only routes can still be called by scoped API keys without checking the key scope.

The most sensitive example is API-key self-management: a narrowly-scoped API key may be able to call `/api-key/keys` and mint a broader or unscoped key for the same subject.

---

## Fixes That Look Good

### 1. API-key scope propagation

Relevant files:

- `src/plugins/api-key/index.ts`
- `src/core/http/principal.ts`
- `src/core/types.ts`
- `src/core/iam/iam-service.ts`
- `src/core/iam/permission-evaluator.ts`
- `src/hono/middleware/auth.ts`
- `src/hono/middleware/rbac.ts`
- `src/express/middleware.ts`
- `src/sveltekit/handle.ts`

The API-key plugin now returns scopes from principal resolution:

```ts
return { subject: resolved.subject, scopes: resolved.scopes };
```

The resolved principal now carries scopes:

```ts
export interface ResolvedPrincipal {
  subject: Subject;
  claims?: TokenClaims;
  scopes?: string[] | null;
}
```

IAM permission checks now use credential-level narrowing:

```ts
const allowed = withinCredentialScope(context?.credentialScopes, resource, action)
  && evaluatePermissions(permissions, resource, action, evaluationMode, enrichedContext);
```

This is the right architectural direction.

The new API-key tests include a useful regression case proving a scoped key is denied when it tries to call a route outside its scope.

### 2. Built-in impersonation route is permission-gated

Relevant file:

- `src/core/auth/auth-endpoints.ts`

The impersonation endpoint now has:

```ts
.permission('fortress', 'impersonate')
```

This fixes the core HTTP route-level issue.

### 3. Core refresh-token rotation is safer

Relevant file:

- `src/core/auth/auth-service.ts`

The refresh flow now uses a transaction and a conditional update:

```ts
where: [
  { field: 'tokenHash', operator: '=', value: tokenHash },
  { field: 'isRevoked', operator: '=', value: false },
],
data: { isRevoked: true },
```

That means only one concurrent refresh caller can claim the token. Losers fall into the reuse path.

This is a meaningful improvement over the previous read-check-update sequence.

### 4. OAuth refresh-token rotation is safer

Relevant file:

- `src/plugins/oauth/index.ts`

OAuth refresh-token grant now uses a transaction and a conditional claim on `usedAt IS NULL`.

This addresses the same class of race in the OAuth refresh-token flow.

### 5. Permission identity improved

Relevant file:

- `src/core/internal-adapter.ts`

`findOrCreatePermission` now includes:

- `resource`
- `action`
- `effect`
- `conditions`

This is much better than identifying permissions only by `resource + action`.

### 6. Drizzle adapter gained `rawQuery`

Relevant file:

- `src/drizzle/adapter.ts`

The Drizzle adapter now supports `rawQuery`, which allows the optimized IAM permission resolution path to run.

### 7. Documentation/package metadata improved

Relevant files:

- `SECURITY.md`
- `package.json`
- `jsr.json`

Improvements include:

- supported version table updated to `0.1.x`
- package files now include docs, examples, SECURITY, and CHANGELOG
- JSR config no longer excludes docs/examples

---

## Remaining Concerns

### 1. API-key scopes are still bypassable on bearer-only routes

Severity: High

Credential scopes are currently enforced inside `fortress.iam.checkPermission`. That means scopes only matter when a route triggers an IAM permission check.

Routes that only declare:

```ts
.security('bearer')
```

will authenticate the API key principal but will not check the key scope.

This is especially sensitive for API-key self-service routes:

```text
POST   /api-key/keys
GET    /api-key/keys
DELETE /api-key/keys/:id
POST   /api-key/keys/:id/rotate
```

A narrowly-scoped API key may be able to call `POST /api-key/keys` and mint a broader or unscoped key for the same subject.

Recommended fix:

- Either disallow API-key principals from API-key management routes; or
- add explicit permissions to API-key self-management routes, such as `apiKey:selfManage`; and
- require API-key scopes to include those permissions before key management is allowed.

Suggested policy:

```text
JWT user session: may self-manage API keys
API-key credential: denied from self-managing API keys unless explicitly allowed by credential scope and IAM
```

For production, the safest default is to deny API-key credentials from minting or rotating API keys.

### 2. Programmatic impersonation check is conditional

Severity: Medium/High

In `auth-service.ts`, direct calls to:

```ts
fortress.auth.impersonate(adminUserId, targetUserId)
```

only enforce `fortress:impersonate` if the permission row exists.

This preserves legacy behavior, but it is not ideal for a production auth library. Impersonation should fail closed.

Recommended fix:

- always call IAM for `fortress:impersonate`
- deny if the permission is missing or not granted

Suggested behavior:

```ts
const allowed = await iam.checkPermission(
  { type: 'USER', id: adminUserId },
  'fortress',
  'impersonate',
);
if (!allowed) throw Errors.forbidden('Missing required permission: fortress:impersonate');
```

If backwards compatibility is required, put the relaxed behavior behind an explicit config flag.

### 3. `isNull` is now core-required but adapter contract still says optional

Severity: Medium

Core code now uses:

```ts
{ field: 'conditions', operator: 'isNull', value: null }
```

and OAuth refresh uses:

```ts
{ field: 'usedAt', operator: 'isNull', value: null }
```

But the adapter type currently describes additional operators such as `isNull` as optional adapter extensions.

Recommended fix:

- update `src/adapters/database/types.ts`
- include `isNull` in `CoreOperator`
- document that all production adapters must support it

### 4. Unique constraints with nullable `tenant_id` are incomplete

Severity: Medium

The new uniqueness constraints are good, but constraints like:

```ts
unique().on(table.roleId, table.subjectType, table.subjectId, table.tenantId)
```

do not prevent duplicate global rows where `tenant_id IS NULL` in Postgres or SQLite.

The code-level pre-check helps, but it is not race-safe.

Recommended fix:

- use partial unique indexes for `tenant_id IS NULL`
- and a separate unique constraint/index for non-null tenant IDs; or
- use expression indexes with `coalesce(tenant_id, '')` where supported

Example target semantics:

```text
unique(role_id, subject_type, subject_id) where tenant_id is null
unique(role_id, subject_type, subject_id, tenant_id) where tenant_id is not null
```

Same concern applies to direct permission bindings.

### 5. Plugin middleware does not receive credential scopes

Severity: Low/Medium

`handle-request.ts` and `sveltekit/handle.ts` pass subject/user/claims into plugin middleware, but not scopes.

If future plugin middleware wants to inspect credential scopes, that information is not available.

Recommended fix:

- add `fortressScopes?: string[] | null` to `PluginRequestContext`
- pass scopes in `after-auth` and `after-rbac` middleware contexts
- consider Hono/Express plugin middleware too if needed

### 6. Missing targeted regression tests

Severity: Medium

The suite is green and broad, but I would add targeted tests for the new security fixes.

Recommended tests:

- HTTP `/auth/impersonate` denies a user without `fortress:impersonate`
- direct `fortress.auth.impersonate()` denies without `fortress:impersonate`
- scoped API key cannot call `/api-key/keys` to mint broader keys
- concurrent core refresh calls: exactly one succeeds
- concurrent OAuth refresh calls: exactly one succeeds
- duplicate global role binding with `tenantId = null` cannot be inserted twice
- duplicate global direct permission binding with `tenantId = null` cannot be inserted twice
- permission identity differs by conditions/effect

---

## Working Tree Notes

The working tree includes deletions:

- `CLAUDE.md`
- `docs/oauth-compliance-plan.html`

Make sure these deletions are intentional before committing.

New docs present:

- `docs/independent-audit-report.html`
- `docs/p0-fixes.patch`
- `docs/production-readiness-roadmap.md`
- `docs/tdmp-user-perspective-review.html`
- `docs/fixes-assessment-2026-06-05.md`

---

## Recommended Next Steps

### Before merging the P0 fixes

1. Fix API-key self-management scope bypass.
2. Decide whether programmatic impersonation should fail closed.
3. Promote `isNull` into the core database adapter contract.
4. Add targeted regression tests for impersonation and API-key self-management.

### Shortly after merge

1. Add concurrency tests for core and OAuth refresh rotation.
2. Add stronger uniqueness handling for nullable tenant bindings.
3. Add migration notes for the new uniqueness constraints.
4. Update production-readiness docs based on these fixes.

## Final Assessment

These changes materially improve Fortress. The original high-risk issues are being addressed in the right places, and the test suite passing is encouraging.

However, the API-key scope model still has an important gap: scope narrowing only happens when IAM permission checks happen. Any bearer-only route remains a potential bypass surface for scoped API keys.

Until that is fixed, I would consider the P0 security work **mostly complete but not done**.
