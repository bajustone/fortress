# Security remediation migration notes (2026-06-05)

This note covers schema/config changes introduced by the remediation pass for `docs/remediation-plan-2026-06-05.md`.

## Cookie defaults

Cookies now default to `Secure` + `__Host-` names regardless of `NODE_ENV`.

Local HTTP development must explicitly opt out:

```ts
createFortress({
  // ...
  cookies: { secure: false },
})
```

## CSRF

Pipeline CSRF is enabled by default for unsafe Fortress routes that carry either a Fortress access cookie or refresh cookie. Browser clients using auth cookies must include the configured header (default `X-Fortress-CSRF`) on `POST`/`PUT`/`PATCH`/`DELETE` requests. The check still applies if an `Authorization` or API-key header is present alongside cookies; pure bearer/API-key requests with no Fortress cookies are skipped.

Pure bearer/API deployments can opt out:

```ts
createFortress({
  // ...
  csrf: { enabled: false },
})
```

## SQLite adapter

SQLite transactions are serialized and use `BEGIN IMMEDIATE`. This matches SQLite's single-writer model and restores atomic compare-and-set behavior for refresh-token rotation and OAuth authorization-code exchange.

Nested SQLite transactions on the same adapter are explicitly unsupported. If a transaction callback calls `tx.transaction(...)`, the adapter now throws a clear `BAD_REQUEST` error instead of deadlocking behind its own queued transaction.

## Schema changes

### OAuth pending flow ownership + opaque handles

Add `flow_id`, nullable `user_id`, and nullable `used_at` to `fortress_oauth_pending_flow`:

```sql
ALTER TABLE fortress_oauth_pending_flow ADD COLUMN flow_id TEXT;
ALTER TABLE fortress_oauth_pending_flow ADD COLUMN user_id INTEGER;
ALTER TABLE fortress_oauth_pending_flow ADD COLUMN used_at TIMESTAMP;

-- For active legacy rows, backfill flow_id with sufficiently random values
-- using your migration/runtime tooling, then enforce uniqueness/not-null.
CREATE UNIQUE INDEX IF NOT EXISTS uniq_oauth_pending_flow_flow_id
  ON fortress_oauth_pending_flow (flow_id);
```

Existing `user_id` and `used_at` values can remain `NULL`; the first authenticated consent-flow read claims the flow for that user. Approval/denial atomically claims `used_at` before minting an authorization code, then deletes the flow in the same transaction. New authorize requests bind `user_id` up front when the user is already authenticated. New routes use `flow_id` (opaque random token) instead of the sequential integer primary key.

### Permission uniqueness with NULL conditions

Replace the old plain unique constraint over `(resource, action, effect, conditions)` with split partial unique indexes:

```sql
-- Before adding indexes, clean up any existing duplicates with conditions IS NULL.
-- Keep the lowest id for each duplicate group.
DELETE FROM fortress_permission
WHERE conditions IS NULL
  AND id NOT IN (
    SELECT MIN(id)
    FROM fortress_permission
    WHERE conditions IS NULL
    GROUP BY resource, action, effect
  );

CREATE UNIQUE INDEX IF NOT EXISTS uniq_permission_no_conditions
  ON fortress_permission (resource, action, effect)
  WHERE conditions IS NULL;

CREATE UNIQUE INDEX IF NOT EXISTS uniq_permission_with_conditions
  ON fortress_permission (resource, action, effect, conditions)
  WHERE conditions IS NOT NULL;
```

PostgreSQL uses the same logical indexes. If your migration tool created the old unnamed unique constraint, drop it before adding the partial indexes.

## OAuth behavior changes

- `grant_types` is enforced for `authorization_code` and `refresh_token`.
- Public clients (`tokenEndpointAuthMethod: 'none'`) must have PKCE-bound codes; codes without a challenge fail at exchange.
- Consent-flow get/approve/deny is user-bound, uses opaque random flow handles, returns 404 for another user, and approval is atomically single-use.
- Refresh-token concurrency intentionally uses strict replay semantics: a duplicate loser revokes the entire family.
- OIDC refresh responses include a fresh `id_token` when the token family scope includes `openid`.
