# Admin / operator recipes (P1-8)

Fortress is API-first by design — there is no reference UI shipped with
the library. The `admin` plugin (`@bajustone/fortress/plugins/admin`)
already exposes IAM CRUD as HTTP routes; this page collects the
**operator-workflow recipes** that combine those routes (and a few
service-layer helpers) into common admin tasks.

Drop these into your own admin app (Next.js / SvelteKit / Hono) or wire
them to a CLI. Every recipe is plain HTTP or `fortress.iam.*` /
`fortress.plugins.*` calls — no extra dependencies beyond what's
already installed.

## Setup

Mount the admin plugin so the IAM endpoints exist:

```ts
import { admin } from '@bajustone/fortress/plugins/admin';
import { apiKey } from '@bajustone/fortress/plugins/api-key';

createFortress({
  // ...
  plugins: [
    admin({ apiKeyRoutes: true }),  // also mounts admin api-key routes
    apiKey({ prefix: 'fortress', routes: true }),
    // ... rest of your plugins
  ],
});
```

Bootstrap the first admin user once:

```sh
curl -X POST https://your-app/iam/admin/bootstrap \
  -H 'Authorization: Bearer <a freshly-issued JWT for the user>' \
  -H 'Content-Type: application/json' \
  -d '{}'
```

This creates the `fortress-admin` role with every `fortress:*`
permission and binds it to the calling user. Run once per deployment;
subsequent calls 409 unless the role is empty.

## Users

Standard auth endpoints handle most user lifecycle:

| Task | API |
|---|---|
| Create user | `POST /auth/register` or `fortress.auth.createUser(...)` |
| Disable user | `fortress.auth.setUserActive(userId, false)` |
| Reset password (admin) | `fortress.auth.setUserPassword(userId, newPassword)` |
| Force email re-verification | clear `email_verified` row, call email-verification plugin's `send` method |
| Delete user | `fortress.auth.deleteUser(userId)` — cascades to sessions, role bindings, direct perms |

## Roles, groups, permissions

`@bajustone/fortress/plugins/admin` routes:

```
POST   /iam/roles                          create role
DELETE /iam/roles/:id                      delete role
GET    /iam/roles                          list roles
GET    /iam/permissions                    list permissions
POST   /iam/permissions/bind/user          bind a permission to a user
POST   /iam/permissions/bind/group         bind to a group
POST   /iam/permissions/bind/service-account  bind to a service account
DELETE /iam/permissions/bind/*             unbind variants
POST   /iam/role-bindings/user             bind a role to a user
POST   /iam/role-bindings/group            bind a role to a group
POST   /iam/role-bindings/service-account  bind a role to a service account
DELETE /iam/role-bindings/*                unbind variants
POST   /iam/groups                         create group
POST   /iam/groups/:id/members             add user to group
DELETE /iam/groups/:id/members/:userId     remove user from group
```

All require an authenticated user with the matching `fortress:*`
permission (e.g. `fortress:createRole`). The admin bootstrap binds them
to the first admin.

For declarative management (recommended for production), use
**policy-as-code** instead — see [docs/policy-as-code.md](./policy-as-code.md).

## Sessions and revocation

```ts
// List sessions for a user (callable from an admin route).
const sessions = await fortress.auth.listSessions(userId);

// Revoke a single session.
await fortress.auth.revokeSession(userId, sessionId);

// Revoke every refresh token for a user (forces logout everywhere on
// next access-token expiry; access tokens are stateless so they remain
// valid until they expire — keep TTL short).
await fortress.auth.revokeAllSessions(userId);
```

To force-logout immediately even before access-token expiry, set the
user inactive (`setUserActive(userId, false)`); the auth pipeline
rejects requests whose JWT subject resolves to an inactive user.

## Service accounts and API keys

Service accounts are first-class IAM subjects. They have no sessions —
they authenticate via API keys.

```ts
// Create the service account.
const sa = await fortress.iam.createServiceAccount({
  name: 'ci-bot',
  displayName: 'CI Bot',
});

// Bind a role to it.
const role = (await fortress.iam.getRoles()).find(r => r.name === 'editor')!;
await fortress.iam.bindRoleToServiceAccount(sa.id, role.id);

// Mint an API key for the service account (admin plugin route, requires apiKey:manage).
const res = await fetch(`/admin/service-accounts/${sa.id}/api-keys`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'Authorization': `Bearer ${adminJwt}` },
  body: JSON.stringify({ name: 'ci-pipeline' }),
});
const { key } = await res.json();  // returned ONCE; store in secret manager
```

API keys carry `subjectType: 'SERVICE_ACCOUNT'`; the resolver populates
the request principal so RBAC works the same as for users.

## OAuth clients

OAuth clients have secrets; manage via the OAuth plugin's admin
methods (`fortress.plugins.oauth.createClient(...)`,
`updateClient(...)`, `deleteClient(...)`). Secrets are returned **once**
on create — re-issue with `rotateClientSecret(clientId)` and update RPs
out-of-band.

For policy-as-code: OAuth clients are intentionally NOT covered by the
policy file (secrets do not belong in a checked-in JSON file). Track
them in your secret manager and run create/update via a one-off script.

## Audit logs

```ts
// Read a page of audit log entries.
const page = await fortress.plugins['audit-log'].listEntries({
  limit: 100,
  offset: 0,
  // optional filters:
  eventType: 'LOGIN_FAILURE',
  userId,
  after: new Date(Date.now() - 7 * 24 * 3600 * 1000),
});

// Verify the hash chain (when hashChain: true was passed at plugin construction).
const verified = await fortress.plugins['audit-log'].verifyChain();
if (!verified.ok) {
  console.error(`Chain broken at index ${verified.brokenAt}`);
}
```

The verifier walks every row and recomputes the SHA-256 chain. Run as a
scheduled job; alert when `ok === false`.

## Permission debugging — "why does user X have permission Y?"

Fortress ships `explainPermission` for this exact question:

```ts
import { explainPermission } from '@bajustone/fortress';

const explain = await explainPermission(
  fortress.config.database,
  fortress.iam,
  { type: 'USER', id: 42 },
  'article',
  'delete',
);

console.log(explain.allowed);          // true | false
console.log(explain.sources);          // every grant + its source (role / direct / group)
console.log(explain.roleBindings);     // roles the user is bound to
console.log(explain.groupMemberships); // groups the user belongs to
```

Each source carries enough context to point a human at the misconfig:

```ts
explain.sources[0]
// {
//   via: 'role',
//   role: 'editor',
//   group: { id: 7, name: 'eng' },          // when inherited via group
//   permission: { id, resource, action, effect, conditions, description }
// }
```

With `rbac.evaluationMode: 'deny-overrides'`, any matching `DENY` source
flips `allowed` to `false` regardless of matching `ALLOW` sources. In the
default `allow-only` mode, DENY entries are intentionally ignored. Wildcard permissions
(`resource: '*'`, `action: '*'`) match every check; you'll see them
listed as sources when they apply.

Wrap this in an admin route and you have a one-click "why does this
permission resolve the way it does" debugger.

## Building an admin console UI

The library doesn't ship one. Wire the routes above to your framework
of choice; common starting points:

- **Hono + React/HTMX:** drop the existing admin plugin routes under
  `/admin/*`, build a small SPA against them. The `mountFortress` call
  already mounts every IAM route.
- **SvelteKit:** use the SvelteKit adapter; build admin pages under
  `/routes/admin/+page.server.ts` that call `fortress.iam.*` directly.
  No HTTP roundtrip needed.
- **CLI:** wrap the IAM methods in a thin commander/citty CLI; useful
  for one-off ops and for environments without admin UI access.

In every case, gate the routes/pages with `permission('fortress', '...')`
declarations on the endpoint (`fortress` will RBAC-check before
dispatch) or `fortress.iam.checkPermission(subject, 'fortress', '...')`
in your handler.
