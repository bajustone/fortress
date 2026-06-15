# Admin Plugin

## Overview

The `admin` plugin provides a complete set of endpoints for managing Fortress's own resources: users, roles, groups, permissions, role bindings, permission bindings, and resource sync. The first-admin bootstrap endpoint is opt-in and protected by a one-time secret.

All admin endpoints are protected by `fortress:*` permissions enforced through the RBAC middleware. Until a user has been bootstrapped with the `fortress-admin` role, no one can access these routes. There is no ambient superadmin bypass.

## Installation

Import the `admin` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { admin } from '@bajustone/fortress/plugins/admin';

const fortress = createFortress({
  jwt: { key: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    admin({ bootstrap: { enabled: true, secret: process.env.FORTRESS_ADMIN_BOOTSTRAP_SECRET } }),
  ],
});
```

## Configuration

All fields on `AdminPluginOptions` are optional:

| Option | Type | Default | Description |
|---|---|---|---|
| `resource` | `string` | `'fortress'` | Resource name used in permission declarations. Change this if `fortress` conflicts with your application's resource naming. |
| `bootstrap` | `{ enabled: boolean; secret?: string }` | disabled | Mount the one-time first-admin bootstrap route. `secret` defaults to `FORTRESS_ADMIN_BOOTSTRAP_SECRET`. |
| `apiKeyRoutes` | `boolean` | `false` | Mount the admin-side api-key management endpoints under `/admin/users/:userId/api-keys/*` and `/admin/service-accounts/:id/api-keys/*`. Requires the `api-key` plugin to also be registered. See [API Key Management](#api-key-management) below. |

## Bootstrap

Before any admin endpoints can be used, you must bootstrap the first admin user. The bootstrap route is **not mounted by default**; enable it only during setup. It creates the `fortress-admin` role, registers all required permissions (auto-discovered from endpoint definitions across all plugins), and binds them to the specified user.

```ts
// Via the plugin method or HTTP, while bootstrap.enabled is true.
await fortress.plugins.admin.bootstrap({
  userId: '1',
  secret: process.env.FORTRESS_ADMIN_BOOTSTRAP_SECRET!,
});
```

Or via HTTP:

```
POST /iam/admin/bootstrap
Authorization: Bearer <access-token>
Content-Type: application/json

{ "userId": "1", "secret": "<one-time-secret>" }
```

Bootstrap succeeds only while zero `fortress-admin` bindings exist and the supplied secret matches the configured one-time secret. It cannot be used to re-bootstrap.

### What bootstrap does

1. Verifies the target user exists.
2. Scans all registered endpoint definitions (core auth, core IAM, and all plugins) to discover every declared `permission`.
3. Creates the corresponding `resource` and `permission` records if they do not already exist.
4. Creates the `fortress-admin` role (system role, cannot be updated or deleted via normal role endpoints).
5. Links every discovered permission to the `fortress-admin` role.
6. Binds the role to the specified user.

## Usage

### User management

```ts
// List users with pagination and search
const { users, total } = await fortress.plugins.admin.listUsers({
  limit: 20,
  offset: 0,
  search: 'alice',
  sortBy: 'id',
  sortDirection: 'desc',
});

// Get a single user
const user = await fortress.plugins.admin.getUserById({ id: '42' });

// Update a user
await fortress.plugins.admin.updateUser({ id: '42', name: 'New Name', isActive: false });

// Delete a user
await fortress.plugins.admin.deleteUser({ id: '42' });

// Create a user (admin-initiated, requires fortress:manageUsers)
const newUser = await fortress.plugins.admin.createUser({
  email: 'alice@example.com',
  name: 'Alice',
  password: 'SecurePass123!',
});
```

### Role management

```ts
// List all roles
const roles = await fortress.plugins.admin.getRoles();

// Get role with its permissions
const role = await fortress.plugins.admin.getRole({ id: '1' });
// role.permissions => Permission[]

// Create a role
const newRole = await fortress.plugins.admin.createRole({
  name: 'editor',
  permissions: [{ resource: 'post', action: 'publish' }],
  description: 'Content editors',
});

// Update role name/description
await fortress.plugins.admin.updateRole({ id: '1', name: 'editor', description: 'Content editors' });

// Delete a role
await fortress.plugins.admin.deleteRole({ id: '1' });

// Add a permission to a role
await fortress.plugins.admin.addPermissionToRole({ id: '1', resource: 'post', action: 'publish' });

// Bind a role to a user
await fortress.plugins.admin.bindRoleToUser({ id: '1', userId: 42 });

// Bind a role to a group
await fortress.plugins.admin.bindRoleToGroup({ id: '1', groupId: 5 });

// Unbind a role
await fortress.plugins.admin.unbindRole({ id: '1', subjectType: 'USER', subjectId: 42 });
```

System roles (like `fortress-admin`) cannot be updated or deleted through the admin endpoints.

### Group management

```ts
// List groups
const { groups, total } = await fortress.plugins.admin.listGroups({ limit: 20 });

// Create a group
const group = await fortress.plugins.admin.createGroup({ name: 'devs', description: 'Developer team' });

// Get group with members
const detail = await fortress.plugins.admin.getGroup({ id: '5' });
// detail.users => FortressUser[]

// Update group
await fortress.plugins.admin.updateGroup({ id: '5', name: 'devs', description: 'Developer team' });

// Delete group
await fortress.plugins.admin.deleteGroup({ id: '5' });

// List group members separately
const members = await fortress.plugins.admin.getGroupUsers({ id: '5' });

// Add/remove users from groups
await fortress.plugins.admin.addUserToGroup({ id: '5', userId: 42 });
await fortress.plugins.admin.removeUserFromGroup({ id: '5', userId: 42 });
```

### Permission management

```ts
// List all permissions, optionally filtered by resource
const perms = await fortress.plugins.admin.listPermissions({ resource: 'post' });

// Create a new permission
const perm = await fortress.plugins.admin.createPermission({
  resource: 'invoice',
  action: 'create',
  effect: 'ALLOW',
  description: 'Allow creating invoices',
});

// Delete a permission
await fortress.plugins.admin.deletePermission({ id: '99' });

// Get user permissions
const userPerms = await fortress.plugins.admin.getUserPermissions({ id: '42' });

// Check a specific permission
const { allowed } = await fortress.plugins.admin.checkPermission({
  userId: 42, resource: 'post', action: 'publish',
});

// Bind/unbind permissions directly to users or groups
await fortress.plugins.admin.bindPermissionToUser({ userId: 42, permission: { resource: 'post', action: 'publish' } });
await fortress.plugins.admin.bindPermissionToGroup({ groupId: 5, permission: { resource: 'post', action: 'publish' } });
await fortress.plugins.admin.unbindPermissionFromUser({ userId: 42, permissionId: 99 });
await fortress.plugins.admin.unbindPermissionFromGroup({ groupId: 5, permissionId: 99 });
```

### Resource sync

```ts
// Pull resources from database into file
await fortress.plugins.admin.syncResources({ direction: 'pull' });

// Push resources from file into database
await fortress.plugins.admin.syncResources({ direction: 'push', filePath: './custom-resources.json' });
```

### Service account management

Service accounts are non-human IAM principals used for CI/CD, M2M, devices, etc. The admin plugin proxies the core `/iam/service-accounts/*` endpoints (CRUD + role bindings + direct permission bindings) so they run through the admin plugin's permission gating when the admin plugin is registered alongside core fortress.

```ts
// Create a service account
const sa = await fortress.plugins.admin.createServiceAccount({
  name: 'ci-deploy',
  displayName: 'CI Deploy',
  description: 'Runs production deploys from GitHub Actions',
});

// List / get / update / delete
const { serviceAccounts, total } = await fortress.plugins.admin.listServiceAccounts({ limit: 20 });
const found = await fortress.plugins.admin.getServiceAccount({ id: sa.id });
await fortress.plugins.admin.updateServiceAccount({ id: sa.id, isActive: false });
await fortress.plugins.admin.deleteServiceAccount({ id: sa.id });

// Bind / unbind roles and direct permissions (same shape as the user variants)
await fortress.plugins.admin.bindRoleToServiceAccount({ serviceAccountId: sa.id, id: roleId });
await fortress.plugins.admin.bindPermissionToServiceAccount({
  serviceAccountId: sa.id,
  permission: { resource: 'deploy', action: 'run' },
});
```

See the [IAM service account docs](../../README.md#service-accounts) for the conceptual overview and `checkPermission({ type: 'SERVICE_ACCOUNT', id }, ...)` examples.

### API key management

When `apiKeyRoutes: true` is passed to the admin plugin (and the `api-key` plugin is also registered), six admin HTTP routes are mounted under `/admin/users/:userId/api-keys/*` and `/admin/service-accounts/:id/api-keys/*`. All are guarded by the `apiKey:manage` permission, which bootstrap auto-registers into the `fortress-admin` role when the flag is on.

```ts
import { createFortress } from '@bajustone/fortress';
import { apiKey } from '@bajustone/fortress/plugins/api-key';
import { admin } from '@bajustone/fortress/plugins/admin';

const fortress = createFortress({
  jwt: { key: '...' },
  database: adapter,
  plugins: [
    apiKey({ prefix: 'myapp' }),
    admin({ apiKeyRoutes: true }),
  ],
});
```

**Bootstrapping a service account's first credential.** A fresh service account has no login path — it can't self-mint. The `POST /admin/service-accounts/:id/api-keys` endpoint is the only supported way to issue its initial key:

```bash
curl -X POST http://localhost:3000/admin/service-accounts/42/api-keys \
  -H "Authorization: Bearer $ADMIN_JWT" \
  -H "Content-Type: application/json" \
  -d '{"name":"ci-deploy-github-actions"}'
# Returns { "key": "myapp_sk_...", "id": 7 } — store the raw key immediately.
```

From then on, the service account authenticates incoming requests with `Authorization: ApiKey myapp_sk_...` or `X-API-Key: myapp_sk_...` — the api-key plugin's `resolvePrincipal` hook turns the header into a subject principal and RBAC flows through as usual.

Admin-minted keys respect the same configured knobs (`prefix`, `maxKeysPerSubject`, `defaultExpirySeconds`) as self-service keys — the admin plugin re-enters the api-key plugin's `methods(ctx)` factory to mint, so there's no duplicate config.

## Endpoints

All endpoints require bearer authentication and the corresponding `fortress:*` permission. The bootstrap endpoint only requires authentication (no permission check).

### Bootstrap

| Method | Path | Permission |
|---|---|---|
| POST | `/iam/admin/bootstrap` | *(authenticated only)* |

### User endpoints

| Method | Path | Permission |
|---|---|---|
| GET | `/auth/users` | `fortress:viewUsers` |
| GET | `/auth/users/:id` | `fortress:viewUsers` |
| POST | `/auth/users` | `fortress:manageUsers` |
| PUT | `/auth/users/:id` | `fortress:manageUsers` |
| DELETE | `/auth/users/:id` | `fortress:manageUsers` |

### Role endpoints

| Method | Path | Permission |
|---|---|---|
| GET | `/iam/roles` | `fortress:viewRoles` |
| GET | `/iam/roles/:id` | `fortress:viewRoles` |
| POST | `/iam/roles` | `fortress:createRole` |
| PUT | `/iam/roles/:id` | `fortress:manageRoles` |
| DELETE | `/iam/roles/:id` | `fortress:deleteRole` |
| POST | `/iam/roles/:id/permissions` | `fortress:manageRoles` |
| POST | `/iam/roles/:id/bind/user` | `fortress:bindRole` |
| POST | `/iam/roles/:id/bind/group` | `fortress:bindRole` |
| DELETE | `/iam/roles/:id/bind` | `fortress:unbindRole` |

### Group endpoints

| Method | Path | Permission |
|---|---|---|
| GET | `/iam/groups` | `fortress:viewGroups` |
| GET | `/iam/groups/:id` | `fortress:viewGroups` |
| POST | `/iam/groups` | `fortress:createGroup` |
| PUT | `/iam/groups/:id` | `fortress:manageGroup` |
| DELETE | `/iam/groups/:id` | `fortress:manageGroup` |
| GET | `/iam/groups/:id/users` | `fortress:viewGroups` |
| POST | `/iam/groups/:id/users` | `fortress:manageGroup` |
| DELETE | `/iam/groups/:id/users/:userId` | `fortress:manageGroup` |

### Permission endpoints

| Method | Path | Permission |
|---|---|---|
| GET | `/iam/permissions` | `fortress:viewPermissions` |
| POST | `/iam/permissions` | `fortress:managePermissions` |
| DELETE | `/iam/permissions/:id` | `fortress:managePermissions` |
| GET | `/iam/users/:id/permissions` | `fortress:viewPermissions` |
| POST | `/iam/check` | `fortress:viewPermissions` |
| POST | `/iam/permissions/bind/user` | `fortress:managePermissions` |
| POST | `/iam/permissions/bind/group` | `fortress:managePermissions` |
| DELETE | `/iam/permissions/bind/user` | `fortress:managePermissions` |
| DELETE | `/iam/permissions/bind/group` | `fortress:managePermissions` |

### Service account endpoints (core IAM, proxied through admin)

These come from core IAM — the admin plugin re-registers them on its own `routes` array so they dispatch through the admin plugin's permission gating.

| Method | Path | Permission |
|---|---|---|
| POST | `/iam/service-accounts` | `fortress:createServiceAccount` |
| GET | `/iam/service-accounts` | `fortress:viewServiceAccounts` |
| GET | `/iam/service-accounts/:id` | `fortress:viewServiceAccounts` |
| PATCH | `/iam/service-accounts/:id` | `fortress:manageServiceAccount` |
| DELETE | `/iam/service-accounts/:id` | `fortress:manageServiceAccount` |
| GET | `/iam/service-accounts/:id/permissions` | `fortress:viewPermissions` |
| POST | `/iam/roles/:id/bind/service-account` | `fortress:bindRole` |
| DELETE | `/iam/roles/:id/bind/service-account` | `fortress:unbindRole` |
| POST | `/iam/permissions/bind/service-account` | `fortress:managePermissions` |
| DELETE | `/iam/permissions/bind/service-account` | `fortress:managePermissions` |

### API key admin endpoints (opt-in via `apiKeyRoutes: true`)

Mounted only when `admin({ apiKeyRoutes: true })`. All six require the `apiKey:manage` permission, which bootstrap auto-registers. Requires the `api-key` plugin to also be registered.

| Method | Path | Purpose |
|---|---|---|
| POST | `/admin/users/:userId/api-keys` | Mint a key on behalf of any user. |
| GET | `/admin/users/:userId/api-keys` | List any user's non-revoked keys. |
| DELETE | `/admin/users/:userId/api-keys/:id` | Revoke any user's key (ownership is not enforced). |
| POST | `/admin/service-accounts/:id/api-keys` | Mint a key on behalf of a service account. **This is the only HTTP path for bootstrapping a fresh service account's first credential.** |
| GET | `/admin/service-accounts/:id/api-keys` | List a service account's non-revoked keys. |
| DELETE | `/admin/service-accounts/:id/api-keys/:keyId` | Revoke a service account's key. |

### Resource endpoints

| Method | Path | Permission |
|---|---|---|
| GET | `/iam/resources` | `fortress:viewResources` |
| POST | `/iam/sync` | `fortress:managePermissions` |

## Bootstrap Hardening

The bootstrap endpoint is intentionally not mounted unless `bootstrap.enabled` is true. A request must be authenticated and must include the configured one-time secret. The secret is compared in constant time, and a successful bootstrap permanently closes the path by creating the first `fortress-admin` binding.

For emergency access after bootstrap, grant or repair IAM role bindings out-of-band using a trusted migration/seed process with direct database access; the HTTP bootstrap route will not re-open.

## Permissions Reference

The admin plugin uses all fortress permissions declared across admin and core IAM endpoints:

| Permission | Used by |
|---|---|
| `fortress:viewUsers` | List users, get user by ID |
| `fortress:manageUsers` | Create user, update user, delete user |
| `fortress:viewRoles` | List roles, get role with permissions |
| `fortress:createRole` | Create role |
| `fortress:deleteRole` | Delete role |
| `fortress:manageRoles` | Update role, add permission to role |
| `fortress:bindRole` | Bind role to user, group, or service account |
| `fortress:unbindRole` | Unbind role |
| `fortress:viewGroups` | List groups, get group, list group members |
| `fortress:createGroup` | Create group |
| `fortress:manageGroup` | Update group, delete group, add/remove group members |
| `fortress:viewPermissions` | List permissions, get user/service-account permissions, check permission |
| `fortress:managePermissions` | Create/delete permissions, bind/unbind permissions, resource sync |
| `fortress:viewResources` | List available resources |
| `fortress:createServiceAccount` | Create a service account |
| `fortress:viewServiceAccounts` | List and get service accounts |
| `fortress:manageServiceAccount` | Update / delete a service account |
| `apiKey:manage` | *(only when `apiKeyRoutes: true`)* Admin mint/list/revoke of any user's or service account's api keys |

## How It Works

1. **Default deny** -- All admin endpoints declare a `permission` in their endpoint metadata. The RBAC middleware enforces these permissions automatically. Without the `fortress-admin` role, every request is denied.
2. **Auto-discovery** -- The bootstrap method scans all registered endpoint definitions (core + plugins) to discover every `{ resource, action }` pair. This means adding new plugins with permission-protected endpoints automatically includes those permissions in the bootstrap role.
3. **Delegation** -- Admin methods delegate to the core `auth` and `iam` services. The plugin does not duplicate business logic; it provides the permission-gated route layer on top of existing service methods.
4. **Bootstrap is one-time** -- The bootstrap route is opt-in, secret-gated, and refuses to run after any `fortress-admin` role binding exists.
