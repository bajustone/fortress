# Admin Plugin

## Overview

The `admin` plugin provides a complete set of CRUD endpoints for managing Fortress's own resources: users, roles, groups, and permissions. It ships 15 endpoints plus a bootstrap endpoint for first-time admin setup.

All admin endpoints are protected by `fortress:*` permissions enforced through the RBAC middleware. Until a user has been bootstrapped with the `fortress-admin` role, no one can access these routes. Optionally, a set of `adminUserIds` can be designated as superadmins who bypass all permission checks entirely.

## Installation

Import the `admin` factory and pass it in the `plugins` array when creating a Fortress instance:

```ts
import { createFortress } from '@bajustone/fortress';
import { admin } from '@bajustone/fortress/plugins/admin';

const fortress = createFortress({
  jwt: { secret: 'your-secret-at-least-32-bytes!!' },
  database: adapter,
  plugins: [
    admin({ adminUserIds: [1] }),
  ],
});
```

## Configuration

All fields on `AdminPluginOptions` are optional:

| Option | Type | Default | Description |
|---|---|---|---|
| `adminUserIds` | `number[]` | `[]` | User IDs that bypass all permission checks (superadmins). These users can access any fortress admin endpoint without being assigned the corresponding permissions. |
| `resource` | `string` | `'fortress'` | Resource name used in permission declarations. Change this if `fortress` conflicts with your application's resource naming. |

## Bootstrap

Before any admin endpoints can be used, you must bootstrap the first admin user. The bootstrap endpoint creates the `fortress-admin` role, registers all required permissions (auto-discovered from endpoint definitions across all plugins), and binds them to the specified user.

```ts
// Via the plugin method
await fortress.plugins.admin.bootstrap({ userId: 1 });
```

Or via HTTP:

```
POST /iam/admin/bootstrap
Authorization: Bearer <access-token>
Content-Type: application/json

{ "userId": 1 }
```

Bootstrap can only be called once. After the `fortress-admin` role exists, only superadmins (those in `adminUserIds`) can re-bootstrap.

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
```

### Role management

```ts
// Get role with its permissions
const role = await fortress.plugins.admin.getRole({ id: '1' });
// role.permissions => Permission[]

// Update role name/description
await fortress.plugins.admin.updateRole({ id: '1', name: 'editor', description: 'Content editors' });

// Add a permission to a role
await fortress.plugins.admin.addPermissionToRole({ id: '1', resource: 'post', action: 'publish' });
```

System roles (like `fortress-admin`) cannot be updated through the update endpoint.

### Group management

```ts
// List groups
const { groups, total } = await fortress.plugins.admin.listGroups({ limit: 20 });

// Get group with members
const group = await fortress.plugins.admin.getGroup({ id: '5' });
// group.users => FortressUser[]

// Update group
await fortress.plugins.admin.updateGroup({ id: '5', name: 'devs', description: 'Developer team' });

// Delete group
await fortress.plugins.admin.deleteGroup({ id: '5' });

// List group members separately
const members = await fortress.plugins.admin.getGroupUsers({ id: '5' });
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
```

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
| PUT | `/auth/users/:id` | `fortress:manageUsers` |
| DELETE | `/auth/users/:id` | `fortress:manageUsers` |

### Role endpoints

| Method | Path | Permission |
|---|---|---|
| GET | `/iam/roles/:id` | `fortress:viewRoles` |
| PUT | `/iam/roles/:id` | `fortress:manageRoles` |
| POST | `/iam/roles/:id/permissions` | `fortress:manageRoles` |

### Group endpoints

| Method | Path | Permission |
|---|---|---|
| GET | `/iam/groups` | `fortress:viewGroups` |
| GET | `/iam/groups/:id` | `fortress:viewGroups` |
| PUT | `/iam/groups/:id` | `fortress:manageGroup` |
| DELETE | `/iam/groups/:id` | `fortress:manageGroup` |
| GET | `/iam/groups/:id/users` | `fortress:viewGroups` |

### Permission endpoints

| Method | Path | Permission |
|---|---|---|
| GET | `/iam/permissions` | `fortress:viewPermissions` |
| POST | `/iam/permissions` | `fortress:managePermissions` |
| DELETE | `/iam/permissions/:id` | `fortress:managePermissions` |

## Superadmin Bypass

When `adminUserIds` is provided, the plugin registers middleware on `/iam/*`, `/auth/users/*`, and `/auth/users` paths. For requests from a user whose ID is in the `adminUserIds` set, all permission checks are bypassed -- the request proceeds regardless of whether the user holds the required permissions.

This is useful for:

- Initial setup before bootstrap has been run.
- Emergency access when role bindings are misconfigured.
- Automated scripts that need unrestricted fortress access.

The superadmin bypass is framework-agnostic. It extracts the user ID from Hono's context (`c.get('fortressUserId')`) or Express's request object (`req.fortressUserId`), depending on which adapter is in use.

## Permissions Reference

The admin plugin declares eight distinct permissions, all on the `fortress` resource:

| Permission | Used by |
|---|---|
| `fortress:viewUsers` | List users, get user by ID |
| `fortress:manageUsers` | Update user, delete user |
| `fortress:viewRoles` | Get role with permissions |
| `fortress:manageRoles` | Update role, add permission to role |
| `fortress:viewGroups` | List groups, get group, list group members |
| `fortress:manageGroup` | Update group, delete group |
| `fortress:viewPermissions` | List permissions |
| `fortress:managePermissions` | Create permission, delete permission |

## How It Works

1. **Default deny** -- All admin endpoints declare a `permission` in their endpoint metadata. The RBAC middleware enforces these permissions automatically. Without the `fortress-admin` role (or superadmin status), every request is denied.
2. **Auto-discovery** -- The bootstrap method scans all registered endpoint definitions (core + plugins) to discover every `{ resource, action }` pair. This means adding new plugins with permission-protected endpoints automatically includes those permissions in the bootstrap role.
3. **Delegation** -- Admin methods delegate to the core `auth` and `iam` services. The plugin does not duplicate business logic; it provides the permission-gated route layer on top of existing service methods.
4. **Plugin middleware** -- When `adminUserIds` is configured, the plugin registers `after-auth` middleware that checks whether the authenticated user is a superadmin. If so, subsequent permission checks are bypassed. Non-superadmin requests pass through to the standard RBAC enforcement.
