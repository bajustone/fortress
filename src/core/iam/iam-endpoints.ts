import { authRef } from '../auth/auth-endpoints';
import { arr, bool, defineComponents, endpoint, enums, int, nullable, obj, record, recordOf, str } from '../schema-builder';

// ── Component schemas (typed registry) ──────────────────────────────

const Role = obj(
  {
    id: int('Role ID'),
    name: str('Role name'),
    description: nullable(str('Role description')),
    isSystem: bool('Whether this is a system role'),
  },
  'id',
  'name',
);

const Group = obj(
  {
    id: int('Group ID'),
    name: str('Group name'),
    description: nullable(str('Group description')),
  },
  'id',
  'name',
);

const Permission = obj(
  {
    id: int('Permission ID'),
    resource: str('Resource name'),
    action: str('Action name'),
    effect: enums('ALLOW', 'DENY'),
    conditions: arr(obj({
      field: str('Condition field'),
      operator: enums('eq', 'neq', 'in', 'startsWith'),
      value: str('Condition value'),
    }), 'Permission conditions'),
    description: nullable(str('Permission description')),
  },
  'id',
  'resource',
  'action',
  'effect',
);

const PermissionInput = obj(
  {
    resource: str('Resource name'),
    action: str('Action name'),
    effect: enums('ALLOW', 'DENY'),
    conditions: arr(obj({
      field: str('Condition field'),
      operator: enums('eq', 'neq', 'in', 'startsWith'),
      value: str('Condition value'),
    })),
  },
  'resource',
  'action',
);

const ServiceAccount = obj(
  {
    id: int('Service account ID'),
    name: str('Machine identifier — immutable after creation'),
    displayName: nullable(str('Human-readable label')),
    description: nullable(str('Free-form description')),
    isActive: bool('Whether the account can authenticate and resolve permissions'),
    createdAt: str('ISO 8601 creation timestamp'),
    updatedAt: str('ISO 8601 update timestamp'),
  },
  'id',
  'name',
  'isActive',
);

const iamComponents = defineComponents({
  Role,
  Group,
  Permission,
  PermissionInput,
  ServiceAccount,
});

/** Reusable OpenAPI component schemas referenced by the core IAM endpoints. */
export const iamComponentSchemas = iamComponents.components;

/** Typed `$ref` helper bound to {@link iamComponentSchemas}. */
export const iamRef = iamComponents.ref;

// ── IAM endpoint definitions (keyed by handler name) ───────────────

/**
 * Declarative endpoint definitions for fortress's built-in IAM admin routes
 * (users, groups, roles, permissions, role bindings, service accounts).
 *
 * Keyed by handler name so each entry's full generic type survives to the
 * typed `fortress.call.*` proxy. Materialized into the runtime route
 * table via `Object.values(iamEndpoints)`.
 */
export const iamEndpoints = {
  // ── Resources ──

  getResources: endpoint('GET', '/iam/resources')
    .summary('List all available resources')
    .tags('IAM', 'Resources')
    .security('bearer')
    .permission('fortress', 'viewResources')
    .response(200, 'Available resources with their actions', obj({
      resources: recordOf(obj({
        actions: arr(str('Action name'), 'Available actions'),
        description: str('Resource description'),
      }), 'Map of resource name to definition'),
    }, 'resources'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('getResources')
    .build(),

  // ── Roles ──

  getRoles: endpoint('GET', '/iam/roles')
    .summary('List all roles')
    .tags('IAM', 'Roles')
    .security('bearer')
    .permission('fortress', 'viewRoles')
    .response(200, 'All roles', arr(iamRef('Role')))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('getRoles')
    .build(),

  createRole: endpoint('POST', '/iam/roles')
    .summary('Create a role')
    .tags('IAM', 'Roles')
    .security('bearer')
    .permission('fortress', 'createRole')
    .body(obj(
      {
        name: str('Role name'),
        permissions: arr(iamRef('PermissionInput'), 'Permissions to assign'),
        description: str('Role description'),
      },
      'name',
      'permissions',
    ))
    .response(201, 'Role created', iamRef('Role'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('createRole')
    .build(),

  deleteRole: endpoint('DELETE', '/iam/roles/:id')
    .summary('Delete a role')
    .tags('IAM', 'Roles')
    .security('bearer')
    .permission('fortress', 'deleteRole')
    .params(obj({ id: int('Role ID') }, 'id'))
    .response(200, 'Role deleted', obj({ ok: bool() }, 'ok'))
    .response(400, 'Cannot delete system role', authRef('ErrorResponse'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('deleteRole')
    .build(),

  // ── Role Bindings ──

  bindRoleToUser: endpoint('POST', '/iam/roles/:id/bind/user')
    .summary('Bind role to a user')
    .tags('IAM', 'Roles')
    .security('bearer')
    .permission('fortress', 'bindRole')
    .params(obj({ id: int('Role ID') }, 'id'))
    .body(obj(
      { userId: int('User ID'), tenantId: str('Tenant ID (optional)') },
      'userId',
    ))
    .response(200, 'Role bound to user', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('bindRoleToUser')
    .build(),

  bindRoleToGroup: endpoint('POST', '/iam/roles/:id/bind/group')
    .summary('Bind role to a group')
    .tags('IAM', 'Roles')
    .security('bearer')
    .permission('fortress', 'bindRole')
    .params(obj({ id: int('Role ID') }, 'id'))
    .body(obj(
      { groupId: int('Group ID'), tenantId: str('Tenant ID (optional)') },
      'groupId',
    ))
    .response(200, 'Role bound to group', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('bindRoleToGroup')
    .build(),

  unbindRole: endpoint('DELETE', '/iam/roles/:id/bind')
    .summary('Unbind a role')
    .tags('IAM', 'Roles')
    .security('bearer')
    .permission('fortress', 'unbindRole')
    .params(obj({ id: int('Role ID') }, 'id'))
    .body(obj(
      {
        subjectType: enums('USER', 'GROUP', 'SERVICE_ACCOUNT'),
        subjectId: int('Subject ID'),
        tenantId: str('Tenant ID (optional)'),
      },
      'subjectType',
      'subjectId',
    ))
    .response(200, 'Role unbound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('unbindRole')
    .build(),

  // ── Groups ──

  createGroup: endpoint('POST', '/iam/groups')
    .summary('Create a group')
    .tags('IAM', 'Groups')
    .security('bearer')
    .permission('fortress', 'createGroup')
    .body(obj(
      { name: str('Group name'), description: str('Group description') },
      'name',
    ))
    .response(201, 'Group created', iamRef('Group'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('createGroup')
    .build(),

  addUserToGroup: endpoint('POST', '/iam/groups/:id/users')
    .summary('Add user to group')
    .tags('IAM', 'Groups')
    .security('bearer')
    .permission('fortress', 'manageGroup')
    .params(obj({ id: int('Group ID') }, 'id'))
    .body(obj({ userId: int('User ID') }, 'userId'))
    .response(200, 'User added to group', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('addUserToGroup')
    .build(),

  removeUserFromGroup: endpoint('DELETE', '/iam/groups/:id/users/:userId')
    .summary('Remove user from group')
    .tags('IAM', 'Groups')
    .security('bearer')
    .permission('fortress', 'manageGroup')
    .params(obj({ id: int('Group ID'), userId: int('User ID') }, 'id', 'userId'))
    .response(200, 'User removed from group', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('removeUserFromGroup')
    .build(),

  // ── Permissions ──

  getUserPermissions: endpoint('GET', '/iam/users/:id/permissions')
    .summary('Get user permissions')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .permission('fortress', 'viewPermissions')
    .params(obj({ id: int('User ID') }, 'id'))
    .query(obj({ tenantId: str('Tenant ID (optional)') }))
    .response(200, 'User permissions', arr(iamRef('Permission')))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('getUserPermissions')
    .build(),

  checkPermission: endpoint('POST', '/iam/check')
    .summary('Check if user has permission')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .permission('fortress', 'viewPermissions')
    .body(obj(
      {
        userId: int('User ID'),
        resource: str('Resource name'),
        action: str('Action name'),
        context: record('Permission context'),
      },
      'userId',
      'resource',
      'action',
    ))
    .response(200, 'Permission check result', obj({ allowed: bool('Whether permission is granted') }, 'allowed'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('checkPermission')
    .build(),

  bindPermissionToUser: endpoint('POST', '/iam/permissions/bind/user')
    .summary('Bind permission directly to a user')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .permission('fortress', 'managePermissions')
    .body(obj(
      {
        userId: int('User ID'),
        permission: iamRef('PermissionInput'),
        tenantId: str('Tenant ID (optional)'),
      },
      'userId',
      'permission',
    ))
    .response(200, 'Permission bound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('bindPermissionToUser')
    .build(),

  bindPermissionToGroup: endpoint('POST', '/iam/permissions/bind/group')
    .summary('Bind permission directly to a group')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .permission('fortress', 'managePermissions')
    .body(obj(
      {
        groupId: int('Group ID'),
        permission: iamRef('PermissionInput'),
        tenantId: str('Tenant ID (optional)'),
      },
      'groupId',
      'permission',
    ))
    .response(200, 'Permission bound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('bindPermissionToGroup')
    .build(),

  unbindPermissionFromUser: endpoint('DELETE', '/iam/permissions/bind/user')
    .summary('Unbind permission from a user')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .permission('fortress', 'managePermissions')
    .body(obj(
      {
        userId: int('User ID'),
        permissionId: int('Permission ID'),
        tenantId: str('Tenant ID (optional)'),
      },
      'userId',
      'permissionId',
    ))
    .response(200, 'Permission unbound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('unbindPermissionFromUser')
    .build(),

  unbindPermissionFromGroup: endpoint('DELETE', '/iam/permissions/bind/group')
    .summary('Unbind permission from a group')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .permission('fortress', 'managePermissions')
    .body(obj(
      {
        groupId: int('Group ID'),
        permissionId: int('Permission ID'),
        tenantId: str('Tenant ID (optional)'),
      },
      'groupId',
      'permissionId',
    ))
    .response(200, 'Permission unbound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('unbindPermissionFromGroup')
    .build(),

  // ── Service Accounts ──

  createServiceAccount: endpoint('POST', '/iam/service-accounts')
    .summary('Create a service account')
    .description('Create a non-human IAM principal. Service accounts hold roles and direct permissions just like users, but have no sessions, passwords, or group memberships. The `name` is immutable after creation.')
    .tags('IAM', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'createServiceAccount')
    .body(obj(
      {
        name: str('Machine identifier (immutable)'),
        displayName: str('Human-readable label'),
        description: str('Free-form description'),
      },
      'name',
    ))
    .response(201, 'Service account created', iamRef('ServiceAccount'))
    .response(400, 'Bad request', authRef('ErrorResponse'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('createServiceAccount')
    .build(),

  listServiceAccounts: endpoint('GET', '/iam/service-accounts')
    .summary('List service accounts')
    .tags('IAM', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'viewServiceAccounts')
    .query(obj({
      limit: int('Page size (default 50)'),
      offset: int('Offset from the start of the list'),
    }))
    .response(200, 'Service accounts', obj({
      serviceAccounts: arr(iamRef('ServiceAccount')),
      total: int('Total service accounts'),
    }, 'serviceAccounts', 'total'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('listServiceAccounts')
    .build(),

  getServiceAccount: endpoint('GET', '/iam/service-accounts/:id')
    .summary('Get a service account by ID')
    .tags('IAM', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'viewServiceAccounts')
    .params(obj({ id: int('Service account ID') }, 'id'))
    .response(200, 'Service account', iamRef('ServiceAccount'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .response(404, 'Not found', authRef('ErrorResponse'))
    .handler('getServiceAccount')
    .build(),

  updateServiceAccount: endpoint('PATCH', '/iam/service-accounts/:id')
    .summary('Update a service account')
    .description('Update displayName, description, or isActive. The `name` field is immutable — to rename, delete and recreate.')
    .tags('IAM', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'manageServiceAccount')
    .params(obj({ id: int('Service account ID') }, 'id'))
    .body(obj({
      displayName: nullable(str('New human-readable label')),
      description: nullable(str('New description')),
      isActive: bool('Whether the account is active'),
    }))
    .response(200, 'Service account updated', iamRef('ServiceAccount'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .response(404, 'Not found', authRef('ErrorResponse'))
    .handler('updateServiceAccount')
    .build(),

  deleteServiceAccount: endpoint('DELETE', '/iam/service-accounts/:id')
    .summary('Delete a service account')
    .description('Hard-deletes the service account and cascades to role bindings, direct permission bindings, and (via plugin observer) api keys owned by the account.')
    .tags('IAM', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'manageServiceAccount')
    .params(obj({ id: int('Service account ID') }, 'id'))
    .response(200, 'Service account deleted', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .response(404, 'Not found', authRef('ErrorResponse'))
    .handler('deleteServiceAccount')
    .build(),

  getServiceAccountPermissions: endpoint('GET', '/iam/service-accounts/:id/permissions')
    .summary('Get effective permissions for a service account')
    .tags('IAM', 'Service Accounts', 'Permissions')
    .security('bearer')
    .permission('fortress', 'viewPermissions')
    .params(obj({ id: int('Service account ID') }, 'id'))
    .query(obj({ tenantId: str('Tenant ID (optional)') }))
    .response(200, 'Service account permissions', arr(iamRef('Permission')))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('getServiceAccountPermissions')
    .build(),

  bindRoleToServiceAccount: endpoint('POST', '/iam/roles/:id/bind/service-account')
    .summary('Bind role to a service account')
    .tags('IAM', 'Roles', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'bindRole')
    .params(obj({ id: int('Role ID') }, 'id'))
    .body(obj(
      { serviceAccountId: int('Service account ID'), tenantId: str('Tenant ID (optional)') },
      'serviceAccountId',
    ))
    .response(200, 'Role bound to service account', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('bindRoleToServiceAccount')
    .build(),

  unbindRoleFromServiceAccount: endpoint('DELETE', '/iam/roles/:id/bind/service-account')
    .summary('Unbind role from a service account')
    .tags('IAM', 'Roles', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'unbindRole')
    .params(obj({ id: int('Role ID') }, 'id'))
    .body(obj(
      { serviceAccountId: int('Service account ID'), tenantId: str('Tenant ID (optional)') },
      'serviceAccountId',
    ))
    .response(200, 'Role unbound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('unbindRoleFromServiceAccount')
    .build(),

  bindPermissionToServiceAccount: endpoint('POST', '/iam/permissions/bind/service-account')
    .summary('Bind permission directly to a service account')
    .tags('IAM', 'Permissions', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'managePermissions')
    .body(obj(
      {
        serviceAccountId: int('Service account ID'),
        permission: iamRef('PermissionInput'),
        tenantId: str('Tenant ID (optional)'),
      },
      'serviceAccountId',
      'permission',
    ))
    .response(200, 'Permission bound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('bindPermissionToServiceAccount')
    .build(),

  unbindPermissionFromServiceAccount: endpoint('DELETE', '/iam/permissions/bind/service-account')
    .summary('Unbind permission from a service account')
    .tags('IAM', 'Permissions', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'managePermissions')
    .body(obj(
      {
        serviceAccountId: int('Service account ID'),
        permissionId: int('Permission ID'),
        tenantId: str('Tenant ID (optional)'),
      },
      'serviceAccountId',
      'permissionId',
    ))
    .response(200, 'Permission unbound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('unbindPermissionFromServiceAccount')
    .build(),
} as const;
