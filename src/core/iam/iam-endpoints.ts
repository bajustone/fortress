import type { ComponentSchemas, EndpointDefinition } from '../endpoint';
import { arr, bool, endpoint, enums, int, nullable, obj, ref, str } from '../schema-builder';

// ── Component Schemas (reusable via $ref) ───────────────────────────

export const iamComponentSchemas: ComponentSchemas = {
  Role: obj(
    {
      id: int('Role ID'),
      name: str('Role name'),
      description: nullable(str('Role description')),
      isSystem: bool('Whether this is a system role'),
    },
    'id',
    'name',
  ),

  Group: obj(
    {
      id: int('Group ID'),
      name: str('Group name'),
      description: nullable(str('Group description')),
    },
    'id',
    'name',
  ),

  Permission: obj(
    {
      id: int('Permission ID'),
      resource: str('Resource name'),
      action: str('Action name'),
      effect: enums('ALLOW', 'DENY'),
      conditions: {
        type: 'array',
        items: obj({
          field: str('Condition field'),
          operator: enums('eq', 'neq', 'in', 'startsWith'),
          value: str('Condition value'),
        }),
        description: 'Permission conditions',
      },
      description: nullable(str('Permission description')),
    },
    'id',
    'resource',
    'action',
    'effect',
  ),

  PermissionInput: obj(
    {
      resource: str('Resource name'),
      action: str('Action name'),
      effect: enums('ALLOW', 'DENY'),
      conditions: {
        type: 'array',
        items: obj({
          field: str('Condition field'),
          operator: enums('eq', 'neq', 'in', 'startsWith'),
          value: str('Condition value'),
        }),
      },
    },
    'resource',
    'action',
  ),
};

// ── IAM Endpoint Definitions ────────────────────────────────────────

export const iamEndpoints: EndpointDefinition[] = [
  // ── Resources ──

  endpoint('GET', '/iam/resources')
    .summary('List all available resources')
    .tags('IAM', 'Resources')
    .security('bearer')
    .response(200, 'Available resources with their actions', obj({
      resources: {
        type: 'object',
        additionalProperties: obj({
          actions: arr(str('Action name'), 'Available actions'),
          description: str('Resource description'),
        }),
        description: 'Map of resource name to definition',
      },
    }, 'resources'))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('getResources')
    .build(),

  // ── Roles ──

  endpoint('GET', '/iam/roles')
    .summary('List all roles')
    .tags('IAM', 'Roles')
    .security('bearer')
    .response(200, 'All roles', arr(ref('Role')))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('getRoles')
    .build(),

  endpoint('POST', '/iam/roles')
    .summary('Create a role')
    .tags('IAM', 'Roles')
    .security('bearer')
    .body(obj(
      {
        name: str('Role name'),
        permissions: arr(ref('PermissionInput'), 'Permissions to assign'),
        description: str('Role description'),
      },
      'name',
      'permissions',
    ))
    .response(201, 'Role created', ref('Role'))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('createRole')
    .build(),

  endpoint('DELETE', '/iam/roles/:id')
    .summary('Delete a role')
    .tags('IAM', 'Roles')
    .security('bearer')
    .params(obj({ id: int('Role ID') }, 'id'))
    .response(200, 'Role deleted', obj({ ok: bool() }))
    .response(400, 'Cannot delete system role', ref('ErrorResponse'))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('deleteRole')
    .build(),

  // ── Role Bindings ──

  endpoint('POST', '/iam/roles/:id/bind/user')
    .summary('Bind role to a user')
    .tags('IAM', 'Roles')
    .security('bearer')
    .params(obj({ id: int('Role ID') }, 'id'))
    .body(obj(
      { userId: int('User ID'), tenantId: str('Tenant ID (optional)') },
      'userId',
    ))
    .response(200, 'Role bound to user', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('bindRoleToUser')
    .build(),

  endpoint('POST', '/iam/roles/:id/bind/group')
    .summary('Bind role to a group')
    .tags('IAM', 'Roles')
    .security('bearer')
    .params(obj({ id: int('Role ID') }, 'id'))
    .body(obj(
      { groupId: int('Group ID'), tenantId: str('Tenant ID (optional)') },
      'groupId',
    ))
    .response(200, 'Role bound to group', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('bindRoleToGroup')
    .build(),

  endpoint('DELETE', '/iam/roles/:id/bind')
    .summary('Unbind a role')
    .tags('IAM', 'Roles')
    .security('bearer')
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
    .response(200, 'Role unbound', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('unbindRole')
    .build(),

  // ── Groups ──

  endpoint('POST', '/iam/groups')
    .summary('Create a group')
    .tags('IAM', 'Groups')
    .security('bearer')
    .body(obj(
      { name: str('Group name'), description: str('Group description') },
      'name',
    ))
    .response(201, 'Group created', ref('Group'))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('createGroup')
    .build(),

  endpoint('POST', '/iam/groups/:id/users')
    .summary('Add user to group')
    .tags('IAM', 'Groups')
    .security('bearer')
    .params(obj({ id: int('Group ID') }, 'id'))
    .body(obj({ userId: int('User ID') }, 'userId'))
    .response(200, 'User added to group', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('addUserToGroup')
    .build(),

  endpoint('DELETE', '/iam/groups/:id/users/:userId')
    .summary('Remove user from group')
    .tags('IAM', 'Groups')
    .security('bearer')
    .params(obj({ id: int('Group ID'), userId: int('User ID') }, 'id', 'userId'))
    .response(200, 'User removed from group', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('removeUserFromGroup')
    .build(),

  // ── Permissions ──

  endpoint('GET', '/iam/users/:id/permissions')
    .summary('Get user permissions')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .params(obj({ id: int('User ID') }, 'id'))
    .query(obj({ tenantId: str('Tenant ID (optional)') }))
    .response(200, 'User permissions', arr(ref('Permission')))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('getUserPermissions')
    .build(),

  endpoint('POST', '/iam/check')
    .summary('Check if user has permission')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .body(obj(
      {
        userId: int('User ID'),
        resource: str('Resource name'),
        action: str('Action name'),
        context: { type: 'object', additionalProperties: true, description: 'Permission context' },
      },
      'userId',
      'resource',
      'action',
    ))
    .response(200, 'Permission check result', obj({ allowed: bool('Whether permission is granted') }, 'allowed'))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('checkPermission')
    .build(),

  endpoint('POST', '/iam/permissions/bind/user')
    .summary('Bind permission directly to a user')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .body(obj(
      {
        userId: int('User ID'),
        permission: ref('PermissionInput'),
        tenantId: str('Tenant ID (optional)'),
      },
      'userId',
      'permission',
    ))
    .response(200, 'Permission bound', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('bindPermissionToUser')
    .build(),

  endpoint('POST', '/iam/permissions/bind/group')
    .summary('Bind permission directly to a group')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .body(obj(
      {
        groupId: int('Group ID'),
        permission: ref('PermissionInput'),
        tenantId: str('Tenant ID (optional)'),
      },
      'groupId',
      'permission',
    ))
    .response(200, 'Permission bound', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('bindPermissionToGroup')
    .build(),

  endpoint('DELETE', '/iam/permissions/bind/user')
    .summary('Unbind permission from a user')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .body(obj(
      {
        userId: int('User ID'),
        permissionId: int('Permission ID'),
        tenantId: str('Tenant ID (optional)'),
      },
      'userId',
      'permissionId',
    ))
    .response(200, 'Permission unbound', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('unbindPermissionFromUser')
    .build(),

  endpoint('DELETE', '/iam/permissions/bind/group')
    .summary('Unbind permission from a group')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .body(obj(
      {
        groupId: int('Group ID'),
        permissionId: int('Permission ID'),
        tenantId: str('Tenant ID (optional)'),
      },
      'groupId',
      'permissionId',
    ))
    .response(200, 'Permission unbound', obj({ ok: bool() }))
    .response(401, 'Not authenticated', ref('ErrorResponse'))
    .handler('unbindPermissionFromGroup')
    .build(),
];
