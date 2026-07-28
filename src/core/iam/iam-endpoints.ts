import type { ErrorResponseWire, OkResponseWire } from '../auth/auth-endpoints';
import type { EndpointDefinition } from '../endpoint';
import type { FortressSchema } from '../json-schema';
import { authRef } from '../auth/auth-endpoints';
import { defineEndpoints } from '../define-endpoints';
import { arr, bool, defineComponents, endpoint, enums, id, int, nullable, obj, oneOf, record, recordOf, str } from '../schema-builder';

// Sentinel for "no body / query / params" matching EndpointDefinition's default.

interface EmptyInput {}

// ── Wire-format shapes (what endpoint handlers serialize to JSON) ──────

/** Wire shape of a persisted role. `description` and `isSystem` are optional nullable on the wire. */
export interface RoleWire {
  id: string;
  name: string;
  description?: string | null;
  isSystem?: boolean;
}

/** Wire shape of a persisted group. */
export interface GroupWire {
  id: string;
  name: string;
  description?: string | null;
}

/** Wire shape of a permission condition. `operator` is restricted to the supported set. */
export interface PermissionConditionWire {
  field: string;
  operator: 'eq' | 'neq' | 'in' | 'startsWith';
  value: string;
}

/** Wire shape of a persisted permission. */
export interface PermissionWire {
  id: string;
  resource: string;
  action: string;
  effect: 'ALLOW' | 'DENY';
  conditions?: PermissionConditionWire[];
  description?: string | null;
}

/** Wire shape of a permission-creation input. */
export interface PermissionInputWire {
  resource: string;
  action: string;
  effect?: 'ALLOW' | 'DENY';
  conditions?: PermissionConditionWire[];
}

/** Wire shape of the subject a permission check is evaluated against. */
export interface CheckSubjectWire {
  type: 'USER' | 'GROUP' | 'SERVICE_ACCOUNT';
  id: string;
}

/** Legacy user-only form of the permission-check body. */
export interface CheckPermissionByUserWire {
  userId: string;
  subject?: never;
  resource: string;
  action: string;
  context?: Record<string, unknown>;
}

/** Subject-aware form of the permission-check body. */
export interface CheckPermissionBySubjectWire {
  subject: CheckSubjectWire;
  userId?: never;
  resource: string;
  action: string;
  context?: Record<string, unknown>;
}

/**
 * Body accepted by `POST /iam/check`. Exactly one of `userId` or `subject`
 * must be present; the `?: never` arms make supplying both a compile error,
 * matching the `oneOf` schema that rejects it at runtime.
 */
export type CheckPermissionBodyWire = CheckPermissionByUserWire | CheckPermissionBySubjectWire;

/** Wire shape of a persisted service account. Date fields are ISO strings on the wire. */
export interface ServiceAccountWire {
  id: string;
  name: string;
  displayName?: string | null;
  description?: string | null;
  isActive: boolean;
  createdAt?: string;
  updatedAt?: string;
}

// ── Component schemas (typed registry) ──────────────────────────────────

const Role: FortressSchema<RoleWire> = obj(
  {
    id: id('Role ID'),
    name: str('Role name'),
    description: nullable(str('Role description')),
    isSystem: bool('Whether this is a system role'),
  },
  'id',
  'name',
) as FortressSchema<RoleWire>;

const Group: FortressSchema<GroupWire> = obj(
  {
    id: id('Group ID'),
    name: str('Group name'),
    description: nullable(str('Group description')),
  },
  'id',
  'name',
) as FortressSchema<GroupWire>;

const Permission: FortressSchema<PermissionWire> = obj(
  {
    id: id('Permission ID'),
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
) as FortressSchema<PermissionWire>;

const PermissionInput: FortressSchema<PermissionInputWire> = obj(
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
) as FortressSchema<PermissionInputWire>;

const ServiceAccount: FortressSchema<ServiceAccountWire> = obj(
  {
    id: id('Service account ID'),
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
) as FortressSchema<ServiceAccountWire>;

/** Explicit registry type so JSR's fast-check doesn't walk into the deeply-inferred `defineComponents` return. */
interface IamComponents {
  readonly components: {
    readonly Role: FortressSchema<RoleWire>;
    readonly Group: FortressSchema<GroupWire>;
    readonly Permission: FortressSchema<PermissionWire>;
    readonly PermissionInput: FortressSchema<PermissionInputWire>;
    readonly ServiceAccount: FortressSchema<ServiceAccountWire>;
  };
  readonly ref: <K extends keyof IamComponents['components']>(
    name: K,
  ) => FortressSchema<IamComponents['components'][K] extends FortressSchema<infer U> ? U : never>;
}

const iamComponents: IamComponents = defineComponents({
  Role,
  Group,
  Permission,
  PermissionInput,
  ServiceAccount,
}) as IamComponents;

/** Reusable OpenAPI component schemas referenced by the core IAM endpoints. */
export const iamComponentSchemas: IamComponents['components'] = iamComponents.components;

/** Typed `$ref` helper bound to {@link iamComponentSchemas}. */
export const iamRef: IamComponents['ref'] = iamComponents.ref;

// ── IAM endpoint definitions (keyed by handler name) ───────────────

/** Resource catalog response shape. */
interface ResourceCatalogWire {
  resources: Record<string, { actions: string[]; description?: string }>;
}

/** Paged service-account list response shape. */
interface ServiceAccountsListWire {
  serviceAccounts: ServiceAccountWire[];
  total: number;
}

/**
 * Typed record of every core IAM endpoint. Declared explicitly so JSR's
 * fast-check passes without `--allow-slow-types`, while
 * `InferEndpointCallInput<typeof iamEndpoints.X>` still resolves per-handler.
 */
export interface IamEndpointsMap {
  getResources: EndpointDefinition<
    EmptyInput,
    EmptyInput,
    EmptyInput,
    { 200: ResourceCatalogWire; 401: ErrorResponseWire }
  >;
  getRoles: EndpointDefinition<
    EmptyInput,
    EmptyInput,
    EmptyInput,
    { 200: RoleWire[]; 401: ErrorResponseWire }
  >;
  createRole: EndpointDefinition<
    { name: string; permissions: PermissionInputWire[]; description?: string },
    EmptyInput,
    EmptyInput,
    { 201: RoleWire; 401: ErrorResponseWire }
  >;
  deleteRole: EndpointDefinition<
    EmptyInput,
    EmptyInput,
    { id: string },
    { 200: OkResponseWire; 400: ErrorResponseWire; 401: ErrorResponseWire }
  >;
  bindRoleToUser: EndpointDefinition<
    { userId: string; tenantId?: string },
    EmptyInput,
    { id: string },
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  bindRoleToGroup: EndpointDefinition<
    { groupId: string; tenantId?: string },
    EmptyInput,
    { id: string },
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  unbindRole: EndpointDefinition<
    {
      subjectType: 'USER' | 'GROUP' | 'SERVICE_ACCOUNT';
      subjectId: string;
      tenantId?: string;
    },
    EmptyInput,
    { id: string },
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  createGroup: EndpointDefinition<
    { name: string; description?: string },
    EmptyInput,
    EmptyInput,
    { 201: GroupWire; 401: ErrorResponseWire }
  >;
  addUserToGroup: EndpointDefinition<
    { userId: string },
    EmptyInput,
    { id: string },
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  removeUserFromGroup: EndpointDefinition<
    EmptyInput,
    EmptyInput,
    { id: string; userId: string },
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  getUserPermissions: EndpointDefinition<
    EmptyInput,
    { tenantId?: string },
    { id: string },
    { 200: PermissionWire[]; 401: ErrorResponseWire }
  >;
  checkPermission: EndpointDefinition<
    CheckPermissionBodyWire,
    EmptyInput,
    EmptyInput,
    { 200: { allowed: boolean }; 401: ErrorResponseWire }
  >;
  bindPermissionToUser: EndpointDefinition<
    { userId: string; permission: PermissionInputWire; tenantId?: string },
    EmptyInput,
    EmptyInput,
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  bindPermissionToGroup: EndpointDefinition<
    { groupId: string; permission: PermissionInputWire; tenantId?: string },
    EmptyInput,
    EmptyInput,
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  unbindPermissionFromUser: EndpointDefinition<
    { userId: string; permissionId: string; tenantId?: string },
    EmptyInput,
    EmptyInput,
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  unbindPermissionFromGroup: EndpointDefinition<
    { groupId: string; permissionId: string; tenantId?: string },
    EmptyInput,
    EmptyInput,
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  createServiceAccount: EndpointDefinition<
    { name: string; displayName?: string; description?: string },
    EmptyInput,
    EmptyInput,
    { 201: ServiceAccountWire; 400: ErrorResponseWire; 401: ErrorResponseWire }
  >;
  listServiceAccounts: EndpointDefinition<
    EmptyInput,
    { limit?: number; offset?: number },
    EmptyInput,
    { 200: ServiceAccountsListWire; 401: ErrorResponseWire }
  >;
  getServiceAccount: EndpointDefinition<
    EmptyInput,
    EmptyInput,
    { id: string },
    { 200: ServiceAccountWire; 401: ErrorResponseWire; 404: ErrorResponseWire }
  >;
  updateServiceAccount: EndpointDefinition<
    { displayName?: string | null; description?: string | null; isActive?: boolean },
    EmptyInput,
    { id: string },
    { 200: ServiceAccountWire; 401: ErrorResponseWire; 404: ErrorResponseWire }
  >;
  deleteServiceAccount: EndpointDefinition<
    EmptyInput,
    EmptyInput,
    { id: string },
    { 200: OkResponseWire; 401: ErrorResponseWire; 404: ErrorResponseWire }
  >;
  getServiceAccountPermissions: EndpointDefinition<
    EmptyInput,
    { tenantId?: string },
    { id: string },
    { 200: PermissionWire[]; 401: ErrorResponseWire }
  >;
  bindRoleToServiceAccount: EndpointDefinition<
    { serviceAccountId: string; tenantId?: string },
    EmptyInput,
    { id: string },
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  unbindRoleFromServiceAccount: EndpointDefinition<
    { serviceAccountId: string; tenantId?: string },
    EmptyInput,
    { id: string },
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  bindPermissionToServiceAccount: EndpointDefinition<
    { serviceAccountId: string; permission: PermissionInputWire; tenantId?: string },
    EmptyInput,
    EmptyInput,
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
  unbindPermissionFromServiceAccount: EndpointDefinition<
    { serviceAccountId: string; permissionId: string; tenantId?: string },
    EmptyInput,
    EmptyInput,
    { 200: OkResponseWire; 401: ErrorResponseWire }
  >;
}

/**
 * Declarative endpoint definitions for fortress's built-in IAM admin routes.
 * The explicit `IamEndpointsMap` annotation keeps JSR fast-check happy
 * without sacrificing per-handler inference for `fortress.call.*`.
 */
export const iamEndpoints: IamEndpointsMap = defineEndpoints({
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
    .build() as IamEndpointsMap['getResources'],

  // ── Roles ──

  getRoles: endpoint('GET', '/iam/roles')
    .summary('List all roles')
    .tags('IAM', 'Roles')
    .security('bearer')
    .permission('fortress', 'viewRoles')
    .response(200, 'All roles', arr(iamRef('Role')))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('getRoles')
    .build() as IamEndpointsMap['getRoles'],

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
    .build() as IamEndpointsMap['createRole'],

  deleteRole: endpoint('DELETE', '/iam/roles/:id')
    .summary('Delete a role')
    .tags('IAM', 'Roles')
    .security('bearer')
    .permission('fortress', 'deleteRole')
    .params(obj({ id: id('Role ID') }, 'id'))
    .response(200, 'Role deleted', obj({ ok: bool() }, 'ok'))
    .response(400, 'Cannot delete system role', authRef('ErrorResponse'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('deleteRole')
    .build() as IamEndpointsMap['deleteRole'],

  // ── Role Bindings ──

  bindRoleToUser: endpoint('POST', '/iam/roles/:id/bind/user')
    .summary('Bind role to a user')
    .tags('IAM', 'Roles')
    .security('bearer')
    .permission('fortress', 'bindRole')
    .params(obj({ id: id('Role ID') }, 'id'))
    .body(obj(
      { userId: id('User ID'), tenantId: str('Tenant ID (optional)') },
      'userId',
    ))
    .response(200, 'Role bound to user', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('bindRoleToUser')
    .build() as IamEndpointsMap['bindRoleToUser'],

  bindRoleToGroup: endpoint('POST', '/iam/roles/:id/bind/group')
    .summary('Bind role to a group')
    .tags('IAM', 'Roles')
    .security('bearer')
    .permission('fortress', 'bindRole')
    .params(obj({ id: id('Role ID') }, 'id'))
    .body(obj(
      { groupId: id('Group ID'), tenantId: str('Tenant ID (optional)') },
      'groupId',
    ))
    .response(200, 'Role bound to group', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('bindRoleToGroup')
    .build() as IamEndpointsMap['bindRoleToGroup'],

  unbindRole: endpoint('DELETE', '/iam/roles/:id/bind')
    .summary('Unbind a role')
    .tags('IAM', 'Roles')
    .security('bearer')
    .permission('fortress', 'unbindRole')
    .params(obj({ id: id('Role ID') }, 'id'))
    .body(obj(
      {
        subjectType: enums('USER', 'GROUP', 'SERVICE_ACCOUNT'),
        subjectId: id('Subject ID'),
        tenantId: str('Tenant ID (optional)'),
      },
      'subjectType',
      'subjectId',
    ))
    .response(200, 'Role unbound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('unbindRole')
    .build() as IamEndpointsMap['unbindRole'],

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
    .build() as IamEndpointsMap['createGroup'],

  addUserToGroup: endpoint('POST', '/iam/groups/:id/users')
    .summary('Add user to group')
    .tags('IAM', 'Groups')
    .security('bearer')
    .permission('fortress', 'manageGroup')
    .params(obj({ id: id('Group ID') }, 'id'))
    .body(obj({ userId: id('User ID') }, 'userId'))
    .response(200, 'User added to group', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('addUserToGroup')
    .build() as IamEndpointsMap['addUserToGroup'],

  removeUserFromGroup: endpoint('DELETE', '/iam/groups/:id/users/:userId')
    .summary('Remove user from group')
    .tags('IAM', 'Groups')
    .security('bearer')
    .permission('fortress', 'manageGroup')
    .params(obj({ id: id('Group ID'), userId: id('User ID') }, 'id', 'userId'))
    .response(200, 'User removed from group', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('removeUserFromGroup')
    .build() as IamEndpointsMap['removeUserFromGroup'],

  // ── Permissions ──

  getUserPermissions: endpoint('GET', '/iam/users/:id/permissions')
    .summary('Get user permissions')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .permission('fortress', 'viewPermissions')
    .params(obj({ id: id('User ID') }, 'id'))
    .query(obj({ tenantId: str('Tenant ID (optional)') }))
    .response(200, 'User permissions', arr(iamRef('Permission')))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('getUserPermissions')
    .build() as IamEndpointsMap['getUserPermissions'],

  checkPermission: endpoint('POST', '/iam/check')
    .summary('Check if user has permission')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .permission('fortress', 'viewPermissions')
    // `oneOf` is exactly-one, so a body carrying both `userId` and `subject`
    // matches both arms and is rejected, as is a body carrying neither.
    .body(oneOf(
      obj(
        {
          userId: id('User ID'),
          resource: str('Resource name'),
          action: str('Action name'),
          context: record('Permission context'),
        },
        'userId',
        'resource',
        'action',
      ),
      obj(
        {
          subject: obj(
            {
              type: enums('USER', 'GROUP', 'SERVICE_ACCOUNT'),
              id: id('Subject ID'),
            },
            'type',
            'id',
          ),
          resource: str('Resource name'),
          action: str('Action name'),
          context: record('Permission context'),
        },
        'subject',
        'resource',
        'action',
      ),
    ))
    .response(200, 'Permission check result', obj({ allowed: bool('Whether permission is granted') }, 'allowed'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('checkPermission')
    .build() as IamEndpointsMap['checkPermission'],

  bindPermissionToUser: endpoint('POST', '/iam/permissions/bind/user')
    .summary('Bind permission directly to a user')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .permission('fortress', 'managePermissions')
    .body(obj(
      {
        userId: id('User ID'),
        permission: iamRef('PermissionInput'),
        tenantId: str('Tenant ID (optional)'),
      },
      'userId',
      'permission',
    ))
    .response(200, 'Permission bound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('bindPermissionToUser')
    .build() as IamEndpointsMap['bindPermissionToUser'],

  bindPermissionToGroup: endpoint('POST', '/iam/permissions/bind/group')
    .summary('Bind permission directly to a group')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .permission('fortress', 'managePermissions')
    .body(obj(
      {
        groupId: id('Group ID'),
        permission: iamRef('PermissionInput'),
        tenantId: str('Tenant ID (optional)'),
      },
      'groupId',
      'permission',
    ))
    .response(200, 'Permission bound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('bindPermissionToGroup')
    .build() as IamEndpointsMap['bindPermissionToGroup'],

  unbindPermissionFromUser: endpoint('DELETE', '/iam/permissions/bind/user')
    .summary('Unbind permission from a user')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .permission('fortress', 'managePermissions')
    .body(obj(
      {
        userId: id('User ID'),
        permissionId: id('Permission ID'),
        tenantId: str('Tenant ID (optional)'),
      },
      'userId',
      'permissionId',
    ))
    .response(200, 'Permission unbound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('unbindPermissionFromUser')
    .build() as IamEndpointsMap['unbindPermissionFromUser'],

  unbindPermissionFromGroup: endpoint('DELETE', '/iam/permissions/bind/group')
    .summary('Unbind permission from a group')
    .tags('IAM', 'Permissions')
    .security('bearer')
    .permission('fortress', 'managePermissions')
    .body(obj(
      {
        groupId: id('Group ID'),
        permissionId: id('Permission ID'),
        tenantId: str('Tenant ID (optional)'),
      },
      'groupId',
      'permissionId',
    ))
    .response(200, 'Permission unbound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('unbindPermissionFromGroup')
    .build() as IamEndpointsMap['unbindPermissionFromGroup'],

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
    .build() as IamEndpointsMap['createServiceAccount'],

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
    .build() as IamEndpointsMap['listServiceAccounts'],

  getServiceAccount: endpoint('GET', '/iam/service-accounts/:id')
    .summary('Get a service account by ID')
    .tags('IAM', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'viewServiceAccounts')
    .params(obj({ id: id('Service account ID') }, 'id'))
    .response(200, 'Service account', iamRef('ServiceAccount'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .response(404, 'Not found', authRef('ErrorResponse'))
    .handler('getServiceAccount')
    .build() as IamEndpointsMap['getServiceAccount'],

  updateServiceAccount: endpoint('PATCH', '/iam/service-accounts/:id')
    .summary('Update a service account')
    .description('Update displayName, description, or isActive. The `name` field is immutable — to rename, delete and recreate.')
    .tags('IAM', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'manageServiceAccount')
    .params(obj({ id: id('Service account ID') }, 'id'))
    .body(obj({
      displayName: nullable(str('New human-readable label')),
      description: nullable(str('New description')),
      isActive: bool('Whether the account is active'),
    }))
    .response(200, 'Service account updated', iamRef('ServiceAccount'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .response(404, 'Not found', authRef('ErrorResponse'))
    .handler('updateServiceAccount')
    .build() as IamEndpointsMap['updateServiceAccount'],

  deleteServiceAccount: endpoint('DELETE', '/iam/service-accounts/:id')
    .summary('Delete a service account')
    .description('Hard-deletes the service account and cascades to role bindings, direct permission bindings, and (via plugin observer) api keys owned by the account.')
    .tags('IAM', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'manageServiceAccount')
    .params(obj({ id: id('Service account ID') }, 'id'))
    .response(200, 'Service account deleted', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .response(404, 'Not found', authRef('ErrorResponse'))
    .handler('deleteServiceAccount')
    .build() as IamEndpointsMap['deleteServiceAccount'],

  getServiceAccountPermissions: endpoint('GET', '/iam/service-accounts/:id/permissions')
    .summary('Get effective permissions for a service account')
    .tags('IAM', 'Service Accounts', 'Permissions')
    .security('bearer')
    .permission('fortress', 'viewPermissions')
    .params(obj({ id: id('Service account ID') }, 'id'))
    .query(obj({ tenantId: str('Tenant ID (optional)') }))
    .response(200, 'Service account permissions', arr(iamRef('Permission')))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('getServiceAccountPermissions')
    .build() as IamEndpointsMap['getServiceAccountPermissions'],

  bindRoleToServiceAccount: endpoint('POST', '/iam/roles/:id/bind/service-account')
    .summary('Bind role to a service account')
    .tags('IAM', 'Roles', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'bindRole')
    .params(obj({ id: id('Role ID') }, 'id'))
    .body(obj(
      { serviceAccountId: id('Service account ID'), tenantId: str('Tenant ID (optional)') },
      'serviceAccountId',
    ))
    .response(200, 'Role bound to service account', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('bindRoleToServiceAccount')
    .build() as IamEndpointsMap['bindRoleToServiceAccount'],

  unbindRoleFromServiceAccount: endpoint('DELETE', '/iam/roles/:id/bind/service-account')
    .summary('Unbind role from a service account')
    .tags('IAM', 'Roles', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'unbindRole')
    .params(obj({ id: id('Role ID') }, 'id'))
    .body(obj(
      { serviceAccountId: id('Service account ID'), tenantId: str('Tenant ID (optional)') },
      'serviceAccountId',
    ))
    .response(200, 'Role unbound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('unbindRoleFromServiceAccount')
    .build() as IamEndpointsMap['unbindRoleFromServiceAccount'],

  bindPermissionToServiceAccount: endpoint('POST', '/iam/permissions/bind/service-account')
    .summary('Bind permission directly to a service account')
    .tags('IAM', 'Permissions', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'managePermissions')
    .body(obj(
      {
        serviceAccountId: id('Service account ID'),
        permission: iamRef('PermissionInput'),
        tenantId: str('Tenant ID (optional)'),
      },
      'serviceAccountId',
      'permission',
    ))
    .response(200, 'Permission bound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('bindPermissionToServiceAccount')
    .build() as IamEndpointsMap['bindPermissionToServiceAccount'],

  unbindPermissionFromServiceAccount: endpoint('DELETE', '/iam/permissions/bind/service-account')
    .summary('Unbind permission from a service account')
    .tags('IAM', 'Permissions', 'Service Accounts')
    .security('bearer')
    .permission('fortress', 'managePermissions')
    .body(obj(
      {
        serviceAccountId: id('Service account ID'),
        permissionId: id('Permission ID'),
        tenantId: str('Tenant ID (optional)'),
      },
      'serviceAccountId',
      'permissionId',
    ))
    .response(200, 'Permission unbound', obj({ ok: bool() }, 'ok'))
    .response(401, 'Not authenticated', authRef('ErrorResponse'))
    .handler('unbindPermissionFromServiceAccount')
    .build() as IamEndpointsMap['unbindPermissionFromServiceAccount'],
});
