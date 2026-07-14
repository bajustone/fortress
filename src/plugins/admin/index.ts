/**
 * Admin plugin for fortress.
 *
 * Bootstraps an initial admin user and applies a default-deny policy to the
 * IAM management endpoints, then exposes the full admin CRUD surface
 * (users, groups, roles, permissions, role bindings) as HTTP routes guarded
 * by fortress's own RBAC. Required if you want a self-service IAM admin UI
 * out of the box.
 *
 * @module
 */

import type { EndpointDefinition, EndpointPermission } from '../../core/endpoint';
import type { ResourceFile } from '../../core/iam/resource-sync';
import type { FortressPlugin, PluginContext, PluginRouteContext } from '../../core/plugin';
import type { FortressUser, Group, Permission, PermissionInput, Role, SubjectType } from '../../core/types';
import type { ApiKeyInfo } from '../api-key/core';
import type { ApiKeyMethods } from '../api-key/index';
import { authEndpoints } from '../../core/auth/auth-endpoints';
import { Errors } from '../../core/errors';
import { iamEndpoints } from '../../core/iam/iam-endpoints';
import { pullResources } from '../../core/iam/resource-sync';
import { listKeysForSubject, revokeKeyAsAdmin } from '../api-key/core';

export interface AdminPluginOptions {
  /** Resource name for fortress admin permissions. Default: 'fortress'. */
  resource?: string;
  /** Opt-in one-time bootstrap route. Disabled by default. */
  bootstrap?: {
    enabled: boolean;
    /** One-time secret. Defaults to process.env.FORTRESS_ADMIN_BOOTSTRAP_SECRET. */
    secret?: string;
  };
  /**
   * Mount admin-side api-key management routes under
   * `/admin/users/:userId/api-keys/*` and
   * `/admin/service-accounts/:id/api-keys/*`. Default `false`.
   *
   * When enabled, the admin plugin exposes POST, GET, and DELETE endpoints
   * for any user's or service account's API keys, guarded by the
   * `apiKey:manage` permission (auto-registered into the `fortress-admin`
   * role via bootstrap). The POST endpoints are the only supported path
   * for bootstrapping a service account's first key — a fresh service
   * account has no credential of its own, so an admin must mint the
   * initial key on its behalf. Requires the `api-key` plugin to also be
   * registered, since the `api_key` model lives there.
   */
  apiKeyRoutes?: boolean;
}

/**
 * Collect all unique permission declarations from endpoint definitions.
 */
function collectPermissions(endpoints: EndpointDefinition[]): EndpointPermission[] {
  const seen = new Set<string>();
  const result: EndpointPermission[] = [];

  for (const ep of endpoints) {
    const perm = ep.meta?.permission;
    if (!perm)
      continue;
    const key = `${perm.resource}:${perm.action}`;
    if (seen.has(key))
      continue;
    seen.add(key);
    result.push(perm);
  }

  return result;
}

// ── Inline JSON Schema helpers ────────────────────────────────────

const userRef = { $ref: '#/components/schemas/User' };
const permissionRef = { $ref: '#/components/schemas/Permission' };
const permissionInputRef = { $ref: '#/components/schemas/PermissionInput' };
const errorRef = { $ref: '#/components/schemas/ErrorResponse' };

function intSchema(desc: string): { type: 'integer'; description: string } {
  return { type: 'integer', description: desc };
}

function strSchema(desc: string): { type: 'string'; description: string } {
  return { type: 'string', description: desc };
}

function boolSchema(desc: string): { type: 'boolean'; description: string } {
  return { type: 'boolean', description: desc };
}

/**
 * Parse a value to a required non-empty subject-id string.
 *
 * IDs are opaque strings at the fortress API surface (RFC 7519 §4.1.2 for
 * JWT `sub`, and per the v0.3.0 lock-in audit). Numeric inputs are accepted
 * and stringified — numeric-keyed adapters keep working transparently.
 */
const encoder = new TextEncoder();

function timingSafeEqual(a: string, b: string): boolean {
  const left = encoder.encode(a);
  const right = encoder.encode(b);
  const len = Math.max(left.length, right.length);
  let diff = left.length ^ right.length;
  for (let i = 0; i < len; i++)
    diff |= (left[i] ?? 0) ^ (right[i] ?? 0);
  return diff === 0;
}

function requireId(v: unknown, name: string): string {
  if (v == null || v === '')
    throw Errors.badRequest(`${name} is required`);
  if (typeof v === 'string')
    return v;
  if (typeof v === 'number' && Number.isFinite(v))
    return String(v);
  throw Errors.badRequest(`${name} must be a string or number`);
}

// ── Admin endpoint definitions ────────────────────────────────────

const adminAuthEndpoints: EndpointDefinition[] = [
  // GET /auth/users — list users (paginated, searchable)
  {
    method: 'GET',
    path: '/auth/users',
    handler: 'listUsers',
    meta: {
      summary: 'List users',
      description: 'List all users with pagination and optional search',
      tags: ['Auth', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewUsers' },
    },
    input: {
      query: {
        type: 'object',
        properties: {
          limit: intSchema('Max results (default 50)'),
          offset: intSchema('Skip results (default 0)'),
          search: strSchema('Search by email'),
          sortBy: strSchema('Sort field (default: id)'),
          sortDirection: { type: 'string', enum: ['asc', 'desc'], description: 'Sort direction' },
        },
      },
    },
    responses: {
      200: {
        description: 'User list',
        schema: {
          type: 'object',
          properties: {
            users: { type: 'array', items: userRef, description: 'List of users' },
            total: intSchema('Total number of users'),
          },
          required: ['users', 'total'],
        },
      },
      401: { description: 'Not authenticated' },
      403: { description: 'Insufficient permissions' },
    },
  },

  // GET /auth/users/:id — get user by ID
  {
    method: 'GET',
    path: '/auth/users/:id',
    handler: 'getUserById',
    meta: {
      summary: 'Get user by ID',
      tags: ['Auth', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewUsers' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('User ID') },
        required: ['id'],
      },
    },
    responses: {
      200: { description: 'User details', schema: userRef },
      401: { description: 'Not authenticated' },
      403: { description: 'Insufficient permissions' },
      404: { description: 'User not found', schema: errorRef },
    },
  },

  // PUT /auth/users/:id — update user
  {
    method: 'PUT',
    path: '/auth/users/:id',
    handler: 'updateUser',
    meta: {
      summary: 'Update user',
      tags: ['Auth', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageUsers' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('User ID') },
        required: ['id'],
      },
      body: {
        type: 'object',
        properties: {
          name: strSchema('Display name'),
          email: { type: 'string', format: 'email', description: 'User email' },
          isActive: boolSchema('Account active status'),
          password: strSchema('New password (will be hashed)'),
        },
      },
    },
    responses: {
      200: { description: 'Updated user', schema: userRef },
      401: { description: 'Not authenticated' },
      403: { description: 'Insufficient permissions' },
      404: { description: 'User not found', schema: errorRef },
      409: { description: 'Email already in use', schema: errorRef },
    },
  },

  // DELETE /auth/users/:id — delete user
  {
    method: 'DELETE',
    path: '/auth/users/:id',
    handler: 'deleteUser',
    meta: {
      summary: 'Delete user',
      tags: ['Auth', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageUsers' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('User ID') },
        required: ['id'],
      },
    },
    responses: {
      200: { description: 'User deleted', schema: { type: 'object', properties: { ok: boolSchema('Success') } } },
      401: { description: 'Not authenticated' },
      403: { description: 'Insufficient permissions' },
      404: { description: 'User not found', schema: errorRef },
    },
  },

  // POST /auth/users — admin-initiated user creation
  {
    method: 'POST',
    path: '/auth/users',
    handler: 'createUser',
    meta: {
      summary: 'Create a user (admin)',
      description: 'Admin-initiated user creation. Unlike /auth/register, requires authentication and manageUsers permission.',
      tags: ['Auth', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageUsers' },
    },
    input: {
      body: {
        type: 'object',
        properties: {
          email: { type: 'string', format: 'email', description: 'User email' },
          name: strSchema('Display name'),
          password: strSchema('User password'),
          isActive: boolSchema('Set active status (default true)'),
        },
        required: ['email', 'name'],
      },
    },
    responses: {
      201: { description: 'User created', schema: userRef },
      401: { description: 'Not authenticated' },
      403: { description: 'Insufficient permissions' },
      409: { description: 'Email already exists', schema: errorRef },
    },
  },
];

const adminIamEndpoints: EndpointDefinition[] = [
  // GET /iam/roles/:id — get role with permissions
  {
    method: 'GET',
    path: '/iam/roles/:id',
    handler: 'getRole',
    meta: {
      summary: 'Get role with permissions',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewRoles' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Role ID') },
        required: ['id'],
      },
    },
    responses: {
      200: {
        description: 'Role with permissions',
        schema: {
          type: 'object',
          properties: {
            id: intSchema('Role ID'),
            name: strSchema('Role name'),
            description: { type: 'string', nullable: true, description: 'Role description' },
            isSystem: boolSchema('Whether this is a system role'),
            permissions: { type: 'array', items: permissionRef, description: 'Role permissions' },
          },
          required: ['id', 'name', 'permissions'],
        },
      },
      404: { description: 'Role not found', schema: errorRef },
    },
  },

  // PUT /iam/roles/:id — update role
  {
    method: 'PUT',
    path: '/iam/roles/:id',
    handler: 'updateRole',
    meta: {
      summary: 'Update role',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageRoles' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Role ID') },
        required: ['id'],
      },
      body: {
        type: 'object',
        properties: {
          name: strSchema('Role name'),
          description: strSchema('Role description'),
        },
      },
    },
    responses: {
      200: { description: 'Updated role', schema: { $ref: '#/components/schemas/Role' } },
      400: { description: 'Cannot update system role', schema: errorRef },
      404: { description: 'Role not found', schema: errorRef },
    },
  },

  // GET /iam/groups — list groups (paginated)
  {
    method: 'GET',
    path: '/iam/groups',
    handler: 'listGroups',
    meta: {
      summary: 'List groups',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewGroups' },
    },
    input: {
      query: {
        type: 'object',
        properties: {
          limit: intSchema('Max results (default 50)'),
          offset: intSchema('Skip results (default 0)'),
        },
      },
    },
    responses: {
      200: {
        description: 'Group list',
        schema: {
          type: 'object',
          properties: {
            groups: { type: 'array', items: { $ref: '#/components/schemas/Group' }, description: 'List of groups' },
            total: intSchema('Total number of groups'),
          },
          required: ['groups', 'total'],
        },
      },
    },
  },

  // GET /iam/groups/:id — get group with members
  {
    method: 'GET',
    path: '/iam/groups/:id',
    handler: 'getGroup',
    meta: {
      summary: 'Get group with members',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewGroups' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Group ID') },
        required: ['id'],
      },
    },
    responses: {
      200: {
        description: 'Group with members',
        schema: {
          type: 'object',
          properties: {
            id: intSchema('Group ID'),
            name: strSchema('Group name'),
            description: { type: 'string', nullable: true, description: 'Group description' },
            users: { type: 'array', items: userRef, description: 'Group members' },
          },
          required: ['id', 'name', 'users'],
        },
      },
      404: { description: 'Group not found', schema: errorRef },
    },
  },

  // PUT /iam/groups/:id — update group
  {
    method: 'PUT',
    path: '/iam/groups/:id',
    handler: 'updateGroup',
    meta: {
      summary: 'Update group',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageGroup' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Group ID') },
        required: ['id'],
      },
      body: {
        type: 'object',
        properties: {
          name: strSchema('Group name'),
          description: strSchema('Group description'),
        },
      },
    },
    responses: {
      200: { description: 'Updated group', schema: { $ref: '#/components/schemas/Group' } },
      404: { description: 'Group not found', schema: errorRef },
    },
  },

  // DELETE /iam/groups/:id — delete group
  {
    method: 'DELETE',
    path: '/iam/groups/:id',
    handler: 'deleteGroup',
    meta: {
      summary: 'Delete group',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageGroup' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Group ID') },
        required: ['id'],
      },
    },
    responses: {
      200: { description: 'Group deleted', schema: { type: 'object', properties: { ok: boolSchema('Success') } } },
      404: { description: 'Group not found', schema: errorRef },
    },
  },

  // GET /iam/groups/:id/users — list group members
  {
    method: 'GET',
    path: '/iam/groups/:id/users',
    handler: 'getGroupUsers',
    meta: {
      summary: 'List group members',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewGroups' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Group ID') },
        required: ['id'],
      },
    },
    responses: {
      200: {
        description: 'Group members',
        schema: { type: 'array', items: userRef },
      },
    },
  },

  // GET /iam/permissions — list all permissions
  {
    method: 'GET',
    path: '/iam/permissions',
    handler: 'listPermissions',
    meta: {
      summary: 'List permissions',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'viewPermissions' },
    },
    input: {
      query: {
        type: 'object',
        properties: {
          resource: strSchema('Filter by resource name'),
        },
      },
    },
    responses: {
      200: {
        description: 'Permission list',
        schema: { type: 'array', items: permissionRef },
      },
    },
  },

  // POST /iam/permissions — create permission
  {
    method: 'POST',
    path: '/iam/permissions',
    handler: 'createPermission',
    meta: {
      summary: 'Create permission',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'managePermissions' },
    },
    input: {
      body: permissionInputRef,
    },
    responses: {
      200: { description: 'Created permission', schema: permissionRef },
    },
  },

  // DELETE /iam/permissions/:id — delete permission
  {
    method: 'DELETE',
    path: '/iam/permissions/:id',
    handler: 'deletePermission',
    meta: {
      summary: 'Delete permission',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'managePermissions' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Permission ID') },
        required: ['id'],
      },
    },
    responses: {
      200: { description: 'Permission deleted', schema: { type: 'object', properties: { ok: boolSchema('Success') } } },
      404: { description: 'Permission not found', schema: errorRef },
    },
  },

  // POST /iam/roles/:id/permissions — add permission to role
  {
    method: 'POST',
    path: '/iam/roles/:id/permissions',
    handler: 'addPermissionToRole',
    meta: {
      summary: 'Add permission to role',
      tags: ['IAM', 'Admin'],
      security: ['bearer'],
      permission: { resource: 'fortress', action: 'manageRoles' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Role ID') },
        required: ['id'],
      },
      body: permissionInputRef,
    },
    responses: {
      200: { description: 'Permission added', schema: { type: 'object', properties: { ok: boolSchema('Success') } } },
      404: { description: 'Role not found', schema: errorRef },
    },
  },
];

// ── Sync endpoint ────────────────────────────────────────────────

const syncEndpoint: EndpointDefinition = {
  method: 'POST',
  path: '/iam/sync',
  handler: 'syncResources',
  meta: {
    summary: 'Sync IAM resources',
    description: 'Push or pull resource definitions to/from the resource file',
    tags: ['IAM', 'Admin'],
    security: ['bearer'],
    permission: { resource: 'fortress', action: 'managePermissions' },
  },
  input: {
    body: {
      type: 'object',
      properties: {
        direction: { type: 'string', enum: ['push', 'pull'], description: 'Sync direction' },
        filePath: strSchema('Resource file path (optional)'),
      },
      required: ['direction'],
    },
  },
  responses: {
    200: { description: 'Sync complete', schema: { type: 'object', properties: { ok: boolSchema('Success') } } },
    401: { description: 'Not authenticated' },
    403: { description: 'Insufficient permissions' },
  },
};

// ── Bootstrap endpoint ────────────────────────────────────────────

const bootstrapEndpoint: EndpointDefinition = {
  method: 'POST',
  path: '/iam/admin/bootstrap',
  handler: 'bootstrap',
  meta: {
    summary: 'Bootstrap admin user',
    description: 'Opt-in emergency bootstrap. Assigns all fortress admin permissions only while zero fortress-admin bindings exist and only when the caller presents the one-time bootstrap secret. Creates the fortress resource and permissions if they do not exist.',
    tags: ['IAM', 'Admin'],
    security: ['bearer'],
  },
  input: {
    body: {
      type: 'object',
      properties: {
        userId: { type: 'integer', description: 'Target user ID. Defaults to the authenticated caller.' },
        secret: { type: 'string', description: 'One-time bootstrap secret' },
      },
    },
  },
  responses: {
    200: { description: 'Admin bootstrapped', schema: { type: 'object', properties: { ok: { type: 'boolean' }, role: { type: 'object' } } } },
    401: { description: 'Not authenticated' },
    403: { description: 'Bootstrap disabled, bad secret, or already bootstrapped' },
  },
};

// ── Admin-side api-key management endpoints ─────────────────────────
//
// Mounted only when `admin({ apiKeyRoutes: true })`. Guarded by the
// `apiKey:manage` permission (auto-discovered into the `fortress-admin` role
// by `bootstrap` when these routes are present). Requires the `api-key`
// plugin to be registered alongside admin, since the `api_key` model lives
// there.

const apiKeyInfoSchema = {
  type: 'object' as const,
  properties: {
    id: intSchema('Database id'),
    name: strSchema('Key label'),
    keyPrefix: strSchema('First 12 characters of the key, for identification'),
    scopes: { type: 'array' as const, items: { type: 'string' as const }, nullable: true },
    expiresAt: { type: 'string' as const, format: 'date-time', nullable: true },
    lastUsedAt: { type: 'string' as const, format: 'date-time', nullable: true },
    createdAt: { type: 'string' as const, format: 'date-time' },
  },
  required: ['id', 'name', 'keyPrefix', 'createdAt'] as string[],
};

const createKeyBodySchema = {
  type: 'object' as const,
  properties: {
    name: strSchema('Human-readable key label'),
    scopes: { type: 'array' as const, items: { type: 'string' as const }, description: 'Optional permission scopes attached to the key' },
    expiresAt: { type: 'string' as const, description: 'Optional expiry (ISO 8601 string)' },
  },
  required: ['name'] as string[],
};

const createKeyResponseSchema = {
  type: 'object' as const,
  properties: {
    key: strSchema('Raw API key — shown exactly once, store it immediately'),
    id: intSchema('Database id of the key'),
  },
  required: ['key', 'id'] as string[],
};

const adminApiKeyEndpoints: EndpointDefinition[] = [
  // ── User-scoped admin api-key management ──────────────────────

  {
    method: 'POST',
    path: '/admin/users/:userId/api-keys',
    handler: 'adminCreateUserApiKey',
    meta: {
      summary: 'Mint an API key for any user',
      description: 'Create a new API key owned by any user, bypassing the self-service `maxKeysPerSubject` check is NOT done — the same limit applies. The raw key is returned exactly once and cannot be retrieved later. Requires the `apiKey:manage` permission. Typical use: provisioning keys during tenant onboarding or replacing a lost key on a user\'s behalf.',
      tags: ['Admin', 'API Keys'],
      security: ['bearer'],
      permission: { resource: 'apiKey', action: 'manage' },
    },
    input: {
      params: {
        type: 'object',
        properties: { userId: intSchema('Target user ID') },
        required: ['userId'],
      },
      body: createKeyBodySchema,
    },
    responses: {
      201: { description: 'Key created', schema: createKeyResponseSchema },
      400: { description: 'Bad request', schema: errorRef },
      401: { description: 'Not authenticated', schema: errorRef },
      403: { description: 'Forbidden', schema: errorRef },
      404: { description: 'User not found', schema: errorRef },
    },
  },

  {
    method: 'GET',
    path: '/admin/users/:userId/api-keys',
    handler: 'adminListUserApiKeys',
    meta: {
      summary: 'List a user\'s API keys',
      description: 'Return the active (non-revoked) API keys belonging to any user. Raw keys and hashes are never returned. Requires the `apiKey:manage` permission.',
      tags: ['Admin', 'API Keys'],
      security: ['bearer'],
      permission: { resource: 'apiKey', action: 'manage' },
    },
    input: {
      params: {
        type: 'object',
        properties: { userId: intSchema('Target user ID') },
        required: ['userId'],
      },
    },
    responses: {
      200: {
        description: 'Keys',
        schema: {
          type: 'object',
          properties: {
            keys: { type: 'array', items: apiKeyInfoSchema },
          },
          required: ['keys'],
        },
      },
      401: { description: 'Not authenticated', schema: errorRef },
      403: { description: 'Forbidden', schema: errorRef },
    },
  },

  {
    method: 'DELETE',
    path: '/admin/users/:userId/api-keys/:id',
    handler: 'adminRevokeUserApiKey',
    meta: {
      summary: 'Revoke a user\'s API key',
      description: 'Revoke any API key by id, bypassing the self-service ownership check. Requires the `apiKey:manage` permission. Typically used to respond to leaked keys or compromised accounts.',
      tags: ['Admin', 'API Keys'],
      security: ['bearer'],
      permission: { resource: 'apiKey', action: 'manage' },
    },
    input: {
      params: {
        type: 'object',
        properties: {
          userId: intSchema('Target user ID (for URL namespacing; ownership is not enforced)'),
          id: intSchema('Key id to revoke'),
        },
        required: ['userId', 'id'],
      },
    },
    responses: {
      200: {
        description: 'Revoked',
        schema: {
          type: 'object',
          properties: { ok: boolSchema('Success') },
          required: ['ok'],
        },
      },
      401: { description: 'Not authenticated', schema: errorRef },
      403: { description: 'Forbidden', schema: errorRef },
      404: { description: 'Not found', schema: errorRef },
    },
  },

  // ── Service-account-scoped admin api-key management ───────────
  //
  // Service accounts have no login path — they can't self-mint their
  // first key. These endpoints are the only supported way to bootstrap
  // a service account's credentials.

  {
    method: 'POST',
    path: '/admin/service-accounts/:id/api-keys',
    handler: 'adminCreateServiceAccountApiKey',
    meta: {
      summary: 'Mint an API key for a service account',
      description: 'Create a new API key owned by a service account. This is the primary entry point for bootstrapping a service account\'s credentials — a fresh service account has no way to authenticate until an admin mints its first key. The raw key is returned exactly once and cannot be retrieved later. Requires the `apiKey:manage` permission.',
      tags: ['Admin', 'API Keys', 'Service Accounts'],
      security: ['bearer'],
      permission: { resource: 'apiKey', action: 'manage' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Target service account ID') },
        required: ['id'],
      },
      body: createKeyBodySchema,
    },
    responses: {
      201: { description: 'Key created', schema: createKeyResponseSchema },
      400: { description: 'Bad request', schema: errorRef },
      401: { description: 'Not authenticated', schema: errorRef },
      403: { description: 'Forbidden', schema: errorRef },
      404: { description: 'Service account not found', schema: errorRef },
    },
  },

  {
    method: 'GET',
    path: '/admin/service-accounts/:id/api-keys',
    handler: 'adminListServiceAccountApiKeys',
    meta: {
      summary: 'List a service account\'s API keys',
      description: 'Return the active (non-revoked) API keys owned by a service account. Raw keys and hashes are never returned. Requires the `apiKey:manage` permission.',
      tags: ['Admin', 'API Keys', 'Service Accounts'],
      security: ['bearer'],
      permission: { resource: 'apiKey', action: 'manage' },
    },
    input: {
      params: {
        type: 'object',
        properties: { id: intSchema('Target service account ID') },
        required: ['id'],
      },
    },
    responses: {
      200: {
        description: 'Keys',
        schema: {
          type: 'object',
          properties: {
            keys: { type: 'array', items: apiKeyInfoSchema },
          },
          required: ['keys'],
        },
      },
      401: { description: 'Not authenticated', schema: errorRef },
      403: { description: 'Forbidden', schema: errorRef },
    },
  },

  {
    method: 'DELETE',
    path: '/admin/service-accounts/:id/api-keys/:keyId',
    handler: 'adminRevokeServiceAccountApiKey',
    meta: {
      summary: 'Revoke a service account\'s API key',
      description: 'Revoke any API key by id, bypassing the self-service ownership check. Requires the `apiKey:manage` permission.',
      tags: ['Admin', 'API Keys', 'Service Accounts'],
      security: ['bearer'],
      permission: { resource: 'apiKey', action: 'manage' },
    },
    input: {
      params: {
        type: 'object',
        properties: {
          id: intSchema('Target service account ID (for URL namespacing; ownership is not enforced)'),
          keyId: intSchema('Key id to revoke'),
        },
        required: ['id', 'keyId'],
      },
    },
    responses: {
      200: {
        description: 'Revoked',
        schema: {
          type: 'object',
          properties: { ok: boolSchema('Success') },
          required: ['ok'],
        },
      },
      401: { description: 'Not authenticated', schema: errorRef },
      403: { description: 'Forbidden', schema: errorRef },
      404: { description: 'Not found', schema: errorRef },
    },
  },
];

/**
 * Admin plugin — protects fortress routes and provides admin CRUD endpoints.
 *
 * Adds endpoints for:
 * - User management (list, get, update, delete)
 * - Role management (get, update, add permissions)
 * - Group management (list, get, update, delete, members)
 * - Permission management (list, create, delete)
 * - Admin bootstrap
 *
 * Works with the RBAC middleware's security-aware default deny:
 * - All endpoints declare `permission: { resource: 'fortress', action: '...' }`
 * - RBAC middleware enforces these automatically
 * - Admin plugin adds opt-in one-time-secret bootstrap functionality
 *
 * @example
 * ```ts
 * import { admin } from '@bajustone/fortress/plugins/admin';
 *
 * const fortress = createFortress({
 *   plugins: [
 *     admin({ bootstrap: { enabled: true, secret: process.env.FORTRESS_ADMIN_BOOTSTRAP_SECRET } }),
 *   ],
 * });
 * ```
 */
export function admin(options: AdminPluginOptions = {}): FortressPlugin {
  const mountApiKeyRoutes = options.apiKeyRoutes === true;
  const mountBootstrap = options.bootstrap?.enabled === true;
  const bootstrapSecret = options.bootstrap?.secret ?? process.env.FORTRESS_ADMIN_BOOTSTRAP_SECRET;

  return {
    name: 'admin',

    // Admin routes are aggregated from several internal arrays into a
    // record keyed by `${method}_${path}` so collisions with core handler
    // names (e.g. `createUser` exists in both auth-endpoints.ts and admin)
    // are impossible. Admin routes exist for default-deny protection and
    // aren't exposed via the typed `fortress.call.*` surface.
    routes: Object.fromEntries(
      [
        ...(mountBootstrap ? [bootstrapEndpoint] : []),
        syncEndpoint,
        ...adminAuthEndpoints,
        ...adminIamEndpoints,
        ...Object.values(iamEndpoints) as EndpointDefinition[],
        ...(mountApiKeyRoutes ? adminApiKeyEndpoints : []),
      ].map(ep => [`${ep.method}_${ep.path}`, ep]),
    ),

    methods: (ctx: PluginContext) => ({
      async getResources(): Promise<ResourceFile> {
        return pullResources(ctx.db);
      },

      async bootstrap(
        body: { userId?: string; secret?: string },
        routeCtx?: PluginRouteContext,
      ): Promise<{ ok: boolean; role: Role }> {
        if (!mountBootstrap)
          throw Errors.notFound('Admin bootstrap route is disabled');
        if (!bootstrapSecret)
          throw Errors.forbidden('Admin bootstrap secret is not configured');
        if (!body.secret || !timingSafeEqual(body.secret, bootstrapSecret))
          throw Errors.forbidden('Invalid admin bootstrap secret');

        const callerId = routeCtx?.userId;
        const userId = body.userId ?? callerId;
        if (userId == null)
          throw Errors.unauthorized('User not authenticated');
        const db = ctx.db;

        return db.transaction(async (tx) => {
          // Serialize the one-time gate across processes. SQLite transaction
          // adapters acquire a writer lock; PostgreSQL uses an advisory lock.
          if (tx.dialect === 'pg' && tx.rawQuery)
            await tx.rawQuery('SELECT pg_advisory_xact_lock(hashtext(?))', ['fortress-admin-bootstrap']);

          // Verify user exists
          const user = await tx.findOne<{ id: string }>({
            model: 'user',
            where: [{ field: 'id', operator: '=', value: userId }],
          });
          if (!user) {
            throw Errors.notFound('User not found');
          }

          // One-time bootstrap: any existing fortress-admin binding closes
          // the bootstrap path permanently. A plain authenticated caller can
          // never self-grant without the secret, and nobody can re-bootstrap.
          const existingRole = await tx.findOne<Role>({
            model: 'role',
            where: [{ field: 'name', operator: '=', value: 'fortress-admin' }],
          });
          if (existingRole) {
            const existingAdmins = await tx.count({
              model: 'role_binding',
              where: [{ field: 'roleId', operator: '=', value: existingRole.id }],
            });
            if (existingAdmins > 0)
              throw Errors.forbidden('Admin already bootstrapped');
          }

          // Auto-discover all permissions from endpoint definitions
          const plugins = ctx.config.plugins ?? [];
          const pluginEndpoints: EndpointDefinition[] = [];
          for (const plugin of plugins) {
            if (plugin.routes)
              pluginEndpoints.push(...Object.values(plugin.routes) as EndpointDefinition[]);
          }
          const allEndpoints: EndpointDefinition[] = [
            ...Object.values(authEndpoints) as EndpointDefinition[],
            ...Object.values(iamEndpoints) as EndpointDefinition[],
            ...pluginEndpoints,
          ];
          const declaredPermissions = collectPermissions(allEndpoints);

          // Ensure each resource exists
          const resources = new Set(declaredPermissions.map(p => p.resource));
          for (const resource of resources) {
            const existing = await tx.findOne<{ name: string }>({
              model: 'resource',
              where: [{ field: 'name', operator: '=', value: resource }],
            });
            if (!existing) {
              await tx.create({ model: 'resource', data: { name: resource, description: `Auto-registered by admin plugin` } });
            }
          }

          // Find or create each permission
          const permissionIds: string[] = [];
          for (const perm of declaredPermissions) {
            let existing = await tx.findOne<{ id: string }>({
              model: 'permission',
              where: [
                { field: 'resource', operator: '=', value: perm.resource },
                { field: 'action', operator: '=', value: perm.action },
              ],
            });
            if (!existing) {
              existing = await tx.create<{ id: string }>({
                model: 'permission',
                data: {
                  resource: perm.resource,
                  action: perm.action,
                  effect: 'ALLOW',
                  description: `${perm.action} ${perm.resource}`,
                },
              });
            }
            permissionIds.push(existing.id);
          }

          // Create or find the fortress-admin role
          let adminRole = existingRole;
          if (!adminRole) {
            adminRole = await tx.create<Role>({
              model: 'role',
              data: { name: 'fortress-admin', description: 'Full fortress administration', isSystem: true },
            });
          }

          // Link all permissions to the role
          for (const permId of permissionIds) {
            const existingLink = await tx.findOne<{ id: string }>({
              model: 'role_permission',
              where: [
                { field: 'roleId', operator: '=', value: adminRole.id },
                { field: 'permissionId', operator: '=', value: permId },
              ],
            });
            if (!existingLink) {
              await tx.create({ model: 'role_permission', data: { roleId: adminRole.id, permissionId: permId } });
            }
          }

          // Bind the role to the user
          const existingBinding = await tx.findOne<{ id: string }>({
            model: 'role_binding',
            where: [
              { field: 'roleId', operator: '=', value: adminRole.id },
              { field: 'subjectType', operator: '=', value: 'USER' },
              { field: 'subjectId', operator: '=', value: userId },
            ],
          });
          if (!existingBinding) {
            await tx.create({
              model: 'role_binding',
              data: { roleId: adminRole.id, subjectType: 'USER', subjectId: userId, tenantId: null },
            });
          }

          return { ok: true, role: adminRole };
        });
      },

      // ── Auth admin — delegates to core auth service ──────────

      async listUsers(body: Record<string, string>): Promise<{ users: FortressUser[]; total: number }> {
        if (!ctx.auth)
          throw Errors.database('Auth service not available');
        return ctx.auth.listUsers({
          limit: body.limit ? Number(body.limit) : undefined,
          offset: body.offset ? Number(body.offset) : undefined,
          search: body.search,
          sortBy: body.sortBy,
          sortDirection: body.sortDirection as 'asc' | 'desc' | undefined,
        });
      },

      async getUserById(body: Record<string, string>): Promise<FortressUser> {
        if (!ctx.auth)
          throw Errors.database('Auth service not available');
        return ctx.auth.getUserById(requireId(body.id, 'id'));
      },

      async createUser(body: Record<string, unknown>): Promise<FortressUser> {
        if (!ctx.auth)
          throw Errors.database('Auth service not available');
        return ctx.auth.createUser({
          email: body.email as string,
          name: body.name as string,
          password: body.password as string | undefined,
          isActive: body.isActive as boolean | undefined,
        });
      },

      async updateUser(body: Record<string, unknown>): Promise<FortressUser> {
        if (!ctx.auth)
          throw Errors.database('Auth service not available');
        const { id, ...data } = body;
        return ctx.auth.updateUser(requireId(id, 'id'), data as { name?: string; email?: string; isActive?: boolean; password?: string });
      },

      async deleteUser(body: Record<string, string>): Promise<{ ok: boolean }> {
        if (!ctx.auth)
          throw Errors.database('Auth service not available');
        await ctx.auth.deleteUser(requireId(body.id, 'id'));
        return { ok: true };
      },

      // ── IAM admin — delegates to core IAM service ────────────

      async getRole(body: Record<string, string>): Promise<Role & { permissions: Permission[] }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.getRole(requireId(body.id, 'id'));
      },

      async updateRole(body: Record<string, unknown>): Promise<Role> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        const { id, ...data } = body;
        return ctx.iam.updateRole(requireId(id, 'id'), data as { name?: string; description?: string });
      },

      async listGroups(body: Record<string, string>): Promise<{ groups: Group[]; total: number }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.listGroups({
          limit: body.limit ? Number(body.limit) : undefined,
          offset: body.offset ? Number(body.offset) : undefined,
        });
      },

      async getGroup(body: Record<string, string>): Promise<Group & { users: FortressUser[] }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.getGroup(requireId(body.id, 'id'));
      },

      async updateGroup(body: Record<string, unknown>): Promise<Group> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        const { id, ...data } = body;
        return ctx.iam.updateGroup(requireId(id, 'id'), data as { name?: string; description?: string });
      },

      async deleteGroup(body: Record<string, string>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.deleteGroup(requireId(body.id, 'id'));
        return { ok: true };
      },

      async getGroupUsers(body: Record<string, string>): Promise<FortressUser[]> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.getGroupUsers(requireId(body.id, 'id'));
      },

      async listPermissions(body: Record<string, string>): Promise<Permission[]> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.listPermissions({
          resource: body.resource || undefined,
        });
      },

      async createPermission(body: PermissionInput): Promise<Permission> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.createPermission(body);
      },

      async deletePermission(body: Record<string, string>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.deletePermission(requireId(body.id, 'id'));
        return { ok: true };
      },

      async addPermissionToRole(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        const { id, ...permission } = body;
        await ctx.iam.addPermissionToRole(requireId(id, 'id'), permission as unknown as PermissionInput);
        return { ok: true };
      },

      // ── Core IAM operations — previously spec-only ─────────────

      async getRoles(): Promise<Role[]> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.getRoles();
      },

      async createRole(body: Record<string, unknown>): Promise<Role> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.createRole(
          body.name as string,
          (body.permissions ?? []) as PermissionInput[],
          body.description as string | undefined,
        );
      },

      async deleteRole(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.deleteRole(requireId(body.id, 'id'));
        return { ok: true };
      },

      async bindRoleToUser(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.bindRoleToUser(
          requireId(body.userId, 'userId'),
          requireId(body.id, 'id'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async bindRoleToGroup(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.bindRoleToGroup(
          requireId(body.groupId, 'groupId'),
          requireId(body.id, 'id'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async unbindRole(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.unbindRole(
          body.subjectType as SubjectType,
          requireId(body.subjectId, 'subjectId'),
          requireId(body.id, 'id'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async createGroup(body: Record<string, unknown>): Promise<Group> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.createGroup(
          body.name as string,
          body.description as string | undefined,
        );
      },

      async addUserToGroup(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.addUserToGroup(
          requireId(body.id, 'id'),
          requireId(body.userId, 'userId'),
        );
        return { ok: true };
      },

      async removeUserFromGroup(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.removeUserFromGroup(
          requireId(body.id, 'id'),
          requireId(body.userId, 'userId'),
        );
        return { ok: true };
      },

      async getUserPermissions(body: Record<string, unknown>): Promise<Permission[]> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.getPermissionsForSubject(
          { type: 'USER', id: requireId(body.id, 'id') },
          body.tenantId as string | undefined,
        );
      },

      async checkPermission(body: Record<string, unknown>): Promise<{ allowed: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        const allowed = await ctx.iam.checkPermission(
          { type: 'USER', id: requireId(body.userId, 'userId') },
          body.resource as string,
          body.action as string,
          body.context as Record<string, unknown> | undefined,
        );
        return { allowed };
      },

      async bindPermissionToUser(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.bindPermissionToUser(
          requireId(body.userId, 'userId'),
          body.permission as PermissionInput,
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async bindPermissionToGroup(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.bindPermissionToGroup(
          requireId(body.groupId, 'groupId'),
          body.permission as PermissionInput,
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async unbindPermissionFromUser(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.unbindPermissionFromUser(
          requireId(body.userId, 'userId'),
          requireId(body.permissionId, 'permissionId'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async unbindPermissionFromGroup(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.unbindPermissionFromGroup(
          requireId(body.groupId, 'groupId'),
          requireId(body.permissionId, 'permissionId'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      // ── Service-account IAM proxies ────────────────────────────
      //
      // The admin plugin re-exports `iamEndpoints` on its own `routes` so
      // that IAM routes get dispatched through `dispatchPlugin`. That
      // means every IAM handler referenced by those endpoint definitions
      // must exist on this plugin's methods object — thin proxies that
      // delegate to `ctx.iam`. Without these, hitting any
      // `/iam/service-accounts/*` route through an instance that has the
      // admin plugin registered returns a 404 from the dispatcher.

      async createServiceAccount(body: Record<string, unknown>): Promise<unknown> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.createServiceAccount({
          name: String(body.name ?? ''),
          displayName: body.displayName as string | undefined,
          description: body.description as string | undefined,
        });
      },

      async listServiceAccounts(body: Record<string, unknown>): Promise<unknown> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.listServiceAccounts({
          limit: body.limit != null ? Number(body.limit) : undefined,
          offset: body.offset != null ? Number(body.offset) : undefined,
        });
      },

      async getServiceAccount(body: Record<string, unknown>): Promise<unknown> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.getServiceAccount(requireId(body.id, 'id'));
      },

      async updateServiceAccount(body: Record<string, unknown>): Promise<unknown> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.updateServiceAccount(requireId(body.id, 'id'), {
          displayName: body.displayName as string | null | undefined,
          description: body.description as string | null | undefined,
          isActive: body.isActive as boolean | undefined,
        });
      },

      async deleteServiceAccount(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.deleteServiceAccount(requireId(body.id, 'id'));
        return { ok: true };
      },

      async getServiceAccountPermissions(body: Record<string, unknown>): Promise<Permission[]> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        return ctx.iam.getPermissionsForSubject(
          { type: 'SERVICE_ACCOUNT', id: requireId(body.id, 'id') },
          body.tenantId as string | undefined,
        );
      },

      async bindRoleToServiceAccount(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.bindRoleToServiceAccount(
          requireId(body.serviceAccountId, 'serviceAccountId'),
          requireId(body.id, 'id'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async unbindRoleFromServiceAccount(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.unbindRoleFromServiceAccount(
          requireId(body.serviceAccountId, 'serviceAccountId'),
          requireId(body.id, 'id'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async bindPermissionToServiceAccount(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.bindPermissionToServiceAccount(
          requireId(body.serviceAccountId, 'serviceAccountId'),
          body.permission as PermissionInput,
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      async unbindPermissionFromServiceAccount(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.unbindPermissionFromServiceAccount(
          requireId(body.serviceAccountId, 'serviceAccountId'),
          requireId(body.permissionId, 'permissionId'),
          body.tenantId as string | undefined,
        );
        return { ok: true };
      },

      // ── Admin api-key management ───────────────────────────────
      //
      // Read/delete delegate to the stateless helpers in `api-key/core.ts`.
      // Create re-enters the api-key plugin's `methods` factory so the
      // configured knobs (prefix, maxKeysPerSubject, defaultExpirySeconds)
      // apply to admin-minted keys exactly as they do to self-service
      // keys — no duplicate config. All of these are available as
      // programmatic methods regardless of the `apiKeyRoutes` flag — only
      // the HTTP mounting is gated. Requires the `api-key` plugin to be
      // registered (for the `api_key` model).

      async adminCreateUserApiKey(
        body: Record<string, unknown>,
      ): Promise<{ key: string; id: string }> {
        const userId = requireId(body.userId, 'userId');
        // Verify the user exists so we never mint an orphan key.
        const user = await ctx.db.findOne<{ id: string }>({
          model: 'user',
          where: [{ field: 'id', operator: '=', value: userId }],
        });
        if (!user)
          throw Errors.notFound('User not found');
        const apiKeyMethods = getApiKeyMethods(ctx);
        // Intentionally no routeCtx — we want `input.subject` to target
        // the named user, not the admin who's calling us.
        return apiKeyMethods.createKey({
          subject: { type: 'USER', id: userId },
          name: String(body.name ?? ''),
          scopes: Array.isArray(body.scopes) ? (body.scopes as string[]).map(String) : undefined,
          expiresAt: body.expiresAt as string | Date | undefined,
        });
      },

      async adminListUserApiKeys(
        body: Record<string, unknown>,
      ): Promise<{ keys: ApiKeyInfo[] }> {
        const keys = await listKeysForSubject(ctx.db, {
          type: 'USER',
          id: requireId(body.userId, 'userId'),
        });
        return { keys };
      },

      async adminRevokeUserApiKey(
        body: Record<string, unknown>,
      ): Promise<{ ok: boolean }> {
        await revokeKeyAsAdmin(ctx.db, requireId(body.id, 'id'));
        return { ok: true };
      },

      // ── Service-account-scoped admin api-key handlers ─────────

      async adminCreateServiceAccountApiKey(
        body: Record<string, unknown>,
      ): Promise<{ key: string; id: string }> {
        const serviceAccountId = requireId(body.id, 'id');
        // Verify the service account exists so we never mint an orphan
        // key. Inactive service accounts are allowed here — the key will
        // just fail to authenticate until the account is reactivated,
        // which is occasionally useful for pre-provisioning.
        const sa = await ctx.db.findOne<{ id: string }>({
          model: 'service_account',
          where: [{ field: 'id', operator: '=', value: serviceAccountId }],
        });
        if (!sa)
          throw Errors.notFound('Service account not found');
        const apiKeyMethods = getApiKeyMethods(ctx);
        return apiKeyMethods.createKey({
          subject: { type: 'SERVICE_ACCOUNT', id: serviceAccountId },
          name: String(body.name ?? ''),
          scopes: Array.isArray(body.scopes) ? (body.scopes as string[]).map(String) : undefined,
          expiresAt: body.expiresAt as string | Date | undefined,
        });
      },

      async adminListServiceAccountApiKeys(
        body: Record<string, unknown>,
      ): Promise<{ keys: ApiKeyInfo[] }> {
        const keys = await listKeysForSubject(ctx.db, {
          type: 'SERVICE_ACCOUNT',
          id: requireId(body.id, 'id'),
        });
        return { keys };
      },

      async adminRevokeServiceAccountApiKey(
        body: Record<string, unknown>,
      ): Promise<{ ok: boolean }> {
        await revokeKeyAsAdmin(ctx.db, requireId(body.keyId, 'keyId'));
        return { ok: true };
      },

      // ── Resource sync ──────────────────────────────────────────

      async syncResources(body: Record<string, unknown>): Promise<{ ok: boolean }> {
        if (!ctx.iam)
          throw Errors.database('IAM service not available');
        await ctx.iam.syncResources(
          body.direction as 'push' | 'pull',
          body.filePath as string | undefined,
        );
        return { ok: true };
      },
    }),
  };
}

// --- Helpers ---

/**
 * Look up the api-key plugin on the fortress config and return its
 * methods bound to the current context. Used by the admin plugin's
 * create-key handlers so admin-minted keys go through the same
 * configured knobs (prefix, limits, default expiry) as self-service
 * keys — no duplicate config.
 *
 * Rerunning the api-key plugin's `methods` factory is cheap and safe:
 * it just returns a fresh object literal, and the plugin's internal
 * `observerRegistered` flag prevents the IAM cascade observer from
 * being attached twice.
 */
function getApiKeyMethods(ctx: PluginContext): ApiKeyMethods {
  const apiKeyPlugin = (ctx.config.plugins ?? []).find(p => p.name === 'api-key');
  if (!apiKeyPlugin?.methods)
    throw Errors.database('api-key plugin is not registered');
  return apiKeyPlugin.methods(ctx) as unknown as ApiKeyMethods;
}
