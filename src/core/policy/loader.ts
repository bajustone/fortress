/**
 * Load a {@link PolicyDocument} from disk with optional env-specific
 * override. Node filesystem/path modules are imported only when these
 * file-oriented helpers run, keeping the package root import runtime-neutral.
 *
 * @module
 */

import type { PolicyDocument } from './types';
import { Errors } from '../errors';

export interface LoadPolicyOptions {
  /** Override the default `fortress.policy.json` path. */
  filePath?: string;
  /** Pick an env-specific file (`fortress.policy.<env>.json`). Defaults to `process.env.FORTRESS_ENV`. */
  env?: string;
  /** Working directory when resolving the default file paths. Defaults to `process.cwd()`. */
  cwd?: string;
}

/** Default base file name. */
export const DEFAULT_POLICY_FILE = 'fortress.policy.json';

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

function stringField(value: unknown, path: string): string {
  if (typeof value !== 'string' || value.length === 0)
    throw Errors.badRequest(`${path} must be a non-empty string`);
  return value;
}

function optionalString(value: unknown, path: string): string | undefined {
  if (value === undefined)
    return undefined;
  return stringField(value, path);
}

function collection(value: unknown, path: string): Record<string, unknown>[] {
  if (value === undefined)
    return [];
  if (
    !Array.isArray(value)
    || value.some(item => !isRecord(item))
    || Object.keys(value).length !== value.length
  ) {
    throw Errors.badRequest(`${path} must be a dense array of objects`);
  }
  return value;
}

function assertAllowedFields(
  value: Record<string, unknown>,
  allowed: readonly string[],
  path: string,
): void {
  const allowedSet = new Set(allowed);
  for (const key of Object.keys(value)) {
    if (!allowedSet.has(key))
      throw Errors.badRequest(`Unknown field '${path}.${key}'`);
  }
}

function assertUniqueNames(items: Array<{ name: string }>, path: string): void {
  const names = new Set<string>();
  for (const item of items) {
    if (names.has(item.name))
      throw Errors.badRequest(`${path} contains duplicate name '${item.name}'`);
    names.add(item.name);
  }
}

/** Validate and normalize an untrusted policy JSON value. */
export function parsePolicyDocument(value: unknown): PolicyDocument {
  if (!isRecord(value))
    throw Errors.badRequest('Policy document must be an object');
  const allowed = new Set(['$comment', '$schema', 'resources', 'roles', 'groups', 'serviceAccounts']);
  for (const annotation of ['$comment', '$schema'] as const) {
    if (value[annotation] !== undefined && typeof value[annotation] !== 'string')
      throw Errors.badRequest(`${annotation} must be a string`);
  }
  for (const key of Object.keys(value)) {
    if (!allowed.has(key))
      throw Errors.badRequest(`Unknown policy field '${key}'`);
  }

  const resources = collection(value.resources, 'resources').map((item, index) => {
    assertAllowedFields(item, ['name', 'actions', 'description'], `resources[${index}]`);
    if (!Array.isArray(item.actions) || item.actions.some(action => typeof action !== 'string' || action.length === 0))
      throw Errors.badRequest(`resources[${index}].actions must be an array of non-empty strings`);
    return {
      name: stringField(item.name, `resources[${index}].name`),
      actions: [...new Set(item.actions as string[])],
      description: optionalString(item.description, `resources[${index}].description`),
    };
  });
  const roles = collection(value.roles, 'roles').map((item, index) => {
    assertAllowedFields(item, ['name', 'description', 'permissions'], `roles[${index}]`);
    if (!Array.isArray(item.permissions))
      throw Errors.badRequest(`roles[${index}].permissions must be an array of objects`);
    const permissions = collection(item.permissions, `roles[${index}].permissions`).map((permission, permissionIndex) => {
      assertAllowedFields(
        permission,
        ['resource', 'action', 'effect'],
        `roles[${index}].permissions[${permissionIndex}]`,
      );
      const effect = permission.effect;
      if (effect !== undefined && effect !== 'ALLOW' && effect !== 'DENY')
        throw Errors.badRequest(`roles[${index}].permissions[${permissionIndex}].effect must be ALLOW or DENY`);
      const normalizedEffect: 'ALLOW' | 'DENY' = effect === 'DENY' ? 'DENY' : 'ALLOW';
      return {
        resource: stringField(permission.resource, `roles[${index}].permissions[${permissionIndex}].resource`),
        action: stringField(permission.action, `roles[${index}].permissions[${permissionIndex}].action`),
        ...(normalizedEffect === 'DENY' ? { effect: normalizedEffect } : {}),
      };
    });
    const uniquePermissions = new Map(
      permissions.map(permission => [
        `${permission.resource}\u0000${permission.action}\u0000${permission.effect ?? 'ALLOW'}`,
        permission,
      ]),
    );
    return {
      name: stringField(item.name, `roles[${index}].name`),
      description: optionalString(item.description, `roles[${index}].description`),
      permissions: [...uniquePermissions.values()],
    };
  });
  const groups = collection(value.groups, 'groups').map((item, index) => {
    assertAllowedFields(item, ['name', 'description'], `groups[${index}]`);
    return {
      name: stringField(item.name, `groups[${index}].name`),
      description: optionalString(item.description, `groups[${index}].description`),
    };
  });
  const serviceAccounts = collection(value.serviceAccounts, 'serviceAccounts').map((item, index) => {
    assertAllowedFields(
      item,
      ['name', 'displayName', 'description', 'isActive', 'roles'],
      `serviceAccounts[${index}]`,
    );
    if (item.roles !== undefined && (!Array.isArray(item.roles) || item.roles.some(role => typeof role !== 'string' || role.length === 0)))
      throw Errors.badRequest(`serviceAccounts[${index}].roles must be an array of non-empty strings`);
    if (item.isActive !== undefined && typeof item.isActive !== 'boolean')
      throw Errors.badRequest(`serviceAccounts[${index}].isActive must be a boolean`);
    return {
      name: stringField(item.name, `serviceAccounts[${index}].name`),
      displayName: optionalString(item.displayName, `serviceAccounts[${index}].displayName`),
      description: optionalString(item.description, `serviceAccounts[${index}].description`),
      ...(typeof item.isActive === 'boolean' ? { isActive: item.isActive } : {}),
      ...(Array.isArray(item.roles) ? { roles: [...new Set(item.roles as string[])] } : {}),
    };
  });

  assertUniqueNames(resources, 'resources');
  assertUniqueNames(roles, 'roles');
  assertUniqueNames(groups, 'groups');
  assertUniqueNames(serviceAccounts, 'serviceAccounts');
  return {
    ...(value.resources !== undefined ? { resources } : {}),
    ...(value.roles !== undefined ? { roles } : {}),
    ...(value.groups !== undefined ? { groups } : {}),
    ...(value.serviceAccounts !== undefined ? { serviceAccounts } : {}),
  };
}

async function exists(filePath: string): Promise<boolean> {
  const { access } = await import('node:fs/promises');
  try {
    await access(filePath);
    return true;
  }
  catch (err) {
    if ((err as { code?: string }).code === 'ENOENT')
      return false;
    throw err;
  }
}

/** Return the resolved policy-file path for an environment, or `null` if no file exists. */
export async function resolvePolicyPath(options: LoadPolicyOptions = {}): Promise<string | null> {
  if (options.filePath)
    return await exists(options.filePath) ? options.filePath : null;

  const { join } = await import('node:path');
  const cwd = options.cwd ?? process.cwd();
  const env = options.env ?? process.env.FORTRESS_ENV;
  if (env) {
    const envPath = join(cwd, `fortress.policy.${env}.json`);
    if (await exists(envPath))
      return envPath;
  }
  const basePath = join(cwd, DEFAULT_POLICY_FILE);
  return await exists(basePath) ? basePath : null;
}

/** Load and parse a policy document. Throws when the file is missing or unparseable. */
export async function loadPolicy(options: LoadPolicyOptions = {}): Promise<{ policy: PolicyDocument; filePath: string }> {
  const filePath = await resolvePolicyPath(options);
  if (!filePath)
    throw Errors.notFound(`No policy file found (looked for fortress.policy.<env>.json then fortress.policy.json)`);
  try {
    const { readFile } = await import('node:fs/promises');
    const text = await readFile(filePath, 'utf-8');
    const parsed = JSON.parse(text) as unknown;
    return { policy: parsePolicyDocument(parsed), filePath };
  }
  catch (err) {
    if (err instanceof SyntaxError)
      throw Errors.badRequest(`Failed to parse policy file ${filePath}: ${err.message}`);
    throw err;
  }
}
