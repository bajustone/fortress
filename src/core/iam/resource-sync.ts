import type { DatabaseAdapter } from '../../adapters/database';
import { Errors } from '../errors';

export interface ResourceDefinition {
  actions: string[];
  description?: string;
}

export interface ResourceFile {
  resources: Record<string, ResourceDefinition>;
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null && !Array.isArray(value);
}

/** Validate and normalize the canonical map-shaped resource document. */
export function parseResourceFile(value: unknown): ResourceFile {
  if (!isRecord(value))
    throw Errors.badRequest('fortress.resources.json must be an object');
  if (Array.isArray(value.resources)) {
    throw Errors.badRequest(
      'fortress.resources.json uses the legacy resources array; use a map keyed by resource name',
    );
  }
  if (!isRecord(value.resources))
    throw Errors.badRequest('fortress.resources.json must have a resources object map');

  const resources: Record<string, ResourceDefinition> = {};
  for (const [name, raw] of Object.entries(value.resources)) {
    if (!name || ['__proto__', 'constructor', 'prototype'].includes(name))
      throw Errors.badRequest(`Resource name '${name}' is reserved or empty`);
    if (!isRecord(raw))
      throw Errors.badRequest(`Resource '${name}' must be an object`);
    if (!Array.isArray(raw.actions) || raw.actions.some(action => typeof action !== 'string' || action.length === 0))
      throw Errors.badRequest(`Resource '${name}' actions must be an array of non-empty strings`);
    if (raw.description !== undefined && typeof raw.description !== 'string')
      throw Errors.badRequest(`Resource '${name}' description must be a string`);
    resources[name] = {
      actions: [...new Set(raw.actions as string[])],
      ...(typeof raw.description === 'string' ? { description: raw.description } : {}),
    };
  }
  return { resources };
}

/**
 * Load a fortress.resources.json file.
 * Node filesystem APIs are loaded only when this file-oriented helper runs;
 * importing Fortress remains safe in runtimes without `node:fs`.
 */
export async function loadResourceFile(filePath: string): Promise<ResourceFile> {
  const { readFile } = await import('node:fs/promises');
  let text: string;
  try {
    text = await readFile(filePath, 'utf-8');
  }
  catch (err) {
    if ((err as { code?: string }).code === 'ENOENT')
      return { resources: {} };
    throw err;
  }
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  }
  catch (err) {
    throw Errors.badRequest(`Failed to parse resource file ${filePath}: ${err instanceof Error ? err.message : String(err)}`);
  }
  return parseResourceFile(parsed);
}

/**
 * Write a fortress.resources.json file.
 * Node filesystem APIs are loaded only when this helper runs.
 */
export async function writeResourceFile(filePath: string, data: ResourceFile): Promise<void> {
  const { writeFile } = await import('node:fs/promises');
  await writeFile(filePath, JSON.stringify(data, null, 2), 'utf-8');
}

/**
 * Push resources from JSON file to database.
 * Creates or updates resources and their permissions.
 */
export async function pushResources(db: DatabaseAdapter, resources: ResourceFile): Promise<void> {
  for (const [name, definition] of Object.entries(resources.resources)) {
    // Upsert resource
    const existing = await db.findOne<{ name: string }>({
      model: 'resource',
      where: [{ field: 'name', operator: '=', value: name }],
    });

    if (!existing) {
      await db.create({
        model: 'resource',
        data: { name, description: definition.description ?? null },
      });
    }

    // Sync permissions for this resource
    for (const action of definition.actions) {
      const existingPerm = await db.findOne<{ id: string }>({
        model: 'permission',
        where: [
          { field: 'resource', operator: '=', value: name },
          { field: 'action', operator: '=', value: action },
        ],
      });

      if (!existingPerm) {
        await db.create({
          model: 'permission',
          data: {
            resource: name,
            action,
            effect: 'ALLOW',
            description: `${action} ${name}`,
          },
        });
      }
    }
  }
}

/**
 * Pull resources from database to ResourceFile format.
 */
export async function pullResources(db: DatabaseAdapter): Promise<ResourceFile> {
  const resources = await db.findMany<{ name: string; description: string | null }>({
    model: 'resource',
    sortBy: { field: 'name', direction: 'asc' },
  });

  const result: ResourceFile = { resources: {} };

  for (const resource of resources) {
    const permissions = await db.findMany<{ action: string }>({
      model: 'permission',
      where: [{ field: 'resource', operator: '=', value: resource.name }],
      sortBy: { field: 'id', direction: 'asc' },
    });

    result.resources[resource.name] = {
      actions: permissions.map(p => p.action),
      ...(resource.description ? { description: resource.description } : {}),
    };
  }

  return result;
}

/**
 * Generate TypeScript type definitions from a resource file.
 */
export function generateResourceTypes(resources: ResourceFile): string {
  const resourceNames = Object.keys(resources.resources);

  if (resourceNames.length === 0) {
    return `export type FortressResource = never;\nexport type FortressAction<R extends FortressResource> = never;\n`;
  }

  const resourceType = resourceNames.map(name => JSON.stringify(name)).join(' | ');

  const actionBranches = resourceNames
    .map((name) => {
      const rawActions = resources.resources[name].actions;
      const actions = rawActions.length > 0
        ? rawActions.map(action => JSON.stringify(action)).join(' | ')
        : 'never';
      return `  R extends ${JSON.stringify(name)} ? ${actions} :`;
    })
    .join('\n');

  return [
    `export type FortressResource = ${resourceType};`,
    `export type FortressAction<R extends FortressResource> =`,
    actionBranches,
    `  never;`,
    '',
  ].join('\n');
}
