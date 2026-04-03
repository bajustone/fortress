import type { DatabaseAdapter } from '../../adapters/database';
import { existsSync } from 'node:fs';
import { readFile, writeFile } from 'node:fs/promises';

export interface ResourceDefinition {
  actions: string[];
  description?: string;
}

export interface ResourceFile {
  resources: Record<string, ResourceDefinition>;
}

/**
 * Load a fortress.resources.json file.
 * Uses node:fs which works in Bun, Deno, and Node.
 */
export async function loadResourceFile(filePath: string): Promise<ResourceFile> {
  if (!existsSync(filePath)) {
    return { resources: {} };
  }
  const text = await readFile(filePath, 'utf-8');
  return JSON.parse(text) as ResourceFile;
}

/**
 * Write a fortress.resources.json file.
 * Uses node:fs which works in Bun, Deno, and Node.
 */
export async function writeResourceFile(filePath: string, data: ResourceFile): Promise<void> {
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
      const existingPerm = await db.findOne<{ id: number }>({
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
  });

  const result: ResourceFile = { resources: {} };

  for (const resource of resources) {
    const permissions = await db.findMany<{ action: string }>({
      model: 'permission',
      where: [{ field: 'resource', operator: '=', value: resource.name }],
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

  const resourceType = resourceNames.map(n => `'${n}'`).join(' | ');

  const actionBranches = resourceNames
    .map((name) => {
      const actions = resources.resources[name].actions.map(a => `'${a}'`).join(' | ');
      return `  R extends '${name}' ? ${actions} :`;
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
