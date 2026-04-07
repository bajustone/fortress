#!/usr/bin/env bun
/* eslint-disable no-console -- CLI tool requires console output */

import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join } from 'node:path';
import { authComponentSchemas, authEndpoints } from '../src/core/auth/auth-endpoints';
import { iamComponentSchemas, iamEndpoints } from '../src/core/iam/iam-endpoints';
import { buildOpenAPISpec } from '../src/plugins/openapi/spec-builder';

const HELP_TEXT = `
fortress — CLI tool for @bajustone/fortress

Usage:
  fortress <command> [options]

Commands:
  init                Scaffold config, .env template, and fortress.resources.json
  sync:push           Push resources from JSON file to database
  sync:pull           Pull resources from database to JSON file
  sync:types          Generate TypeScript types from fortress.resources.json
  generate-secret     Generate a 64-byte cryptographically random hex secret
  openapi             Generate OpenAPI 3.1 spec from endpoint definitions
  schemas             Generate schema code from endpoint definitions

Options:
  --help, -h          Show this help message

openapi options:
  --out, -o <file>    Output file (default: stdout)
  --title <title>     API title (default: 'Fortress Auth API')
  --version <ver>     API version (default: '1.0.0')

schemas options:
  --format <fmt>      Schema format: 'zod' | 'json-schema' (default: 'json-schema')
  --out, -o <file>    Output file (default: stdout)

Examples:
  fortress init
  fortress sync:types
  fortress generate-secret
  fortress openapi --out openapi.json
  fortress schemas --format zod --out src/generated/fortress-schemas.ts
`.trim();

const CONFIG_TEMPLATE = `import type { FortressConfig } from '@bajustone/fortress';

const config: FortressConfig = {
  database: undefined!, // Replace with your DatabaseAdapter (e.g. createDrizzleAdapter(db))
  jwt: {
    secret: process.env.FORTRESS_JWT_SECRET!,
    issuer: 'my-app',
    accessTokenExpirySeconds: 900,   // 15 minutes
    refreshTokenExpirySeconds: 604800, // 7 days
  },
  plugins: [],
};

export default config;
`;

const ENV_TEMPLATE = `# Fortress configuration
# Generate a secret with: fortress generate-secret
FORTRESS_JWT_SECRET=
`;

const RESOURCES_TEMPLATE = JSON.stringify(
  {
    $schema: 'https://github.com/bajustone/fortress/blob/main/schemas/fortress.resources.schema.json',
    resources: [
      {
        name: 'article',
        description: 'Blog articles',
        actions: ['create', 'read', 'update', 'delete', 'publish'],
      },
    ],
  },
  null,
  2,
);

function cmdInit(): void {
  const cwd = process.cwd();
  const files: Array<{ path: string; content: string; label: string }> = [
    { path: join(cwd, 'fortress.config.ts'), content: CONFIG_TEMPLATE, label: 'fortress.config.ts' },
    { path: join(cwd, '.env.example'), content: ENV_TEMPLATE, label: '.env.example' },
    { path: join(cwd, 'fortress.resources.json'), content: RESOURCES_TEMPLATE, label: 'fortress.resources.json' },
  ];

  for (const file of files) {
    if (existsSync(file.path)) {
      console.log(`  skip  ${file.label} (already exists)`);
    }
    else {
      writeFileSync(file.path, file.content, 'utf-8');
      console.log(`  create  ${file.label}`);
    }
  }

  console.log('\nDone! Next steps:');
  console.log('  1. Run "fortress generate-secret" and paste the value into .env');
  console.log('  2. Configure your database adapter in fortress.config.ts');
  console.log('  3. Define your resources in fortress.resources.json');
  console.log('  4. Run "fortress sync:types" to generate TypeScript types');
}

function cmdSyncPush(): void {
  console.log('sync:push requires a running database connection.\n');
  console.log('Use this in your application code instead:\n');
  console.log('  import { createFortress } from \'@bajustone/fortress\';');
  console.log('');
  console.log('  const fortress = createFortress(config);');
  console.log('  await fortress.iam.syncResources(\'push\');');
}

function cmdSyncPull(): void {
  console.log('sync:pull requires a running database connection.\n');
  console.log('Use this in your application code instead:\n');
  console.log('  import { createFortress } from \'@bajustone/fortress\';');
  console.log('');
  console.log('  const fortress = createFortress(config);');
  console.log('  await fortress.iam.syncResources(\'pull\');');
}

interface ResourceDefinition {
  name: string;
  actions: string[];
}

interface ResourcesFile {
  resources: ResourceDefinition[];
}

function cmdSyncTypes(): void {
  const cwd = process.cwd();
  const resourcesPath = join(cwd, 'fortress.resources.json');

  if (!existsSync(resourcesPath)) {
    console.error('Error: fortress.resources.json not found in the current directory.');
    console.error('Run "fortress init" to create one.');
    process.exit(1);
  }

  let parsed: ResourcesFile;
  try {
    const raw = readFileSync(resourcesPath, 'utf-8');
    parsed = JSON.parse(raw) as ResourcesFile;
  }
  catch {
    console.error('Error: Could not parse fortress.resources.json');
    process.exit(1);
  }

  if (!parsed.resources || !Array.isArray(parsed.resources)) {
    console.error('Error: fortress.resources.json must have a "resources" array');
    process.exit(1);
  }

  const resourceNames = parsed.resources.map(r => r.name);
  const allActions = new Set<string>();
  const resourceActionMap: Record<string, string[]> = {};

  for (const resource of parsed.resources) {
    resourceActionMap[resource.name] = resource.actions;
    for (const action of resource.actions) {
      allActions.add(action);
    }
  }

  let output = '// Auto-generated by "fortress sync:types" — do not edit manually\n\n';

  // Resource union type
  output += `export type FortressResource = ${resourceNames.map(n => `'${n}'`).join(' | ')};\n\n`;

  // Action union type (all unique actions across resources)
  const sortedActions = [...allActions].sort();
  output += `export type FortressAction = ${sortedActions.map(a => `'${a}'`).join(' | ')};\n\n`;

  // Per-resource action map
  output += 'export interface FortressResourceActions {\n';
  for (const resource of parsed.resources) {
    const actions = resource.actions.map(a => `'${a}'`).join(' | ');
    output += `  ${resource.name}: ${actions};\n`;
  }
  output += '}\n';

  const outPath = join(cwd, 'fortress.resources.d.ts');
  writeFileSync(outPath, output, 'utf-8');
  console.log(`Generated ${outPath}`);
  console.log(`  ${resourceNames.length} resource(s), ${allActions.size} unique action(s)`);
}

function cmdGenerateSecret(): void {
  const bytes = new Uint8Array(64);
  crypto.getRandomValues(bytes);
  const hex = Array.from(bytes).map(b => b.toString(16).padStart(2, '0')).join('');
  console.log(hex);
}

function parseArg(args: string[], flag: string, alias?: string): string | undefined {
  for (let i = 0; i < args.length; i++) {
    if (args[i] === flag || (alias && args[i] === alias)) {
      return args[i + 1];
    }
  }
  return undefined;
}

function cmdOpenAPI(args: string[]): void {
  const title = parseArg(args, '--title') ?? 'Fortress Auth API';
  const version = parseArg(args, '--version') ?? '1.0.0';
  const outFile = parseArg(args, '--out') ?? parseArg(args, '-o');

  const allEndpoints = [...authEndpoints, ...iamEndpoints];
  const componentSchemas = { ...authComponentSchemas, ...iamComponentSchemas };

  const spec = buildOpenAPISpec(allEndpoints, componentSchemas, { title, version });
  const json = JSON.stringify(spec, null, 2);

  if (outFile) {
    writeFileSync(outFile, json, 'utf-8');
    console.log(`OpenAPI spec written to ${outFile}`);
    const pathCount = Object.keys(spec.paths).length;
    console.log(`  ${pathCount} endpoints, OpenAPI 3.1.0`);
  }
  else {
    process.stdout.write(json);
  }
}

function cmdSchemas(args: string[]): void {
  const format = parseArg(args, '--format') ?? 'json-schema';
  const outFile = parseArg(args, '--out') ?? parseArg(args, '-o');

  if (format === 'json-schema') {
    const allSchemas = { ...authComponentSchemas, ...iamComponentSchemas };
    const json = JSON.stringify(allSchemas, null, 2);

    if (outFile) {
      writeFileSync(outFile, json, 'utf-8');
      console.log(`JSON Schema written to ${outFile}`);
      console.log(`  ${Object.keys(allSchemas).length} component schemas`);
    }
    else {
      process.stdout.write(json);
    }
    return;
  }

  if (format === 'zod') {
    const allSchemas = { ...authComponentSchemas, ...iamComponentSchemas };
    const allEndpoints = [...authEndpoints, ...iamEndpoints];

    let output = '// Auto-generated by "fortress schemas --format zod" — do not edit manually\n';
    output += '// Requires: zod\n\n';
    output += 'import { z } from \'zod\';\n\n';

    // Generate component schemas
    output += '// ── Component Schemas ─────────────────────────────────────────────\n\n';
    for (const [name, schema] of Object.entries(allSchemas)) {
      output += `export const ${name}Schema = ${jsonSchemaToZodCodegen(schema as any)};\n\n`;
    }

    // Generate endpoint input schemas
    output += '// ── Endpoint Input Schemas ────────────────────────────────────────\n\n';
    for (const ep of allEndpoints) {
      if (ep.input?.body) {
        const handlerName = ep.handler.charAt(0).toUpperCase() + ep.handler.slice(1);
        output += `export const ${handlerName}BodySchema = ${jsonSchemaToZodCodegen(ep.input.body)};\n\n`;
      }
    }

    if (outFile) {
      writeFileSync(outFile, output, 'utf-8');
      console.log(`Zod schemas written to ${outFile}`);
      console.log(`  ${Object.keys(allSchemas).length} component schemas, ${allEndpoints.filter((e: any) => e.input?.body).length} body schemas`);
    }
    else {
      process.stdout.write(output);
    }
    return;
  }

  console.error(`Unknown format: ${format}. Supported: json-schema, zod`);
  process.exit(1);
}

/** Convert a JSON Schema object to Zod code string (codegen, not runtime). */
function jsonSchemaToZodCodegen(schema: any): string {
  if (schema.$ref) {
    const name = schema.$ref.replace('#/components/schemas/', '');
    return `${name}Schema`;
  }

  if (schema.oneOf) {
    const variants = schema.oneOf.map((s: any) => jsonSchemaToZodCodegen(s));
    return `z.union([${variants.join(', ')}])`;
  }

  if (schema.anyOf) {
    const variants = schema.anyOf.map((s: any) => jsonSchemaToZodCodegen(s));
    return `z.union([${variants.join(', ')}])`;
  }

  if (schema.enum) {
    const values = schema.enum.map((v: any) => JSON.stringify(v));
    return `z.enum([${values.join(', ')}])`;
  }

  switch (schema.type) {
    case 'string': {
      let s = 'z.string()';
      if (schema.format === 'email')
        s += '.email()';
      if (schema.format === 'uri')
        s += '.url()';
      if (schema.minLength)
        s += `.min(${schema.minLength})`;
      if (schema.maxLength)
        s += `.max(${schema.maxLength})`;
      if (schema.nullable)
        s += '.nullable()';
      return s;
    }
    case 'number':
      return schema.nullable ? 'z.number().nullable()' : 'z.number()';
    case 'integer':
      return schema.nullable ? 'z.number().int().nullable()' : 'z.number().int()';
    case 'boolean':
      return schema.nullable ? 'z.boolean().nullable()' : 'z.boolean()';
    case 'null':
      return 'z.null()';
    case 'array': {
      const items = schema.items ? jsonSchemaToZodCodegen(schema.items) : 'z.any()';
      return `z.array(${items})`;
    }
    case 'object': {
      if (!schema.properties) {
        return schema.additionalProperties ? 'z.record(z.string(), z.any())' : 'z.object({})';
      }
      const required = new Set(schema.required ?? []);
      const fields = Object.entries(schema.properties).map(([key, propSchema]: [string, any]) => {
        const zodType = jsonSchemaToZodCodegen(propSchema);
        return required.has(key) ? `  ${key}: ${zodType}` : `  ${key}: ${zodType}.optional()`;
      });
      return `z.object({\n${fields.join(',\n')},\n})`;
    }
    default:
      return 'z.any()';
  }
}

// --- Main ---

const args = process.argv.slice(2);
const command = args[0];

if (!command || command === '--help' || command === '-h') {
  console.log(HELP_TEXT);
  process.exit(0);
}

switch (command) {
  case 'init':
    cmdInit();
    break;
  case 'sync:push':
    cmdSyncPush();
    break;
  case 'sync:pull':
    cmdSyncPull();
    break;
  case 'sync:types':
    cmdSyncTypes();
    break;
  case 'generate-secret':
    cmdGenerateSecret();
    break;
  case 'openapi':
    cmdOpenAPI(args.slice(1));
    break;
  case 'schemas':
    cmdSchemas(args.slice(1));
    break;
  default:
    console.error(`Unknown command: ${command}`);
    console.error('Run "fortress --help" for usage information.');
    process.exit(1);
}
