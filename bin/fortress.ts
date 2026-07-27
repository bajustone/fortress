#!/usr/bin/env bun
/* eslint-disable no-console -- CLI tool requires console output */

import type { FortressManifestRuntime, FortressMigrationRuntime, MigrateResult } from '../src/core/capabilities';
import type { FortressConfig } from '../src/core/config';
import type { ComponentSchemas, EndpointDefinition } from '../src/core/endpoint';
import type { RouteManifestEntry } from '../src/core/manifest/route-manifest';
import type { OpenAPISpec } from '../src/plugins/openapi/spec-builder';
import { existsSync, readFileSync, writeFileSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { pathToFileURL } from 'node:url';
import { authComponentSchemas, authEndpoints } from '../src/core/auth/auth-endpoints';
import { iamComponentSchemas, iamEndpoints } from '../src/core/iam/iam-endpoints';
import { parseResourceFile } from '../src/core/iam/resource-sync';
import { detectRouteManifestDrift, hasRouteManifestDrift } from '../src/core/manifest/drift';
import { buildRouteManifest } from '../src/core/manifest/route-manifest';
import { describeRouteSurface } from '../src/core/manifest/route-surface';
import { renderMigrationSqlExport } from '../src/core/migrations/artifacts';
import { getFortressMigrations, getLatestMigrationVersion } from '../src/core/migrations/migrations';
import { loadPolicy, resolvePolicyPath } from '../src/core/policy/loader';
import { buildOpenAPISpec } from '../src/plugins/openapi/spec-builder';
import { checkPublicRoutes } from '../src/testing/checks';

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
  manifest            Generate route-security manifest from endpoint metadata
  manifest:check      Check route manifest drift against endpoints/OpenAPI/RBAC
  check:routes        Alias for manifest:check (CI namespace)
  check:public-routes Fail if any non-allow-listed route is public/oauth-protocol
  check:migrations    Alias for migrate:check (CI namespace)
  policy:summary      Parse fortress.policy.json and print a summary (offline)
  policy:diff         How-to: run diffPolicy() programmatically (DB-bound)
  policy:apply        How-to: run applyPolicyPlan() programmatically (DB-bound)
  policy:check        How-to: assert in-sync policy in CI (DB-bound)
  migrate:status      Show bundled Fortress migration catalog status
  migrate:up          Apply migrations through an explicit application module
  migrate:export      Export review-only bundled SQL (up or down)
  migrate:down        Deprecated alias for down SQL export
  migrate:diff        Explain live schema drift checking API
  migrate:check       Check bundled migration catalog consistency

Route command scope:
  openapi, schemas, manifest, manifest:check, check:routes, and
  check:public-routes cover only Fortress's own auth + IAM routes unless you
  pass --module <path>. Point them at a module exporting your 'config' to
  include your plugin and host-owned routes; the route surface is derived
  without calling createFortress(), so no plugin worker starts. A module
  exporting a configured 'fortress' instance also works, at the cost of
  constructing your app. Optional exports: 'componentSchemas', 'dispose'.

Options:
  --help, -h          Show this help message

openapi options:
  --module <path>     Module exporting your 'config' (or a 'fortress' instance)
  --out, -o <file>    Output file (default: stdout)
  --title <title>     API title (default: 'Fortress Auth API')
  --version <ver>     API version (default: '1.0.0')
  --operation-id <s>  operationId style: 'methodPath' | 'handler' (default: 'methodPath')

schemas options:
  --module <path>     Module exporting your 'config' (or a 'fortress' instance)
  --format <fmt>      Schema format: 'zod' | 'json-schema' (default: 'json-schema')
  --out, -o <file>    Output file (default: stdout)

manifest options:
  --module <path>     Module exporting your 'config' (or a 'fortress' instance)
  --out, -o <file>    Output file (default: stdout)

manifest:check / check:routes options:
  --module <path>     Module exporting your 'config' (or a 'fortress' instance)

check:public-routes options:
  --module <path>     Module exporting your 'config' (or a 'fortress' instance)
  --allow "<M> <path>"  Allow one public route; repeatable

live migration options:
  --module <path>     Trusted module exporting a configured 'fortress' value
  --target-version N  Stop after a non-negative migration version

SQL export/catalog options:
  --dialect <dialect> sqlite | pg (required for migrate:export)
  --direction <dir>   up | down (required for migrate:export)
  --out, -o <file>    Write SQL/status to file where supported

Examples:
  fortress init
  fortress sync:types
  fortress generate-secret
  fortress openapi --out openapi.json
  fortress schemas --format zod --out src/generated/fortress-schemas.ts
  fortress manifest --out route-manifest.json
  fortress manifest --module ./fortress.config.ts --out route-manifest.json
  fortress manifest:check --module ./fortress.config.ts
  fortress check:routes
  fortress check:public-routes --module ./fortress.config.ts
  fortress check:public-routes --allow "GET /health"
  fortress check:migrations
  fortress migrate:up --module ./fortress.migrate.ts
  fortress migrate:export --dialect pg --direction up --out fortress-pg.sql
  fortress policy:summary --file fortress.policy.production.json
`.trim();

const CONFIG_TEMPLATE = `import type { FortressConfig } from '@bajustone/fortress';

/**
 * Fortress configuration, and the module the route CLI reads:
 *
 *   fortress manifest --module ./fortress.config.ts
 *   fortress check:public-routes --module ./fortress.config.ts
 *   fortress openapi --module ./fortress.config.ts --out openapi.json
 *
 * Those commands derive your route surface from this \`config\` export without
 * calling createFortress(), so importing this file must stay free of side
 * effects — no createFortress() at module scope, no opening a database.
 *
 * Without --module they cover Fortress's own auth + IAM routes only, not your
 * plugins or host-owned routes.
 */
export const config: FortressConfig = {
  database: undefined!, // Replace with your DatabaseAdapter (e.g. createSqliteDrizzleAdapter(db))
  jwt: {
    key: process.env.FORTRESS_JWT_SECRET!,
    issuer: 'my-app',
    accessTokenExpirySeconds: 900,   // 15 minutes
    refreshTokenExpirySeconds: 604800, // 7 days
  },
  plugins: [],
  // routes: { ... }  // host-owned endpoint definitions; these show up in CLI checks too
};

/**
 * \`fortress migrate:up\` needs a real instance, which means constructing the
 * app (and starting any plugin workers). Keep that in its own module so the
 * route checks above never pay for it:
 *
 *   // fortress.migrate.ts
 *   import { createFortress } from '@bajustone/fortress';
 *   import { config } from './fortress.config';
 *
 *   export const fortress = createFortress(config);
 *   export function dispose() { /* close database handles *\\/ }
 *
 *   $ fortress migrate:up --module ./fortress.migrate.ts
 */

export default config;
`;

const ENV_TEMPLATE = `# Fortress configuration
# Generate a secret with: fortress generate-secret
FORTRESS_JWT_SECRET=
`;

const RESOURCES_TEMPLATE = JSON.stringify(
  {
    $schema: 'https://github.com/bajustone/fortress/blob/main/schemas/fortress.resources.schema.json',
    resources: {
      article: {
        description: 'Blog articles',
        actions: ['create', 'read', 'update', 'delete', 'publish'],
      },
    },
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
  console.log('  5. Point the checks at your app: "fortress check:public-routes --module ./fortress.config.ts"');
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

function cmdSyncTypes(): void {
  const cwd = process.cwd();
  const resourcesPath = join(cwd, 'fortress.resources.json');

  if (!existsSync(resourcesPath)) {
    console.error('Error: fortress.resources.json not found in the current directory.');
    console.error('Run "fortress init" to create one.');
    process.exit(1);
  }

  let parsed;
  try {
    const raw = readFileSync(resourcesPath, 'utf-8');
    parsed = parseResourceFile(JSON.parse(raw));
  }
  catch (err) {
    console.error(`Error: ${err instanceof Error ? err.message : 'Could not parse fortress.resources.json'}`);
    process.exit(1);
  }

  const resourceNames = Object.keys(parsed.resources);
  const allActions = new Set<string>();
  const resourceActionMap: Record<string, string[]> = {};

  for (const [name, resource] of Object.entries(parsed.resources)) {
    resourceActionMap[name] = resource.actions;
    for (const action of resource.actions) {
      allActions.add(action);
    }
  }

  let output = '// Auto-generated by "fortress sync:types" — do not edit manually\n\n';

  // Resource union type
  const resourceUnion = resourceNames.length > 0
    ? resourceNames.map(name => JSON.stringify(name)).join(' | ')
    : 'never';
  output += `export type FortressResource = ${resourceUnion};\n\n`;

  // Action union type (all unique actions across resources)
  const sortedActions = [...allActions].sort();
  const actionUnion = sortedActions.length > 0
    ? sortedActions.map(action => JSON.stringify(action)).join(' | ')
    : 'never';
  output += `export type FortressAction = ${actionUnion};\n\n`;

  // Per-resource action map
  output += 'export interface FortressResourceActions {\n';
  for (const [name, resource] of Object.entries(parsed.resources)) {
    const actions = resource.actions.length > 0
      ? resource.actions.map(action => JSON.stringify(action)).join(' | ')
      : 'never';
    output += `  ${JSON.stringify(name)}: ${actions};\n`;
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

// --- Argument parsing ---

/**
 * How one named option is spelled and how many times it may appear.
 *
 * Every command parses through {@link parseCliArgs} so an unrecognised flag is
 * a hard error rather than a silent no-op. That matters most for the security
 * checks: a typo like `--modul ./app.ts` must fail loudly instead of quietly
 * reporting a core-only pass.
 */
interface CliOptionSpec {
  /** Flags that select this option, e.g. `['--out', '-o']`. */
  readonly flags: readonly string[];
  /** Accumulate every occurrence instead of rejecting the second one. */
  readonly repeatable?: boolean;
  /**
   * Accept a value beginning with `-`. Reserved for free-form text; a value
   * that is itself a registered flag is still rejected.
   */
  readonly allowLeadingDash?: boolean;
}

type CliOptionRegistry<TOption extends string> = Readonly<Record<TOption, CliOptionSpec>>;

interface ParsedCliArgs<TOption extends string> {
  /** Single value for an option, or `undefined` when it was not supplied. */
  get: (option: TOption) => string | undefined;
  /** Every value supplied for a repeatable option, in argv order. */
  getAll: (option: TOption) => string[];
}

/**
 * Parse `--flag value` pairs against a registry, rejecting unknown flags,
 * flags the command does not accept, duplicates of non-repeatable options,
 * and missing values.
 *
 * Each command passes its own registry so error wording stays scoped: an
 * option another command owns reports "cannot be used with", while a flag no
 * command owns reports "Unknown argument".
 */
function parseCliArgs<TOption extends string>(
  args: string[],
  command: string,
  registry: CliOptionRegistry<TOption>,
  allowed: readonly TOption[],
): ParsedCliArgs<TOption> {
  const flagToOption = new Map<string, TOption>();
  for (const [option, spec] of Object.entries(registry) as Array<[TOption, CliOptionSpec]>) {
    for (const flag of spec.flags)
      flagToOption.set(flag, option);
  }

  const allowedOptions = new Set(allowed);
  const collected = new Map<TOption, string[]>();

  for (let index = 0; index < args.length; index += 2) {
    const flag = args[index]!;
    const option = flagToOption.get(flag);
    if (!option)
      throw new Error(`Unknown argument '${flag}' for ${command}`);
    if (!allowedOptions.has(option))
      throw new Error(`${flag} cannot be used with ${command}`);

    const spec = registry[option];
    const existing = collected.get(option);
    if (existing && !spec.repeatable)
      throw new Error(`Duplicate argument '${flag}' for ${command}`);

    const value = args[index + 1];
    if (!value || (!spec.allowLeadingDash && value.startsWith('-')) || flagToOption.has(value))
      throw new Error(`${flag} requires a value`);

    if (existing)
      existing.push(value);
    else
      collected.set(option, [value]);
  }

  return {
    get: option => collected.get(option)?.[0],
    getAll: option => collected.get(option) ?? [],
  };
}

/** Options shared by the route-derived commands (manifest, OpenAPI, schemas, checks). */
type RouteOption = 'allow' | 'format' | 'module' | 'operationId' | 'out' | 'title' | 'version';

const ROUTE_OPTIONS = {
  allow: { flags: ['--allow'], repeatable: true },
  format: { flags: ['--format'] },
  module: { flags: ['--module'] },
  operationId: { flags: ['--operation-id'] },
  out: { flags: ['--out', '-o'] },
  title: { flags: ['--title'], allowLeadingDash: true },
  version: { flags: ['--version'], allowLeadingDash: true },
} as const satisfies CliOptionRegistry<RouteOption>;

function parseRouteArgs(
  args: string[],
  command: string,
  allowed: readonly RouteOption[],
): ParsedCliArgs<RouteOption> {
  return parseCliArgs(args, command, ROUTE_OPTIONS, allowed);
}

type PolicyOption = 'env' | 'file';

const POLICY_OPTIONS = {
  env: { flags: ['--env'] },
  file: { flags: ['--file', '-f'] },
} as const satisfies CliOptionRegistry<PolicyOption>;

function parseOperationIdStyle(value: string | undefined): 'handler' | 'methodPath' {
  const style = value ?? 'methodPath';
  if (style !== 'handler' && style !== 'methodPath')
    throw new Error(`Unknown operation-id style '${style}'. Use methodPath or handler.`);
  return style;
}

/**
 * Core auth + IAM component schemas.
 *
 * The spec is always built through {@link buildOpenAPISpec} with these merged
 * in, rather than through `fortress.toOpenAPI()`, because the instance method
 * forwards no component schemas — it would emit an empty `components.schemas`
 * and leave every core `$ref` dangling. An application module can contribute
 * its own via a `componentSchemas` export, which is merged on top.
 */
function coreComponentSchemas(): ComponentSchemas {
  return { ...authComponentSchemas, ...iamComponentSchemas };
}

/**
 * Merge application component schemas over Fortress's own, refusing to
 * redefine a core name.
 *
 * Silently letting an application `User` replace the core `User` would change
 * the meaning of core operations in the emitted spec without any signal.
 */
function mergeComponentSchemas(appSchemas: ComponentSchemas, modulePath: string): ComponentSchemas {
  const core = coreComponentSchemas();
  const collisions = Object.keys(appSchemas).filter(name => Object.hasOwn(core, name));
  if (collisions.length > 0) {
    throw new Error(
      `Application module '${modulePath}' redefines Fortress component schema(s): ${collisions.join(', ')}. `
      + `Core operations reference these by name, so overriding them would silently change their meaning. `
      + `Rename the application schema(s).`,
    );
  }
  return { ...core, ...appSchemas };
}

/**
 * OpenAPI requires operationId to be unique across the document. Neither
 * strategy guarantees that on its own: handler names are unique per plugin,
 * not per application, and `methodPath` normalisation maps `/foo-bar` and
 * `/foo_bar` onto the same id. Report the clash with both routes and advice
 * that matches the strategy in use.
 */
function assertUniqueOperationIds(spec: OpenAPISpec, strategy: 'handler' | 'methodPath'): void {
  const advice = strategy === 'handler'
    ? `Handler names are unique per plugin, not per application — re-run without --operation-id handler, or rename one of the handlers.`
    : `Generated IDs normalise punctuation, so these paths collide — try --operation-id handler, or rename one of the routes.`;

  const seen = new Map<string, string>();
  for (const [path, operations] of Object.entries(spec.paths)) {
    for (const [method, operation] of Object.entries(operations)) {
      const id = operation.operationId;
      if (id === undefined)
        continue;
      const route = `${method.toUpperCase()} ${path}`;
      const previous = seen.get(id);
      if (previous)
        throw new Error(`Duplicate operationId '${id}' generated for ${previous} and ${route}. ${advice}`);
      seen.set(id, route);
    }
  }
}

const LOCAL_COMPONENT_REF_PREFIX = '#/components/schemas/';

/** Collect every local component `$ref` reachable from a schema fragment. */
function collectLocalRefs(value: unknown, into: Set<string>): void {
  if (Array.isArray(value)) {
    for (const item of value)
      collectLocalRefs(item, into);
    return;
  }
  if (typeof value !== 'object' || value === null)
    return;

  for (const [key, entry] of Object.entries(value)) {
    if (key === '$ref' && typeof entry === 'string' && entry.startsWith(LOCAL_COMPONENT_REF_PREFIX))
      into.add(entry.slice(LOCAL_COMPONENT_REF_PREFIX.length));
    else
      collectLocalRefs(entry, into);
  }
}

/**
 * Fail on a `$ref` that points at a component the document does not define.
 *
 * A spec with a dangling reference is invalid but still serializes happily, so
 * without this the command exits 0 and the breakage surfaces in whatever
 * consumes the spec later.
 */
function assertResolvableRefs(spec: OpenAPISpec): void {
  const referenced = new Set<string>();
  collectLocalRefs(spec.paths, referenced);
  const defined = spec.components?.schemas ?? {};
  // A component may reference another component.
  collectLocalRefs(defined, referenced);

  const dangling = [...referenced].filter(name => !Object.hasOwn(defined, name)).sort();
  if (dangling.length > 0) {
    throw new Error(
      `OpenAPI spec references undefined component schema(s): ${dangling.join(', ')}. `
      + `Export them from your module as 'componentSchemas' so the spec resolves.`,
    );
  }
}

async function cmdOpenAPI(args: string[]): Promise<void> {
  const parsed = parseRouteArgs(args, 'openapi', ['module', 'operationId', 'out', 'title', 'version']);
  const title = parsed.get('title') ?? 'Fortress Auth API';
  const version = parsed.get('version') ?? '1.0.0';
  const outFile = parsed.get('out');
  const operationId = parseOperationIdStyle(parsed.get('operationId'));

  await withRouteSurface(parsed.get('module'), ({ fortress, scopeNote, componentSchemas }) => {
    const spec = buildOpenAPISpec(fortress.endpoints, componentSchemas, {
      title,
      version,
      operationId,
    });
    assertUniqueOperationIds(spec, operationId);
    assertResolvableRefs(spec);
    const json = JSON.stringify(spec, null, 2);

    if (outFile) {
      writeFileSync(outFile, json, 'utf-8');
      console.log(`OpenAPI spec written to ${outFile}`);
      console.log(`  ${Object.keys(spec.paths).length} path(s), OpenAPI 3.1.0`);
    }
    else {
      process.stdout.write(json);
    }
    printScope(scopeNote, !outFile);
  });
}

// --- Route surface resolution ---

/**
 * The introspection surface every route-derived command works against. A real
 * `Fortress` instance satisfies this structurally, so `--module` output needs
 * no casts and no library-side change.
 */
type CliRouteSurface = Pick<FortressManifestRuntime, 'config' | 'endpoints' | 'manifest'>;

/**
 * Fortress's own auth + IAM routes, with no plugins and no host-owned routes.
 * This is the deliberate fallback when the caller does not point the CLI at an
 * application module; commands label it as such so a green check is never read
 * as covering the caller's own routes.
 */
function buildCoreFortressForCli(): CliRouteSurface {
  const endpoints = [
    ...Object.values(authEndpoints) as EndpointDefinition[],
    ...Object.values(iamEndpoints) as EndpointDefinition[],
  ];
  return {
    endpoints,
    config: { plugins: [], csrf: undefined } as unknown as FortressManifestRuntime['config'],
    get manifest() {
      return buildRouteManifest(this);
    },
  };
}

const CORE_ONLY_NOTE
  = 'Scope: core-only (Fortress auth + IAM routes). '
    + 'Pass --module <path> to include plugin and host-owned routes.';

interface LoadedAppModule {
  fortress: CliRouteSurface;
  /** How the surface was obtained, so the scope note can be precise. */
  source: 'config' | 'instance';
  /** Application component schemas to merge with Fortress's own. */
  componentSchemas: ComponentSchemas;
  dispose?: () => void | Promise<void>;
}

const MODULE_CONTRACT_HINT
  = `must export either a Fortress config as named export 'config' (preferred — read without constructing the app) `
    + `or a configured instance as named export 'fortress'`;

function isRouteSurface(value: unknown): value is CliRouteSurface {
  return isRecord(value)
    && Array.isArray(value.endpoints)
    && Array.isArray(value.manifest)
    && isRecord(value.config);
}

/**
 * Does this export actually look like a Fortress config?
 *
 * `config` is a common export name — framework configs, build configs, app
 * settings. Accepting any object under that name would silently derive the
 * bare core surface and report it as `Scope: application`: a green check that
 * covered none of the caller's routes, which is precisely the failure #15
 * exists to remove. Require the shape `FortressConfig` mandates instead.
 */
function isFortressConfig(value: unknown): value is FortressConfig {
  if (!isRecord(value) || Array.isArray(value))
    return false;
  if (!isRecord(value.jwt) || Array.isArray(value.jwt) || !('key' in value.jwt))
    return false;
  if (value.plugins !== undefined && !Array.isArray(value.plugins))
    return false;
  // `routes` is a record of endpoint definitions; an array is a different shape.
  if (value.routes !== undefined && (!isRecord(value.routes) || Array.isArray(value.routes)))
    return false;
  return true;
}

/**
 * Resolve a loaded module to a route surface.
 *
 * `config` wins over `fortress` because deriving the surface from config never
 * calls a plugin's `methods()` factory. Constructing an instance does, and
 * plugins start workers there — the webhook plugin's queue runs a startup
 * recovery sweep against the database — so the CLI avoids construction
 * whenever the module gives it the declarative input instead.
 */
function validateAppModule(value: unknown, modulePath: string): LoadedAppModule {
  if (!isRecord(value))
    throw new Error(`Application module '${modulePath}' did not export an object`);

  if (value.componentSchemas !== undefined && !isRecord(value.componentSchemas))
    throw new Error(`Application module export 'componentSchemas' must be an object when provided`);
  if (value.dispose !== undefined && typeof value.dispose !== 'function')
    throw new Error(`Application module export 'dispose' must be a function when provided`);

  const common = {
    componentSchemas: (value.componentSchemas ?? {}) as ComponentSchemas,
    dispose: value.dispose as LoadedAppModule['dispose'],
  };

  if (isFortressConfig(value.config))
    return { fortress: describeRouteSurface(value.config), source: 'config', ...common };

  if (isRouteSurface(value.fortress))
    return { fortress: value.fortress, source: 'instance', ...common };

  // Past this point neither export is usable. Say which one was wrong rather
  // than falling back to a surface that does not describe the caller's app.
  if (value.fortress !== undefined) {
    throw new Error(
      `Application module '${modulePath}' export 'fortress' is not a configured Fortress instance `
      + `(expected 'endpoints', 'manifest', and 'config').`,
    );
  }

  if (value.config !== undefined) {
    throw new Error(
      `Application module '${modulePath}' export 'config' is not a Fortress config `
      + `(expected a 'jwt' object with a 'key', and 'plugins'/'routes' of the right shape). `
      + `Refusing to report application scope for a surface that would not include your routes.`,
    );
  }

  throw new Error(
    `Application module '${modulePath}' ${MODULE_CONTRACT_HINT}. `
    + `Add \`export const config = { ... };\` to the module.`,
  );
}

async function loadAppModule(modulePath: string): Promise<LoadedAppModule> {
  const imported = await importCliModule(modulePath);
  try {
    return validateAppModule(imported, modulePath);
  }
  catch (error) {
    await disposeQuietly(imported, 'Application module cleanup also failed');
    throw error;
  }
}

interface ResolvedRouteSurface {
  fortress: CliRouteSurface;
  /** Printed before/alongside command output so scope is never implicit. */
  scopeNote: string;
  /** Fortress component schemas plus anything the module contributed. */
  componentSchemas: ComponentSchemas;
  dispose?: () => void | Promise<void>;
}

/**
 * Finish resolving a loaded module into a runnable surface.
 *
 * This can still throw: `manifest` is a lazy getter, so a malformed
 * `csrf.skipPaths` (or any other config the manifest builder rejects) surfaces
 * here rather than at load time. It runs inside the cleanup boundary so the
 * module's `dispose()` is not skipped when it does.
 */
function describeLoadedSurface(loaded: LoadedAppModule, modulePath: string): ResolvedRouteSurface {
  const routeCount = loaded.fortress.manifest.length;
  const via = loaded.source === 'config' ? 'config' : 'constructed instance';
  return {
    fortress: loaded.fortress,
    scopeNote: `Scope: application (${routeCount} route(s) from ${modulePath}, via ${via}).`,
    componentSchemas: mergeComponentSchemas(loaded.componentSchemas, modulePath),
    dispose: loaded.dispose,
  };
}

/**
 * Run a route-derived command against the resolved surface, always disposing
 * the loaded module afterwards. Failures set `process.exitCode` rather than
 * calling `process.exit` so `dispose()` is not skipped.
 *
 * Everything after a successful import happens under the cleanup boundary —
 * including manifest construction and schema merging, both of which can throw.
 */
async function withRouteSurface(
  modulePath: string | undefined,
  run: (surface: ResolvedRouteSurface) => void,
): Promise<void> {
  if (!modulePath) {
    run({
      fortress: buildCoreFortressForCli(),
      scopeNote: CORE_ONLY_NOTE,
      componentSchemas: coreComponentSchemas(),
    });
    return;
  }

  const loaded = await loadAppModule(modulePath);
  let runError: unknown;
  let runFailed = false;
  try {
    run(describeLoadedSurface(loaded, modulePath));
  }
  catch (error) {
    runFailed = true;
    runError = error;
  }

  let cleanupError: unknown;
  let cleanupFailed = false;
  try {
    await loaded.dispose?.();
  }
  catch (error) {
    cleanupFailed = true;
    cleanupError = error;
  }

  if (runFailed) {
    if (cleanupFailed)
      console.error(`Application module cleanup also failed: ${describeError(cleanupError)}`);
    throw runError;
  }
  if (cleanupFailed)
    throw cleanupError;
}

/** Emit the scope note without polluting stdout when stdout carries the payload. */
function printScope(note: string, payloadOnStdout: boolean): void {
  if (payloadOnStdout)
    console.error(note);
  else
    console.log(note);
}

async function cmdManifest(args: string[]): Promise<void> {
  const parsed = parseRouteArgs(args, 'manifest', ['module', 'out']);
  const outFile = parsed.get('out');

  await withRouteSurface(parsed.get('module'), ({ fortress, scopeNote }) => {
    const manifest = buildRouteManifest(fortress);
    const json = JSON.stringify(manifest, null, 2);

    if (outFile) {
      writeFileSync(outFile, json, 'utf-8');
      console.log(`Route manifest written to ${outFile}`);
      console.log(`  ${manifest.length} route(s)`);
    }
    else {
      process.stdout.write(json);
    }
    printScope(scopeNote, !outFile);
  });
}

async function cmdManifestCheck(args: string[], command: string): Promise<void> {
  const parsed = parseRouteArgs(args, command, ['module']);

  await withRouteSurface(parsed.get('module'), ({ fortress, scopeNote, componentSchemas }) => {
    const openapi = buildOpenAPISpec(fortress.endpoints, componentSchemas, {
      title: 'Fortress Auth API',
      version: '1.0.0',
    });
    const drift = detectRouteManifestDrift(fortress, { openapi });

    if (hasRouteManifestDrift(drift)) {
      console.error('Route manifest drift detected:');
      console.error(JSON.stringify(drift, null, 2));
      console.error(scopeNote);
      process.exitCode = 1;
      return;
    }

    console.log('Route manifest check passed.');
    console.log(scopeNote);
  });
}

async function cmdCheckPublicRoutes(args: string[]): Promise<void> {
  // Repeated `--allow '<METHOD> <path>'` entries augment (never replace) the
  // default Fortress allow-list. Without `--module` this only sees Fortress's
  // own auth + IAM routes, so the scope note is part of the result.
  const parsed = parseRouteArgs(args, 'check:public-routes', ['allow', 'module']);

  await withRouteSurface(parsed.get('module'), ({ fortress, scopeNote }) => {
    const result = checkPublicRoutes(fortress, { allow: parsed.getAll('allow') });
    if (!result.ok) {
      console.error('Public-route check failed:');
      for (const msg of result.messages)
        console.error(`  - ${msg}`);
      console.error(scopeNote);
      process.exitCode = 1;
      return;
    }
    console.log(`Public-route check passed (${fortress.manifest.length} route(s) reviewed, allow-list ok).`);
    console.log(scopeNote);
  });
}

async function cmdPolicySummary(args: string[]): Promise<void> {
  const parsed = parseCliArgs(args, 'policy:summary', POLICY_OPTIONS, ['env', 'file']);
  const filePath = parsed.get('file');
  const env = parsed.get('env');
  const resolved = await resolvePolicyPath({ filePath, env });
  if (!resolved) {
    console.error('No fortress.policy.json (or fortress.policy.<env>.json) found in the current directory.');
    process.exit(1);
  }
  const { policy, filePath: loaded } = await loadPolicy({ filePath, env });
  console.log(`Policy file: ${loaded}`);
  console.log(`  resources: ${(policy.resources ?? []).length}`);
  console.log(`  roles: ${(policy.roles ?? []).length}`);
  console.log(`  groups: ${(policy.groups ?? []).length}`);
  console.log(`  serviceAccounts: ${(policy.serviceAccounts ?? []).length}`);
  for (const role of policy.roles ?? []) {
    console.log(`    role ${role.name}: ${role.permissions.length} permission(s)`);
  }
}

function cmdPolicyHowto(name: 'diff' | 'apply' | 'check'): void {
  console.log(`policy:${name} requires a live database connection.\n`);
  console.log('Run from your application code instead:\n');
  console.log('  import { createFortress } from \'@bajustone/fortress\';');
  console.log('  import {');
  console.log('    loadPolicy, diffPolicy, applyPolicyPlan,');
  console.log('  } from \'@bajustone/fortress\';');
  console.log('');
  console.log('  const fortress = createFortress(config);');
  console.log('  const { policy } = await loadPolicy();');
  console.log('  const plan = await diffPolicy(policy, fortress.iam);');
  if (name === 'diff') {
    console.log('  console.log(plan.ops);');
  }
  else if (name === 'apply') {
    console.log('  const result = await applyPolicyPlan(plan, fortress.iam);');
    console.log('  if (result.errors.length) throw new Error(JSON.stringify(result.errors));');
  }
  else {
    console.log('  if (!plan.inSync) {');
    console.log('    console.error(\'policy drift\', plan.ops);');
    console.log('    process.exit(1);');
    console.log('  }');
  }
}

type MigrationOption = 'dialect' | 'direction' | 'module' | 'out' | 'targetVersion';

type ParsedMigrationArgs = Partial<Record<MigrationOption, string>>;

const MIGRATION_OPTIONS = {
  dialect: { flags: ['--dialect'] },
  direction: { flags: ['--direction'] },
  module: { flags: ['--module'] },
  out: { flags: ['--out', '-o'] },
  // A negative or otherwise malformed version reaches parseTargetVersion so it
  // reports the numeric contract instead of a generic "requires a value".
  targetVersion: { flags: ['--target-version'], allowLeadingDash: true },
} as const satisfies CliOptionRegistry<MigrationOption>;

const MIGRATION_OPTION_NAMES = Object.keys(MIGRATION_OPTIONS) as MigrationOption[];

function parseMigrationArgs(
  args: string[],
  command: string,
  allowed: readonly MigrationOption[],
): ParsedMigrationArgs {
  const parsed = parseCliArgs(args, command, MIGRATION_OPTIONS, allowed);
  const result: ParsedMigrationArgs = {};
  for (const option of MIGRATION_OPTION_NAMES) {
    const value = parsed.get(option);
    if (value !== undefined)
      result[option] = value;
  }
  return result;
}

function requireMigrationOption(
  parsed: ParsedMigrationArgs,
  option: MigrationOption,
  flag: string,
): string {
  const value = parsed[option];
  if (!value)
    throw new Error(`${flag} requires a value`);
  return value;
}

function parseDialect(value: string | undefined, required = false): 'sqlite' | 'pg' {
  if (required && !value)
    throw new Error('--dialect requires a value');
  const dialect = value ?? 'sqlite';
  if (dialect !== 'sqlite' && dialect !== 'pg')
    throw new Error(`Unsupported dialect '${dialect}'. Use sqlite or pg.`);
  return dialect;
}

const DECIMAL_INTEGER_PATTERN = /^\d+$/;

function parseTargetVersion(raw: string | undefined): number | undefined {
  if (raw === undefined)
    return undefined;
  // Number() coerces whitespace, hex/binary/exponent syntax, and signs; require plain digits.
  const targetVersion = DECIMAL_INTEGER_PATTERN.test(raw) ? Number(raw) : Number.NaN;
  if (!Number.isSafeInteger(targetVersion))
    throw new Error(`--target-version must be a non-negative safe integer (received '${raw}')`);
  return targetVersion;
}

function writeOrPrint(content: string, outFile: string | undefined, label: string): void {
  if (outFile) {
    writeFileSync(outFile, content, 'utf-8');
    console.log(`${label} written to ${outFile}`);
  }
  else {
    process.stdout.write(content);
  }
}

function cmdMigrateStatus(args: string[]): void {
  const parsed = parseMigrationArgs(args, 'migrate:status', ['dialect', 'out']);
  const dialect = parseDialect(parsed.dialect);
  const migrations = getFortressMigrations(dialect);
  const body = {
    dialect,
    latestVersion: getLatestMigrationVersion(dialect),
    bundledMigrations: migrations.map(migration => ({
      version: migration.version,
      name: migration.name,
    })),
    note: 'For live database status, call getMigrationStatus(databaseAdapter) from application code so Fortress can use your configured connection.',
  };
  writeOrPrint(`${JSON.stringify(body, null, 2)}\n`, parsed.out, 'Migration status');
}

function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === 'object' && value !== null;
}

interface LoadedMigrationModule {
  fortress: FortressMigrationRuntime;
  migrateApp?: () => Promise<void>;
  dispose?: () => void | Promise<void>;
}

function validateMigrationModule(value: unknown): LoadedMigrationModule {
  if (!isRecord(value))
    throw new Error('Migration module did not export an object');
  if (!isRecord(value.fortress) || typeof value.fortress.migrate !== 'function')
    throw new Error(`Migration module must export a configured Fortress instance as named export 'fortress'`);
  if (value.migrateApp !== undefined && typeof value.migrateApp !== 'function')
    throw new Error(`Migration module export 'migrateApp' must be a function when provided`);
  if (value.dispose !== undefined && typeof value.dispose !== 'function')
    throw new Error(`Migration module export 'dispose' must be a function when provided`);
  return value as unknown as LoadedMigrationModule;
}

function describeError(error: unknown): string {
  return error instanceof Error ? error.message : String(error);
}

/**
 * Import a caller-supplied module by cwd-relative path. The import error is
 * deliberately left unwrapped so runtime diagnostics ("Cannot find module …")
 * reach the operator verbatim.
 */
async function importCliModule(modulePath: string): Promise<unknown> {
  const specifier = pathToFileURL(resolve(process.cwd(), modulePath)).href;
  return await import(specifier);
}

/** Best-effort `dispose()` on a module that failed validation. */
async function disposeQuietly(imported: unknown, label: string): Promise<void> {
  if (!isRecord(imported) || typeof imported.dispose !== 'function')
    return;
  try {
    await imported.dispose();
  }
  catch (cleanupError) {
    console.error(`${label}: ${describeError(cleanupError)}`);
  }
}

async function loadMigrationModule(modulePath: string): Promise<LoadedMigrationModule> {
  const imported = await importCliModule(modulePath);
  try {
    return validateMigrationModule(imported);
  }
  catch (error) {
    await disposeQuietly(imported, 'Migration module cleanup also failed');
    throw error;
  }
}

function printMigrationResult(result: MigrateResult): void {
  const migration = result.fortress;
  console.log(
    `Migration complete (${migration.dialect} ${migration.fromVersion} -> ${migration.toVersion}; `
    + `${migration.applied.length} applied; app migration ${result.appRan ? 'ran' : 'skipped'}).`,
  );
}

async function cmdMigrateUp(args: string[]): Promise<void> {
  if (args.includes('--dialect'))
    throw new Error('--dialect cannot be used with live migration; the module adapter owns the dialect');
  const parsed = parseMigrationArgs(args, 'migrate:up', ['module', 'targetVersion']);
  const modulePath = requireMigrationOption(parsed, 'module', '--module');
  const targetVersion = parseTargetVersion(parsed.targetVersion);
  const loaded = await loadMigrationModule(modulePath);
  let result: MigrateResult | undefined;
  let migrationError: unknown;
  let migrationFailed = false;
  let cleanupError: unknown;
  let cleanupFailed = false;
  try {
    result = await loaded.fortress.migrate({
      migrateApp: loaded.migrateApp,
      targetVersion,
    });
  }
  catch (error) {
    migrationFailed = true;
    migrationError = error;
  }
  try {
    await loaded.dispose?.();
  }
  catch (error) {
    cleanupFailed = true;
    cleanupError = error;
  }
  if (migrationFailed) {
    if (cleanupFailed)
      console.error(`Migration cleanup also failed: ${cleanupError instanceof Error ? cleanupError.message : String(cleanupError)}`);
    throw migrationError;
  }
  if (cleanupFailed)
    throw cleanupError;
  if (!result || !isRecord(result.fortress) || !Array.isArray(result.fortress.applied))
    throw new Error('Migration module returned an invalid migration result');
  printMigrationResult(result);
}

function cmdMigrateExport(args: string[]): void {
  const parsed = parseMigrationArgs(args, 'migrate:export', ['dialect', 'direction', 'out']);
  const dialect = parseDialect(parsed.dialect, true);
  const direction = requireMigrationOption(parsed, 'direction', '--direction');
  if (direction !== 'up' && direction !== 'down')
    throw new Error(`Unsupported migration direction '${direction}'. Use up or down.`);
  const sql = renderMigrationSqlExport(dialect, direction);
  writeOrPrint(sql, parsed.out, `${direction === 'up' ? 'Forward' : 'Rollback'} migration SQL`);
  if (direction === 'up')
    console.error('Warning: exported SQL omits runtime data steps and is for review/tooling only; use migrate:up --module for execution.');
}

function cmdMigrateDown(args: string[]): void {
  const parsed = parseMigrationArgs(args, 'migrate:down', ['dialect', 'out']);
  console.error('Warning: migrate:down is deprecated; use migrate:export --direction down --dialect <sqlite|pg>.');
  const dialect = parseDialect(parsed.dialect);
  writeOrPrint(renderMigrationSqlExport(dialect, 'down'), parsed.out, 'Rollback migration SQL');
}

function cmdMigrateDiff(args: string[]): void {
  parseMigrationArgs(args, 'migrate:diff', []);
  console.log('Live migration drift checks require your application database adapter.');
  console.log('Use this in application or CI code:');
  console.log('  import { detectMigrationDrift, hasMigrationDrift } from \'@bajustone/fortress\';');
  console.log('  const drift = await detectMigrationDrift(database);');
  console.log('  if (hasMigrationDrift(drift)) process.exit(1);');
}

function cmdMigrateCheck(args: string[]): void {
  const parsed = parseMigrationArgs(args, 'migrate:check', ['dialect']);
  const dialect = parseDialect(parsed.dialect);
  const migrations = getFortressMigrations(dialect);
  const versions = new Set<number>();
  for (const migration of migrations) {
    if (versions.has(migration.version)) {
      console.error(`Duplicate migration version ${migration.version}`);
      process.exit(1);
    }
    versions.add(migration.version);
    if (migration.dialect !== dialect) {
      console.error(`Migration ${migration.version} (${migration.name}) has dialect '${migration.dialect}', expected '${dialect}'`);
      process.exit(1);
    }
    if (!migration.up.trim() || !migration.down.trim()) {
      console.error(`Migration ${migration.version} (${migration.name}) is missing up/down SQL`);
      process.exit(1);
    }
  }
  console.log(`Migration catalog check passed (${dialect}, latest=${getLatestMigrationVersion(dialect)}).`);
}

const NON_IDENTIFIER_RUN_RE = /[^\w$]+(.)?/g;
const LEADING_DIGITS_RE = /^\d+/;
const VALID_IDENTIFIER_RE = /^[a-z_$][\w$]*$/i;

/** Component schema name → the exported const it is emitted as. */
type ComponentIdentifiers = Map<string, string>;

function quotePropertyKey(key: string): string {
  return VALID_IDENTIFIER_RE.test(key) ? key : JSON.stringify(key);
}

/**
 * Map every component schema name onto a unique, valid export identifier.
 *
 * Component names are free-form in JSON Schema — `Foo-Bar` and `123.Name` are
 * both legal and neither is a TypeScript identifier. One map serves both the
 * declarations and every `$ref` that resolves to them, so the two cannot drift.
 */
function buildComponentIdentifiers(componentSchemas: ComponentSchemas): ComponentIdentifiers {
  const taken = new Set<string>();
  const identifiers: ComponentIdentifiers = new Map();

  for (const name of Object.keys(componentSchemas)) {
    const base = toIdentifierPart(name) || 'Component';
    let candidate = `${base}Schema`;
    for (let suffix = 2; taken.has(candidate); suffix += 1)
      candidate = `${base}${suffix}Schema`;
    taken.add(candidate);
    identifiers.set(name, candidate);
  }

  return identifiers;
}

/** Local component names a schema fragment refers to. */
function componentDependencies(schema: unknown): Set<string> {
  const refs = new Set<string>();
  collectLocalRefs(schema, refs);
  return refs;
}

/**
 * Order component declarations so each is defined before it is used.
 *
 * A component referring to one declared later would hit the temporal dead
 * zone at import time. Kahn's algorithm emits everything it can order; what
 * remains is a cycle (or something depending on one) and is emitted through
 * `z.lazy()`, whose body is not evaluated until first use.
 */
function orderComponents(componentSchemas: ComponentSchemas): { eager: string[]; lazy: string[] } {
  const names = Object.keys(componentSchemas);
  const known = new Set(names);
  // A self-reference counts as a dependency: it can never be satisfied
  // eagerly, which is exactly what forces a recursive schema to be deferred.
  const pending = new Map(
    names.map(name => [
      name,
      new Set(Array.from(componentDependencies(componentSchemas[name])).filter(ref => known.has(ref))),
    ]),
  );

  const eager: string[] = [];
  let progressed = true;
  while (progressed) {
    progressed = false;
    for (const [name, deps] of pending) {
      if (deps.size > 0)
        continue;
      eager.push(name);
      pending.delete(name);
      for (const remaining of pending.values())
        remaining.delete(name);
      progressed = true;
    }
  }

  return { eager, lazy: [...pending.keys()] };
}

/** Strip anything that cannot appear in a TypeScript identifier, PascalCasing across the removals. */
function toIdentifierPart(value: string): string {
  const cleaned = value
    .replace(NON_IDENTIFIER_RUN_RE, (_, next: string | undefined) => (next ? next.toUpperCase() : ''))
    .replace(LEADING_DIGITS_RE, '');
  return cleaned.charAt(0).toUpperCase() + cleaned.slice(1);
}

/**
 * Pick a unique, valid export name per endpoint body schema.
 *
 * Handler names are only unique within a plugin — two plugins may each define
 * `submit` — and nothing stops one containing punctuation (`schools.get`).
 * Emitting them verbatim produces a file that does not compile, so qualify a
 * clashing name with its owning plugin and fail loudly if that still collides.
 */
function resolveSchemaExportNames(
  endpoints: EndpointDefinition[],
  manifest: RouteManifestEntry[],
  components: ComponentIdentifiers,
): Map<EndpointDefinition, string> {
  const originByRoute = new Map(manifest.map(entry => [`${entry.method} ${entry.path}`, entry.plugin]));
  // Component schemas are emitted into the same module namespace, so their
  // resolved identifiers are already spoken for.
  const taken = new Map<string, string>(
    Array.from(components, ([name, identifier]) => [identifier, `component schema '${name}'`]),
  );
  const names = new Map<EndpointDefinition, string>();

  for (const endpoint of endpoints) {
    const route = `${endpoint.method} ${endpoint.path}`;
    const owner = originByRoute.get(route);
    const base = toIdentifierPart(endpoint.handler);
    const qualified = `${toIdentifierPart(owner ?? 'host')}${base}`;

    const candidate = [`${base}BodySchema`, `${qualified}BodySchema`].find(name => !taken.has(name));
    if (!candidate) {
      throw new Error(
        `Cannot generate a unique schema export for ${route} (handler '${endpoint.handler}'): `
        + `'${base}BodySchema' is already used by ${taken.get(`${base}BodySchema`)} and the `
        + `plugin-qualified fallback '${qualified}BodySchema' is used by ${taken.get(`${qualified}BodySchema`)}. `
        + `Rename one of the handlers.`,
      );
    }
    taken.set(candidate, `${route} (handler '${endpoint.handler}')`);
    names.set(endpoint, candidate);
  }

  return names;
}

async function cmdSchemas(args: string[]): Promise<void> {
  const parsed = parseRouteArgs(args, 'schemas', ['format', 'module', 'out']);
  const format = parsed.get('format') ?? 'json-schema';
  const outFile = parsed.get('out');

  if (format !== 'json-schema' && format !== 'zod')
    throw new Error(`Unknown format: ${format}. Supported: json-schema, zod`);

  await withRouteSurface(parsed.get('module'), ({ fortress, scopeNote, componentSchemas }) => {
    const allSchemas = componentSchemas;

    if (format === 'json-schema') {
      const json = JSON.stringify(allSchemas, null, 2);
      if (outFile) {
        writeFileSync(outFile, json, 'utf-8');
        console.log(`JSON Schema written to ${outFile}`);
        console.log(`  ${Object.keys(allSchemas).length} component schemas`);
      }
      else {
        process.stdout.write(json);
      }
      printScope(scopeNote, !outFile);
      return;
    }

    const bodyEndpoints = fortress.endpoints.filter(ep => ep.input?.body);
    const components = buildComponentIdentifiers(allSchemas);
    const exportNames = resolveSchemaExportNames(bodyEndpoints, fortress.manifest, components);
    const { eager, lazy } = orderComponents(allSchemas);

    let output = '// Auto-generated by "fortress schemas --format zod" — do not edit manually\n';
    output += '// Requires: zod\n\n';
    output += 'import { z } from \'zod\';\n\n';

    // Generate component schemas, dependencies first.
    output += '// ── Component Schemas ─────────────────────────────────────────────\n\n';
    for (const name of eager) {
      const body = jsonSchemaToZodCodegen(allSchemas[name] as any, components);
      output += `export const ${components.get(name)!} = ${body};\n\n`;
    }
    if (lazy.length > 0) {
      output += '// Recursive or mutually-referential schemas; deferred so each\n';
      output += '// reference resolves after every declaration is in scope.\n\n';
      for (const name of lazy) {
        const body = jsonSchemaToZodCodegen(allSchemas[name] as any, components);
        output += `export const ${components.get(name)!}: z.ZodTypeAny = z.lazy(() => ${body});\n\n`;
      }
    }

    // Generate endpoint input schemas
    output += '// ── Endpoint Input Schemas ────────────────────────────────────────\n\n';
    for (const ep of bodyEndpoints) {
      output += `export const ${exportNames.get(ep)!} = ${jsonSchemaToZodCodegen(ep.input!.body, components)};\n\n`;
    }

    if (outFile) {
      writeFileSync(outFile, output, 'utf-8');
      console.log(`Zod schemas written to ${outFile}`);
      console.log(`  ${Object.keys(allSchemas).length} component schemas, ${bodyEndpoints.length} body schemas`);
    }
    else {
      process.stdout.write(output);
    }
    printScope(scopeNote, !outFile);
  });
}

/** Convert a JSON Schema object to Zod code string (codegen, not runtime). */
function jsonSchemaToZodCodegen(schema: any, components: ComponentIdentifiers): string {
  if (schema.$ref) {
    if (typeof schema.$ref !== 'string' || !schema.$ref.startsWith(LOCAL_COMPONENT_REF_PREFIX))
      throw new Error(`Cannot generate Zod for non-local $ref '${String(schema.$ref)}'.`);
    const name = schema.$ref.slice(LOCAL_COMPONENT_REF_PREFIX.length);
    const identifier = components.get(name);
    if (!identifier) {
      throw new Error(
        `Schema references undefined component '${name}'. `
        + `Export it from your module as 'componentSchemas'.`,
      );
    }
    return identifier;
  }

  if (schema.oneOf) {
    const variants = schema.oneOf.map((s: any) => jsonSchemaToZodCodegen(s, components));
    return `z.union([${variants.join(', ')}])`;
  }

  if (schema.anyOf) {
    const variants = schema.anyOf.map((s: any) => jsonSchemaToZodCodegen(s, components));
    return `z.union([${variants.join(', ')}])`;
  }

  if (schema.enum) {
    const values = schema.enum.map((v: any) => JSON.stringify(v));
    // z.enum only accepts string members; anything else has to be a union of
    // literals, which is what a numeric or mixed JSON Schema enum needs.
    if (schema.enum.every((v: unknown) => typeof v === 'string'))
      return `z.enum([${values.join(', ')}])`;
    return `z.union([${values.map((v: string) => `z.literal(${v})`).join(', ')}])`;
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
      const items = schema.items ? jsonSchemaToZodCodegen(schema.items, components) : 'z.any()';
      return `z.array(${items})`;
    }
    case 'object': {
      if (!schema.properties) {
        return schema.additionalProperties ? 'z.record(z.string(), z.any())' : 'z.object({})';
      }
      const required = new Set(schema.required ?? []);
      const fields = Object.entries(schema.properties).map(([key, propSchema]: [string, any]) => {
        const zodType = jsonSchemaToZodCodegen(propSchema, components);
        // Property names come from application schemas and need not be valid
        // identifiers — `first-name` and `2fa` are both legal JSON Schema.
        return `  ${quotePropertyKey(key)}: ${required.has(key) ? zodType : `${zodType}.optional()`}`;
      });
      return `z.object({\n${fields.join(',\n')},\n})`;
    }
    default:
      return 'z.any()';
  }
}

// --- Main ---

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const command = args[0];

  if (!command || command === '--help' || command === '-h') {
    console.log(HELP_TEXT);
    return;
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
      await cmdOpenAPI(args.slice(1));
      break;
    case 'schemas':
      await cmdSchemas(args.slice(1));
      break;
    case 'manifest':
      await cmdManifest(args.slice(1));
      break;
    case 'manifest:check':
      await cmdManifestCheck(args.slice(1), 'manifest:check');
      break;
    case 'migrate:status':
      cmdMigrateStatus(args.slice(1));
      break;
    case 'migrate:up':
      await cmdMigrateUp(args.slice(1));
      break;
    case 'migrate:export':
      cmdMigrateExport(args.slice(1));
      break;
    case 'migrate:down':
      cmdMigrateDown(args.slice(1));
      break;
    case 'migrate:diff':
      cmdMigrateDiff(args.slice(1));
      break;
    case 'migrate:check':
      cmdMigrateCheck(args.slice(1));
      break;
    case 'check:routes':
      await cmdManifestCheck(args.slice(1), 'check:routes');
      break;
    case 'check:public-routes':
      await cmdCheckPublicRoutes(args.slice(1));
      break;
    case 'check:migrations':
      cmdMigrateCheck(args.slice(1));
      break;
    case 'policy:summary':
      await cmdPolicySummary(args.slice(1));
      break;
    case 'policy:diff':
      cmdPolicyHowto('diff');
      break;
    case 'policy:apply':
      cmdPolicyHowto('apply');
      break;
    case 'policy:check':
      cmdPolicyHowto('check');
      break;
    default:
      console.error(`Unknown command: ${command}`);
      console.error('Run "fortress --help" for usage information.');
      process.exitCode = 1;
  }
}

main().catch((error) => {
  console.error(`Error: ${error instanceof Error ? error.message : String(error)}`);
  process.exitCode = 1;
});
