import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, symlinkSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';
import Database from 'better-sqlite3';
import { drizzle } from 'drizzle-orm/better-sqlite3';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';
import { migrateUp } from './core/migrations/engine';
import { createSqliteDrizzleAdapter } from './drizzle/adapter';

const CLI_PATH = fileURLToPath(new URL('../bin/fortress.ts', import.meta.url));
const RUNTIME_ERROR_RE = /(?:TypeError|ReferenceError|SyntaxError):/;

interface CommandCase {
  name: string;
  args: string[];
  expectedStatus?: number;
  output?: string;
}

function runCli(
  cwd: string,
  args: string[],
  env: Record<string, string> = {},
): ReturnType<typeof spawnSync> {
  return spawnSync('bun', [CLI_PATH, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, ...env, NO_COLOR: '1' },
    timeout: 20_000,
  });
}

const CORE_ONLY_SCOPE = 'Scope: core-only';
const APP_SCOPE = 'Scope: application';

interface AppModuleOptions {
  /** Add an unreviewed public plugin route. */
  leak?: boolean;
  /** Which export shape the module presents to `--module`. */
  shape?: 'config' | 'instance' | 'default';
  /** Add a second plugin reusing a handler name, plus a punctuated handler. */
  collide?: boolean;
  /** Export application component schemas and a route that `$ref`s one. */
  componentSchemas?: boolean;
}

/**
 * Write a `--module` fixture: a plugin route plus a host-owned route.
 *
 * The plugin's `methods()` factory writes a marker file. That is how the tests
 * tell the two loading paths apart — deriving the surface from `config` must
 * never run it, while constructing an instance necessarily does.
 */
function writeAppModule(dir: string, file: string, opts: AppModuleOptions = {}): void {
  const fortressUrl = new URL('./core/fortress.ts', import.meta.url).href;
  const builderUrl = new URL('./core/schema-builder.ts', import.meta.url).href;
  const testingUrl = new URL('./testing/index.ts', import.meta.url).href;
  const marker = `${file}.methods-ran`;

  const leakRoute = `
        leak: endpoint('GET', '/reports/leak')
          .summary('Unreviewed public plugin route')
          .security('none')
          .response(200, 'ok', obj({ ok: str() }, 'ok'))
          .handler('leak')
          .build(),`;

  // A second plugin whose handler name collides with the first, and a handler
  // that is not a valid TypeScript identifier.
  const collidingPlugin = `
    const exportsPlugin = {
      name: 'exports',
      routes: {
        createReport: endpoint('POST', '/exports')
          .summary('Colliding handler name')
          .permission('export', 'create')
          .body(obj({ title: str() }, 'title'))
          .response(200, 'ok', obj({ ok: str() }, 'ok'))
          .handler('createReport')
          .build(),
        'schools.get': endpoint('POST', '/exports/schools')
          .summary('Handler that is not an identifier')
          .permission('export', 'read')
          .body(obj({ id: str() }, 'id'))
          .response(200, 'ok', obj({ ok: str() }, 'ok'))
          .handler('schools.get')
          .build(),
      },
      methods: () => ({ createReport: async () => ({ ok: 'yes' }), 'schools.get': async () => ({ ok: 'yes' }) }),
    };`;

  // Authored as a literal definition because the fluent builder takes a
  // Standard Schema validator, and the point here is a raw component `$ref`.
  const refRoute = `
        refRoute: {
          method: 'POST',
          path: '/reports/ref',
          handler: 'refRoute',
          meta: { summary: 'Route referencing an application component schema', permission: { resource: 'report', action: 'create' } },
          input: { body: { $ref: '#/components/schemas/AppReport' } },
          responses: { 200: { description: 'ok' } },
        },`;

  writeFileSync(join(dir, file), `
    import { writeFileSync } from 'node:fs';
    import { createFortress } from ${JSON.stringify(fortressUrl)};
    import { endpoint, obj, str } from ${JSON.stringify(builderUrl)};
    import { createTestAdapter } from ${JSON.stringify(testingUrl)};

    const reportsPlugin = {
      name: 'reports',
      routes: {
        createReport: endpoint('POST', '/reports')
          .summary('Create a report')
          .permission('report', 'create')
          .body(obj({ title: str() }, 'title'))
          .response(200, 'ok', obj({ ok: str() }, 'ok'))
          .handler('createReport')
          .build(),${opts.leak ? leakRoute : ''}${opts.componentSchemas ? refRoute : ''}
      },
      // Stands in for a plugin that starts a worker or touches the database
      // here, as the bundled webhook plugin's queue does.
      methods: () => {
        writeFileSync(${JSON.stringify(marker)}, 'yes');
        return {
          createReport: async () => ({ ok: 'yes' }),
          leak: async () => ({ ok: 'yes' }),
          refRoute: async () => ({ ok: 'yes' }),
        };
      },
    };
    ${opts.collide ? collidingPlugin : ''}

    const appConfig = {
      jwt: { key: 'cli-app-module-secret-at-least-32-chars' },
      database: createTestAdapter(),
      plugins: [reportsPlugin${opts.collide ? ', exportsPlugin' : ''}],
      routes: {
        hostStats: endpoint('GET', '/host/stats')
          .summary('Host-owned stats route')
          ${opts.leak ? `.security('none')` : `.permission('stats', 'read')`}
          .response(200, 'ok', obj({ ok: str() }, 'ok'))
          .handler('hostStats')
          .build(),
      },
    };
    ${opts.componentSchemas
      ? `export const componentSchemas = { AppReport: obj({ title: str() }, 'title') };`
      : ''}
    ${opts.shape === 'instance'
      ? 'export const fortress = createFortress(appConfig);'
      : opts.shape === 'default'
        ? 'export default createFortress(appConfig);'
        : 'export const config = appConfig;'}

    export async function dispose() {
      await Bun.write(${JSON.stringify(`${file}.disposed`)}, 'yes');
    }
  `);
}

/**
 * Import a generated Zod module and return its exports.
 *
 * The file is written into a temp cwd where `zod` does not resolve, so the
 * bare specifier is rewritten to the resolved URL — the same trick the live
 * migration fixture uses for `drizzle-orm`. Transpiling the output is not
 * enough: the defects these tests cover (a `__proto__` key that never becomes
 * a property, a `oneOf` that accepts two matches) all compile perfectly.
 */
async function importGenerated(file: string): Promise<Record<string, { safeParse: (value: unknown) => { success: boolean; data?: unknown } }>> {
  const zodUrl = import.meta.resolve('zod');
  const source = readFileSync(file, 'utf8').replace(`from 'zod'`, `from ${JSON.stringify(zodUrl)}`);
  const executable = `${file.replace(/\.ts$/, '')}.executable.ts`;
  writeFileSync(executable, source);
  return await import(pathToFileURL(executable).href) as never;
}

describe('fortress CLI smoke tests', () => {
  let cwd: string;

  beforeAll(() => {
    cwd = mkdtempSync(join(tmpdir(), 'fortress-cli-'));
  });

  afterAll(() => {
    rmSync(cwd, { recursive: true, force: true });
  });

  it('invokes every documented command without an uncaught runtime error', () => {
    expect(runCli(cwd, ['init']).status).toBe(0);
    writeFileSync(join(cwd, 'fortress.policy.json'), '{}');
    writeFileSync(join(cwd, 'migration-module.ts'), `
      export const fortress = {
        async migrate(options) {
          if (options.migrateApp) await options.migrateApp();
          return {
            fortress: { dialect: 'sqlite', fromVersion: 0, toVersion: 0, applied: [] },
            appRan: Boolean(options.migrateApp),
          };
        },
      };
    `);

    const commands: CommandCase[] = [
      { name: 'help', args: ['--help'] },
      { name: 'sync:push', args: ['sync:push'] },
      { name: 'sync:pull', args: ['sync:pull'] },
      { name: 'sync:types', args: ['sync:types'] },
      { name: 'generate-secret', args: ['generate-secret'] },
      { name: 'openapi', args: ['openapi', '--out', 'openapi.json'], output: 'openapi.json' },
      { name: 'schemas json-schema', args: ['schemas', '--format', 'json-schema', '--out', 'schemas.json'], output: 'schemas.json' },
      { name: 'schemas zod', args: ['schemas', '--format', 'zod', '--out', 'schemas.ts'], output: 'schemas.ts' },
      { name: 'openapi operation-id handler', args: ['openapi', '--operation-id', 'handler', '--out', 'openapi-handler.json'], output: 'openapi-handler.json' },
      { name: 'manifest', args: ['manifest', '--out', 'manifest.json'], output: 'manifest.json' },
      { name: 'manifest:check', args: ['manifest:check'] },
      { name: 'check:routes', args: ['check:routes'] },
      { name: 'check:public-routes', args: ['check:public-routes'] },
      { name: 'check:public-routes allow', args: ['check:public-routes', '--allow', 'GET /health'] },
      { name: 'policy:summary', args: ['policy:summary'] },
      { name: 'policy:diff', args: ['policy:diff'] },
      { name: 'policy:apply', args: ['policy:apply'] },
      { name: 'policy:check', args: ['policy:check'] },
      { name: 'migrate:status sqlite', args: ['migrate:status', '--dialect', 'sqlite', '--out', 'migration-status.json'], output: 'migration-status.json' },
      { name: 'migrate:status pg', args: ['migrate:status', '--dialect', 'pg'] },
      { name: 'migrate:up', args: ['migrate:up', '--module', './migration-module.ts'] },
      { name: 'migrate:export up', args: ['migrate:export', '--dialect', 'sqlite', '--direction', 'up', '--out', 'up.sql'], output: 'up.sql' },
      { name: 'migrate:export down', args: ['migrate:export', '--dialect', 'pg', '--direction', 'down', '--out', 'down.sql'], output: 'down.sql' },
      { name: 'migrate:down deprecated alias', args: ['migrate:down', '--out', 'legacy-down.sql'], output: 'legacy-down.sql' },
      { name: 'migrate:diff', args: ['migrate:diff'] },
      { name: 'migrate:check', args: ['migrate:check'] },
      { name: 'check:migrations', args: ['check:migrations', '--dialect', 'pg'] },
    ];

    for (const command of commands) {
      const result = runCli(cwd, command.args);
      const diagnostic = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;
      expect(result.error, command.name).toBeUndefined();
      expect(result.status, `${command.name}: ${diagnostic}`).toBe(command.expectedStatus ?? 0);
      expect(diagnostic, command.name).not.toMatch(RUNTIME_ERROR_RE);
      if (command.output)
        expect(readFileSync(join(cwd, command.output), 'utf8').length, command.name).toBeGreaterThan(0);
    }
  }, 30_000);

  it('awaits the explicit migration module, forwards options, and disposes it', () => {
    writeFileSync(join(cwd, 'lifecycle-module.ts'), `
      const delay = (ms) => new Promise(resolve => setTimeout(resolve, ms));
      export const fortress = {
        async migrate(options) {
          await delay(10);
          await Bun.write('target-version.txt', String(options.targetVersion));
          if (options.migrateApp) await options.migrateApp();
          return {
            fortress: { dialect: 'pg', fromVersion: 2, toVersion: options.targetVersion, applied: [{}, {}] },
            appRan: Boolean(options.migrateApp),
          };
        },
      };
      export async function migrateApp() { await Bun.write('app-ran.txt', 'yes'); }
      export async function dispose() { await Bun.write('disposed.txt', 'yes'); }
    `);

    const result = runCli(cwd, [
      'migrate:up',
      '--module',
      './lifecycle-module.ts',
      '--target-version',
      '7',
    ]);
    expect(result.status, String(result.stderr)).toBe(0);
    expect(result.stdout).toContain('Migration complete (pg 2 -> 7; 2 applied; app migration ran).');
    expect(readFileSync(join(cwd, 'target-version.txt'), 'utf8')).toBe('7');
    expect(readFileSync(join(cwd, 'app-ran.txt'), 'utf8')).toBe('yes');
    expect(readFileSync(join(cwd, 'disposed.txt'), 'utf8')).toBe('yes');
  });

  it('rejects malformed live migration invocations with controlled diagnostics', () => {
    writeFileSync(join(cwd, 'invalid-module.ts'), 'export const fortress = {};');
    writeFileSync(join(cwd, 'rejecting-module.ts'), `
      export const fortress = { async migrate() { throw new Error('migration rejected'); } };
      export async function dispose() { await Bun.write('rejection-disposed.txt', 'yes'); }
    `);
    writeFileSync(join(cwd, 'must-not-import.ts'), `
      await Bun.write('typo-imported.txt', 'yes');
      export const fortress = { async migrate() { throw new Error('must not run'); } };
    `);
    const cases = [
      { args: ['migrate:up'], message: '--module requires a value' },
      { args: ['migrate:up', '--module', '-x'], message: '--module requires a value' },
      { args: ['migrate:up', '--module', './missing.ts'], message: 'Cannot find module' },
      { args: ['migrate:up', '--module', './invalid-module.ts'], message: `named export 'fortress'` },
      { args: ['migrate:up', '--module', './invalid-module.ts', '--target-version', '-1'], message: 'non-negative safe integer' },
      { args: ['migrate:up', '--module', './must-not-import.ts', '--target-version', ' '], message: 'non-negative safe integer' },
      { args: ['migrate:up', '--module', './must-not-import.ts', '--target-version', '  5  '], message: 'non-negative safe integer' },
      { args: ['migrate:up', '--module', './must-not-import.ts', '--target-version', '0x10'], message: 'non-negative safe integer' },
      { args: ['migrate:up', '--module', './must-not-import.ts', '--target-version', '1e3'], message: 'non-negative safe integer' },
      { args: ['migrate:up', '--module', './must-not-import.ts', '--target-version', '+5'], message: 'non-negative safe integer' },
      { args: ['migrate:up', '--module', './must-not-import.ts', '--target-version', '5.0'], message: 'non-negative safe integer' },
      { args: ['migrate:up', '--module', './must-not-import.ts', '--target-version', '99999999999999999999'], message: 'non-negative safe integer' },
      { args: ['migrate:up', '--module', './invalid-module.ts', '--dialect', 'pg'], message: 'adapter owns the dialect' },
      { args: ['migrate:up', '--module', './invalid-module.ts', '--out', 'x.sql'], message: '--out cannot be used' },
      { args: ['migrate:up', '--module', './rejecting-module.ts'], message: 'migration rejected' },
      { args: ['migrate:up', '--module', './must-not-import.ts', '--target-verison', '5'], message: `Unknown argument '--target-verison'` },
      { args: ['migrate:up', '--module', './must-not-import.ts', 'trailing'], message: `Unknown argument 'trailing'` },
      { args: ['migrate:up', '--module', './must-not-import.ts', '--module', './invalid-module.ts'], message: `Duplicate argument '--module'` },
      { args: ['migrate:up', '--module', './must-not-import.ts', '--target-version', '5', '--target-version', '6'], message: `Duplicate argument '--target-version'` },
    ];

    for (const testCase of cases) {
      const result = runCli(cwd, testCase.args);
      const diagnostic = `${result.stdout}\n${result.stderr}`;
      expect(result.status, diagnostic).toBe(1);
      expect(diagnostic).toContain(testCase.message);
      expect(diagnostic).not.toMatch(RUNTIME_ERROR_RE);
    }
    expect(readFileSync(join(cwd, 'rejection-disposed.txt'), 'utf8')).toBe('yes');
    expect(existsSync(join(cwd, 'typo-imported.txt'))).toBe(false);
  });

  it('derives the route surface from config without constructing the application', () => {
    writeAppModule(cwd, 'pure-module.ts', { shape: 'config' });
    writeAppModule(cwd, 'instance-module.ts', { shape: 'instance' });

    const pure = runCli(cwd, ['manifest', '--module', './pure-module.ts', '--out', 'pure-manifest.json']);
    expect(pure.status, String(pure.stderr)).toBe(0);
    expect(pure.stdout).toContain('via config');
    // Plugin `methods()` is where plugins start workers and hit the database
    // (the webhook queue's startup recovery sweep, for example). The config
    // path must never reach it.
    expect(existsSync(join(cwd, 'pure-module.ts.methods-ran'))).toBe(false);

    const constructed = runCli(cwd, ['manifest', '--module', './instance-module.ts', '--out', 'instance-manifest.json']);
    expect(constructed.status, String(constructed.stderr)).toBe(0);
    expect(constructed.stdout).toContain('via constructed instance');
    expect(existsSync(join(cwd, 'instance-module.ts.methods-ran'))).toBe(true);

    // Both paths must describe the same routes.
    const normalise = (file: string): string => {
      const entries = JSON.parse(readFileSync(join(cwd, file), 'utf8')) as Array<Record<string, unknown>>;
      return JSON.stringify(entries.map(entry => `${entry.method} ${entry.path} ${entry.plugin} ${entry.classification}`).sort());
    };
    expect(normalise('pure-manifest.json')).toBe(normalise('instance-manifest.json'));
  }, 30_000);

  it('merges application component schemas supplied by the module', () => {
    writeAppModule(cwd, 'schemas-module.ts', { componentSchemas: true });

    const core = runCli(cwd, ['schemas', '--format', 'json-schema', '--out', 'core-components.json']);
    expect(core.status, String(core.stderr)).toBe(0);
    const app = runCli(cwd, ['schemas', '--format', 'json-schema', '--module', './schemas-module.ts', '--out', 'app-components.json']);
    expect(app.status, String(app.stderr)).toBe(0);

    const coreSchemas = JSON.parse(readFileSync(join(cwd, 'core-components.json'), 'utf8')) as Record<string, unknown>;
    const appSchemas = JSON.parse(readFileSync(join(cwd, 'app-components.json'), 'utf8')) as Record<string, unknown>;
    expect(coreSchemas.AppReport).toBeUndefined();
    expect(appSchemas.AppReport).toBeDefined();

    // An endpoint referencing an application component must resolve.
    const openapi = runCli(cwd, ['openapi', '--module', './schemas-module.ts', '--out', 'ref-openapi.json']);
    expect(openapi.status, String(openapi.stderr)).toBe(0);
    const spec = JSON.parse(readFileSync(join(cwd, 'ref-openapi.json'), 'utf8')) as {
      components: { schemas: Record<string, unknown> };
    };
    const refs = Array.from(
      readFileSync(join(cwd, 'ref-openapi.json'), 'utf8').matchAll(/"\$ref":\s*"#\/components\/schemas\/([^"]+)"/g),
      match => match[1]!,
    );
    expect(refs).toContain('AppReport');
    for (const ref of new Set(refs))
      expect(spec.components.schemas[ref], `dangling $ref: ${ref}`).toBeDefined();
  }, 30_000);

  it('generates unique, compilable Zod identifiers across plugins', () => {
    writeAppModule(cwd, 'collide-module.ts', { collide: true });

    const result = runCli(cwd, ['schemas', '--format', 'zod', '--module', './collide-module.ts', '--out', 'collide-schemas.ts']);
    expect(result.status, String(result.stderr)).toBe(0);
    const generated = readFileSync(join(cwd, 'collide-schemas.ts'), 'utf8');

    // Two plugins both declare a `createReport` handler; the second must be
    // qualified rather than redeclared, and `schools.get` must be sanitised.
    const declared = Array.from(generated.matchAll(/^export const (\w+) = /gm), match => match[1]!);
    expect(new Set(declared).size, `duplicate declarations in:\n${generated}`).toBe(declared.length);
    for (const name of declared)
      expect(name, 'invalid TypeScript identifier').toMatch(/^[A-Z_$][\w$]*$/);
    expect(declared).toContain('CreateReportBodySchema');
    expect(declared).toContain('ExportsCreateReportBodySchema');
    expect(declared).toContain('SchoolsGetBodySchema');

    // The generated file must actually compile. `zod` is external because it
    // is not a dependency of this repo; the check here is the generated code.
    const parsed = spawnSync('bun', ['build', '--target', 'node', '--external', 'zod', join(cwd, 'collide-schemas.ts'), '--outfile', join(cwd, 'collide-build.js')], {
      cwd,
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
      timeout: 20_000,
    });
    expect(parsed.status, `${parsed.stdout}\n${parsed.stderr}`).toBe(0);
  }, 30_000);

  it('refuses to treat an unrelated `config` export as an application surface', () => {
    // `config` is a common export name. Accepting any object under it would
    // derive the bare core surface and label it `Scope: application` — a green
    // check covering none of the caller's routes.
    writeFileSync(join(cwd, 'foreign-config.ts'), `export const config = { build: { outDir: 'dist' } };`);
    const foreign = runCli(cwd, ['check:public-routes', '--module', './foreign-config.ts']);
    expect(foreign.status, String(foreign.stdout)).toBe(1);
    expect(foreign.stderr).toContain(`export 'config' is not a Fortress config`);
    expect(String(foreign.stdout)).not.toContain(APP_SCOPE);

    for (const malformed of [
      `export const config = { database: undefined, jwt: { key: 'k' }, plugins: 'nope' };`,
      `export const config = { database: undefined, jwt: { key: 'k' }, routes: [] };`,
      `export const config = { database: undefined, jwt: {} };`,
    ]) {
      writeFileSync(join(cwd, 'malformed-config.ts'), malformed);
      const result = runCli(cwd, ['manifest', '--module', './malformed-config.ts']);
      expect(result.status, malformed).toBe(1);
      expect(`${result.stdout}\n${result.stderr}`, malformed).not.toMatch(RUNTIME_ERROR_RE);
    }

    // A module whose `config` is unusable but which exports a real instance
    // must fall through to the instance rather than fail or report core-only.
    writeAppModule(cwd, 'competing-module.ts', { shape: 'instance' });
    const competing = readFileSync(join(cwd, 'competing-module.ts'), 'utf8');
    writeFileSync(join(cwd, 'competing-module.ts'), `${competing}\nexport const config = { unrelated: true };\n`);
    const result = runCli(cwd, ['manifest', '--module', './competing-module.ts', '--out', 'competing.json']);
    expect(result.status, String(result.stderr)).toBe(0);
    expect(result.stdout).toContain('via constructed instance');
    const entries = JSON.parse(readFileSync(join(cwd, 'competing.json'), 'utf8')) as Array<{ path: string }>;
    expect(entries.some(entry => entry.path === '/reports')).toBe(true);
  }, 30_000);

  it('rejects dangling and colliding component schemas', () => {
    // A `$ref` with no matching component serializes fine but is invalid.
    writeFileSync(join(cwd, 'dangling-module.ts'), `
      export const config = {
        database: undefined,
        jwt: { key: 'dangling-secret-at-least-32-chars-long' },
        routes: {
          broken: {
            method: 'POST',
            path: '/broken',
            handler: 'broken',
            meta: { summary: 'Dangling ref', permission: { resource: 'x', action: 'y' } },
            input: { body: { $ref: '#/components/schemas/Missing' } },
            responses: { 200: { description: 'ok' } },
          },
        },
      };
    `);
    const dangling = runCli(cwd, ['openapi', '--module', './dangling-module.ts', '--out', 'dangling.json']);
    expect(dangling.status, String(dangling.stdout)).toBe(1);
    expect(dangling.stderr).toContain('undefined component schema(s): Missing');

    // Redefining a core component would silently change core operations.
    writeFileSync(join(cwd, 'shadow-module.ts'), `
      export const config = { database: undefined, jwt: { key: 'shadow-secret-at-least-32-chars-long!' } };
      export const componentSchemas = { User: { type: 'object', properties: {} } };
    `);
    const shadow = runCli(cwd, ['openapi', '--module', './shadow-module.ts']);
    expect(shadow.status, String(shadow.stdout)).toBe(1);
    expect(shadow.stderr).toContain('redefines Fortress component schema(s): User');
  }, 30_000);

  it('rejects non-record component schemas and non-object schema values', () => {
    const cases = [
      { name: 'array-record', schemas: `[{ type: 'string' }]`, message: 'must be a plain object' },
      { name: 'array-value', schemas: `{ Thing: [] }`, message: 'must be a schema object' },
      { name: 'number-value', schemas: `{ Thing: 42 }`, message: 'must be a schema object' },
      { name: 'null-value', schemas: `{ Thing: null }`, message: 'must be a schema object' },
    ];
    for (const testCase of cases) {
      writeFileSync(join(cwd, `invalid-components-${testCase.name}.ts`), `
        export const config = { database: undefined, jwt: { key: 'components-secret-at-least-32-chars-ok' } };
        export const componentSchemas = ${testCase.schemas};
      `);
      for (const command of [
        ['openapi'],
        ['schemas', '--format', 'json-schema'],
        ['schemas', '--format', 'zod'],
      ]) {
        const result = runCli(cwd, [...command, '--module', `./invalid-components-${testCase.name}.ts`]);
        const diagnostic = `${result.stdout}\n${result.stderr}`;
        expect(result.status, `${testCase.name} ${command.join(' ')}: ${diagnostic}`).toBe(1);
        expect(diagnostic).toContain(testCase.message);
        expect(diagnostic).not.toMatch(RUNTIME_ERROR_RE);
      }
    }
  }, 30_000);

  it('treats property and annotation data as data while cleaning schema nodes', () => {
    writeFileSync(join(cwd, 'schema-data-locations.ts'), `
      export const config = {
        database: undefined,
        jwt: { key: 'schema-data-secret-at-least-32-chars' },
      };
      export const componentSchemas = {
        DataLocations: {
          type: 'object',
          properties: {
            '$ref': { type: 'string' },
            '~field': {
              type: 'string',
              default: { '$ref': '#/components/schemas/Missing', '~field': 'nested-default' },
            },
          },
          default: { '$ref': '#/components/schemas/Missing', '~field': 'root-default' },
          '~extension': { '~field': 'schema-extension-data' },
          '~standard': { validate() { throw new Error('runtime-only'); } },
        },
      };
    `);

    const openapi = runCli(cwd, ['openapi', '--module', './schema-data-locations.ts', '--out', 'schema-data-openapi.json']);
    expect(openapi.status, String(openapi.stderr)).toBe(0);
    const spec = JSON.parse(readFileSync(join(cwd, 'schema-data-openapi.json'), 'utf8')) as {
      components: { schemas: Record<string, any> };
    };
    const openapiSchema = spec.components.schemas.DataLocations;
    expect(openapiSchema.properties).toHaveProperty('$ref');
    expect(openapiSchema.properties).toHaveProperty('~field');
    expect(openapiSchema.default).toEqual({ '$ref': '#/components/schemas/Missing', '~field': 'root-default' });
    expect(openapiSchema.properties['~field'].default).toEqual({
      '$ref': '#/components/schemas/Missing',
      '~field': 'nested-default',
    });
    expect(openapiSchema['~extension']).toEqual({ '~field': 'schema-extension-data' });
    expect(openapiSchema).not.toHaveProperty('~standard');

    const jsonSchema = runCli(cwd, ['schemas', '--format', 'json-schema', '--module', './schema-data-locations.ts', '--out', 'schema-data.json']);
    expect(jsonSchema.status, String(jsonSchema.stderr)).toBe(0);
    const emitted = JSON.parse(readFileSync(join(cwd, 'schema-data.json'), 'utf8')) as Record<string, any>;
    expect(emitted.DataLocations.properties).toHaveProperty('$ref');
    expect(emitted.DataLocations.properties).toHaveProperty('~field');
    expect(emitted.DataLocations.default['~field']).toBe('root-default');
    expect(emitted.DataLocations.properties['~field'].default['~field']).toBe('nested-default');
    expect(emitted.DataLocations['~extension']).toEqual({ '~field': 'schema-extension-data' });
    expect(emitted.DataLocations).not.toHaveProperty('~standard');

    // Dependency ordering/codegen use the same schema-aware walker and must
    // not mistake the legal `$ref` property name or default data for a ref.
    const zod = runCli(cwd, ['schemas', '--format', 'zod', '--module', './schema-data-locations.ts', '--out', 'schema-data-zod.ts']);
    expect(zod.status, String(zod.stderr)).toBe(0);
  }, 30_000);

  it('generates compilable Zod for hostile component and property names', () => {
    writeFileSync(join(cwd, 'hostile-module.ts'), `
      export const config = {
        database: undefined,
        jwt: { key: 'hostile-secret-at-least-32-chars-long' },
        routes: {
          hostile: {
            method: 'POST',
            path: '/hostile',
            handler: 'hostile',
            meta: { summary: 'Hostile names', permission: { resource: 'x', action: 'y' } },
            input: { body: { $ref: '#/components/schemas/Foo-Bar' } },
            responses: { 200: { description: 'ok' } },
          },
        },
      };
      export const componentSchemas = {
        'Foo-Bar': {
          type: 'object',
          required: ['first-name'],
          properties: {
            'first-name': { type: 'string' },
            '2fa': { type: 'boolean' },
            'kind': { enum: [1, 2, 3] },
            'child': { $ref: '#/components/schemas/123.Name' },
          },
        },
        '123.Name': {
          type: 'object',
          properties: { 'self': { $ref: '#/components/schemas/123.Name' } },
        },
        'Foo_Bar': { type: 'object', properties: { ok: { type: 'string' } } },
      };
    `);

    const result = runCli(cwd, ['schemas', '--format', 'zod', '--module', './hostile-module.ts', '--out', 'hostile-schemas.ts']);
    expect(result.status, String(result.stderr)).toBe(0);
    const generated = readFileSync(join(cwd, 'hostile-schemas.ts'), 'utf8');

    const declared = Array.from(generated.matchAll(/^export const (\w+)/gm), match => match[1]!);
    expect(new Set(declared).size, `duplicate declarations in:\n${generated}`).toBe(declared.length);
    for (const name of declared)
      expect(name, 'invalid TypeScript identifier').toMatch(/^[A-Z_$][\w$]*$/i);
    // Invalid property names must be quoted, not emitted bare.
    expect(generated).toContain('"first-name"');
    expect(generated).toContain('"2fa"');
    // A numeric enum cannot be z.enum.
    expect(generated).not.toMatch(/z\.enum\(\[1/);
    // The self-referential component must be deferred.
    expect(generated).toContain('z.lazy(');

    const built = spawnSync('bun', ['build', '--target', 'node', '--external', 'zod', join(cwd, 'hostile-schemas.ts'), '--outfile', join(cwd, 'hostile-build.js')], {
      cwd,
      encoding: 'utf8',
      env: { ...process.env, NO_COLOR: '1' },
      timeout: 20_000,
    });
    expect(built.status, `${built.stdout}\n${built.stderr}\n---\n${generated}`).toBe(0);
  }, 30_000);

  it('disposes the module when resolution itself fails', () => {
    // `manifest` is a lazy getter, so a config the manifest builder rejects
    // throws after the module is loaded but before the command runs.
    writeFileSync(join(cwd, 'late-failure-module.ts'), `
      export const config = {
        database: undefined,
        jwt: { key: 'late-failure-secret-at-least-32-chars' },
        csrf: { get skipPaths() { throw new Error('malformed csrf config'); } },
      };
      export async function dispose() { await Bun.write('late-failure.disposed', 'yes'); }
    `);

    const result = runCli(cwd, ['manifest', '--module', './late-failure-module.ts']);
    expect(result.status, String(result.stdout)).toBe(1);
    expect(result.stderr).toContain('malformed csrf config');
    expect(readFileSync(join(cwd, 'late-failure.disposed'), 'utf8')).toBe('yes');
  }, 30_000);

  it('generates Zod that actually enforces what the schema declares', async () => {
    // `properties` is built through JSON.parse so `__proto__` is a real own
    // property — a plain object literal would set the prototype instead, and
    // the key would vanish before the CLI ever saw it.
    writeFileSync(join(cwd, 'semantics-module.ts'), `
      const parse = (json) => JSON.parse(json);
      Object.defineProperties(Object.prototype, {
        nullable: { value: true, configurable: true },
        additionalProperties: { value: false, configurable: true },
      });
      export const config = {
        database: undefined,
        jwt: { key: 'semantics-secret-at-least-32-chars-ok' },
      };
      export const componentSchemas = {
        Proto: parse('{"type":"object","required":["__proto__"],"properties":{"__proto__":{"type":"string"}}}'),
        OptionalProto: { type: 'object', properties: parse('{"__proto__":{"type":"string"}}') },
        NestedOptionalProto: {
          type: 'object',
          required: ['child'],
          properties: { child: { type: 'object', properties: parse('{"__proto__":{"type":"string"}}') } },
        },
        ProtoAllOf: { allOf: [
          { type: 'object', properties: parse('{"__proto__":{"type":"string"}}') },
          { type: 'object', properties: {} },
        ] },
        ProtoAnyOf: { anyOf: [
          { type: 'object', properties: parse('{"__proto__":{"type":"string"}}') },
          { type: 'string' },
        ] },
        Overlapping: { oneOf: [{ type: 'number' }, { type: 'integer' }] },
        OverlappingObjects: { oneOf: [
          { type: 'object', required: ['a'], properties: { a: { type: 'string' } } },
          { type: 'object', required: ['b'], properties: { b: { type: 'number' } } },
        ] },
        Both: { allOf: [
          { type: 'object', required: ['a'], properties: { a: { type: 'string' } } },
          { type: 'object', required: ['b'], properties: { b: { type: 'number' } } },
        ] },
        EmptyProps: { type: 'object', properties: {} },
        EmptyPropsRef: { $ref: '#/components/schemas/EmptyProps' },
        AdditionalSchemaIdentity: { type: 'object', additionalProperties: { type: 'string' } },
        KnownWithNumericExtras: {
          type: 'object',
          required: ['known'],
          properties: { known: { type: 'string' } },
          additionalProperties: { type: 'number' },
        },
        InheritedNullable: { type: 'string' },
        InheritedStrictness: { type: 'object', properties: {} },
        Constant: { const: 'only-this' },
        ConstantObject: { const: { a: 1, nested: { ok: true } } },
        ConstantArray: { const: [1] },
        ConstantProto: parse('{"const":{"__proto__":"x"}}'),
        StructuredEnum: { enum: [{ a: 1 }, [1], 'primitive'] },
        ArrayIdentity: { type: 'array', items: { type: 'number' } },
        TupleIdentity: { type: 'array', items: [{ type: 'string' }, { type: 'number' }] },
        ArrayAllOfIdentity: { allOf: [
          { type: 'array', items: { type: 'number' } },
          { type: 'array', items: { type: 'integer' } },
        ] },
        ArrayAnyOfIdentity: { anyOf: [
          { type: 'array', items: { type: 'number' } },
          { type: 'string' },
        ] },
        IntegerArray: { type: 'array', items: { type: 'integer' } },
        IntegerArrayRefSibling: { $ref: '#/components/schemas/IntegerArray', items: { type: 'integer' } },
        KnownObject: { type: 'object', required: ['known'], properties: { known: { type: 'string' } } },
        KnownObjectRefSibling: { $ref: '#/components/schemas/KnownObject', required: ['known'] },
        BaseString: { type: 'string' },
        RefSibling: { $ref: '#/components/schemas/BaseString', minLength: 3 },
        TypelessRequired: { required: ['x'] },
        RefWithRequired: { $ref: '#/components/schemas/BaseString', required: ['x'] },
        TypelessItems: { items: { type: 'string' } },
        UnicodeBounds: { minLength: 2, maxLength: 2 },
        ExplicitUnicodeBounds: { type: 'string', minLength: 2, maxLength: 2 },
        ConstSibling: { const: 'x', minLength: 2 },
        EnumTypeSibling: { type: 'string', enum: ['ok', 1] },
        EnumLengthSibling: { enum: ['x'], minLength: 2 },
        RequiredUndeclared: { type: 'object', required: ['x'], properties: {} },
        Passthrough: { type: 'object', required: ['known'], properties: { known: { type: 'string' } } },
        EmptyPassthrough: { type: 'object', properties: {} },
        Bounded: { type: 'object', required: ['s', 'n'], properties: {
          s: { type: 'string', pattern: '^ab+c$', maxLength: 4 },
          n: { type: 'integer', minimum: 0, maximum: 0 },
        } },
        Strict: { type: 'object', required: ['a'], properties: { a: { type: 'string' } }, additionalProperties: false },
        Nullable: { type: 'string', nullable: true },
      };
      export async function dispose() {
        delete Object.prototype.nullable;
        delete Object.prototype.additionalProperties;
      }
    `);

    const result = runCli(cwd, ['schemas', '--format', 'zod', '--module', './semantics-module.ts', '--out', 'semantics.ts']);
    expect(result.status, String(result.stderr)).toBe(0);
    const schemas = await importGenerated(join(cwd, 'semantics.ts'));

    // A required `__proto__` must actually be required and must survive a
    // successful parse as an own property. Zod's normal object reconstruction
    // otherwise triggers the legacy prototype setter and drops the key.
    expect(schemas.ProtoSchema!.safeParse({}).success, 'required __proto__ was not enforced').toBe(false);
    const protoInput = JSON.parse('{"__proto__":"x"}');
    const protoResult = schemas.ProtoSchema!.safeParse(protoInput);
    expect(protoResult.success).toBe(true);
    expect(protoResult.data).toBe(protoInput);
    expect(Object.hasOwn(protoResult.data as object, '__proto__')).toBe(true);
    expect(Reflect.get(protoResult.data as object, '__proto__')).toBe('x');

    // Presence is based on own properties, never Object.prototype or a custom
    // prototype. Optional/nested/composed schemas preserve identity too.
    const inheritedProto = Object.create(JSON.parse('{"__proto__":"inherited"}')) as object;
    expect(Object.hasOwn(inheritedProto, '__proto__')).toBe(false);
    expect(schemas.ProtoSchema!.safeParse(inheritedProto).success, 'inherited __proto__ satisfied required').toBe(false);

    const optionalInput = {};
    const optionalResult = schemas.OptionalProtoSchema!.safeParse(optionalInput);
    expect(optionalResult).toEqual({ success: true, data: optionalInput });
    expect(optionalResult.data).toBe(optionalInput);
    const optionalOwnInput = JSON.parse('{"__proto__":"x"}');
    expect(schemas.OptionalProtoSchema!.safeParse(optionalOwnInput)).toEqual({ success: true, data: optionalOwnInput });
    expect(schemas.OptionalProtoSchema!.safeParse(JSON.parse('{"__proto__":1}')).success).toBe(false);

    const nestedInput = { child: {} };
    const nestedResult = schemas.NestedOptionalProtoSchema!.safeParse(nestedInput);
    expect(nestedResult).toEqual({ success: true, data: nestedInput });
    expect(nestedResult.data).toBe(nestedInput);
    const composedInput = {};
    const allOfResult = schemas.ProtoAllOfSchema!.safeParse(composedInput);
    const anyOfResult = schemas.ProtoAnyOfSchema!.safeParse(composedInput);
    expect(allOfResult).toEqual({ success: true, data: composedInput });
    expect(anyOfResult).toEqual({ success: true, data: composedInput });
    expect(allOfResult.data).toBe(composedInput);
    expect(anyOfResult.data).toBe(composedInput);
    const composedOwnInput = JSON.parse('{"__proto__":"x"}');
    for (const name of ['ProtoAllOfSchema', 'ProtoAnyOfSchema'] as const) {
      const composedOwnResult = schemas[name]!.safeParse(composedOwnInput);
      expect(composedOwnResult.success).toBe(true);
      expect(composedOwnResult.data).toBe(composedOwnInput);
      expect(Object.hasOwn(composedOwnResult.data as object, '__proto__')).toBe(true);
    }

    // JSON Schema `oneOf` is exactly-one; 1 matches both number and integer.
    expect(schemas.OverlappingSchema!.safeParse(1).success, 'value matching two variants was accepted').toBe(false);
    expect(schemas.OverlappingSchema!.safeParse(1.5).success).toBe(true);
    // Exactness must be checked before Zod's first object branch strips `b`.
    expect(schemas.OverlappingObjectsSchema!.safeParse({ a: 'x', b: 1 }).success, 'raw input matching both object variants was accepted').toBe(false);
    expect(schemas.OverlappingObjectsSchema!.safeParse({ a: 'x' }).success).toBe(true);

    // `allOf` must require every member, not accept anything.
    expect(schemas.BothSchema!.safeParse({ a: 'x', b: 1 }).success).toBe(true);
    expect(schemas.BothSchema!.safeParse({ a: 'x' }).success, 'allOf accepted a partial value').toBe(false);
    expect(schemas.BothSchema!.safeParse('anything').success).toBe(false);

    expect(schemas.EmptyPropsSchema!.safeParse({}).success).toBe(true);
    for (const name of ['EmptyPropsSchema', 'EmptyPropsRefSchema', 'AdditionalSchemaIdentitySchema'] as const) {
      const identityInput = JSON.parse('{"__proto__":"x"}');
      const identityResult = schemas[name]!.safeParse(identityInput);
      expect(identityResult.success, `${name} rejected an allowed own __proto__`).toBe(true);
      expect(identityResult.data).toBe(identityInput);
      expect(Object.hasOwn(identityResult.data as object, '__proto__')).toBe(true);
    }
    expect(schemas.AdditionalSchemaIdentitySchema!.safeParse({ bad: 1 }).success).toBe(false);
    expect(schemas.AdditionalSchemaIdentitySchema!.safeParse(JSON.parse('{"__proto__":1}')).success, 'schema-valued additionalProperties skipped __proto__').toBe(false);
    const hiddenValidAdditional = {};
    Object.defineProperty(hiddenValidAdditional, '__proto__', { value: 'x', enumerable: false });
    const hiddenValidResult = schemas.AdditionalSchemaIdentitySchema!.safeParse(hiddenValidAdditional);
    expect(hiddenValidResult.success).toBe(true);
    expect(hiddenValidResult.data).toBe(hiddenValidAdditional);
    const hiddenInvalidAdditional = {};
    Object.defineProperty(hiddenInvalidAdditional, '__proto__', { value: 1, enumerable: false });
    expect(schemas.AdditionalSchemaIdentitySchema!.safeParse(hiddenInvalidAdditional).success, 'schema-valued additionalProperties skipped non-enumerable __proto__').toBe(false);
    const hiddenInvalidOrdinary = {};
    Object.defineProperty(hiddenInvalidOrdinary, 'extra', { value: 1, enumerable: false });
    expect(schemas.AdditionalSchemaIdentitySchema!.safeParse(hiddenInvalidOrdinary).success, 'schema-valued additionalProperties skipped a non-enumerable key').toBe(false);

    const numericExtrasInput = { known: 'x', extra: 1 };
    const numericExtrasResult = schemas.KnownWithNumericExtrasSchema!.safeParse(numericExtrasInput);
    expect(numericExtrasResult.success).toBe(true);
    expect(numericExtrasResult.data).toBe(numericExtrasInput);
    expect(schemas.KnownWithNumericExtrasSchema!.safeParse({ known: 'x', extra: 'wrong' }).success).toBe(false);

    // Only own schema keywords apply; custom/polluted prototypes cannot add
    // nullable, additionalProperties, or other assertions.
    expect(schemas.InheritedNullableSchema!.safeParse('x').success).toBe(true);
    expect(schemas.InheritedNullableSchema!.safeParse(null).success, 'inherited nullable weakened the schema').toBe(false);
    expect(schemas.InheritedStrictnessSchema!.safeParse({ extra: 1 }).success, 'inherited additionalProperties was applied').toBe(true);

    expect(schemas.ConstantSchema!.safeParse('only-this').success).toBe(true);
    expect(schemas.ConstantSchema!.safeParse('other').success, 'const was dropped').toBe(false);

    const constantObjectInput = { a: 1, nested: { ok: true } };
    const constantObjectResult = schemas.ConstantObjectSchema!.safeParse(constantObjectInput);
    expect(constantObjectResult.success).toBe(true);
    expect(constantObjectResult.data).toBe(constantObjectInput);
    expect(schemas.ConstantObjectSchema!.safeParse({ a: 1, nested: { ok: false } }).success).toBe(false);
    const constantArrayInput = [1];
    const constantArrayResult = schemas.ConstantArraySchema!.safeParse(constantArrayInput);
    expect(constantArrayResult.success).toBe(true);
    expect(constantArrayResult.data).toBe(constantArrayInput);
    expect(schemas.ConstantArraySchema!.safeParse(1).success, 'array const incorrectly matched a scalar').toBe(false);
    expect(schemas.ConstantArraySchema!.safeParse([2]).success).toBe(false);
    const constantProtoInput = JSON.parse('{"__proto__":"x"}');
    const constantProtoResult = schemas.ConstantProtoSchema!.safeParse(constantProtoInput);
    expect(constantProtoResult.success).toBe(true);
    expect(constantProtoResult.data).toBe(constantProtoInput);
    expect(Object.hasOwn(constantProtoResult.data as object, '__proto__')).toBe(true);
    expect(schemas.StructuredEnumSchema!.safeParse({ a: 1 }).success).toBe(true);
    expect(schemas.StructuredEnumSchema!.safeParse([1]).success).toBe(true);
    expect(schemas.StructuredEnumSchema!.safeParse({ a: 2 }).success).toBe(false);
    expect(schemas.StructuredEnumSchema!.safeParse(1).success).toBe(false);

    // Array and tuple validation, including composition, must not clone output.
    for (const [name, input] of [
      ['ArrayIdentitySchema', [1, 2]],
      ['TupleIdentitySchema', ['x', 1]],
      ['ArrayAllOfIdentitySchema', [1, 2]],
      ['ArrayAnyOfIdentitySchema', [1, 2]],
      ['IntegerArrayRefSiblingSchema', [1, 2]],
    ] as const) {
      const arrayResult = schemas[name]!.safeParse(input);
      expect(arrayResult.success, `${name} rejected a valid array`).toBe(true);
      expect(arrayResult.data).toBe(input);
    }

    // `$ref`, `const`, and `enum` assertions combine with every sibling.
    expect(schemas.RefSiblingSchema!.safeParse('abc').success).toBe(true);
    expect(schemas.RefSiblingSchema!.safeParse('x').success, '$ref discarded minLength').toBe(false);

    // Typeless assertion keywords constrain only instances of their type.
    expect(schemas.TypelessRequiredSchema!.safeParse('not-an-object').success).toBe(true);
    expect(schemas.TypelessRequiredSchema!.safeParse({}).success).toBe(false);
    expect(schemas.TypelessRequiredSchema!.safeParse({ x: 1 }).success).toBe(true);
    expect(schemas.RefWithRequiredSchema!.safeParse('text').success, 'typeless required incorrectly rejected a referenced string').toBe(true);
    expect(schemas.TypelessItemsSchema!.safeParse('not-an-array').success).toBe(true);
    expect(schemas.TypelessItemsSchema!.safeParse(['ok']).success).toBe(true);
    expect(schemas.TypelessItemsSchema!.safeParse([1]).success, 'typeless items ignored an invalid array element').toBe(false);

    // JSON Schema string lengths count Unicode code points, not UTF-16 units.
    for (const name of ['UnicodeBoundsSchema', 'ExplicitUnicodeBoundsSchema'] as const) {
      expect(schemas[name]!.safeParse('😀').success, `${name} counted one code point as two`).toBe(false);
      expect(schemas[name]!.safeParse('😀a').success).toBe(true);
      expect(schemas[name]!.safeParse('😀ab').success).toBe(false);
    }
    expect(schemas.UnicodeBoundsSchema!.safeParse(1).success).toBe(true);

    expect(schemas.ConstSiblingSchema!.safeParse('x').success, 'const discarded minLength').toBe(false);
    expect(schemas.EnumTypeSiblingSchema!.safeParse('ok').success).toBe(true);
    expect(schemas.EnumTypeSiblingSchema!.safeParse(1).success, 'enum discarded type').toBe(false);
    expect(schemas.EnumLengthSiblingSchema!.safeParse('x').success, 'enum discarded minLength').toBe(false);
    expect(schemas.RequiredUndeclaredSchema!.safeParse({}).success, 'required key absent from properties was ignored').toBe(false);
    expect(schemas.RequiredUndeclaredSchema!.safeParse({ x: 1 }).success).toBe(true);

    // Allowed additional properties survive parsing, not merely validation.
    const passthroughInput = { known: 'x', extra: 1 };
    const passthroughResult = schemas.PassthroughSchema!.safeParse(passthroughInput);
    expect(passthroughResult).toEqual({ success: true, data: passthroughInput });
    expect(passthroughResult.data).toBe(passthroughInput);
    const emptyPassthroughInput = { extra: 1 };
    const emptyPassthroughResult = schemas.EmptyPassthroughSchema!.safeParse(emptyPassthroughInput);
    expect(emptyPassthroughResult).toEqual({
      success: true,
      data: emptyPassthroughInput,
    });
    expect(emptyPassthroughResult.data).toBe(emptyPassthroughInput);

    // Bounds of 0 are falsy and used to be skipped entirely.
    expect(schemas.BoundedSchema!.safeParse({ s: 'abc', n: 0 }).success).toBe(true);
    expect(schemas.BoundedSchema!.safeParse({ s: 'xyz', n: 0 }).success, 'pattern was dropped').toBe(false);
    expect(schemas.BoundedSchema!.safeParse({ s: 'abbbbc', n: 0 }).success, 'maxLength was dropped').toBe(false);
    expect(schemas.BoundedSchema!.safeParse({ s: 'abc', n: 1 }).success, 'maximum: 0 was dropped').toBe(false);

    expect(schemas.StrictSchema!.safeParse({ a: 'x' }).success).toBe(true);
    expect(schemas.StrictSchema!.safeParse({ a: 'x', extra: 1 }).success, 'additionalProperties:false was dropped').toBe(false);
    expect(schemas.StrictSchema!.safeParse(JSON.parse('{"a":"x","__proto__":"bypass"}')).success, 'additionalProperties:false skipped __proto__').toBe(false);
    const hiddenStrictProto = { a: 'x' };
    Object.defineProperty(hiddenStrictProto, '__proto__', { value: 'bypass', enumerable: false });
    expect(schemas.StrictSchema!.safeParse(hiddenStrictProto).success, 'additionalProperties:false skipped non-enumerable __proto__').toBe(false);
    const hiddenStrictOrdinary = { a: 'x' };
    Object.defineProperty(hiddenStrictOrdinary, 'extra', { value: 'bypass', enumerable: false });
    expect(schemas.StrictSchema!.safeParse(hiddenStrictOrdinary).success, 'additionalProperties:false skipped a non-enumerable key').toBe(false);

    expect(schemas.NullableSchema!.safeParse(null).success).toBe(true);
    expect(schemas.NullableSchema!.safeParse('x').success).toBe(true);
    expect(schemas.NullableSchema!.safeParse(1).success).toBe(false);

    // Identity-preserving wrappers must retain the wrapped schema's output
    // type; unused @ts-expect-error directives catch a regression to `any`.
    const projectNodeModules = fileURLToPath(new URL('../node_modules', import.meta.url));
    if (!existsSync(join(cwd, 'node_modules')))
      symlinkSync(projectNodeModules, join(cwd, 'node_modules'), 'dir');
    writeFileSync(join(cwd, 'semantics-inference.ts'), `
      import { z } from 'zod';
      import { ArrayIdentitySchema, ConstantObjectSchema, IntegerArrayRefSiblingSchema, KnownObjectRefSiblingSchema, KnownWithNumericExtrasSchema, PassthroughSchema } from './semantics';

      type ObjectOutput = z.infer<typeof PassthroughSchema>;
      const goodObject: ObjectOutput = { known: 'x', extra: 1 };
      // @ts-expect-error known remains a required string, not any
      const badObject: ObjectOutput = { known: 1 };

      type ArrayOutput = z.infer<typeof ArrayIdentitySchema>;
      const goodArray: ArrayOutput = [1, 2];
      // @ts-expect-error array items remain numbers, not any
      const badArray: ArrayOutput = ['x'];

      type RefSiblingOutput = z.infer<typeof IntegerArrayRefSiblingSchema>;
      type IsAny<T> = 0 extends (1 & T) ? true : false;
      const refSiblingIsTyped: IsAny<RefSiblingOutput> = false;
      const goodRefSibling: RefSiblingOutput = [1, 2];
      // @ts-expect-error an untyped items sibling must not erase the referenced item type
      const badRefSibling: RefSiblingOutput = ['x'];

      type NumericExtrasOutput = z.infer<typeof KnownWithNumericExtrasSchema>;
      const goodNumericExtras: NumericExtrasOutput = { known: 'x', extra: 1 };
      declare const parsedNumericExtras: NumericExtrasOutput;
      const safeExtra: unknown = parsedNumericExtras.extra;
      // @ts-expect-error manually validated extras remain unknown, never falsely number-typed
      const unsafeExtra: number = parsedNumericExtras.extra;
      // @ts-expect-error declared fields retain their own types
      const badKnownWithExtras: NumericExtrasOutput = { known: 1, extra: 2 };

      type ObjectRefSiblingOutput = z.infer<typeof KnownObjectRefSiblingSchema>;
      const objectRefSiblingIsTyped: IsAny<ObjectRefSiblingOutput> = false;
      const goodObjectRefSibling: ObjectRefSiblingOutput = { known: 'x' };
      // @ts-expect-error a required sibling must not erase the referenced property type
      const badObjectRefSibling: ObjectRefSiblingOutput = { known: 1 };

      type ConstOutput = z.infer<typeof ConstantObjectSchema>;
      const goodConst: ConstOutput = { a: 1, nested: { ok: true } };
      // @ts-expect-error structured const retains its literal output type
      const badConst: ConstOutput = { a: 2, nested: { ok: true } };
      void [goodObject, badObject, goodArray, badArray, refSiblingIsTyped, goodRefSibling, badRefSibling, goodNumericExtras, safeExtra, unsafeExtra, badKnownWithExtras, objectRefSiblingIsTyped, goodObjectRefSibling, badObjectRefSibling, goodConst, badConst];
    `);
    const inferred = spawnSync(join(projectNodeModules, '.bin', 'tsc'), [
      '--noEmit',
      '--strict',
      '--skipLibCheck',
      '--moduleResolution',
      'Bundler',
      '--module',
      'ESNext',
      '--target',
      'ES2022',
      'semantics-inference.ts',
    ], { cwd, encoding: 'utf8', timeout: 20_000 });
    expect(inferred.status, `${inferred.stdout}\n${inferred.stderr}`).toBe(0);
  }, 30_000);

  it('conforms to the public JSONSchema assertion subset, including typeless and sibling behavior', async () => {
    writeFileSync(join(cwd, 'conformance-module.ts'), `
      export const config = {
        database: undefined,
        jwt: { key: 'conformance-secret-at-least-32-chars' },
      };
      export const componentSchemas = {
        Anything: {},
        BaseString: { type: 'string' },
        TypeString: { type: 'string' },
        PropertiesOnly: { properties: { x: { type: 'string' } } },
        RequiredOnly: { required: ['x'] },
        AdditionalFalseOnly: { additionalProperties: false },
        AdditionalSchemaOnly: { additionalProperties: { type: 'string' } },
        ItemsOnly: { items: { type: 'string' } },
        EnumOnly: { enum: ['x', 1] },
        ConstOnly: { const: 'x' },
        MinimumOnly: { minimum: 1 },
        MaximumOnly: { maximum: 1 },
        PatternOnly: { pattern: '^x+$' },
        UnicodeLengthOnly: { minLength: 2, maxLength: 2 },
        AnyOfOnly: { anyOf: [{ type: 'string' }, { type: 'number' }] },
        OneOfOnly: { oneOf: [{ type: 'number' }, { type: 'integer' }] },
        AllOfOnly: { allOf: [{ minimum: 0 }, { maximum: 1 }] },
        NullableString: { type: 'string', nullable: true },
        RefRequired: { $ref: '#/components/schemas/BaseString', required: ['x'] },
        RefItems: { $ref: '#/components/schemas/Anything', items: { type: 'string' } },
        CompositionItems: { anyOf: [{}], items: { type: 'string' } },
        ObjectAndArrayKeywords: { required: ['x'], items: { type: 'string' } },
        EnumTypeSibling: { enum: ['x', 1], type: 'string' },
        ConstBoundSibling: { const: 'x', minLength: 2 },
        RefBoundSibling: { $ref: '#/components/schemas/BaseString', minLength: 2 },
      };
    `);

    const result = runCli(cwd, ['schemas', '--format', 'zod', '--module', './conformance-module.ts', '--out', 'conformance.ts']);
    expect(result.status, String(result.stderr)).toBe(0);
    const schemas = await importGenerated(join(cwd, 'conformance.ts'));

    const cases: Array<{
      schema: string;
      valid: unknown[];
      invalid: unknown[];
    }> = [
      { schema: 'TypeStringSchema', valid: ['x'], invalid: [1, null, {}] },
      { schema: 'PropertiesOnlySchema', valid: ['primitive', 1, null, [], {}, { x: 'ok' }], invalid: [{ x: 1 }] },
      { schema: 'RequiredOnlySchema', valid: ['primitive', 1, null, [], { x: 1 }], invalid: [{}] },
      { schema: 'AdditionalFalseOnlySchema', valid: ['primitive', 1, null, [], {}], invalid: [{ x: 1 }] },
      { schema: 'AdditionalSchemaOnlySchema', valid: ['primitive', 1, null, [], {}, { x: 'ok' }], invalid: [{ x: 1 }] },
      { schema: 'ItemsOnlySchema', valid: ['primitive', 1, null, {}, [], ['ok']], invalid: [[1]] },
      { schema: 'EnumOnlySchema', valid: ['x', 1], invalid: ['y', 2, null] },
      { schema: 'ConstOnlySchema', valid: ['x'], invalid: ['y', 1] },
      { schema: 'MinimumOnlySchema', valid: ['ignored', 1, 2], invalid: [0] },
      { schema: 'MaximumOnlySchema', valid: ['ignored', 0, 1], invalid: [2] },
      { schema: 'PatternOnlySchema', valid: [1, 'x', 'xxx'], invalid: ['xy'] },
      { schema: 'UnicodeLengthOnlySchema', valid: [1, '😀a'], invalid: ['😀', '😀ab'] },
      { schema: 'AnyOfOnlySchema', valid: ['x', 1], invalid: [true, null] },
      { schema: 'OneOfOnlySchema', valid: [1.5], invalid: [1, 'x'] },
      { schema: 'AllOfOnlySchema', valid: ['ignored', 0, 1], invalid: [-1, 2] },
      { schema: 'NullableStringSchema', valid: ['x', null], invalid: [1] },
      { schema: 'RefRequiredSchema', valid: ['x'], invalid: [1, {}] },
      { schema: 'RefItemsSchema', valid: ['non-array', ['x']], invalid: [[1]] },
      { schema: 'CompositionItemsSchema', valid: ['non-array', ['x']], invalid: [[1]] },
      { schema: 'ObjectAndArrayKeywordsSchema', valid: ['primitive', { x: 1 }, ['x']], invalid: [{}, [1]] },
      { schema: 'EnumTypeSiblingSchema', valid: ['x'], invalid: [1] },
      { schema: 'ConstBoundSiblingSchema', valid: [], invalid: ['x', 'xx'] },
      { schema: 'RefBoundSiblingSchema', valid: ['xx'], invalid: ['x', 1] },
    ];

    for (const testCase of cases) {
      const schema = schemas[testCase.schema]!;
      for (const value of testCase.valid)
        expect(schema.safeParse(value).success, `${testCase.schema} rejected ${JSON.stringify(value)}`).toBe(true);
      for (const value of testCase.invalid)
        expect(schema.safeParse(value).success, `${testCase.schema} accepted ${JSON.stringify(value)}`).toBe(false);
    }
  }, 30_000);

  it('generates Zod for the core surface that parses real payloads', async () => {
    const result = runCli(cwd, ['schemas', '--format', 'zod', '--out', 'core-schemas.ts']);
    expect(result.status, String(result.stderr)).toBe(0);
    const schemas = await importGenerated(join(cwd, 'core-schemas.ts'));

    // AuthResult is core's only `oneOf`; its branches are discriminated by a
    // literal `status`, so exactly-one semantics must still accept each one.
    const user = { id: '1', email: 'a@b.c', name: 'A', isActive: true, emailVerified: true, createdAt: 'x', updatedAt: 'y' };
    expect(schemas.AuthResultSchema!.safeParse({
      status: 'success',
      user,
      method: 'password',
      accessToken: 't',
      refreshToken: 'r',
    }).success, 'exactly-one oneOf rejected a valid core AuthResult').toBe(true);
    expect(schemas.AuthResultSchema!.safeParse({
      status: 'impersonation',
      user,
      accessToken: 't',
      refreshToken: null,
    }).success).toBe(true);
    expect(schemas.AuthResultSchema!.safeParse({ status: 'nope' }).success).toBe(false);
  }, 30_000);

  it('refuses to generate a weaker validator than the schema declares', () => {
    const cases = [
      { name: 'unsupported-type', schema: `{ type: 'geo-point' }`, message: `unsupported JSON Schema type 'geo-point'` },
      { name: 'type-array', schema: `{ type: ['string', 'null'] }`, message: `type arrays are not supported` },
      { name: 'empty-oneof', schema: `{ oneOf: [] }`, message: `'oneOf' is empty` },
      { name: 'empty-allof', schema: `{ allOf: [] }`, message: `'allOf' is empty` },
      { name: 'bad-minlength', schema: `{ type: 'string', minLength: '3' }`, message: `must be a finite number` },
      { name: 'self-cycle', schema: `(() => { const s = { type: 'object', properties: {} }; s.properties.self = s; return s; })()`, message: 'reference cycle' },
      { name: 'foreign-ref', schema: `{ $ref: '#/components/parameters/Thing' }`, message: `only '#/components/schemas/<name>' refs are supported` },
      { name: 'empty-ref', schema: `{ $ref: '' }`, message: 'empty reference' },
    ];

    for (const testCase of cases) {
      writeFileSync(join(cwd, `weak-${testCase.name}.ts`), `
        export const config = { database: undefined, jwt: { key: 'weak-secret-at-least-32-chars-long-ok' } };
        export const componentSchemas = { Thing: ${testCase.schema} };
      `);
      const result = runCli(cwd, ['schemas', '--format', 'zod', '--module', `./weak-${testCase.name}.ts`]);
      const diagnostic = `${result.stdout}\n${result.stderr}`;
      expect(result.status, `${testCase.name}: ${diagnostic}`).toBe(1);
      expect(diagnostic, testCase.name).toContain(testCase.message);
      expect(diagnostic, testCase.name).not.toMatch(RUNTIME_ERROR_RE);
    }
  }, 30_000);

  it('rejects component names OpenAPI forbids and refs that cannot resolve', () => {
    const cases = [
      { name: 'space', schemas: `{ 'Bad Name': { type: 'string' } }`, message: `Invalid OpenAPI component name 'Bad Name'` },
      { name: 'slash', schemas: `{ 'a/b': { type: 'string' } }`, message: `Invalid OpenAPI component name 'a/b'` },
      { name: 'empty', schemas: `{ '': { type: 'string' } }`, message: `Invalid OpenAPI component name ''` },
      { name: 'tilde', schemas: `{ '~weird': { type: 'string' } }`, message: `Invalid OpenAPI component name '~weird'` },
    ];
    for (const testCase of cases) {
      writeFileSync(join(cwd, `badname-${testCase.name}.ts`), `
        export const config = { database: undefined, jwt: { key: 'badname-secret-at-least-32-chars-ok' } };
        export const componentSchemas = ${testCase.schemas};
      `);
      for (const command of [['openapi'], ['schemas', '--format', 'json-schema']]) {
        const result = runCli(cwd, [...command, '--module', `./badname-${testCase.name}.ts`]);
        const diagnostic = `${result.stdout}\n${result.stderr}`;
        expect(result.status, `${testCase.name} ${command[0]}: ${diagnostic}`).toBe(1);
        expect(diagnostic, testCase.name).toContain(testCase.message);
      }
    }

    // A percent-encoded ref denotes the decoded name, so this resolves.
    writeFileSync(join(cwd, 'encoded-ref.ts'), `
      export const config = {
        database: undefined,
        jwt: { key: 'encoded-secret-at-least-32-chars-long' },
        routes: { e: { method: 'POST', path: '/e', handler: 'e',
          meta: { summary: 'e', permission: { resource: 'x', action: 'y' } },
          input: { body: { $ref: '#/components/schemas/Foo%2DBar' } },
          responses: { 200: { description: 'ok' } } } },
      };
      export const componentSchemas = { 'Foo-Bar': { type: 'object', properties: { a: { type: 'string' } } } };
    `);
    const encoded = runCli(cwd, ['openapi', '--module', './encoded-ref.ts', '--out', 'encoded.json']);
    expect(encoded.status, String(encoded.stderr)).toBe(0);

    // A decoded '/' inside one JSON Pointer token must not become a new path
    // segment when the resolver traverses the document.
    writeFileSync(join(cwd, 'escaped-token-ref.ts'), `
      export const config = {
        database: undefined,
        jwt: { key: 'escaped-token-secret-at-least-32-chars' },
        routes: { e: { method: 'POST', path: '/escaped', handler: 'e',
          meta: { summary: 'e', permission: { resource: 'x', action: 'y' } },
          input: { body: { $ref: '#/components/schemas/Thing/properties/a~1b' } },
          responses: { 200: { description: 'ok' } } } },
      };
      export const componentSchemas = {
        Thing: { type: 'object', properties: { 'a/b': { type: 'string' } } },
      };
    `);
    const escapedToken = runCli(cwd, ['openapi', '--module', './escaped-token-ref.ts', '--out', 'escaped-token.json']);
    expect(escapedToken.status, String(escapedToken.stderr)).toBe(0);

    // Invalid RFC 6901 escapes must fail even when treating them literally
    // would happen to resolve to an existing property.
    for (const [name, token] of [['invalid-tilde', 'a~2'], ['trailing-tilde', 'a~']] as const) {
      writeFileSync(join(cwd, `${name}-ref.ts`), `
        export const config = {
          database: undefined,
          jwt: { key: 'malformed-local-ref-secret-at-least-32-chars' },
          routes: { e: { method: 'POST', path: '/malformed', handler: 'e',
            meta: { summary: 'e', permission: { resource: 'x', action: 'y' } },
            input: { body: { $ref: '#/components/schemas/Thing/properties/${token}' } },
            responses: { 200: { description: 'ok' } } } },
        };
        export const componentSchemas = {
          Thing: { type: 'object', properties: { ${JSON.stringify(token)}: { type: 'string' } } },
        };
      `);
      const malformed = runCli(cwd, ['openapi', '--module', `./${name}-ref.ts`]);
      expect(malformed.status, String(malformed.stdout)).toBe(1);
      expect(malformed.stderr).toContain('Invalid $ref');
      expect(malformed.stderr).toContain('invalid JSON Pointer escape');
    }

    // Malformed external URI-references are not deferred to consumers.
    writeFileSync(join(cwd, 'malformed-external-ref.ts'), `
      export const config = {
        database: undefined,
        jwt: { key: 'malformed-external-ref-secret-at-least-32-chars' },
        routes: { e: { method: 'POST', path: '/external', handler: 'e',
          meta: { summary: 'e', permission: { resource: 'x', action: 'y' } },
          input: { body: { $ref: 'other schema.json#/Thing' } },
          responses: { 200: { description: 'ok' } } } },
      };
    `);
    const malformedExternal = runCli(cwd, ['openapi', '--module', './malformed-external-ref.ts']);
    expect(malformedExternal.status, String(malformedExternal.stdout)).toBe(1);
    expect(malformedExternal.stderr).toContain('Invalid $ref');
    expect(malformedExternal.stderr).toContain('characters not permitted in a URI-reference');

    // A local pointer into a bucket the document does not define must fail.
    writeFileSync(join(cwd, 'other-local-ref.ts'), `
      export const config = {
        database: undefined,
        jwt: { key: 'otherlocal-secret-at-least-32-chars-ok' },
        routes: { o: { method: 'POST', path: '/o', handler: 'o',
          meta: { summary: 'o', permission: { resource: 'x', action: 'y' } },
          input: { body: { $ref: '#/components/parameters/Missing' } },
          responses: { 200: { description: 'ok' } } } },
      };
    `);
    const otherLocal = runCli(cwd, ['openapi', '--module', './other-local-ref.ts']);
    expect(otherLocal.status, String(otherLocal.stdout)).toBe(1);
    expect(otherLocal.stderr).toContain('unresolvable $ref');

    // A malformed non-string $ref must not be masked by a later, legal ref that
    // stringifies to the same value. `$ref: null` and `$ref: 'null'` both
    // stringify to "null"; collecting refs into a map keyed by that string let
    // the legal external ref overwrite — and hide — the malformed one, so the
    // spec shipped with an invalid reference and the command still exited 0.
    writeFileSync(join(cwd, 'masked-ref.ts'), `
      export const config = {
        database: undefined,
        jwt: { key: 'masked-ref-secret-at-least-32-chars-ok' },
      };
      export const componentSchemas = {
        Masked: { type: 'object', properties: { bad: { $ref: null } } },
        Legit: { type: 'object', properties: { ok: { $ref: 'null' } } },
      };
    `);
    const masked = runCli(cwd, ['openapi', '--module', './masked-ref.ts']);
    expect(masked.status, String(masked.stdout)).toBe(1);
    expect(masked.stderr).toContain('Invalid $ref');
    expect(`${masked.stdout}\n${masked.stderr}`).not.toMatch(RUNTIME_ERROR_RE);
  }, 30_000);

  it('refuses to emit an OpenAPI document with duplicate operation IDs', () => {
    writeAppModule(cwd, 'opid-module.ts', { collide: true });

    const result = runCli(cwd, ['openapi', '--module', './opid-module.ts', '--operation-id', 'handler']);
    expect(result.status, String(result.stdout)).toBe(1);
    expect(result.stderr).toContain(`Duplicate operationId 'createReport'`);
    expect(result.stderr).toContain('POST /reports');
    expect(result.stderr).toContain('POST /exports');
    expect(`${result.stdout}\n${result.stderr}`).not.toMatch(RUNTIME_ERROR_RE);

    // The default methodPath strategy stays collision-free.
    const fallback = runCli(cwd, ['openapi', '--module', './opid-module.ts', '--out', 'opid-openapi.json']);
    expect(fallback.status, String(fallback.stderr)).toBe(0);
  }, 30_000);

  it('covers plugin and host-owned routes when given an application module', () => {
    writeAppModule(cwd, 'app-module.ts', { leak: false });

    const manifest = runCli(cwd, ['manifest', '--module', './app-module.ts', '--out', 'app-manifest.json']);
    expect(manifest.status, String(manifest.stderr)).toBe(0);
    expect(manifest.stdout).toContain(APP_SCOPE);
    const entries = JSON.parse(readFileSync(join(cwd, 'app-manifest.json'), 'utf8')) as Array<{
      method: string;
      path: string;
      plugin: string | null;
      classification: string;
      mounted: boolean;
    }>;
    const pluginRoute = entries.find(entry => entry.path === '/reports');
    expect(pluginRoute).toMatchObject({ method: 'POST', plugin: 'reports', classification: 'rbac', mounted: true });
    // Top-level `routes` are host-owned: tracked in the manifest, left unmounted.
    const hostRoute = entries.find(entry => entry.path === '/host/stats');
    expect(hostRoute).toMatchObject({ method: 'GET', plugin: null, classification: 'rbac', mounted: false });

    const openapi = runCli(cwd, ['openapi', '--module', './app-module.ts', '--out', 'app-openapi.json']);
    expect(openapi.status, String(openapi.stderr)).toBe(0);
    const spec = JSON.parse(readFileSync(join(cwd, 'app-openapi.json'), 'utf8')) as {
      paths: Record<string, Record<string, { operationId?: string }>>;
      components: { schemas: Record<string, unknown> };
    };
    expect(Object.keys(spec.paths)).toEqual(expect.arrayContaining(['/reports', '/host/stats']));
    // Core `$ref`s must still resolve — the CLI never emits a bare component-less spec.
    expect(Object.keys(spec.components.schemas).length).toBeGreaterThan(0);
    expect(spec.paths['/reports']?.post?.operationId).toBe('post_reports');

    const handlerIds = runCli(cwd, ['openapi', '--module', './app-module.ts', '--operation-id', 'handler', '--out', 'handler-openapi.json']);
    expect(handlerIds.status, String(handlerIds.stderr)).toBe(0);
    const handlerSpec = JSON.parse(readFileSync(join(cwd, 'handler-openapi.json'), 'utf8')) as {
      paths: Record<string, Record<string, { operationId?: string }>>;
    };
    expect(handlerSpec.paths['/reports']?.post?.operationId).toBe('createReport');

    const schemas = runCli(cwd, ['schemas', '--format', 'zod', '--module', './app-module.ts', '--out', 'app-schemas.ts']);
    expect(schemas.status, String(schemas.stderr)).toBe(0);
    expect(readFileSync(join(cwd, 'app-schemas.ts'), 'utf8')).toContain('CreateReportBodySchema');

    for (const command of ['manifest:check', 'check:routes', 'check:public-routes']) {
      const result = runCli(cwd, [command, '--module', './app-module.ts']);
      expect(result.status, `${command}: ${result.stderr}`).toBe(0);
      expect(result.stdout, command).toContain(APP_SCOPE);
    }

    expect(readFileSync(join(cwd, 'app-module.ts.disposed'), 'utf8')).toBe('yes');
  }, 30_000);

  it('fails the public-route check on an unreviewed application route', () => {
    writeAppModule(cwd, 'leaky-module.ts', { leak: true });

    const result = runCli(cwd, ['check:public-routes', '--module', './leaky-module.ts']);
    expect(result.status, String(result.stdout)).toBe(1);
    expect(result.stderr).toContain('Public-route check failed:');
    expect(result.stderr).toContain('GET /reports/leak');
    expect(result.stderr).toContain('plugin=reports');
    // A top-level route is host-owned, not core; the manifest records its
    // origin as null and the diagnostic must not call that "core".
    expect(result.stderr).toContain('GET /host/stats');
    expect(result.stderr).toContain('plugin=host');
    expect(`${result.stdout}\n${result.stderr}`).not.toMatch(RUNTIME_ERROR_RE);
    // The failure path must still dispose the loaded module.
    expect(readFileSync(join(cwd, 'leaky-module.ts.disposed'), 'utf8')).toBe('yes');

    const allowed = runCli(cwd, [
      'check:public-routes',
      '--module',
      './leaky-module.ts',
      '--allow',
      'GET /reports/leak',
      '--allow',
      'GET /host/stats',
    ]);
    expect(allowed.status, String(allowed.stderr)).toBe(0);
  }, 30_000);

  it('labels no-module route output as core-only and keeps stdout pipeable', () => {
    for (const args of [['manifest:check'], ['check:routes'], ['check:public-routes']]) {
      const result = runCli(cwd, args);
      expect(result.status, String(result.stderr)).toBe(0);
      expect(result.stdout, args[0]).toContain(CORE_ONLY_SCOPE);
    }

    // With no --out the payload owns stdout, so the scope note goes to stderr.
    for (const args of [['manifest'], ['openapi'], ['schemas']]) {
      const result = runCli(cwd, args);
      expect(result.status, String(result.stderr)).toBe(0);
      expect(result.stderr, args[0]).toContain(CORE_ONLY_SCOPE);
      expect(result.stdout, args[0]).not.toContain(CORE_ONLY_SCOPE);
    }
    expect(() => JSON.parse(String(runCli(cwd, ['manifest']).stdout))).not.toThrow();
  }, 30_000);

  it('scaffolds a config module the route commands can read as-is', () => {
    const scaffoldDir = mkdtempSync(join(tmpdir(), 'fortress-init-'));
    try {
      expect(runCli(scaffoldDir, ['init']).status).toBe(0);
      const scaffold = readFileSync(join(scaffoldDir, 'fortress.config.ts'), 'utf8');
      expect(scaffold).toContain('export const config: FortressConfig');
      // Importing the scaffold must not construct the app: the route commands
      // read `config`, and constructing is what starts plugin workers.
      expect(scaffold).not.toMatch(/^\s*(?:export const \w+ = )?createFortress\(/m);

      // The scaffold ships `database: undefined!` and an unset JWT secret, yet
      // the route commands still work, because they never build the instance.
      const result = runCli(scaffoldDir, ['manifest', '--module', './fortress.config.ts', '--out', 'scaffold-manifest.json']);
      expect(result.status, String(result.stderr)).toBe(0);
      expect(result.stdout).toContain('via config');
      expect(`${result.stdout}\n${result.stderr}`).not.toMatch(RUNTIME_ERROR_RE);
      const entries = JSON.parse(readFileSync(join(scaffoldDir, 'scaffold-manifest.json'), 'utf8')) as unknown[];
      expect(entries.length).toBeGreaterThan(0);

      const check = runCli(scaffoldDir, ['check:public-routes', '--module', './fortress.config.ts']);
      expect(check.status, String(check.stderr)).toBe(0);
    }
    finally {
      rmSync(scaffoldDir, { recursive: true, force: true });
    }
  }, 30_000);

  it('rejects malformed route-command invocations instead of silently passing', () => {
    writeFileSync(join(cwd, 'no-instance-module.ts'), 'export const notFortress = {};');
    writeFileSync(join(cwd, 'bad-instance-module.ts'), 'export const fortress = { endpoints: [] };');
    writeFileSync(join(cwd, 'route-must-not-import.ts'), `
      await Bun.write('route-typo-imported.txt', 'yes');
      export const fortress = { endpoints: [], manifest: [], config: {} };
    `);
    // Route commands and migrate:up must agree on the export contract, so a
    // default-only export is rejected by both rather than one of them.
    writeAppModule(cwd, 'default-only-module.ts', { shape: 'default' });

    const cases = [
      // A mistyped flag used to be ignored, reporting a core-only pass with exit 0.
      { args: ['check:public-routes', '--modul', './app-module.ts'], message: `Unknown argument '--modul'` },
      { args: ['manifest:check', '--module'], message: '--module requires a value' },
      { args: ['manifest', '--module', '-x'], message: '--module requires a value' },
      { args: ['manifest', '--module', './missing-module.ts'], message: 'Cannot find module' },
      { args: ['manifest', '--module', './no-instance-module.ts'], message: `named export 'config'` },
      { args: ['manifest', '--module', './bad-instance-module.ts'], message: `is not a configured Fortress instance` },
      { args: ['manifest', '--module', './default-only-module.ts'], message: `named export 'config'` },
      { args: ['migrate:up', '--module', './default-only-module.ts'], message: `named export 'fortress'` },
      { args: ['openapi', '--module', './route-must-not-import.ts', '--operation-id', 'bogus'], message: 'Unknown operation-id style' },
      { args: ['schemas', '--module', './route-must-not-import.ts', '--format', 'yaml'], message: 'Unknown format' },
      { args: ['manifest', '--module', './route-must-not-import.ts', '--module', './app-module.ts'], message: `Duplicate argument '--module'` },
      { args: ['manifest', '--module', './route-must-not-import.ts', 'trailing'], message: `Unknown argument 'trailing'` },
      { args: ['check:public-routes', '--title', 'x'], message: '--title cannot be used with check:public-routes' },
      { args: ['manifest:check', '--out', 'ignored.json'], message: '--out cannot be used with manifest:check' },
      { args: ['check:routes', '--out', 'ignored.json'], message: '--out cannot be used with check:routes' },
    ];

    for (const testCase of cases) {
      const result = runCli(cwd, testCase.args);
      const diagnostic = `${result.stdout}\n${result.stderr}`;
      expect(result.status, diagnostic).toBe(1);
      expect(diagnostic, testCase.args.join(' ')).toContain(testCase.message);
      expect(diagnostic, testCase.args.join(' ')).not.toMatch(RUNTIME_ERROR_RE);
    }
    // Argument validation must happen before the module is imported.
    expect(existsSync(join(cwd, 'route-typo-imported.txt'))).toBe(false);
  }, 30_000);

  it('exports deterministic review SQL with explicit data-step limitations', () => {
    const output = join(cwd, 'review.sql');
    const result = runCli(cwd, [
      'migrate:export',
      '--dialect',
      'sqlite',
      '--direction',
      'up',
      '--out',
      output,
    ]);
    expect(result.status, String(result.stderr)).toBe(0);
    expect(result.stderr).toContain('omits runtime data steps');
    const sql = readFileSync(output, 'utf8');
    expect(sql).toContain('-- runtime-data-step: normalize-email-v2');
    expect(sql).toContain('INSERT INTO fortress_email_migration_ready');

    for (const args of [
      ['migrate:export', '--direction', 'up'],
      ['migrate:export', '--dialect', 'sqlite'],
      ['migrate:export', '--dialect', 'sqlite', '--direction', 'sideways'],
      ['migrate:export', '--dialect', 'sqlite', '--direction', 'up', '--out', 'a.sql', '-o', 'b.sql'],
      ['migrate:export', '--dialect', 'sqlite', '--direction', 'up', 'trailing'],
    ]) {
      const invalid = runCli(cwd, args);
      expect(invalid.status, String(invalid.stderr)).toBe(1);
      expect(`${invalid.stdout}\n${invalid.stderr}`).not.toMatch(RUNTIME_ERROR_RE);
    }

    for (const args of [
      ['migrate:export', '--dialect', 'sqlite', '--direction', 'up', '--out'],
      ['migrate:export', '--dialect', 'sqlite', '--direction', 'up', '-o'],
      ['migrate:export', '--dialect', 'sqlite', '--direction', 'up', '--out', '-x'],
      ['migrate:status', '--out'],
      ['migrate:status', '-o'],
      ['migrate:down', '--out'],
      ['migrate:down', '-o'],
    ]) {
      const missingOut = runCli(cwd, args);
      expect(missingOut.status).toBe(1);
      expect(missingOut.stdout).toBe('');
      expect(missingOut.stderr).toMatch(/(?:--out|-o) requires a value/);
    }

    for (const args of [
      ['migrate:diff', 'trailing'],
      ['migrate:check', '--out', 'ignored.sql'],
      ['migrate:status', '--dialect', 'sqlite', '-x'],
    ]) {
      const invalid = runCli(cwd, args);
      expect(invalid.status).toBe(1);
      expect(`${invalid.stdout}\n${invalid.stderr}`).toContain('Error:');
    }
  });

  it('executes the runtime data step through a real file-backed SQLite module', async () => {
    const databasePath = join(cwd, 'live-migration.sqlite');
    const sqlite = new Database(databasePath);
    sqlite.pragma('foreign_keys = ON');
    const adapter = createSqliteDrizzleAdapter(drizzle(sqlite));
    await migrateUp(adapter, 5);
    const user = await adapter.create<{ id: number }>({
      model: 'user',
      data: { email: 'TE\u0301ST@Example.COM', name: 'Test' },
    });
    await adapter.create({
      model: 'login_identifier',
      data: { userId: user.id, type: 'email', value: 'TE\u0301ST@Example.COM' },
    });
    sqlite.close();

    const fortressUrl = new URL('./core/fortress.ts', import.meta.url).href;
    const adapterUrl = new URL('./drizzle/adapter.ts', import.meta.url).href;
    const drizzleUrl = import.meta.resolve('drizzle-orm/bun-sqlite');
    writeFileSync(join(cwd, 'sqlite-module.ts'), `
      import { Database } from 'bun:sqlite';
      import { drizzle } from ${JSON.stringify(drizzleUrl)};
      import { createFortress } from ${JSON.stringify(fortressUrl)};
      import { createSqliteDrizzleAdapter } from ${JSON.stringify(adapterUrl)};
      const sqlite = new Database(process.env.FORTRESS_CLI_TEST_DATABASE);
      sqlite.exec('PRAGMA foreign_keys = ON');
      export const fortress = createFortress({
        database: createSqliteDrizzleAdapter(drizzle(sqlite)),
        jwt: { key: 'x'.repeat(32) },
      });
      export function dispose() { sqlite.close(); }
    `);

    const result = runCli(
      cwd,
      ['migrate:up', '--module', './sqlite-module.ts'],
      { FORTRESS_CLI_TEST_DATABASE: databasePath },
    );
    expect(result.status, String(result.stderr)).toBe(0);
    expect(result.stdout).toContain('sqlite 5 -> 10; 5 applied');

    const verified = new Database(databasePath, { readonly: true });
    expect(verified.prepare('SELECT version FROM fortress_schema_version WHERE id = 1').pluck().get()).toBe(10);
    expect(verified.prepare('SELECT email FROM fortress_user WHERE id = ?').pluck().get(user.id)).toBe('tést@example.com');
    expect(verified.prepare('SELECT value FROM fortress_login_identifier WHERE user_id = ?').pluck().get(user.id)).toBe('tést@example.com');
    verified.close();
  }, 30_000);
});
