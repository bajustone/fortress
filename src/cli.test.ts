import { spawnSync } from 'node:child_process';
import { existsSync, mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
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
      { name: 'manifest', args: ['manifest', '--out', 'manifest.json'], output: 'manifest.json' },
      { name: 'manifest:check', args: ['manifest:check'] },
      { name: 'check:routes', args: ['check:routes'] },
      { name: 'check:public-routes', args: ['check:public-routes'] },
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
