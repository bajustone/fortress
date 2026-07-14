import { spawnSync } from 'node:child_process';
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { afterAll, beforeAll, describe, expect, it } from 'vitest';

const CLI_PATH = fileURLToPath(new URL('../bin/fortress.ts', import.meta.url));
const RUNTIME_ERROR_RE = /(?:TypeError|ReferenceError|SyntaxError):/;

interface CommandCase {
  name: string;
  args: string[];
  expectedStatus?: number;
  output?: string;
}

function runCli(cwd: string, args: string[]): ReturnType<typeof spawnSync> {
  return spawnSync('bun', [CLI_PATH, ...args], {
    cwd,
    encoding: 'utf8',
    env: { ...process.env, NO_COLOR: '1' },
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
      // Unicode canonicalization requires the runtime migration hook, so SQL
      // export intentionally fails closed with a controlled diagnostic.
      { name: 'migrate:up', args: ['migrate:up'], expectedStatus: 1 },
      { name: 'migrate:down', args: ['migrate:down', '--out', 'down.sql'], output: 'down.sql' },
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
});
