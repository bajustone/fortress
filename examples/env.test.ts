import { spawnSync } from 'node:child_process';
import { resolve } from 'node:path';
import { describe, expect, it } from 'vitest';
import { requireExampleEnv } from './env';

const root = resolve(import.meta.dirname, '..');

describe('example environment setup', () => {
  it('returns a configured value', () => {
    expect(requireExampleEnv('FORTRESS_EXAMPLE_VALUE', {
      FORTRESS_EXAMPLE_VALUE: 'configured',
    })).toBe('configured');
  });

  it('points clean environments to the setup file', () => {
    expect(() => requireExampleEnv('FORTRESS_TOTP_ENCRYPTION_KEY', {}))
      .toThrow('Missing FORTRESS_TOTP_ENCRYPTION_KEY. Copy .env.example to .env');
  });

  it('initializes the Hono app with documented development values', async () => {
    const originalTotpKey = process.env.FORTRESS_TOTP_ENCRYPTION_KEY;
    const originalBootstrapSecret = process.env.FORTRESS_ADMIN_BOOTSTRAP_SECRET;
    process.env.FORTRESS_TOTP_ENCRYPTION_KEY = 'test-only-totp-encryption-key!!!';
    process.env.FORTRESS_ADMIN_BOOTSTRAP_SECRET = 'test-only-bootstrap-secret';

    try {
      const { app, exampleReady } = await import('./hono-app/index');
      await exampleReady;
      const response = await app.request('/health');

      expect(response.status).toBe(200);
      await expect(response.json()).resolves.toEqual({ status: 'ok' });
    }
    finally {
      if (originalTotpKey === undefined)
        delete process.env.FORTRESS_TOTP_ENCRYPTION_KEY;
      else
        process.env.FORTRESS_TOTP_ENCRYPTION_KEY = originalTotpKey;
      if (originalBootstrapSecret === undefined)
        delete process.env.FORTRESS_ADMIN_BOOTSTRAP_SECRET;
      else
        process.env.FORTRESS_ADMIN_BOOTSTRAP_SECRET = originalBootstrapSecret;
    }
  }, 15_000);

  it('makes the documented dev command fail fast with the setup pointer', () => {
    const result = spawnSync('bun', ['run', 'examples/hono-app/index.ts'], {
      cwd: root,
      encoding: 'utf8',
      env: {
        ...process.env,
        FORTRESS_TOTP_ENCRYPTION_KEY: '',
      },
      timeout: 5_000,
    });
    const output = `${result.stdout ?? ''}\n${result.stderr ?? ''}`;

    expect(output).toContain(
      'Missing FORTRESS_TOTP_ENCRYPTION_KEY. Copy .env.example to .env',
    );
    expect(result.error?.message).toBeUndefined();
    expect(result.status).not.toBe(0);
  });
});
