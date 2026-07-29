import { describe, expect, it } from 'vitest';
import { findDocumentationDrift } from './docs-drift-policy.mjs';

const deprecatedSource = `
  export interface RbacOptions {
    /** @deprecated Use unmappedRoutes. */
    defaultDeny?: boolean;
  }
`;

describe('documentation drift policy', () => {
  it('accepts current API, secret, cookie, and version guidance', () => {
    const errors = findDocumentationDrift({
      'README.md': `unmappedRoutes: 'deny'`,
      'docs/hardening.md': '@bajustone/fortress@~1.0 follows semantic versioning',
      'examples/sveltekit-app/README.md': '`alice@example.com` / `correct-horse-battery-staple`',
      'examples/sveltekit-app/src/lib/server/fortress.ts': `
        cookies: { secure: false },
        email: 'alice@example.com',
        password: 'correct-horse-battery-staple',
      `,
      'src/hono/middleware/rbac.ts': deprecatedSource,
      'src/testing/index.ts': `jwt: { key: 'test-only-jwt-secret-at-least-32-bytes' }`,
    }, '1.0.2');

    expect(errors).toEqual([]);
  });

  it('derives deprecated options and the stable major from source', () => {
    const errors = findDocumentationDrift({
      'README.md': 'defaultDeny: true',
      'docs/hardening.md': '@bajustone/fortress@~0.1. Pre-1.0 Fortress',
      'src/hono/middleware/rbac.ts': deprecatedSource,
      'src/testing/index.ts': `jwt: { key: "test" }`,
    }, '1.0.2');

    expect(errors).toEqual(expect.arrayContaining([
      expect.stringContaining('deprecated option defaultDeny'),
      expect.stringContaining('obsolete pre-1.0 release line'),
      expect.stringContaining('obsolete pre-stable guidance'),
      expect.stringContaining('test/example secret shorter than 32 bytes'),
    ]));
  });

  it('binds documented SvelteKit credentials and cookie behavior to source', () => {
    const errors = findDocumentationDrift({
      'examples/sveltekit-app/README.md': '`alice@example.com` / `different-long-password`',
      'examples/sveltekit-app/src/lib/server/fortress.ts': `
        cookies: { secure: true },
        email: 'alice@example.com',
        password: 'correct-horse-battery-staple',
      `,
    });

    expect(errors).toEqual(expect.arrayContaining([
      expect.stringContaining('README credentials do not match'),
      expect.stringContaining('explicitly disable secure cookies'),
    ]));
  });
});
