/**
 * Server-only Fortress instance.
 *
 * In a real SvelteKit project this lives at `src/lib/server/fortress.ts`
 * and is imported as `$lib/server/fortress`. The `lib/server/*` convention
 * guarantees the file never ends up in client bundles.
 */

import { createFortress } from '../../../../../src';
import { oauth } from '../../../../../src/plugins/oauth';
import { createTestAdapter } from '../../../../../src/testing';

export const fortress = createFortress({
  jwt: {
    key: process.env.JWT_SECRET ?? 'dev-secret-minimum-32-bytes-long!!',
    accessTokenExpirySeconds: 900,
    refreshTokenExpirySeconds: 60 * 60 * 24 * 7,
  },
  // In a real project, swap this for createSqliteDrizzleAdapter(...).
  database: createTestAdapter(),
  plugins: [
    oauth({
      issuerUrl: 'http://localhost:5173',
      // Pattern B (SPA-friendly) consent flow. The consent UI lives in
      // SvelteKit; Fortress just owns the state machine.
      enableAuthorizeEndpoint: true,
      enableConsentApi: true,
      // Where Fortress 302s the browser to. These are SvelteKit page paths
      // — host-relative because the API and the web app share an origin
      // in this example. For a cross-origin setup, use absolute URLs.
      loginUrl: '/login',
      consentUrl: '/oauth/consent',
      scopePermissionMap: {
        'read:posts': { resource: 'post', action: 'read' },
        'write:posts': { resource: 'post', action: 'create' },
      },
    }),
  ],
});

/**
 * Seed a demo user + OAuth client on startup so the example actually works
 * end-to-end against the in-memory adapter (which loses state on reload).
 *
 * Don't do this in production — register clients via your admin tooling and
 * persist them in your real database.
 */
export const demoSeedPromise: Promise<{ clientId: string; clientSecret: string }> = (async () => {
  // Demo user: alice@example.com / hunter2.
  // The in-memory adapter is wiped on each process boot, so we always
  // try to create — swallow conflicts if the module is re-evaluated.
  await fortress.auth
    .createUser({
      email: 'alice@example.com',
      name: 'Alice',
      password: 'hunter2',
    })
    .catch(() => undefined);

  // Demo OAuth client. clientId/clientSecret are returned only here, so we
  // log them so the README/CLI can use them.
  const client = await fortress.plugins.oauth.createClient({
    name: 'Example OAuth Client',
    redirectUris: ['http://localhost:5173/oauth/callback-demo'],
    grantTypes: ['authorization_code'],
  });
  if (!client.clientSecret)
    throw new Error('Demo OAuth client must be confidential');

  console.warn(
    `\n[fortress example] OAuth client seeded:\n  client_id=${client.clientId}\n  client_secret=${client.clientSecret}\n  redirect_uri=http://localhost:5173/oauth/callback-demo\n  Try: http://localhost:5173/api/oauth/authorize?client_id=${client.clientId}&redirect_uri=${encodeURIComponent('http://localhost:5173/oauth/callback-demo')}&response_type=code&state=xyz&scope=read:posts\n`,
  );

  return { clientId: client.clientId, clientSecret: client.clientSecret };
})();

// Surface seed errors loudly during dev startup instead of silently leaving
// the promise rejected (which would break the first OAuth flow attempt).
demoSeedPromise.catch((err: unknown) => {
  console.error('[fortress example] demo seed failed:', err);
});
