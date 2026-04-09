/**
 * Server-only Fortress instance.
 *
 * In a real SvelteKit project this lives at `src/lib/server/fortress.ts`
 * and is imported as `$lib/server/fortress`. The `lib/server/*` convention
 * guarantees the file never ends up in client bundles.
 */

import { createFortress } from '../../../../../src';
import { createTestAdapter } from '../../../../../src/testing';

export const fortress = createFortress({
  jwt: {
    secret: process.env.JWT_SECRET ?? 'dev-secret-minimum-32-bytes-long!!',
    accessTokenExpirySeconds: 900,
    refreshTokenExpirySeconds: 60 * 60 * 24 * 7,
  },
  // In a real project, swap this for createDrizzleAdapter(...).
  database: createTestAdapter(),
});
