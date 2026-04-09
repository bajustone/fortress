/**
 * SvelteKit `hooks.server.ts` — wires Fortress into the request pipeline.
 *
 * In a real project this is `src/hooks.server.ts` and uses `sequence` from
 * `@sveltejs/kit/hooks` to compose multiple handles. This example imports
 * via relative paths so it type-checks against the workspace fortress
 * source — adapt to `$lib/server/fortress` and `@sveltejs/kit/hooks` in
 * your own project.
 */

import { createSvelteKitHandle } from '../../../src/sveltekit';
import { fortress } from './lib/server/fortress';

// In a real SvelteKit project:
//   import { sequence } from '@sveltejs/kit/hooks';
//   export const handle = sequence(createSvelteKitHandle(fortress, { basePath: '/api' }));
export const handle = createSvelteKitHandle(fortress, {
  basePath: '/api',
  routeMap: {
    'GET /api/users': { resource: 'user', action: 'list' },
  },
  skipPaths: ['/api/health'],
});
