/**
 * Optional catch-all `+server.ts` mounting. Useful when you want Fortress
 * routes colocated under your normal routes tree instead of intercepted in
 * `hooks.server.ts`. The handle hook approach in `hooks.server.ts` already
 * handles these paths — this file is here to demonstrate the escape hatch.
 *
 * Drop this file (and only this file) into a real SvelteKit project at
 * `src/routes/api/fortress/[...path]/+server.ts` to expose all Fortress
 * routes under `/api/fortress/...` without touching `hooks.server.ts`.
 */

import { toSvelteKitHandler } from '../../../../../../../src/sveltekit';
import { fortress } from '../../../../lib/server/fortress';

export const { GET, POST, PUT, DELETE, PATCH } = toSvelteKitHandler(fortress);
