/**
 * SvelteKit `app.d.ts` — augments `App.Locals` so server load functions
 * see `event.locals.fortress` as a typed object instead of `unknown`.
 *
 * In a real project this lives at `src/app.d.ts`.
 */

import type { FortressLocals } from '../../../src/sveltekit';

declare global {
  namespace App {
    interface Locals extends FortressLocals {}
  }
}

export {};
