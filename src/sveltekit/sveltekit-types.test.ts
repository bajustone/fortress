import type { Action, Handle, RequestHandler } from '@sveltejs/kit';
import type { Fortress } from '../core/fortress';
import { describe, expectTypeOf, it } from 'vitest';
import { fortressActions } from './actions';
import { toSvelteKitHandler } from './catch-all';
import { createSvelteKitHandle } from './handle';
import { protectedRoute } from './protect';

describe('sveltekit public type compatibility', () => {
  it('is assignable to the real strict @sveltejs/kit peer types', () => {
    // Compile-time only. Keeping these assignments in the normal tsc/vitest
    // suite prevents the public adapter surface drifting from the peer types.
    if (false) {
      const fortress = null as unknown as Fortress;
      const handle: Handle = createSvelteKitHandle(fortress);
      const loginAction: Action = fortressActions.login(fortress);
      const registerAction: Action = fortressActions.register(fortress);
      const handlers = toSvelteKitHandler(fortress);
      const get: RequestHandler = handlers.GET;
      const post: RequestHandler = handlers.POST;
      const protectedHandler: RequestHandler = protectedRoute(
        fortress,
        'hostRoute',
        async () => ({ ok: true }),
      );
      void [handle, loginAction, registerAction, get, post, protectedHandler];
    }

    expectTypeOf(createSvelteKitHandle).toBeFunction();
  });
});
