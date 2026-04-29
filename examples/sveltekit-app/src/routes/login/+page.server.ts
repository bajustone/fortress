/**
 * `<form method="POST">` login.
 *
 * Reuses `fortressActions.login` for the actual auth work, then layers a
 * dynamic redirect on top so the same page can also be the landing pad
 * for the OAuth consent flow:
 *
 *   - regular login → /dashboard
 *   - OAuth consent flow (`?flow=<id>`) → /oauth/consent?flow=<id>
 *
 * The corresponding `+page.svelte`:
 *
 * ```svelte
 * <script>
 *   import { enhance } from '$app/forms';
 *   export let form;
 * </script>
 *
 * <form method="POST" use:enhance>
 *   <input name="identifier" required />
 *   <input name="password" type="password" required />
 *   {#if form?.error}<p class="error">{form.error}</p>{/if}
 *   <button>Log in</button>
 * </form>
 * ```
 */

import type { Actions } from '@sveltejs/kit';
import { redirect } from '@sveltejs/kit';
import { fortressActions } from '../../../../../src/sveltekit';
import { fortress } from '../../lib/server/fortress';

const baseLogin = fortressActions.login(fortress); // no static redirectTo

export const actions: Actions = {
  default: async (event) => {
    const result = await baseLogin(event);
    // Failed: bubble the form-fail object back so the page can render the error.
    if (result && 'error' in result)
      return result;

    // Success: pick destination based on whether we're mid-OAuth.
    const flow = event.url.searchParams.get('flow');
    if (flow)
      throw redirect(303, `/oauth/consent?flow=${encodeURIComponent(flow)}`);
    throw redirect(303, '/dashboard');
  },
};
