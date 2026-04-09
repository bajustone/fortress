/**
 * `<form method="POST">` login using `fortressActions.login`.
 *
 * In a real project, the corresponding `+page.svelte`:
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

import { fortressActions } from '../../../../../src/sveltekit';
import { fortress } from '../../lib/server/fortress';

export const actions = {
  default: fortressActions.login(fortress, { redirectTo: '/dashboard' }),
};
