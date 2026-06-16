/**
 * Built-in auth events. These go through the same registry + emit path as
 * user-defined events; the plugin merges them in by default and consumers can
 * exclude individual ones via `builtinEvents({ exclude })`.
 *
 * @module
 */

import type { WebhookEventDeclaration } from './types';

const BUILTIN: readonly WebhookEventDeclaration[] = [
  { name: 'auth.login.success', source: 'afterLogin', description: 'A user authenticated successfully.' },
  { name: 'auth.login.failure', source: 'onLoginFailure', description: 'A login attempt failed.' },
  { name: 'auth.logout', source: 'beforeLogout', description: 'A user logged out.' },
  { name: 'auth.user.registered', source: 'afterRegister', description: 'A new user was registered.' },
  { name: 'auth.token.refreshed', source: 'afterTokenRefresh', description: 'An access token was refreshed.' },
];

/** Names of the built-in auth events (for collision checks). */
export const BUILTIN_EVENT_NAMES: ReadonlySet<string> = new Set(BUILTIN.map(e => e.name));

/**
 * The built-in auth event declarations. Pass `{ exclude: [...] }` to drop
 * individual ones (their auto-emit hook then becomes a no-op).
 */
export function builtinEvents(opts: { exclude?: string[] } = {}): WebhookEventDeclaration[] {
  const all = BUILTIN.map(e => ({ ...e }));
  return opts.exclude ? all.filter(e => !opts.exclude!.includes(e.name)) : all;
}
