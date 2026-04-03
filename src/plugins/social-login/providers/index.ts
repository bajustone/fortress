import type { ProviderDefinition } from '../types';
import { appleProvider } from './apple';
import { discordProvider } from './discord';
import { githubProvider } from './github';
import { googleProvider } from './google';
import { createMicrosoftProvider } from './microsoft';

/** Built-in provider definitions keyed by name (Microsoft uses default 'common' tenant) */
export const builtInProviders: Record<string, ProviderDefinition> = {
  microsoft: createMicrosoftProvider(),
  google: googleProvider,
  github: githubProvider,
  apple: appleProvider,
  discord: discordProvider,
};

export { appleProvider } from './apple';
export { discordProvider } from './discord';
export { githubProvider } from './github';
export { googleProvider } from './google';
export { createMicrosoftProvider } from './microsoft';
export { createOidcProvider } from './oidc';
