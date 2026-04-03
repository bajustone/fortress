import type { ProviderDefinition, ProviderProfile } from '../types';

/** GitHub uses custom OAuth2, not OIDC — no discovery URL */
export const githubProvider: ProviderDefinition = {
  name: 'github',
  authorizationUrl: 'https://github.com/login/oauth/authorize',
  tokenUrl: 'https://github.com/login/oauth/access_token',
  userInfoUrl: 'https://api.github.com/user',
  defaultScopes: ['read:user', 'user:email'],
  mapProfile(raw: Record<string, unknown>): ProviderProfile {
    return {
      id: String(raw.id ?? ''),
      email: String(raw.email ?? ''),
      name: String(raw.name ?? raw.login ?? ''),
      displayName: String(raw.name ?? raw.login ?? ''),
      avatar: raw.avatar_url ? String(raw.avatar_url) : undefined,
      raw,
    };
  },
};
